package capture

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// clientDCIDsBySCID хранит связку SCID клиента → DCID клиента.
// Нужна для расшифровки серверных Initial: их ключи выводятся
// из DCID клиентского Initial, который в серверном пакете не виден.
var clientDCIDsBySCID sync.Map

// QUIC v1 salt из RFC 9001
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExpandLabel реализует TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label

	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	return hkdf.Expand(sha256.New, secret, string(hkdfLabel), length)
}

// quicInitialInfo — информация о QUIC Initial пакете.
type quicInitialInfo struct {
	Version    uint32
	DCID       []byte
	SCID       []byte
	TokenLen   int
	PayloadLen int

	// Данные для расшифровки
	Header        []byte // Long Header + PN (для расчёта nonce)
	ProtectedPart []byte // зашифрованная часть (payload + tag)
	PNOffset      int    // смещение packet number в Header
}

// parseQUICInitial проверяет, что payload — QUIC Initial, и извлекает поля.
func parseQUICInitial(payload []byte) (*quicInitialInfo, bool) {
	if len(payload) < 7 {
		return nil, false
	}

	first := payload[0]
	if first&0x80 == 0 {
		return nil, false
	}
	if first&0x40 == 0 {
		return nil, false
	}
	packetType := (first & 0x30) >> 4
	if packetType != 0 {
		return nil, false
	}

	version := binary.BigEndian.Uint32(payload[1:5])
	if version != 1 {
		return nil, false
	}

	pos := 5
	if pos >= len(payload) {
		return nil, false
	}
	dcidLen := int(payload[pos])
	pos++
	if pos+dcidLen > len(payload) {
		return nil, false
	}
	dcid := payload[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(payload) {
		return nil, false
	}
	scidLen := int(payload[pos])
	pos++
	if pos+scidLen > len(payload) {
		return nil, false
	}
	scid := payload[pos : pos+scidLen]
	pos += scidLen

	// Token Length (varint)
	tokenLen, n := readVarint(payload[pos:])
	pos += n
	pos += int(tokenLen)
	if pos > len(payload) {
		return nil, false
	}

	// Length (varint)
	lengthVal, n := readVarint(payload[pos:])
	pos += n

	pnOffset := pos
	protectedStart := pos
		protectedEnd := pos + int(lengthVal)
			if protectedEnd > len(payload) {
				protectedEnd = len(payload)
			}

			return &quicInitialInfo{
				Version:       version,
				DCID:          dcid,
				SCID:          scid,
				PayloadLen:    int(lengthVal),
				Header:        payload[:protectedStart],
				ProtectedPart: payload[protectedStart:protectedEnd],
				PNOffset:      pnOffset,
			}, true
}

// deriveInitialKeys выводит client initial key, iv и hp из DCID.
func deriveInitialKeys(dcid []byte, isServer bool) (key, iv, hp []byte, err error) {
	label := "client in"
	if isServer {
		label = "server in"
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return nil, nil, nil, err
	}

	secret, err := hkdfExpandLabel(initialSecret, label, nil, 32)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err = hkdfExpandLabel(secret, "quic key", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}

	iv, err = hkdfExpandLabel(secret, "quic iv", nil, 12)
	if err != nil {
		return nil, nil, nil, err
	}

	hp, err = hkdfExpandLabel(secret, "quic hp", nil, 16)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// decryptInitial пытается расшифровать QUIC Initial и вернуть plaintext.
// Если успешно — возвращает CRYPTO-фрейм (содержит TLS ClientHello).
func decryptInitial(info *quicInitialInfo, isServer bool) ([]byte, error) {
	if len(info.ProtectedPart) < 24 {
		return nil, fmt.Errorf("ProtectedPart too short: %d", len(info.ProtectedPart))
	}
	if len(info.DCID) == 0 {
		return nil, fmt.Errorf("empty DCID")
	}
	if len(info.Header) == 0 {
		return nil, fmt.Errorf("empty Header")
	}

	key, iv, hp, err := deriveInitialKeys(info.DCID, isServer)
	if err != nil {
		return nil, err
	}

	// Снимаем header protection
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	sampleOffset := 4
	sample := info.ProtectedPart[sampleOffset : sampleOffset+16]

	mask := make([]byte, 16)
	block.Encrypt(mask, sample)

	// Восстанавливаем FLAGS (первый байт packet, лежит в info.Header[0])
	flags := info.Header[0] ^ (mask[0] & 0x0F)

	// Проверяем, что после снятия защиты это Long Header Initial
	if flags&0xF0 != 0xC0 {
		return nil, fmt.Errorf("not Initial: flags=0x%02x", flags)
	}

	pnLen := int(flags&0x03) + 1

	// Восстанавливаем packet number
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = info.ProtectedPart[i] ^ mask[1+i]
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(pnBytes[i])
	}

	// Nonce = iv XOR pn (pn в последних байтах)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	// AAD = Long Header + восстановленный PN
	aad := make([]byte, 0, len(info.Header)+pnLen)
	aad = append(aad, info.Header...)      // flags + version + DCID + SCID + Token + Length
	aad = append(aad, pnBytes...)          // восстановленный PN
	aad[0] = flags                     // flags с снятой protection

	// Зашифрованные данные — всё после PN
	encryptedStart := pnLen
	if encryptedStart > len(info.ProtectedPart) {
		return nil, fmt.Errorf("no ciphertext")
	}
	ciphertext := info.ProtectedPart[encryptedStart:]

	// AES-GCM decrypt
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// extractQUICSNI парсит QUIC Initial и извлекает SNI.
func extractQUICSNI(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) string {
	info, ok := parseQUICInitial(payload)
	if !ok {
		return ""
	}
	if info.PayloadLen < 100 {
		return ""
	}
	if info.TokenLen > 0 {
		return ""
	}

	// Клиентский Initial (dstPort == 443)
	if dstPort == 443 {
		// Запоминаем SCID клиента → DCID клиента
		if len(info.SCID) > 0 && len(info.DCID) > 0 {
			clientDCIDsBySCID.Store(string(info.SCID), info.DCID)
		}
		plaintext, err := decryptInitial(info, false)
		if err != nil {
			return ""
		}
		return extractSNIFromCrypto(plaintext)
	}

	// Серверный Initial (srcPort == 443)
	if srcPort == 443 {
		// DCID серверного пакета = SCID клиента.
		// Ищем клиентский DCID по этому SCID.
		realDCID, ok := clientDCIDsBySCID.Load(string(info.DCID))
		if !ok {
			return ""
		}
		// Подменяем DCID на клиентский — server keys выводятся из него
		savedDCID := info.DCID
		info.DCID = realDCID.([]byte)
		plaintext, err := decryptInitial(info, true)
		info.DCID = savedDCID // восстанавливаем на случай отладки
		if err != nil {
			return ""
		}
		return extractSNIFromCrypto(plaintext)
	}

	return ""
}

// extractSNIFromCrypto ищет CRYPTO frame (type 6) и внутри — TLS ClientHello.
func extractSNIFromCrypto(plaintext []byte) string {
	pos := 0
	for pos < len(plaintext) {
		frameType := plaintext[pos]
		pos++

		switch frameType {
			case 0x00: // PADDING
				continue
			case 0x01: // PING
				continue
			case 0x02, 0x03: // ACK
				// Слишком сложно парсить, пропускаем
				return ""
			case 0x06: // CRYPTO
				_, n := readVarint(plaintext[pos:])
				pos += n
				length, n := readVarint(plaintext[pos:])
				pos += n
				if pos+int(length) > len(plaintext) {
					return ""
				}
				cryptoData := plaintext[pos : pos+int(length)]

				// Попытка 1: TLS ClientHello (с TLS-record обёрткой)
				if sni := extractSNI(cryptoData); sni != "" {
					return sni
				}

				// Попытка 2: raw ClientHello (handshake без record)
				if len(cryptoData) >= 4 && cryptoData[0] == 0x01 {
					if sni := extractClientHelloSNI(cryptoData); sni != "" {
						return sni
					}
				}

				// Попытка 3: QUIC preamble с plaintext SNI (y.googlevideo.com)
				// Если данные начинаются с ASCII-буквы и содержат точку — это SNI.
				if len(cryptoData) >= 4 {
					c := cryptoData[0]
					if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
						// Ищем точку и конец имени (NUL или непечатаемый байт)
						end := 0
						for end < len(cryptoData) && end < 256 {
							b := cryptoData[end]
							if b == 0 {
								break
							}
							if b < 0x20 || b > 0x7E {
								break
							}
							end++
						}
						if end > 0 && end < len(cryptoData) {
							name := string(cryptoData[:end])
							// Простейшая проверка: имя должно содержать точку
							if strings.Contains(name, ".") {
								return name
							}
						}
					}
				}

				pos += int(length)

				// Отладка: показываем первые байты CRYPTO
				headLen := 32
				if len(cryptoData) < headLen {
					headLen = len(cryptoData)
				}

				// Пробуем оба варианта: с TLS-record заголовком и без
				if sni := extractSNI(cryptoData); sni != "" {
					return sni
				}

				// Если не сработало — возможно, это handshake без TLS-record (raw)
				if len(cryptoData) >= 4 && cryptoData[0] == 0x01 {
					// ClientHello напрямую
					if sni := extractClientHelloSNI(cryptoData); sni != "" {
						fmt.Printf("[CRYPTO-DBG] FOUND SNI (raw)=%s\n", sni)
						return sni
					}
				}

				pos += int(length)
			default:
				return ""
		}
	}
	return ""
}

// readVarint читает QUIC varint и возвращает (value, bytesConsumed).
// RFC 9000: 1-байтный (0xxxxxxx), 2-байтный (10xxxxxx), 4-байтный (110xxxxx), 8-байтный (1110xxxx).
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	first := b[0]
	switch first & 0xC0 {
		case 0x00:
			// 1 байт
			return uint64(first & 0x3F), 1
		case 0x40:
			// 2 байта
			if len(b) < 2 {
				return 0, 0
			}
			return uint64(binary.BigEndian.Uint16(b[:2]) & 0x3FFF), 2
		case 0x80:
			// 4 байта
			if len(b) < 4 {
				return 0, 0
			}
			return uint64(binary.BigEndian.Uint32(b[:4]) & 0x3FFFFFFF), 4
		case 0xC0:
			// 8 байт
			if len(b) < 8 {
				return 0, 0
			}
			return binary.BigEndian.Uint64(b[:8]) & 0x3FFFFFFFFFFFFFFF, 8
	}
	return 0, 0
}

// extractClientHelloSNI парсит handshake-запись ClientHello напрямую,
// без TLS-record обёртки. Используется для QUIC CRYPTO.
func extractClientHelloSNI(data []byte) string {
	// data начинается с handshake: type(1) length(3) ...
	if len(data) < 4 {
		return ""
	}
	if data[0] != 0x01 { // ClientHello
		return ""
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		// Данные обрезаны — SNI может быть в следующем CRYPTO
		if len(data) < 4+hsLen {
			hsLen = len(data) - 4
		}
	}
	body := data[4 : 4+hsLen]

	// Парсим так же, как в extractSNI, но без 5-байтного TLS-заголовка
	if len(body) < 34 {
		return ""
	}
	pos := 34
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(body) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(body) {
		return ""
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen
	if pos+2 > len(body) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(body) {
		end = len(body)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 0x0000 { // server_name
			data := body[pos : pos+extLen]
			if len(data) < 5 {
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if len(data) < 5+nameLen {
				break
			}
			return string(data[5 : 5+nameLen])
		}
		pos += extLen
	}

	return ""
}
