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
	"time"
)

// QUIC v1 salt (RFC 9001).
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// --- Кэш клиентских DCID ---

// Ключи серверного Initial выводятся из DCID клиентского Initial, которого
// в серверском пакете нет: запоминаем SCID клиента → его DCID.
// TTL обязателен — без него sync.Map растёт бесконечно (запись на каждый
// QUIC-коннект).
const quicDCIDTTL = 10 * time.Minute

type quicDCIDEntry struct {
	dcid []byte
	at   time.Time
}

var (
	clientDCIDsBySCID sync.Map // string(SCID) → quicDCIDEntry
	dcidsSweepMu      sync.Mutex
	dcidsLastSweep    time.Time
)

func rememberClientDCID(scid, dcid []byte) {
	clientDCIDsBySCID.Store(string(scid), quicDCIDEntry{dcid: dcid, at: time.Now()})

	// Ленивая уборка — не чаще двух раз за TTL.
	dcidsSweepMu.Lock()
	due := time.Since(dcidsLastSweep) > quicDCIDTTL/2
	dcidsSweepMu.Unlock()
	if due {
		sweepClientDCIDs(time.Now().Add(-quicDCIDTTL))
	}
}

func lookupClientDCID(serverDCID []byte) ([]byte, bool) {
	v, ok := clientDCIDsBySCID.Load(string(serverDCID))
	if !ok {
		return nil, false
	}
	e, ok := v.(quicDCIDEntry)
	if !ok || time.Since(e.at) > quicDCIDTTL {
		return nil, false
	}
	return e.dcid, true
}

func sweepClientDCIDs(cutoff time.Time) {
	clientDCIDsBySCID.Range(func(key, value any) bool {
		if e, ok := value.(quicDCIDEntry); ok && e.at.Before(cutoff) {
			clientDCIDsBySCID.Delete(key)
		}
		return true
	})
	dcidsSweepMu.Lock()
	dcidsLastSweep = time.Now()
	dcidsSweepMu.Unlock()
}

// --- Ключи ---

// hkdfExpandLabel реализует TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label

	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, fullLabel...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	return hkdf.Expand(sha256.New, secret, string(hkdfLabel), length)
}

// deriveInitialKeys выводит initial key/iv/hp из DCID (RFC 9001 §5.2).
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

	if key, err = hkdfExpandLabel(secret, "quic key", nil, 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = hkdfExpandLabel(secret, "quic iv", nil, 12); err != nil {
		return nil, nil, nil, err
	}
	hp, err = hkdfExpandLabel(secret, "quic hp", nil, 16)
	return key, iv, hp, err
}

// --- Разбор Initial ---

// quicInitialInfo — информация о QUIC Initial пакете.
type quicInitialInfo struct {
	DCID       []byte
	SCID       []byte
	TokenLen   int
	PayloadLen int

	Header        []byte // Long Header до начала PN (для AAD и снятия защиты)
	ProtectedPart []byte // PN + шифротекст + тег
	PNOffset      int
}

// parseQUICInitial проверяет, что payload — QUIC v1 Initial, и извлекает поля.
func parseQUICInitial(payload []byte) (*quicInitialInfo, bool) {
	if len(payload) < 7 {
		return nil, false
	}

	// Long Header (0x80) + fixed bit (0x40) + тип Initial (биты 5-4 = 00).
	first := payload[0]
	if first&0xC0 != 0xC0 || first&0x30 != 0x00 {
		return nil, false
	}

	version := binary.BigEndian.Uint32(payload[1:5])
	if version != 1 {
		return nil, false // только QUIC v1
	}

	pos := 5
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

	// Token Length (varint) + токен.
	tokenLen, n := readVarint(payload[pos:])
	if n == 0 {
		return nil, false
	}
	pos += n + int(tokenLen)
	if pos > len(payload) {
		return nil, false
	}

	// Length (varint) — PN + payload + тег.
	lengthVal, n := readVarint(payload[pos:])
	if n == 0 {
		return nil, false
	}
	pos += n

	protectedEnd := pos + int(lengthVal)
	if protectedEnd > len(payload) {
		protectedEnd = len(payload) // обрезанный кадр — дешифровка не пройдёт
	}

	return &quicInitialInfo{
		DCID:          dcid,
		SCID:          scid,
		TokenLen:      int(tokenLen),
		PayloadLen:    int(lengthVal),
		Header:        payload[:pos],
		ProtectedPart: payload[pos:protectedEnd],
		PNOffset:      pos,
	}, true
}

// decryptInitial снимает защиту и расшифровывает Initial,
// возвращая plaintext (фреймы QUIC, обычно CRYPTO с ClientHello).
func decryptInitial(info *quicInitialInfo, isServer bool) ([]byte, error) {
	// Sample для снятия защиты заголовка: 16 байт, начиная с 4 после PN.
	const sampleOffset, sampleLen = 4, 16
	if len(info.ProtectedPart) < sampleOffset+sampleLen {
		return nil, fmt.Errorf("protected part too short: %d", len(info.ProtectedPart))
	}
	if len(info.DCID) == 0 {
		return nil, fmt.Errorf("empty DCID")
	}

	key, iv, hp, err := deriveInitialKeys(info.DCID, isServer)
	if err != nil {
		return nil, err
	}

	// Снятие защиты заголовка (RFC 9001 §5.4.3):
	// для Long Header защищены младшие 4 бита первого байта и PN.
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	sample := info.ProtectedPart[sampleOffset : sampleOffset+sampleLen]
	var mask [sampleLen]byte
	hpBlock.Encrypt(mask[:], sample)

	flags := info.Header[0] ^ (mask[0] & 0x0F)
	if flags&0xF0 != 0xC0 {
		return nil, fmt.Errorf("not Initial after unprotect: flags=0x%02x", flags)
	}
	pnLen := int(flags&0x03) + 1

	// Packet number. Это truncated-кодировка; для первых Initial (а только
	// они нам и нужны — там ClientHello) совпадает с полным значением.
	// На поздних пакетах GCM-аутентификация просто не сойдётся — fail-safe.
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = info.ProtectedPart[i] ^ mask[1+i]
	}
	var pn uint64
	for _, b := range pnBytes {
		pn = pn<<8 | uint64(b)
	}

	// Nonce = IV XOR PN (PN в младших байтах).
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}

	// AAD = заголовок (с уже снятой защитой флагов) + PN.
	aad := make([]byte, 0, len(info.Header)+pnLen)
	aad = append(aad, info.Header...)
	aad = append(aad, pnBytes...)
	aad[0] = flags

	// Шифротекст — всё после PN (включая 16-байтный тег).
	if pnLen >= len(info.ProtectedPart) {
		return nil, fmt.Errorf("no ciphertext")
	}
	ciphertext := info.ProtectedPart[pnLen:]

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, ciphertext, aad)
}

// --- Точка входа ---

// extractQUICSNI парсит QUIC Initial и извлекает SNI.
// Порты задают направление: клиентский Initial (→443) расшифровывается
// клиентскими ключами; серверный (←443) — серверными, для которых нужен
// DCID клиентского Initial (ищем по SCID). srcIP/dstIP не используются —
// сигнатура сохранена для единообразия вызова.
func extractQUICSNI(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) string {
	info, ok := parseQUICInitial(payload)
	if !ok {
		return ""
	}
	if info.PayloadLen < 100 {
		return "" // ClientHello меньше не бывает
	}
	if info.TokenLen > 0 {
		return "" // Initial после Retry (с токеном) не разбираем
	}

	switch {
	case dstPort == portHTTPS: // клиентский Initial
		if len(info.SCID) > 0 && len(info.DCID) > 0 {
			rememberClientDCID(info.SCID, info.DCID)
		}
		plaintext, err := decryptInitial(info, false)
		if err != nil {
			return ""
		}
		return extractSNIFromCrypto(plaintext)

	case srcPort == portHTTPS: // серверный Initial
		clientDCID, ok := lookupClientDCID(info.DCID)
		if !ok {
			return "" // клиентский Initial не видели
		}
		// Ключи серверного Initial выводятся из DCID клиентского.
		info.DCID = clientDCID
		plaintext, err := decryptInitial(info, true)
		if err != nil {
			return ""
		}
		return extractSNIFromCrypto(plaintext)
	}
	return ""
}

// --- Разбор расшифрованного payload ---

// extractSNIFromCrypto ищет CRYPTO-фрейм (type 6) и извлекает SNI
// из TLS ClientHello внутри него.
func extractSNIFromCrypto(plaintext []byte) string {
	pos := 0
	for pos < len(plaintext) {
		frameType := plaintext[pos]
		pos++

		switch frameType {
		case 0x00, 0x01: // PADDING, PING — однобайтовые
			continue

		case 0x06: // CRYPTO: offset(varint) + length(varint) + data
			_, n := readVarint(plaintext[pos:]) // offset — в Initial всегда 0
			if n == 0 {
				return "" // обрезано
			}
			pos += n

			length, n := readVarint(plaintext[pos:])
			if n == 0 {
				return "" // обрезано
			}
			pos += n

			if pos+int(length) > len(plaintext) {
				return "" // обрезано
			}
			cryptoData := plaintext[pos : pos+int(length)]
			pos += int(length) // ВАЖНО: ровно один раз (было дважды)

			if sni := sniFromCryptoData(cryptoData); sni != "" {
				return sni
			}

		default:
			// 0x02/0x03 (ACK) и прочее: формат ACK сложен, а SNI там нет.
			// Initial с ClientHello идёт первым — дальше не ищем.
			return ""
		}
	}
	return ""
}

// sniFromCryptoData извлекает SNI из данных CRYPTO-фрейма.
func sniFromCryptoData(cryptoData []byte) string {
	// Вариант 1: TLS-record (handshake внутри записи).
	if sni := extractSNI(cryptoData); sni != "" {
		return sni
	}
	// Вариант 2: рукопожатие без записи (в QUIC запись не используется).
	if len(cryptoData) >= 4 && cryptoData[0] == 0x01 {
		if sni := extractClientHelloSNI(cryptoData); sni != "" {
			return sni
		}
	}
	// Вариант 3 (эвристика): нестандартный преамбул с plaintext-именем
	// (встречался у y.googlevideo.com). Оставлена как есть — сработает
	// только на расшифрованных (прошедших GCM) данных.
	return sniFromASCIIPreamble(cryptoData)
}

// sniFromASCIIPreamble: данные начинаются с буквы и идут печатаемыми
// байтами до NUL/непечатаемого; отрезок с точкой считаем именем хоста.
func sniFromASCIIPreamble(cryptoData []byte) string {
	if len(cryptoData) < 4 {
		return ""
	}
	c := cryptoData[0]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return ""
	}
	end := 0
	for end < len(cryptoData) && end < 256 {
		b := cryptoData[end]
		if b == 0 || b < 0x20 || b > 0x7E {
			break
		}
		end++
	}
	if end == 0 || end >= len(cryptoData) {
		return ""
	}
	name := string(cryptoData[:end])
	if strings.Contains(name, ".") {
		return name
	}
	return ""
}

// --- Varint ---

// readVarint читает QUIC varint (RFC 9000 §16), возвращает (value, длина).
// n == 0 — данные кончились раньше varint.
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch b[0] & 0xC0 {
	case 0x00:
		return uint64(b[0] & 0x3F), 1
	case 0x40:
		if len(b) < 2 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint16(b[:2]) & 0x3FFF), 2
	case 0x80:
		if len(b) < 4 {
			return 0, 0
		}
		return uint64(binary.BigEndian.Uint32(b[:4]) & 0x3FFFFFFF), 4
	default:
		if len(b) < 8 {
			return 0, 0
		}
		return binary.BigEndian.Uint64(b[:8]) & 0x3FFFFFFFFFFFFFFF, 8
	}
}

// --- ClientHello ---

// extractClientHelloSNI парсит ClientHello напрямую, без TLS-record
// обёртки (в QUIC CRYPTO запись не используется).
func extractClientHelloSNI(data []byte) string {
	if len(data) < 4 || data[0] != 0x01 { // handshake type = ClientHello
		return ""
	}
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hsLen {
		hsLen = len(data) - 4 // обрезано: парсим то, что есть
	}
	body := data[4 : 4+hsLen]

	// legacy_version(2) + random(32) = 34 байта; далее session_id.
	// Проверка "< 35": читаем body[34] — при ровно 34 была паника.
	if len(body) < 35 {
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
			return serverNameFromExt(body[pos : pos+extLen])
		}
		pos += extLen
	}
	return ""
}

// serverNameFromExt разбирает данные расширения server_name.
func serverNameFromExt(ext []byte) string {
	// list_len(2) + type(1, 0x00 = host_name) + name_len(2) + name.
	if len(ext) < 5 || ext[2] != 0x00 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
	if len(ext) < 5+nameLen {
		return ""
	}
	return string(ext[5 : 5+nameLen])
}
