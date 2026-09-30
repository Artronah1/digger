package capture

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ECHSentinel — маркер, что SNI скрыт ECH.
const ECHSentinel = "__ECH__"

// --- Типы расширений ---

const (
	extServerName        = 0x0000
	extSupportedGroups   = 0x000a
	extECPointFormats    = 0x000b
	extSignatureAlgs     = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
	extECH               = 0xfe0d
)

// --- Разбор ClientHello (один на все три fingerprint-а) ---

// clientHello — разобранный ClientHello. Раньше запись и рукопожатие
// парсились одним и тем же кодом в extractSNI/extractJA3/extractJA4.
type clientHello struct {
	version   uint16   // legacy_version
	supported []uint16 // supported_versions (0x002b)
	ciphers   []uint16 // порядок как в пакете
	extTypes  []uint16 // порядок как в пакете
	curves    []uint16 // supported_groups
	pointFmt  []byte   // ec_point_formats
	sigAlgs   []uint16 // signature_algorithms
	sni       string
	hasSNI    bool
	hasECH    bool
	alpn      string // первый протокол из ALPN
}

// parseClientHello разбирает TLS-запись и ClientHello.
// nil — не ClientHello или данные обрезаны.
func parseClientHello(payload []byte) *clientHello {
	// TLS record: content_type(1) version(2) length(2).
	if len(payload) < 5 || payload[0] != 0x16 { // handshake
		return nil
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return nil
	}
	hs := payload[5 : 5+recordLen]

	// Handshake: type(1) length(3).
	if len(hs) < 4 || hs[0] != 0x01 { // ClientHello
		return nil
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return nil
	}
	body := hs[4 : 4+hsLen]

	// legacy_version(2) + random(32) = 34 байта, затем session_id.
	// Проверка "< 35": читаем body[34] — при ровно 34 была паника.
	if len(body) < 35 {
		return nil
	}

	ch := &clientHello{version: binary.BigEndian.Uint16(body[0:2])}

	pos := 34
	if pos >= len(body) {
		return nil
	}
	pos += 1 + int(body[pos]) // session_id

	// Cipher suites: length(2) + список по 2 байта.
	if pos+2 > len(body) {
		return nil
	}
	ciphersLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	ciphersEnd := pos + ciphersLen
	if ciphersEnd > len(body) {
		return nil
	}
	for ; pos+2 <= ciphersEnd; pos += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(body[pos:]))
	}

	// Compression: length(1) + методы.
	if pos >= len(body) {
		return nil
	}
	pos += 1 + int(body[pos])

	// Extensions: length(2) + список type(2) len(2) data.
	if pos+2 > len(body) {
		return nil
	}
	extsLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	end := pos + extsLen
	if end > len(body) {
		end = len(body) // обрезано — парсим что есть
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		data := body[pos : pos+extLen]
		pos += extLen

		ch.extTypes = append(ch.extTypes, extType)
		ch.parseExt(extType, data)
	}

	return ch
}

func (ch *clientHello) parseExt(t uint16, data []byte) {
	switch t {
	case extServerName:
		if ch.sni == "" {
			ch.sni = serverNameFromExt(data) // общий хелпер из quic.go
		}
		ch.hasSNI = true

	case extSupportedGroups:
		if len(data) >= 2 {
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			for p := 2; p+2 <= len(data) && p < 2+listLen; p += 2 {
				ch.curves = append(ch.curves, binary.BigEndian.Uint16(data[p:]))
			}
		}

	case extECPointFormats:
		if len(data) >= 1 {
			n := int(data[0])
			for i := 1; i <= n && i < len(data); i++ {
				ch.pointFmt = append(ch.pointFmt, data[i])
			}
		}

	case extSignatureAlgs:
		if len(data) >= 2 {
			listLen := int(binary.BigEndian.Uint16(data[:2]))
			for p := 2; p+2 <= len(data) && p < 2+listLen; p += 2 {
				ch.sigAlgs = append(ch.sigAlgs, binary.BigEndian.Uint16(data[p:]))
			}
		}

	case extALPN:
		// alpn_list(2) + proto_len(1) + proto: берём первый протокол.
		if len(data) >= 4 {
			protoLen := int(data[2])
			if 3+protoLen <= len(data) {
				ch.alpn = string(data[3 : 3+protoLen])
			}
		}

	case extSupportedVersions:
		if len(data) >= 1 {
			n := int(data[0])
			for i := 0; i < n; i++ {
				p := 1 + 2*i
				if p+2 > len(data) {
					break
				}
				ch.supported = append(ch.supported, binary.BigEndian.Uint16(data[p:]))
			}
		}

	case extECH:
		ch.hasECH = true
	}
}

// maxTLSVersion — максимум из supported_versions, иначе legacy_version.
func (ch *clientHello) maxTLSVersion() uint16 {
	v := ch.version
	for _, sv := range ch.supported {
		if sv > v && sv <= 0x0304 {
			v = sv
		}
	}
	return v
}

// --- SNI ---

// extractSNI достаёт server_name из TLS ClientHello.
// "" — не ClientHello или SNI нет; ECHSentinel — SNI скрыт ECH.
func extractSNI(payload []byte) string {
	ch := parseClientHello(payload)
	if ch == nil {
		return ""
	}
	if ch.sni != "" {
		return ch.sni
	}
	if ch.hasECH {
		return ECHSentinel
	}
	return ""
}

// --- JA3 ---

// extractJA3 вычисляет JA3-отпечаток TLS-клиента.
// https://github.com/salesforce/ja3
//
// GREASE-значения исключаются — раньше включались, и отпечатки
// не совпадали с публичными JA3-базами.
func extractJA3(payload []byte) string {
	ch := parseClientHello(payload)
	if ch == nil {
		return ""
	}

	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s",
		ch.version,
		joinDec(dropGREASE(ch.ciphers), "-"),
		joinDec(dropGREASE(ch.extTypes), "-"),
		joinDec(dropGREASE(ch.curves), "-"),
		joinDec(ch.pointFmt, "-"),
	)

	sum := md5.Sum([]byte(ja3)) //nolint:gosec // MD5 предписан спецификацией JA3
	return hex.EncodeToString(sum[:])
}

// --- JA4 ---

// extractJA4 вычисляет JA4-отпечаток TLS-клиента.
// https://github.com/FoxIO-LLC/ja4 (technical_details.md)
//
// Прежняя реализация расходилась со спецификацией: MD5 вместо SHA-256,
// без сортировки, GREASE/SNI/ALPN не исключались, без "_" между
// списками, десятичные счётчики, версия из legacy_version (0x0303 →
// "t13" почти всегда). Сверь результат с тест-векторами FoxIO
// (ja4/test_vectors) — хеши после этой правки полностью другие.
func extractJA4(payload []byte) string {
	ch := parseClientHello(payload)
	if ch == nil {
		return ""
	}

	// Список расширений для JA4: без GREASE, SNI и ALPN —
	// последние вынесены в поля d/i и ALPN.
	var exts []uint16
	for _, e := range ch.extTypes {
		if isGREASE(e) || e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}

	sniCode := "i"
	if ch.hasSNI {
		sniCode = "d"
	}

	alpnCode := "00"
	if len(ch.alpn) >= 2 {
		alpnCode = ch.alpn[:2] // первые два символа первого протокола
	}

	ciphers := dropGREASE(ch.ciphers)
	nCiphers := len(ciphers)
	slices.Sort(ciphers)
	slices.Sort(exts)

	// Часть 1: t + версия + d/i + шифры(2hex) + расширения(2hex) + ALPN.
	// Часть 2: SHA-256(ciphers,exts) — отсортированные. Часть 3: SHA-256(sigalgs).
	return fmt.Sprintf("t%s%s%02x%02x%s_%s_%s",
		tlsVersionCode(ch.maxTLSVersion()), sniCode, nCiphers, len(exts), alpnCode,
		sha256Hex12(joinHex(ciphers)+"_"+joinHex(exts)),
		sha256Hex12(joinHex(ch.sigAlgs)))
}

func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	default:
		return "10"
	}
}

// --- Хелперы ---

// isGREASE: 0x0a0a, 0x1a1a, …, 0xfafa (RFC 8701).
func isGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0x0f == 0x0a
}

func dropGREASE(v []uint16) []uint16 {
	out := make([]uint16, 0, len(v))
	for _, x := range v {
		if !isGREASE(x) {
			out = append(out, x)
		}
	}
	return out
}

func joinDec[T uint16 | byte](v []T, sep string) string {
	if len(v) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range v {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	}
	return b.String()
}

func joinHex(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%04x", x)
	}
	return b.String()
}

func sha256Hex12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
