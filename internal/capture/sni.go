package capture

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ECHSentinel — маркер, что SNI скрыт ECH.
const ECHSentinel = "__ECH__"

// extractSNI достаёт server_name из TLS ClientHello.
// Возвращает "" если это не ClientHello или SNI отсутствует.
// Возвращает ECHSentinel если ClientHello есть, но SNI скрыт ECH (extension 0xfe0d).
func extractSNI(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}
	// TLS record: content_type(1) version(2) length(2)
	if payload[0] != 0x16 { // handshake
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return ""
	}
	hs := payload[5 : 5+recordLen]

	// Handshake: type(1) length(3)
	if len(hs) < 4 || hs[0] != 0x01 { // ClientHello
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4 : 4+hsLen]

	// ClientHello: version(2) random(32) session_id_len(1)+session_id
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

	sni := ""
	hasECH := false

	// Идём по расширениям: type(2) length(2) data
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		switch extType {
		case 0x0000: // server_name
			data := body[pos : pos+extLen]
			if len(data) < 5 {
				break
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if len(data) < 5+nameLen {
				break
			}
			sni = string(data[5 : 5+nameLen])
		case 0xfe0d: // encrypted_client_hello
			hasECH = true
		}
		pos += extLen
	}

	if sni != "" {
		return sni
	}
	if hasECH {
		return ECHSentinel
	}
	return ""
}

// extractJA3 вычисляет JA3-отпечаток TLS-клиента.
// Возвращает hex-строку (32 символа) или "" если не ClientHello.
//
// JA3 = MD5(version,ciphers,extensions,curves,formats)
// https://github.com/salesforce/ja3
func extractJA3(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}
	if payload[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return ""
	}
	hs := payload[5 : 5+recordLen]

	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4 : 4+hsLen]

	// version(2) random(32)
	if len(body) < 34 {
		return ""
	}
	tlsVersion := binary.BigEndian.Uint16(body[0:2])
	pos := 34

	// session_id
	if pos >= len(body) {
		return ""
	}
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen

	// cipher suites
	if pos+2 > len(body) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	ciphersEnd := pos + cipherSuitesLen
	if ciphersEnd > len(body) {
		return ""
	}
	var ciphers []string
	for pos+2 <= ciphersEnd {
		cs := binary.BigEndian.Uint16(body[pos : pos+2])
		ciphers = append(ciphers, fmt.Sprintf("%d", cs))
		pos += 2
	}

	// compression
	if pos+1 > len(body) {
		return ""
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen

	// extensions
	if pos+2 > len(body) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(body) {
		end = len(body)
	}

	var extensions []string
	var curves []string
	var pointFormats []string

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		extensions = append(extensions, fmt.Sprintf("%d", extType))

		switch extType {
		case 0x000a: // supported_groups
			data := body[pos : pos+extLen]
			if len(data) >= 2 {
				listLen := int(binary.BigEndian.Uint16(data[0:2]))
				p := 2
				for p+2 <= 2+listLen && p+2 <= len(data) {
					g := binary.BigEndian.Uint16(data[p : p+2])
					curves = append(curves, fmt.Sprintf("%d", g))
					p += 2
				}
			}
		case 0x000b: // ec_point_formats
			data := body[pos : pos+extLen]
			if len(data) >= 1 {
				formatsLen := int(data[0])
				for i := 1; i <= formatsLen && i < len(data); i++ {
					pointFormats = append(pointFormats, fmt.Sprintf("%d", data[i]))
				}
			}
		}
		pos += extLen
	}

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(pointFormats, "-"),
	)

	hash := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

// extractJA4 вычисляет JA4-отпечаток TLS-клиента.
// Возвращает строку формата "t13d1516h2_8daaf6152771_b186203b1338" или "".
//
// https://github.com/FoxIO-LLC/ja4
func extractJA4(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}
	if payload[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return ""
	}
	hs := payload[5 : 5+recordLen]

	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4 : 4+hsLen]

	if len(body) < 34 {
		return ""
	}
	tlsVersion := binary.BigEndian.Uint16(body[0:2])
	pos := 34

	if pos >= len(body) {
		return ""
	}
	sessionIDLen := int(body[pos])
	pos += 1 + sessionIDLen

	// cipher suites
	if pos+2 > len(body) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	ciphersEnd := pos + cipherSuitesLen
	if ciphersEnd > len(body) {
		return ""
	}
	var ciphers []uint16
	for pos+2 <= ciphersEnd {
		cs := binary.BigEndian.Uint16(body[pos : pos+2])
		ciphers = append(ciphers, cs)
		pos += 2
	}

	// compression
	if pos+1 > len(body) {
		return ""
	}
	compressionLen := int(body[pos])
	pos += 1 + compressionLen

	// extensions
	if pos+2 > len(body) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extensionsLen
	if end > len(body) {
		end = len(body)
	}

	var extensions []uint16
	var sigAlgs []uint16
	hasSNI := false
	alpn := ""

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		extensions = append(extensions, extType)

		switch extType {
		case 0x0000: // server_name
			hasSNI = true
		case 0x0010: // ALPN
			data := body[pos : pos+extLen]
			if len(data) >= 3 {
				// alpn_list_length(2) + proto_length(1) + proto
				protoLen := int(data[2])
				if 3+protoLen <= len(data) {
					alpn = string(data[3 : 3+protoLen])
				}
			}
		case 0x000d: // signature_algorithms
			data := body[pos : pos+extLen]
			if len(data) >= 2 {
				listLen := int(binary.BigEndian.Uint16(data[0:2]))
				p := 2
				for p+2 <= 2+listLen && p+2 <= len(data) {
					sa := binary.BigEndian.Uint16(data[p : p+2])
					sigAlgs = append(sigAlgs, sa)
					p += 2
				}
			}
		}
		pos += extLen
	}

	// version: t13 = TLS 1.3, t12 = TLS 1.2
	versionStr := "t12"
	if tlsVersion == 0x0304 || tlsVersion == 0x0303 {
		versionStr = "t13"
	}

	// sni: d = domain, i = ip
	sniStr := "i"
	if hasSNI {
		sniStr = "d"
	}

	// alpn: h2 = h2, h1 = http/1.1, ...
	alpnStr := "00"
	switch alpn {
	case "h2":
		alpnStr = "h2"
	case "http/1.1":
		alpnStr = "h1"
	case "h3":
		alpnStr = "h3"
	}

	// cipher+ext hash
	ceString := ""
	for _, c := range ciphers {
		ceString += fmt.Sprintf("%04x,", c)
	}
	for _, e := range extensions {
		ceString += fmt.Sprintf("%04x,", e)
	}
	ceHash := md5.Sum([]byte(ceString))
	ceHex := hex.EncodeToString(ceHash[:])[:12]

	// sig algs hash
	saString := ""
	for _, sa := range sigAlgs {
		saString += fmt.Sprintf("%04x,", sa)
	}
	saHash := md5.Sum([]byte(saString))
	saHex := hex.EncodeToString(saHash[:])[:12]

	return fmt.Sprintf("%s%s%02d%02d%s_%s_%s",
		versionStr, sniStr,
		len(ciphers), len(extensions),
		alpnStr,
		ceHex, saHex)
}
