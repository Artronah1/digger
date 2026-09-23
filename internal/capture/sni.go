package capture

import (
	"encoding/binary"
)

// extractSNI достаёт server_name из TLS ClientHello.
// Возвращает "" если это не ClientHello или SNI отсутствует.
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

	// Идём по расширениям: type(2) length(2) data
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
