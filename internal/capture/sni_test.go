package capture

import (
	"encoding/binary"
	"testing"
)

// buildClientHello собирает минимальный ClientHello с extensions.
func buildClientHello(extensions []byte) []byte {
	// Тело ClientHello
	body := make([]byte, 0)
	body = append(body, 0x03, 0x03)                                      // version TLS 1.2
	body = append(body, make([]byte, 32)...)                             // random
	body = append(body, 0x00)                                            // session_id_len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01)                          // cipher_suites (1)
	body = append(body, 0x01, 0x00)                                      // compression
	body = append(body, byte(len(extensions)>>8), byte(len(extensions))) // extensions_len
	body = append(body, extensions...)

	// Handshake
	hs := make([]byte, 0)
	hs = append(hs, 0x01)                                                     // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body))) // length
	hs = append(hs, body...)

	// TLS record
	rec := make([]byte, 0)
	rec = append(rec, 0x16, 0x03, 0x01)                // content_type, version
	rec = append(rec, byte(len(hs)>>8), byte(len(hs))) // length
	rec = append(rec, hs...)

	return rec
}

func TestExtractSNI_NoECH(t *testing.T) {
	name := "example.com"
	nameBytes := []byte(name)
	listLen := 1 + 2 + len(nameBytes) // name_type + name_len + name

	sniExt := make([]byte, 0)
	sniExt = append(sniExt, 0x00, 0x00)                            // type = server_name
	sniExt = append(sniExt, byte((2+listLen)>>8), byte(2+listLen)) // ext length
	sniExt = append(sniExt, byte(listLen>>8), byte(listLen))       // server_name_list length
	sniExt = append(sniExt, 0x00)                                  // name_type = host_name
	sniExt = append(sniExt, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	sniExt = append(sniExt, nameBytes...)

	ch := buildClientHello(sniExt)
	got := extractSNI(ch)
	if got != name {
		t.Fatalf("expected %q, got %q", name, got)
	}
}

func TestExtractSNI_WithECH(t *testing.T) {
	// extension encrypted_client_hello (0xfe0d)
	echExt := []byte{0xfe, 0x0d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	ch := buildClientHello(echExt)
	got := extractSNI(ch)
	if got != ECHSentinel {
		t.Fatalf("expected ECHSentinel, got %q", got)
	}
}

func TestExtractSNI_NoSNINoECH(t *testing.T) {
	// другой extension (ALPN)
	alpnExt := []byte{0x00, 0x10, 0x00, 0x03, 0x02, 'h', '2'}
	ch := buildClientHello(alpnExt)
	got := extractSNI(ch)
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// _ = binary для подавления unused
var _ = binary.BigEndian
