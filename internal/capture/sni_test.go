package capture

import (
	"encoding/binary"
	"testing"
)

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

func TestExtractJA3_Valid(t *testing.T) {
	// ClientHello с одним расширением
	alpnExt := []byte{0x00, 0x10, 0x00, 0x03, 0x02, 'h', '2'}
	ch := buildClientHello(alpnExt)
	got := extractJA3(ch)
	if got == "" {
		t.Fatal("JA3 пустой")
	}
	if len(got) != 32 {
		t.Fatalf("JA3 должен быть 32 hex, получили %d", len(got))
	}
	// Проверяем hex
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("JA3 не hex: %q", got)
		}
	}
}
