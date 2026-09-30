package capture

import (
	"strings"
	"testing"
)

// randomBytes — детерминированный псевдослучайный payload (xorshift64).
// Первые 4 байта обнулены: случайные значения там могли бы совпасть
// с сигнатурами WireGuard/OpenVPN и тест проверял бы не то, что задумано.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	s := uint64(0x9E3779B97F4A7C15)
	for i := 4; i < n; i++ {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		b[i] = byte(s >> 32)
	}
	return b
}

func TestWireGuardInitiation(t *testing.T) {
	p := make([]byte, 148)
	p[0] = 0x01
	det := detectVPN(p, protoUDP, 40000, 51820)
	if det == nil || det.Proto != "WireGuard" {
		t.Fatalf("WG initiation не пойман: %+v", det)
	}
}

func TestWireGuardResponse(t *testing.T) {
	p := make([]byte, 92)
	p[0] = 0x02
	det := detectVPN(p, protoUDP, 51820, 40000)
	if det == nil || det.Proto != "WireGuard" {
		t.Fatalf("WG response не пойман: %+v", det)
	}
}

func TestWireGuardBadReserved(t *testing.T) {
	p := make([]byte, 148)
	p[0] = 0x01
	p[1] = 0xFF // reserved != 0 — не handshake
	if det := detectVPN(p, protoUDP, 40000, 51820); det != nil {
		t.Fatalf("ложный WG: %+v", det)
	}
}

func TestOpenVPN(t *testing.T) {
	cases := []struct {
		name   string
		opcode uint8
		proto  string
	}{
		{"V2 client (UDP)", 0x07, protoUDP}, // добавлено в этой сессии
		{"V2 server (UDP)", 0x08, protoUDP}, // добавлено в этой сессии
		{"V3 client (UDP)", 0x0A, protoUDP},
		{"V3 (TCP)", 0x0A, protoTCP}, // opcode после 2-байтового префикса длины
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, 64)
			if tc.proto == protoTCP {
				p[2] = tc.opcode << 3 // p[0:2] — префикс длины (0)
			} else {
				p[0] = tc.opcode << 3
			}
			det := detectVPN(p, tc.proto, 40000, 1194)
			if det == nil || det.Proto != "OpenVPN" {
				t.Fatalf("OpenVPN не пойман: %+v", det)
			}
		})
	}
}

func TestIKEv2(t *testing.T) {
	for _, port := range []uint16{500, 4500} {
		p := make([]byte, 32)
		p[17] = 0x20 // версия IKEv2
		det := detectVPN(p, protoUDP, 40000, port)
		if det == nil || det.Proto != "IKEv2" {
			t.Fatalf("IKEv2 (порт %d) не пойман: %+v", port, det)
		}
	}
}

func TestEntropyDetection(t *testing.T) {
	t.Run("случайные данные, нестандартный порт", func(t *testing.T) {
		det := detectVPN(randomBytes(128), protoUDP, 40000, 8388)
		if det == nil || det.Proto != "obfs?" || det.Confidence != "low" {
			t.Fatalf("obfs? не пойман: %+v", det)
		}
	})

	t.Run("стандартные порты исключены", func(t *testing.T) {
		for _, port := range []uint16{443, 53, 80} {
			if det := detectVPN(randomBytes(128), protoUDP, 40000, port); det != nil {
				t.Fatalf("порт %d: ложное срабатывание: %+v", port, det)
			}
		}
	})

	t.Run("текст не считается случайным", func(t *testing.T) {
		text := []byte(strings.Repeat("HTTP/1.1 200 OK\r\n", 5))
		if det := detectVPN(text, protoUDP, 40000, 8388); det != nil {
			t.Fatalf("текст ложно опознан: %+v", det)
		}
	})

	t.Run("TCP: энтропийная эвристика не применяется", func(t *testing.T) {
		if det := detectVPN(randomBytes(128), protoTCP, 40000, 8388); det != nil {
			t.Fatalf("TCP-пакет ложно опознан: %+v", det)
		}
	})
}

func TestIsLikelyRandom(t *testing.T) {
	if !isLikelyRandom(randomBytes(64)) {
		t.Fatal("случайные данные не распознаны (порог 5.0)")
	}
	if isLikelyRandom([]byte(strings.Repeat("HTTP/1.1 200 OK\r\n", 4))) {
		t.Fatal("текст распознан как случайный")
	}
}

func TestNoFalsePositiveTLS(t *testing.T) {
	p := make([]byte, 200)
	p[0] = 0x16
	p[1], p[2] = 0x03, 0x01
	if det := detectVPN(p, protoUDP, 40000, 443); det != nil {
		t.Fatalf("TLS ложно опознан как VPN: %+v", det)
	}
}
