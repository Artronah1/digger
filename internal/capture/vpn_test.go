package capture

import "testing"

func TestWireGuardInitiation(t *testing.T) {
	p := make([]byte, 148)
	p[0] = 0x01
	det := detectVPN(p, "192.168.1.2", "1.2.3.4", 40000, 51820)
	if det == nil || det.Proto != "WireGuard" {
		t.Fatalf("WG initiation не пойман: %+v", det)
	}
}

func TestWireGuardResponse(t *testing.T) {
	p := make([]byte, 92)
	p[0] = 0x02
	det := detectVPN(p, "1.2.3.4", "192.168.1.2", 51820, 40000)
	if det == nil || det.Proto != "WireGuard" {
		t.Fatalf("WG response не пойман: %+v", det)
	}
}

func TestOpenVPN(t *testing.T) {
	p := make([]byte, 64)
	p[0] = 0x0A << 3
	det := detectVPN(p, "192.168.1.2", "1.2.3.4", 40000, 1194)
	if det == nil || det.Proto != "OpenVPN" {
		t.Fatalf("OpenVPN не пойман: %+v", det)
	}
}

func TestIKEv2(t *testing.T) {
	p := make([]byte, 64)
	p[17] = 0x20
	det := detectVPN(p, "192.168.1.2", "1.2.3.4", 40000, 500)
	if det == nil || det.Proto != "IKEv2" {
		t.Fatalf("IKEv2 не пойман: %+v", det)
	}
}

func TestNoFalsePositiveTLS(t *testing.T) {
	p := make([]byte, 200)
	p[0] = 0x16
	p[1], p[2] = 0x03, 0x01
	if det := detectVPN(p, "192.168.1.2", "1.2.3.4", 40000, 443); det != nil {
		t.Fatalf("TLS ложно опознан как VPN: %+v", det)
	}
}
