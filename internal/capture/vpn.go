package capture

import "math"

type VPNDetection struct {
	Proto      string // "WireGuard", "OpenVPN", "IKEv2", "obfs?"
	Port       uint16
	Confidence string // "high", "medium", "low"
}

// detectVPN проверяет payload на сигнатуры VPN-протоколов; nil — не похоже.
// proto нужен: OpenVPN поверх TCP имеет 2-байтовый префикс длины
// (opcode в payload[2]), а энтропийная эвристика осмысленна для UDP
// (иначе TLS-данные на нестандартном TCP-порту флажились как obfs?).
func detectVPN(payload []byte, proto string, srcPort, dstPort uint16) *VPNDetection {
	switch proto {
	case protoUDP:
		return detectVPNUDP(payload, dstPort)
	case protoTCP:
		return detectVPNTCP(payload, dstPort)
	}
	return nil
}

func detectVPNUDP(payload []byte, dstPort uint16) *VPNDetection {
	// WireGuard initiation: 148 байт, type=1, reserved=0, mac2 (последние 16) = 0.
	if len(payload) == 148 && payload[0] == 0x01 &&
		payload[1] == 0 && payload[2] == 0 && payload[3] == 0 &&
		isAllZero(payload[132:148]) {
		return &VPNDetection{Proto: "WireGuard", Port: dstPort, Confidence: "high"}
	}
	// WireGuard response: 92 байта, type=2, reserved=0, mac2 (последние 16) = 0.
	if len(payload) == 92 && payload[0] == 0x02 &&
		payload[1] == 0 && payload[2] == 0 && payload[3] == 0 &&
		isAllZero(payload[76:92]) {
		return &VPNDetection{Proto: "WireGuard", Port: dstPort, Confidence: "high"}
	}

	// OpenVPN (UDP): opcode = payload[0] >> 3.
	if len(payload) >= 16 {
		if d := openvpnReset(payload[0]>>3, dstPort); d != nil {
			return d
		}
	}

	// IKEv2: UDP/500 или UDP/4500, версия (0x20) в байте 17.
	if (dstPort == 500 || dstPort == 4500) && len(payload) >= 28 &&
		payload[17]&0xF0 == 0x20 {
		return &VPNDetection{Proto: "IKEv2", Port: dstPort, Confidence: "high"}
	}

	// Shadowsocks/obfs: высокая энтропия на нестандартном порту.
	if len(payload) >= entropySample &&
		dstPort != portHTTPS && dstPort != portDNS && dstPort != 80 {
		if isLikelyRandom(payload[:entropySample]) {
			return &VPNDetection{Proto: "obfs?", Port: dstPort, Confidence: "low"}
		}
	}
	return nil
}

func detectVPNTCP(payload []byte, dstPort uint16) *VPNDetection {
	// OpenVPN over TCP: 2-байтовый префикс длины, opcode в payload[2].
	if len(payload) >= 16 {
		if d := openvpnReset(payload[2]>>3, dstPort); d != nil {
			return d
		}
	}
	return nil
}

// openvpnReset: HARD_RESET клиента/сервера.
// V2 — 0x07/0x08 (классический, раньше НЕ детектился), V3 — 0x0A/0x0B.
func openvpnReset(opcode uint8, dstPort uint16) *VPNDetection {
	switch opcode {
	case 0x07, 0x08, 0x0A, 0x0B:
		return &VPNDetection{Proto: "OpenVPN", Port: dstPort, Confidence: "high"}
	}
	return nil
}

const (
	entropySample    = 64
	entropyThreshold = 5.0
)

// isLikelyRandom — эмпирическая энтропия Шеннона.
//
// ВАЖНО: энтропия по N байтам не превышает log2(N): для 64 байт
// максимум 6 бит/байт. Порог 7.5 в прежней версии был недостижим —
// эвристика не срабатывала никогда. Случайные данные дают ~5.7,
// текст/структуры — до ~4.5.
func isLikelyRandom(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h > entropyThreshold
}

// isAllZero возвращает true, если все байты равны нулю.
func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
