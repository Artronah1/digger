package capture

import (
	"math"
)

type VPNDetection struct {
	Proto      string // "WireGuard", "OpenVPN", "IKEv2", "obfs?"
	Port       uint16
	Confidence string // "high", "medium", "low"
}

// detectVPN проверяет payload на сигнатуры VPN. Возвращает nil, если не похоже.
func detectVPN(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16) *VPNDetection {
	// --- WireGuard ---
	// Handshake initiation: type=1, reserved=0, затем sender index (4).
	// Фиксированный размер 148 байт (initiation), 92 (response).
	if len(payload) == 148 && payload[0] == 0x01 &&
		payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00 {
		return &VPNDetection{Proto: "WireGuard", Port: dstPort, Confidence: "high"}
	}
	if len(payload) == 92 && payload[0] == 0x02 &&
		payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00 {
		return &VPNDetection{Proto: "WireGuard", Port: dstPort, Confidence: "high"}
	}

	// --- OpenVPN ---
	// opcode = payload[0] >> 3.
	if len(payload) >= 14 {
		opcode := payload[0] >> 3
		if opcode == 0x0A || opcode == 0x0B { // HARD_RESET_CLIENT_V2/V3
			return &VPNDetection{Proto: "OpenVPN", Port: dstPort, Confidence: "high"}
		}
	}

	// --- IKEv2 ---
	// UDP/500 или UDP/4500, version byte = 0x20 (IKEv2).
	if (dstPort == 500 || dstPort == 4500) && len(payload) >= 28 {
		version := payload[17]
		if version&0xF0 == 0x20 {
			return &VPNDetection{Proto: "IKEv2", Port: dstPort, Confidence: "high"}
		}
	}

	// --- Shadowsocks / obfs: эвристика по энтропии ---
	// Не на стандартных портах, нет TLS/QUIC заголовков, высокая энтропия.
	if len(payload) >= 64 && dstPort != 443 && dstPort != 53 && dstPort != 80 {
		if isLikelyRandom(payload[:64]) {
			return &VPNDetection{Proto: "obfs?", Port: dstPort, Confidence: "low"}
		}
	}

	return nil
}

// isLikelyRandom — грубая оценка энтропии Шеннона.
// Случайные байты дают ~8 бит/байт, текст/структуры — заметно меньше.
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
	return h > 7.5
}
