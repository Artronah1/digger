package proc

import (
	"bufio"
	"os"
	"strings"
)

// ArpEntry — одна запись из /proc/net/arp.
type ArpEntry struct {
	IP  string
	MAC string
}

// ScanARP читает /proc/net/arp и возвращает карту IP -> MAC.
func ScanARP() map[string]string {
	result := make(map[string]string)

	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		// Пропускаем нулевые MAC (незаполненные записи)
		if mac == "00:00:00:00:00:00" {
			continue
		}
		result[ip] = mac
	}
	return result
}

// DescribeMAC возвращает человекочитаемое описание MAC.
// "Realtek", "Apple", "random-mac", "multicast" или первые 3 байта.
func DescribeMAC(mac string) string {
	if mac == "" {
		return "unknown"
	}

	// Парсим первые 3 байта
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return "unknown"
	}

	firstByte := parseHexByte(parts[0])
	if firstByte == 0 {
		return "unknown"
	}

	// Multicast (младший бит первого байта = 1)
	if firstByte&0x01 != 0 {
		return "multicast"
	}
	// Locally administered (второй бит = 1)
	if firstByte&0x02 != 0 {
		return "random-mac"
	}

	// OUI lookup
	oui := strings.ToUpper(parts[0] + ":" + parts[1] + ":" + parts[2])
	if vendor, ok := ouiTable[oui]; ok {
		return vendor
	}

	return oui
}

func parseHexByte(s string) byte {
	if len(s) != 2 {
		return 0
	}
	var b byte
	for i := 0; i < 2; i++ {
		c := s[i]
		var v byte
		switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			default:
				return 0
		}
		b = b<<4 | v
	}
	return b
}

// Мини-база OUI для популярных вендоров.
// Формат: "AA:BB:CC" -> "Vendor".
var ouiTable = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
	"00:0D:93": "Apple", "00:10:FA": "Apple", "00:11:24": "Apple",
	"00:14:51": "Apple", "00:16:CB": "Apple", "00:17:F2": "Apple",
	"00:19:E3": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple",
	"00:1D:4F": "Apple", "00:1E:C2": "Apple", "00:1F:5B": "Apple",
	"00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
	"00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple",
	"00:23:DF": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
	"00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
	"00:26:B0": "Apple", "00:26:BB": "Apple",
	"04:0C:CE": "Apple", "04:15:52": "Apple", "04:1E:64": "Apple",
	"04:26:65": "Apple", "04:48:9A": "Apple", "04:54:53": "Apple",
	"04:69:F8": "Apple", "04:D3:CF": "Apple", "04:DB:56": "Apple",
	"04:E5:36": "Apple", "04:F1:3E": "Apple", "04:F7:E4": "Apple",
	"08:66:98": "Apple", "08:6D:41": "Apple", "08:70:45": "Apple",
	"08:74:02": "Apple",
	"10:40:F3": "Apple", "10:93:E9": "Apple", "10:9A:DD": "Apple",
	"10:DD:B1": "Apple",
	// Samsung
	"00:12:FB": "Samsung", "00:13:77": "Samsung", "00:15:99": "Samsung",
	"00:16:32": "Samsung", "00:16:6B": "Samsung", "00:16:6C": "Samsung",
	"00:16:DB": "Samsung", "00:17:C9": "Samsung", "00:17:D5": "Samsung",
	"00:18:AF": "Samsung", "00:1A:8A": "Samsung", "00:1B:98": "Samsung",
	"00:1C:43": "Samsung", "00:1D:25": "Samsung", "00:1D:F6": "Samsung",
	"00:1E:7D": "Samsung", "00:1E:E1": "Samsung", "00:1E:E2": "Samsung",
	"00:1F:CC": "Samsung", "00:1F:CD": "Samsung", "00:21:19": "Samsung",
	"00:21:D1": "Samsung", "00:21:D2": "Samsung", "00:23:39": "Samsung",
	"00:23:3A": "Samsung", "00:23:D6": "Samsung", "00:23:D7": "Samsung",
	"00:24:54": "Samsung", "00:24:90": "Samsung", "00:24:91": "Samsung",
	"00:25:38": "Samsung", "00:25:66": "Samsung", "00:25:67": "Samsung",
	"00:26:37": "Samsung", "00:26:5D": "Samsung", "00:26:5F": "Samsung",
	// Xiaomi
	"00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "08:8E:90": "Xiaomi",
	"0C:1D:AF": "Xiaomi", "10:2A:B3": "Xiaomi", "14:F6:5A": "Xiaomi",
	"18:0F:76": "Xiaomi", "18:59:36": "Xiaomi", "20:34:FB": "Xiaomi",
	"20:47:DA": "Xiaomi", "20:A7:83": "Xiaomi", "24:CF:24": "Xiaomi",
	"28:6C:07": "Xiaomi", "28:E3:1F": "Xiaomi", "2C:9D:1E": "Xiaomi",
	"34:80:B3": "Xiaomi", "34:CE:00": "Xiaomi", "38:A4:ED": "Xiaomi",
	// Realtek
	"00:E0:4C": "Realtek", "52:54:00": "Realtek/QEMU", "00:0C:29": "VMware",
	// Intel
	"00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
	"00:0E:0C": "Intel", "00:0E:35": "Intel", "00:11:11": "Intel",
	"00:12:F0": "Intel", "00:13:02": "Intel", "00:13:20": "Intel",
	"00:13:CE": "Intel", "00:13:E8": "Intel", "00:15:00": "Intel",
	"00:15:17": "Intel", "00:16:6F": "Intel", "00:16:76": "Intel",
	"00:16:EA": "Intel", "00:16:EB": "Intel", "00:18:DE": "Intel",
	"00:19:D1": "Intel", "00:19:D2": "Intel", "00:1A:A0": "Intel",
	"00:1B:21": "Intel", "00:1B:77": "Intel", "00:1C:BF": "Intel",
	"00:1D:E0": "Intel", "00:1D:E1": "Intel", "00:1E:64": "Intel",
	"00:1E:65": "Intel", "00:1E:67": "Intel", "00:1F:3B": "Intel",
	"00:1F:3C": "Intel", "00:21:5C": "Intel", "00:21:5D": "Intel",
	"00:21:6A": "Intel", "00:21:6B": "Intel", "00:22:FB": "Intel",
	"00:23:14": "Intel", "00:23:15": "Intel", "00:24:D6": "Intel",
	"00:24:D7": "Intel", "00:26:C6": "Intel", "00:26:C7": "Intel",
	"08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
	"00:1C:42": "Parallels", "00:05:69": "VMware", "00:50:56": "VMware",
	"00:1C:14": "VMware", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
	"00:15:5D": "Microsoft", "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
	// Espressif (ESP8266/ESP32 — умные лампы, розетки)
	"24:0A:C4": "Espressif", "24:6F:28": "Espressif", "2C:3A:E8": "Espressif",
	"30:AE:A4": "Espressif", "3C:61:05": "Espressif", "3C:71:BF": "Espressif",
	"40:F5:20": "Espressif", "48:3F:DA": "Espressif", "4C:11:AE": "Espressif",
	"54:5A:A6": "Espressif", "5C:CF:7F": "Espressif", "60:01:94": "Espressif",
	"68:C6:3A": "Espressif", "70:03:9F": "Espressif", "7C:9E:BD": "Espressif",
	"80:64:6F": "Espressif", "84:0D:8E": "Espressif", "84:F3:EB": "Espressif",
	"8C:AA:B5": "Espressif", "90:97:D5": "Espressif", "A0:20:A6": "Espressif",
	"A4:7B:9D": "Espressif", "A4:CF:12": "Espressif", "AC:D0:74": "Espressif",
	"B4:E6:2D": "Espressif", "BC:DD:C2": "Espressif", "C4:4F:33": "Espressif",
	"CC:50:E3": "Espressif", "D8:F1:5B": "Espressif", "DC:4F:22": "Espressif",
	"EC:FA:BC": "Espressif", "F4:CF:A2": "Espressif", "FC:F5:C4": "Espressif",
	// Tuya (умный дом)
	"10:52:1C": "Tuya", "18:69:D8": "Tuya", "50:02:91": "Tuya",
	"68:57:2D": "Tuya", "D8:1F:12": "Tuya",
	// TP-Link
	"00:1D:0F": "TP-Link", "00:21:27": "TP-Link", "00:23:CD": "TP-Link",
	"00:25:86": "TP-Link", "00:27:19": "TP-Link", "10:FE:ED": "TP-Link",
	"14:CC:20": "TP-Link", "14:CF:92": "TP-Link", "18:A6:F7": "TP-Link",
	"1C:3B:F3": "TP-Link", "1C:FA:68": "TP-Link", "20:16:D8": "TP-Link",
	"28:2C:B2": "TP-Link", "28:87:BA": "TP-Link", "30:B5:C2": "TP-Link",
	"34:60:F9": "TP-Link", "3C:46:D8": "TP-Link", "3C:84:6A": "TP-Link",
	"40:16:9F": "TP-Link", "44:94:FC": "TP-Link", "48:0E:EC": "TP-Link",
	"4C:E1:73": "TP-Link", "50:64:2B": "TP-Link", "50:C7:BF": "TP-Link",
	"54:A7:03": "TP-Link", "54:C8:0F": "TP-Link", "58:D5:6E": "TP-Link",
	"5C:63:BF": "TP-Link", "5C:89:9A": "TP-Link", "60:32:B1": "TP-Link",
	"60:3A:7C": "TP-Link", "64:56:01": "TP-Link", "64:66:B3": "TP-Link",
	"64:70:02": "TP-Link", "68:FF:7B": "TP-Link",
	"6C:5A:B0": "TP-Link", "70:4F:57": "TP-Link", "74:DA:88": "TP-Link",
	"78:44:76": "TP-Link", "78:8C:B5": "TP-Link", "7C:8B:CA": "TP-Link",
	"80:EA:07": "TP-Link", "84:16:F9": "TP-Link", "88:25:93": "TP-Link",
	"8C:21:0A": "TP-Link", "90:9A:4A": "TP-Link", "94:0C:6D": "TP-Link",
	"98:DA:C4": "TP-Link", "9C:53:22": "TP-Link", "A0:40:A0": "TP-Link",
	"A4:2B:B0": "TP-Link", "A8:57:4E": "TP-Link", "AC:15:A2": "TP-Link",
	"AC:84:C6": "TP-Link", "B0:4E:26": "TP-Link", "B0:95:75": "TP-Link",
	"B4:B0:24": "TP-Link", "B8:F8:83": "TP-Link", "BC:46:99": "TP-Link",
	"C0:06:C3": "TP-Link", "C0:25:E9": "TP-Link", "C0:4A:00": "TP-Link",
	"C4:6E:1F": "TP-Link", "C4:E9:84": "TP-Link", "C8:D7:19": "TP-Link",
	"CC:32:E5": "TP-Link", "CC:68:B6": "TP-Link", "D0:76:E7": "TP-Link",
	"D4:6E:0E": "TP-Link", "D8:07:B6": "TP-Link", "D8:47:32": "TP-Link",
	"DC:9F:DB": "TP-Link", "E4:C3:2A": "TP-Link", "E8:48:B8": "TP-Link",
	"E8:94:F6": "TP-Link", "E8:DE:27": "TP-Link", "EC:08:6B": "TP-Link",
	"EC:17:2F": "TP-Link", "F0:9F:C2": "TP-Link", "F4:28:53": "TP-Link",
	"F4:EC:38": "TP-Link", "F8:1A:67": "TP-Link", "F8:D1:11": "TP-Link",
	"FC:7C:02": "TP-Link",
}
