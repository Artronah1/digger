package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// testdataPath возвращает путь к тестовому PCAP.
func testdataPath(name string) string {
	return filepath.Join("testdata", name)
}

// runPCAP прогоняет PCAP через digger и возвращает Capture.
func runPCAP(t *testing.T, name string) *Capture {
	t.Helper()

	path := testdataPath(name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("testdata/%s не найден", name)
	}

	c, err := NewFromPCAP(path, false)
	if err != nil {
		t.Fatalf("NewFromPCAP: %v", err)
	}

	// Отключаем печать — тесты должны быть чистыми
	c.SetQuiet(true)

	// Читаем весь файл
	c.RunFromPCAP()

	return c
}

func TestRegression_DNS(t *testing.T) {
	c := runPCAP(t, "dns.pcap")
	defer c.Close()

	// Проверяем, что пакеты прочитаны
	if c.stats.PacketsReceived == 0 {
		t.Fatal("не прочитано ни одного пакета")
	}

	if c.stats.PacketsProcessed != c.stats.PacketsReceived {
		t.Errorf("received=%d, processed=%d — есть потери",
			c.stats.PacketsReceived, c.stats.PacketsProcessed)
	}

	// Проверяем, что Capture Health = complete
	if c.stats.PacketsTruncated > 0 {
		t.Errorf("truncated=%d — snaplen мал", c.stats.PacketsTruncated)
	}
	if c.stats.DecodeErrors > 0 {
		t.Errorf("decode_errors=%d", c.stats.DecodeErrors)
	}

	// Проверяем, что есть DNS-запросы
	dnsCount := c.dnsTable.Len()
	if dnsCount == 0 {
		t.Error("DNS-запросы не найдены")
	}
	t.Logf("DNS-запросов: %d", dnsCount)

	// Проверяем, что есть DNS-наблюдения
	obs := c.dnsMapping.SnapshotObservations()
	if len(obs) == 0 {
		t.Error("DNS-наблюдения не найдены")
	}
	t.Logf("DNS-наблюдений: %d", len(obs))
}

func TestRegression_ECH(t *testing.T) {
	// Проверяем, что extractSNI правильно обрабатывает ECH
	// (это уже в sni_test.go, но здесь — интеграционно)
	echExt := []byte{0xfe, 0x0d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}
	ch := buildClientHello(echExt)
	got := extractSNI(ch)
	if got != ECHSentinel {
		t.Errorf("expected ECHSentinel, got %q", got)
	}
}

func TestRegression_ClassifyFlow(t *testing.T) {
	// Проверяем базовую классификацию
	// ECH → direct
	f := &FlowStats{ECH: true}
	if ClassifyFlow(f, nil) != ClassDirect {
		t.Error("ECH должен быть direct")
	}

	// VPN → vpn
	f = &FlowStats{VPNProto: "WireGuard"}
	if ClassifyFlow(f, nil) != ClassVPN {
		t.Error("VPN должен быть vpn")
	}

	// Пустой → unknown
	f = &FlowStats{}
	if ClassifyFlow(f, nil) != ClassUnknown {
		t.Error("пустой должен быть unknown")
	}
}
