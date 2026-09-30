package capture

import (
	"bytes"
	"encoding/binary"
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

	// Изолируемся от реального ~/.digger (AnomalyDetector при создании
	// читает его) — тесты не должны зависеть от истории машины.
	t.Setenv("HOME", t.TempDir())

	path := testdataPath(name)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("testdata/%s не найден: %v", name, err)
	}

	c, err := NewFromPCAP(path, false)
	if err != nil {
		t.Fatalf("NewFromPCAP: %v", err)
	}
	c.SetQuiet(true) // тесты должны быть чистыми

	c.RunFromPCAP()
	return c
}

// --- Хелперы сборки ClientHello ---
// NOTE: если buildClientHello уже определён в sni_test.go — оставь
// одно определение, иначе redeclaration.

// buildClientHello собирает минимальный валидный TLS ClientHello
// с заданными расширениями (каждое — готовые type(2)+len(2)+data).
func buildClientHello(exts ...[]byte) []byte {
	var extBuf bytes.Buffer
	for _, e := range exts {
		extBuf.Write(e)
	}
	extsBytes := extBuf.Bytes()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0)              // session_id_len
	body.Write([]byte{0x00, 0x02}) // cipher_suites_len
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(1)              // compression methods len
	body.WriteByte(0)              // null

	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extsBytes)))
	body.Write(extLen[:])
	body.Write(extsBytes)
	bodyBytes := body.Bytes()

	var out bytes.Buffer
	out.Write([]byte{0x16, 0x03, 0x01}) // handshake record, TLS 1.2
	var recLen [2]byte
	binary.BigEndian.PutUint16(recLen[:], uint16(len(bodyBytes)+4))
	out.Write(recLen[:])
	out.WriteByte(0x01) // ClientHello
	out.WriteByte(byte(len(bodyBytes) >> 16))
	out.WriteByte(byte(len(bodyBytes) >> 8))
	out.WriteByte(byte(len(bodyBytes)))
	out.Write(bodyBytes)
	return out.Bytes()
}

// sniExt — расширение server_name для одного имени.
func sniExt(name string) []byte {
	nameLen := make([]byte, 2)
	binary.BigEndian.PutUint16(nameLen, uint16(len(name)))

	// list: type(1, host_name) + name_len(2) + name
	list := append(append([]byte{0x00}, nameLen...), name...)
	listLen := make([]byte, 2)
	binary.BigEndian.PutUint16(listLen, uint16(len(list)))
	data := append(append([]byte{}, listLen...), list...)

	ext := make([]byte, 4)
	binary.BigEndian.PutUint16(ext[0:2], 0x0000) // server_name
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(data)))
	return append(ext, data...)
}

func TestRegression_DNS(t *testing.T) {
	c := runPCAP(t, "dns.pcap")
	defer c.Close()

	s := c.statsSnapshot()

	if s.PacketsReceived == 0 {
		t.Fatal("не прочитано ни одного пакета")
	}

	// Инвариант учёта: каждый пакет либо обработан, либо попал
	// в корзину потерь. processed == received — слишком сильно:
	// ARP-кадры легитимно дают NoIPLayer.
	if got := s.PacketsProcessed + s.DecodeErrors + s.NoIPLayer + s.ShortPackets; got != s.PacketsReceived {
		t.Errorf("баланс пакетов: %d != received(%d)", got, s.PacketsReceived)
	}
	if s.DecodeErrors > 0 {
		t.Errorf("decode_errors=%d", s.DecodeErrors)
	}
	if s.ShortPackets > 0 {
		t.Errorf("short_packets=%d", s.ShortPackets)
	}
	if s.PacketsTruncated > 0 {
		// Эвристика "len == snaplen": pcap с малым snaplen даёт
		// ложные срабатывания на целых пакетах — не фейлим.
		t.Logf("truncated=%d (эвристика snaplen)", s.PacketsTruncated)
	}

	if dnsCount := c.dnsTable.Len(); dnsCount == 0 {
		t.Error("DNS-запросы не найдены")
	} else {
		t.Logf("DNS-запросов: %d", dnsCount)
	}

	// Требует, чтобы в pcap были и ОТВЕТЫ, а не только запросы.
	if obs := c.dnsMapping.SnapshotObservations(); len(obs) == 0 {
		t.Error("DNS-наблюдения не найдены (в pcap нет ответов?)")
	} else {
		t.Logf("DNS-наблюдений: %d", len(obs))
	}

	if flows := c.flows.Snapshot(); len(flows) == 0 {
		t.Error("потоки не созданы")
	} else {
		t.Logf("потоков: %d", len(flows))
	}
}

func TestRegression_ECH(t *testing.T) {
	echExt := []byte{0xfe, 0x0d, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00}

	t.Run("только ECH — SNI скрыт", func(t *testing.T) {
		if got := extractSNI(buildClientHello(echExt)); got != ECHSentinel {
			t.Errorf("expected ECHSentinel, got %q", got)
		}
	})

	t.Run("только SNI — обычное имя", func(t *testing.T) {
		if got := extractSNI(buildClientHello(sniExt("example.com"))); got != "example.com" {
			t.Errorf("expected example.com, got %q", got)
		}
	})

	t.Run("SNI + ECH — побеждает SNI", func(t *testing.T) {
		// Фиксация ТЕКУЩЕГО приоритета. Это открытый вопрос ревью:
		// при реальном ECH outer-SNI — имя-прикрытие, и флаг ECH
		// при таком приоритете не ставится. Смена поведения здесь
		// должна начаться с покраснения этого теста.
		if got := extractSNI(buildClientHello(sniExt("cover.example"), echExt)); got != "cover.example" {
			t.Errorf("expected cover.example, got %q", got)
		}
	})
}

func TestRegression_ClassifyFlow(t *testing.T) {
	cases := []struct {
		name string
		f    *FlowStats
		want Classification
	}{
		{"ECH → direct", &FlowStats{ECH: true}, ClassDirect},
		{"VPN-детектор → vpn", &FlowStats{VPNProto: "WireGuard"}, ClassVPN},
		{"прокси-процесс без SNI → proxy", &FlowStats{Comm: "xray"}, ClassProxy},
		{"пустой → unknown", &FlowStats{}, ClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyFlow(tc.f, nil); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
