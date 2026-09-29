package capture

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
)

// NewFromPCAP открывает PCAP-файл для чтения.
// Фильтр -f применяется после открытия через SetBPFFilter (не поддерживается для файла).
func NewFromPCAP(path string, verbose bool) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть %s: %w", path, err)
	}

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("не удалось прочитать PCAP %s: %w", path, err)
	}

	dnsMapping := NewDNSMapping()
	anomalyDetector := NewAnomalyDetector()
	flowTable := NewFlowTable()
	flowTable.anomaly = anomalyDetector
	flowTable.dnsMapping = dnsMapping

	return &Capture{
		stopCh:     make(chan struct{}),
		flows:      flowTable,
		dnsTable:   NewDNSTable(),
		dnsMapping: dnsMapping,
		anomaly:    anomalyDetector,
		localIPs:   make(map[string]bool), // не знаем, какие IP локальные
		iface:      path,
		verbose:    verbose,
		outputMode: "text",
		pcapReader: reader,
		pcapFile:   f,
		snaplen:    65536,
	}, nil
}

// RunFromPCAP читает файл до конца и делает финальный вывод.
func (c *Capture) RunFromPCAP() {
	c.stats.StartedAt = time.Now()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		data, _, err := c.pcapReader.ReadPacketData()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ошибка чтения пакета: %v\n", err)
			break
		}

		c.processData(data)
	}

	// Финальный Enrich — чтобы процессы и маршруты успели заполниться
	c.flows.Enrich()

	// Финальный вывод
	c.printAll()
}
