package capture

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// NewFromPCAP открывает PCAP-файл для чтения.
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

	// processData разбирает кадры как Ethernet; файлы с другим link type
	// (raw IP, Linux SLL) молча парсились бы в мусор.
	if lt := reader.LinkType(); lt != layers.LinkTypeEthernet {
		f.Close()
		return nil, fmt.Errorf("pcap %s: link type %v не поддерживается (ожидался Ethernet)", path, lt)
	}

	dnsMapping := NewDNSMapping()
	anomalyDetector := NewAnomalyDetector()
	flowTable := NewFlowTable()
	flowTable.anomaly = anomalyDetector
	flowTable.dnsMapping = dnsMapping
	if hostname, err := os.Hostname(); err == nil {
		flowTable.SetLocalHostname(hostname) // parity с live-режимом
	}

	return &Capture{
		stopCh:     make(chan struct{}),
		flows:      flowTable,
		dnsTable:   NewDNSTable(),
		dnsMapping: dnsMapping,
		anomaly:    anomalyDetector,
		localIPs:   make(map[string]bool), // локальные IP неизвестны
		iface:      path,
		verbose:    verbose,
		outputMode: "text",
		pcapReader: reader,
		pcapFile:   f,
		snaplen:    int(reader.Snaplen()),
	}, nil
}

// RunFromPCAP читает файл до конца и делает финальный вывод.
// Вызывается из Run() (раньше его никто не звал — main падал
// на c.handle.Listen() с nil-хендлом).
func (c *Capture) RunFromPCAP() {
	c.stats.mu.Lock()
	c.stats.StartedAt = time.Now()
	c.stats.mu.Unlock()

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
			fmt.Fprintf(os.Stderr, "digger: ошибка чтения пакета: %v\n", err)
			break
		}
		c.processData(data)
	}

	// Финальный Enrich (процессы/маршруты/классификация) и вывод.
	c.flows.Enrich()
	c.printAll()
}
