package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"digger/internal/baseline"
	"digger/internal/capture"
	"digger/internal/netmap"
	"digger/internal/policy"
)

func main() {
	iface := flag.String("i", "", "интерфейс для захвата (обязательно)")
	filter := flag.String("f", "", "BPF-фильтр в стиле tcpdump (опционально)")
	verbose := flag.Bool("v", false, "подробный вывод пакетов")
	snaplen := flag.Int("s", 65536, "snapshot length (байт на пакет)")
	minPkts := flag.Int("min-pkts", 4, "минимальное число пакетов в потоке для отображения (0 = все)")
	hideIdle := flag.Bool("hide-idle", false, "скрывать потоки без активности > 30 сек")
	activeOnly := flag.Int("active-only", 0, "показывать только потоки с активностью за последние N секунд (0 = все)")
	profile := flag.String("profile", "", "показать тайминг-профиль для указанного SNI (например, chatgpt.com)")
	netmapFlag := flag.Bool("netmap", false, "показать карту policy routing/firewall и выйти")
	dnsAge := flag.Duration("dns-age", 5*time.Minute, "показывать DNS-запросы не старше этого времени (0 = все)")
	routerMode := flag.Bool("router-mode", false, "режим роутера: считать outbound всё, что не от самого роутера")
	logFile := flag.String("log", "", "писать вывод в файл (по умолчанию только в stdout)")
	showPTR := flag.Bool("show-ptr", false, "показывать PTR-запросы в DNS-таблице")
	groupBy := flag.String("group-by", "", "группировать по: app | device")
	appFilter := flag.String("app", "", "показывать только это приложение/устройство")
	output := flag.String("output", "text", "формат вывода: text | json")
	readFile := flag.String("read", "", "читать PCAP-файл вместо live-захвата")
	policyFile := flag.String("policy", "", "файл политики (policy.yaml) для аудита")
	baselineMode := flag.String("baseline", "", "режим baseline: create | check")
	baselineFile := flag.String("baseline-file", "baseline.json", "файл baseline")
	flag.Parse()

	if *netmapFlag {
		netmap.Collect().Print()
		return
	}

	var pol *policy.Policy
	if *policyFile != "" {
		var err error
		pol, err = policy.Load(*policyFile)
		if err != nil {
			log.Fatalf("не удалось загрузить политику: %v", err)
		}
		if *output != "json" {
			fmt.Printf("digger: политика загружена из %s\n", *policyFile)
		}
	}

	if *iface == "" && *readFile == "" {
		fmt.Fprintln(os.Stderr, "ошибка: укажите -i <интерфейс> или -read <файл.pcap>")
		flag.Usage()
		os.Exit(1)
	}

	// Если задан -log, пишем одновременно в stdout и в файл
	var logWriter io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("не удалось открыть файл лога %s: %v", *logFile, err)
		}
		defer f.Close()
		logWriter = io.MultiWriter(os.Stdout, f)
	}

	// Перенаправляем stdout на logWriter через pipe
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("не удалось создать pipe: %v", err)
	}
	os.Stdout = w

	go func() {
		io.Copy(logWriter, r)
	}()

	defer func() {
		w.Close()
		os.Stdout = origStdout
	}()

	var cap *capture.Capture

	if *readFile != "" {
		cap, err = capture.NewFromPCAP(*readFile, *verbose)
		if err != nil {
			log.Fatalf("не удалось открыть PCAP %s: %v", *readFile, err)
		}
	} else {
		cap, err = capture.New(*iface, *snaplen, *verbose)
		if err != nil {
			log.Fatalf("не удалось открыть интерфейс %s: %v", *iface, err)
		}
	}
	defer cap.Close()

	cap.SetMinPkts(*minPkts)
	cap.SetHideIdle(*hideIdle)
	cap.SetActiveOnly(*activeOnly)
	cap.SetDNSAge(*dnsAge)
	cap.SetShowPTR(*showPTR)
	cap.SetGroupBy(*groupBy)
	cap.SetAppFilter(*appFilter)
	cap.SetProfile(*profile)
	cap.SetRouterMode(*routerMode)
	cap.SetOutputMode(*output)
	cap.SetPolicy(pol)
	cap.SetGroupBy(*groupBy)

	if *filter != "" {
		if err := cap.SetFilter(*filter); err != nil {
			log.Fatalf("не удалось установить фильтр %q: %v", *filter, err)
		}
	}

	if *output != "json" {
		if *readFile != "" {
			fmt.Printf("digger: чтение PCAP %s\n", *readFile)
		} else {
			fmt.Printf("digger: захват на %s", *iface)
			if *filter != "" {
				fmt.Printf(", фильтр: %s", *filter)
			}
			fmt.Printf(", min-pkts: %d\n", *minPkts)
			if *groupBy != "" {
				fmt.Printf(", группировка: %s\n", *groupBy)
			}
			if *appFilter != "" {
				fmt.Printf(", фильтр приложения: %s\n", *appFilter)
			}
			if *activeOnly > 0 {
				fmt.Printf(", active-only: %d сек\n", *activeOnly)
			}
			fmt.Println("Нажмите Ctrl+C для остановки...")
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		cap.Run()
		close(done)
	}()

	// Baseline: create
	if *baselineMode == "create" {
		fmt.Fprintf(os.Stderr, "baseline: сбор в течение 60s...\n")

		select {
		case <-time.After(60 * time.Second):
		case <-stop:
			fmt.Fprintln(os.Stderr, "baseline: прервано")
		}

		cap.Stop()
		<-done

		b := cap.BuildBaseline()
		if err := baseline.Save(*baselineFile, b); err != nil {
			log.Fatalf("не удалось сохранить baseline: %v", err)
		}
		fmt.Printf("baseline: сохранён в %s (domains=%d, processes=%d, devices=%d)\n",
			*baselineFile, len(b.Domains), len(b.Processes), len(b.Devices))
		return
	}

	// Baseline: check
	if *baselineMode == "check" {
		old, err := baseline.Load(*baselineFile)
		if err != nil {
			log.Fatalf("не удалось загрузить baseline: %v", err)
		}

		checkDuration := 30 * time.Second
		fmt.Fprintf(os.Stderr, "baseline: проверка в течение %s...\n", checkDuration)

		select {
		case <-time.After(checkDuration):
		case <-stop:
			fmt.Fprintln(os.Stderr, "baseline: прервано")
		}

		cap.Stop()
		<-done

		current := cap.BuildBaseline()
		diff := baseline.Compare(old, current)

		if diff.IsEmpty() {
			fmt.Println("baseline: без изменений")
		} else {
			fmt.Printf("baseline: %d различий\n", diff.Total())
			if len(diff.NewDomains) > 0 {
				fmt.Printf("\nНовые домены (%d):\n", len(diff.NewDomains))
				for _, d := range diff.NewDomains {
					fmt.Printf("  + %s\n", d)
				}
			}
			if len(diff.RemovedDomains) > 0 {
				fmt.Printf("\nПропавшие домены (%d):\n", len(diff.RemovedDomains))
				for _, d := range diff.RemovedDomains {
					fmt.Printf("  - %s\n", d)
				}
			}
			if len(diff.NewProcesses) > 0 {
				fmt.Printf("\nНовые процессы (%d):\n", len(diff.NewProcesses))
				for _, p := range diff.NewProcesses {
					fmt.Printf("  + %s\n", p)
				}
			}
			if len(diff.NewDevices) > 0 {
				fmt.Printf("\nНовые устройства (%d):\n", len(diff.NewDevices))
				for _, d := range diff.NewDevices {
					fmt.Printf("  + %s\n", d)
				}
			}
			if len(diff.ChangedJA3) > 0 {
				fmt.Printf("\nИзменился JA3 (%d):\n", len(diff.ChangedJA3))
				for _, c := range diff.ChangedJA3 {
					fmt.Printf("  ~ %s\n", c)
				}
			}
			if len(diff.ChangedJA4) > 0 {
				fmt.Printf("\nИзменился JA4 (%d):\n", len(diff.ChangedJA4))
				for _, c := range diff.ChangedJA4 {
					fmt.Printf("  ~ %s\n", c)
				}
			}
		}
		return
	}

	// Live-режим: ждём Ctrl+C
	go func() {
		cap.Run()
		close(done)
	}()

	<-stop
	if *output != "json" {
		fmt.Println("\nОстанавливаем захват...")
	}
	cap.Stop()
	<-done
	if *output != "json" {
		fmt.Println("Готово.")
	}
}
