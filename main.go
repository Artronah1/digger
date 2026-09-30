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

	// Опечатка в enum-флаге не должна молча превращаться в другой режим.
	switch *baselineMode {
	case "", "create", "check":
	default:
		fmt.Fprintf(os.Stderr, "ошибка: -baseline должен быть create | check, получено %q\n", *baselineMode)
		os.Exit(1)
	}
	switch *groupBy {
	case "", "app", "device":
	default:
		fmt.Fprintf(os.Stderr, "ошибка: -group-by должен быть app | device, получено %q\n", *groupBy)
		os.Exit(1)
	}
	switch *output {
	case "text", "json":
	default:
		fmt.Fprintf(os.Stderr, "ошибка: -output должен быть text | json, получено %q\n", *output)
		os.Exit(1)
	}

	if *netmapFlag {
		netmap.Collect().Print()
		return
	}

	var pol *policy.Policy
	if *policyFile != "" {
		p, err := policy.Load(*policyFile)
		if err != nil {
			log.Fatalf("не удалось загрузить политику: %v", err)
		}
		pol = p
		if *output != "json" {
			fmt.Printf("digger: политика загружена из %s\n", *policyFile)
		}
	}

	if *iface == "" && *readFile == "" {
		fmt.Fprintln(os.Stderr, "ошибка: укажите -i <интерфейс> или -read <файл.pcap>")
		flag.Usage()
		os.Exit(1)
	}

	// --- Вывод: stdout → (stdout + лог-файл) ---

	var logWriter io.Writer = os.Stdout
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("не удалось открыть файл лога %s: %v", *logFile, err)
		}
		defer f.Close()
		logWriter = io.MultiWriter(os.Stdout, f)
	}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("не удалось создать pipe: %v", err)
	}
	os.Stdout = w

	// Копируем pipe в logWriter. copyDone нужен, чтобы перед выходом
	// дождаться, пока весь вывод покинул буфер pipe — иначе последние
	// строки терялись при завершении программы.
	copyDone := make(chan struct{})
	go func() {
		io.Copy(logWriter, r)
		close(copyDone)
	}()

	defer func() {
		w.Close() // EOF для io.Copy
		<-copyDone
		os.Stdout = origStdout
	}()

	// NOTE: log.Fatalf зовёт os.Exit — deferred-функции не выполняются,
	// хвост вывода из pipe теряется. Фатальные ошибки после этого блока
	// лучше переводить на return.

	// --- Захват ---

	var sniffer *capture.Capture // не "cap": затеняет builtin cap()
	if *readFile != "" {
		sniffer, err = capture.NewFromPCAP(*readFile, *verbose)
		if err != nil {
			log.Fatalf("не удалось открыть PCAP %s: %v", *readFile, err)
		}
	} else {
		sniffer, err = capture.New(*iface, *snaplen, *verbose)
		if err != nil {
			log.Fatalf("не удалось открыть интерфейс %s: %v", *iface, err)
		}
	}
	// Зарегистрирован ПОСЛЕ pipe-дефера → выполнится ПЕРВЫМ (LIFO):
	// захват остановится до того, как закроется pipe вывода.
	defer sniffer.Close()

	sniffer.SetMinPkts(*minPkts)
	sniffer.SetHideIdle(*hideIdle)
	sniffer.SetActiveOnly(*activeOnly)
	sniffer.SetDNSAge(*dnsAge)
	sniffer.SetShowPTR(*showPTR)
	sniffer.SetGroupBy(*groupBy)
	sniffer.SetAppFilter(*appFilter)
	sniffer.SetProfile(*profile)
	sniffer.SetRouterMode(*routerMode)
	sniffer.SetOutputMode(*output)
	sniffer.SetPolicy(pol)

	if *filter != "" {
		if err := sniffer.SetFilter(*filter); err != nil {
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

	// Run запускается РОВНО ОДИН раз. Раньше запускался дважды
	// (перед baseline-блоками и в live-секции): дублированный вывод
	// каждый цикл, а при выходе close(done) дважды → panic.
	done := make(chan struct{})
	go func() {
		sniffer.Run()
		close(done)
	}()

	// Для PCAP-файла ждать таймер бессмысленно: ждём конца файла
	// (Run завершается сам). В live-режиме fileDone = nil — кейс
	// не срабатывает, работает только таймер.
	var fileDone <-chan struct{}
	if *readFile != "" {
		fileDone = done
	}

	waitCollect := func(d time.Duration) bool { // true — прервано сигналом
		select {
		case <-fileDone:
		case <-time.After(d):
		case <-stop:
			fmt.Fprintln(os.Stderr, "baseline: прервано")
			return true
		}
		return false
	}

	// --- Baseline: create ---
	if *baselineMode == "create" {
		fmt.Fprintln(os.Stderr, "baseline: сбор в течение 60s...")
		waitCollect(60 * time.Second)

		sniffer.Stop()
		<-done

		b := sniffer.BuildBaseline()
		if err := baseline.Save(*baselineFile, b); err != nil {
			log.Fatalf("не удалось сохранить baseline: %v", err)
		}
		if *output != "json" {
			fmt.Printf("baseline: сохранён в %s (domains=%d, processes=%d, devices=%d)\n",
				*baselineFile, len(b.Domains), len(b.Processes), len(b.Devices))
		}
		return // захват остановлен: в JSON-режиме код раньше проваливался
		// в мёртвый live-блок и падал
	}

	// --- Baseline: check ---
	if *baselineMode == "check" {
		old, err := baseline.Load(*baselineFile) // err проверяется ДО SetBaseline
		if err != nil {
			log.Fatalf("не удалось загрузить baseline: %v", err)
		}
		sniffer.SetBaseline(old)

		const checkDuration = 30 * time.Second
		fmt.Fprintf(os.Stderr, "baseline: проверка в течение %s...\n", checkDuration)
		waitCollect(checkDuration)

		sniffer.Stop()
		<-done

		diff := baseline.Compare(old, sniffer.BuildBaseline())

		if *output != "json" {
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
		}
		return // см. комментарий в create
	}

	// --- Live-режим: ждём Ctrl+C ---
	<-stop
	if *output != "json" {
		fmt.Println("\nОстанавливаем захват...")
	}
	sniffer.Stop()
	<-done
	if *output != "json" {
		fmt.Println("Готово.")
	}
}
