package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"digger/internal/capture"
	"digger/internal/netmap"
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
	flag.Parse()

	if *netmapFlag {
		netmap.Collect().Print()
		return
	}

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "ошибка: укажите интерфейс через -i")
		flag.Usage()
		os.Exit(1)
	}

	cap, err := capture.New(*iface, *snaplen, *verbose)
	if err != nil {
		log.Fatalf("не удалось открыть интерфейс %s: %v", *iface, err)
	}
	defer cap.Close()

	cap.SetMinPkts(*minPkts)
	cap.SetHideIdle(*hideIdle)
	cap.SetActiveOnly(*activeOnly)
	cap.SetDNSAge(*dnsAge)
	cap.SetProfile(*profile)
	cap.SetRouterMode(*routerMode)

	if *filter != "" {
		if err := cap.SetFilter(*filter); err != nil {
			log.Fatalf("не удалось установить фильтр %q: %v", *filter, err)
		}
	}

	fmt.Printf("digger: захват на %s", *iface)
	if *filter != "" {
		fmt.Printf(", фильтр: %s", *filter)
	}
	fmt.Printf(", min-pkts: %d\n", *minPkts)
	if *activeOnly > 0 {
		fmt.Printf(", active-only: %d сек\n", *activeOnly)
	}
	fmt.Println("Нажмите Ctrl+C для остановки...")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		cap.Run()
		close(done)
	}()

	<-stop
	fmt.Println("\nОстанавливаем захват...")
	cap.Stop()
	<-done
	fmt.Println("Готово.")
}
