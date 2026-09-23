package netmap

import (
	"fmt"
	"os/exec"
	"strings"
)

// Snapshot содержит снимок сетевой конфигурации ядра.
type Snapshot struct {
	Rules4    string
	Rules6    string
	RoutesAll string
	NFT       string
	IPTables  string
}

// Collect собирает снимок через вызовы ip/nft/iptables.
func Collect() *Snapshot {
	s := &Snapshot{}
	s.Rules4 = runCmd("ip", "-4", "rule", "show")
	s.Rules6 = runCmd("ip", "-6", "rule", "show")
	s.RoutesAll = runCmd("ip", "route", "show", "table", "all")
	s.NFT = runCmd("nft", "list", "ruleset")
	if s.NFT == "" {
		s.IPTables = runCmd("iptables-save")
	}
	return s
}

// Print выводит снимок в читаемом виде.
func (s *Snapshot) Print() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  СЕТЕВАЯ КАРТА ЯДРА (policy routing, tables, firewall)       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	fmt.Println()
	fmt.Println("── ip rule (IPv4) ──")
	printOrEmpty(s.Rules4)

	fmt.Println()
	fmt.Println("── ip rule (IPv6) ──")
	printOrEmpty(s.Rules6)

	fmt.Println()
	fmt.Println("── ip route show table all ──")
	printOrEmpty(s.RoutesAll)

	if s.NFT != "" {
		fmt.Println()
		fmt.Println("── nftables ruleset ──")
		printOrEmpty(s.NFT)
	} else if s.IPTables != "" {
		fmt.Println()
		fmt.Println("── iptables-save ──")
		printOrEmpty(s.IPTables)
	} else {
		fmt.Println()
		fmt.Println("── firewall ──")
		fmt.Println("(ни nft, ни iptables не найдены)")
	}
	fmt.Println()
}

func printOrEmpty(s string) {
	if strings.TrimSpace(s) == "" {
		fmt.Println("(пусто)")
		return
	}
	// Ограничиваем вывод, чтобы не залить терминал
	lines := strings.Split(s, "\n")
	max := 50
	if len(lines) > max {
		for _, l := range lines[:max] {
			fmt.Println(l)
		}
		fmt.Printf("... (ещё %d строк)\n", len(lines)-max)
	} else {
		fmt.Println(s)
	}
}

func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(out), "\n")
}
