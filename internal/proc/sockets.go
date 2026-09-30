package proc

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SocketKey struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
}

type SocketInfo struct {
	Inode uint64
	PID   int
	Comm  string
}

// ScanSockets читает /proc/net/tcp и /proc/net/tcp6: 5-tuple -> inode.
func ScanSockets() (map[SocketKey]uint64, error) {
	result := make(map[SocketKey]uint64)
	scanProcTCP([]string{"/proc/net/tcp", "/proc/net/tcp6"}, func(key SocketKey, inode uint64) {
		result[key] = inode
	})
	return result, nil
}

// ScanSocketsByLocalPort — индекс по локальному порту (fallback).
func ScanSocketsByLocalPort() (map[uint16]uint64, error) {
	result := make(map[uint16]uint64)
	scanProcTCP([]string{"/proc/net/tcp", "/proc/net/tcp6"}, func(key SocketKey, inode uint64) {
		result[key.LocalPort] = inode
	})
	return result, nil
}

// scanProcTCP обходит /proc/net/tcp*. Фильтр: LISTEN (st=0A) не нужен
// никому, а записи с inode=0 (TIME_WAIT) раньше ЗАТИРАЛИ живой сокет
// в индексе по порту.
func scanProcTCP(paths []string, fn func(SocketKey, uint64)) {
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // заголовок
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}

			local, err := parseHexAddr(fields[1])
			if err != nil {
				continue
			}
			remote, err := parseHexAddr(fields[2])
			if err != nil {
				continue
			}
			if fields[3] == "0A" { // LISTEN
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 {
				continue
			}

			fn(SocketKey{
				LocalIP:    local.String(),
				LocalPort:  local.Port,
				RemoteIP:   remote.String(),
				RemotePort: remote.Port,
			}, inode)
		}
		f.Close()
	}
}

type SocketAddr struct {
	IP   net.IP
	Port uint16
}

// String нормализует IPv4-mapped IPv6 (::ffff:1.2.3.4 из tcp6) к IPv4 —
// иначе ключ не совпадает с адресом из пакета.
func (a SocketAddr) String() string {
	if v4 := a.IP.To4(); v4 != nil {
		return v4.String()
	}
	return a.IP.String()
}

func parseHexAddr(s string) (SocketAddr, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return SocketAddr{}, fmt.Errorf("bad addr: %s", s)
	}

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return SocketAddr{}, err
	}

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return SocketAddr{}, err
	}

	var ip net.IP
	switch len(ipBytes) {
	case 4: // little-endian dword
		ip = net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
	case 16: // 4 little-endian dword'а
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i*4+0] = ipBytes[i*4+3]
			ip[i*4+1] = ipBytes[i*4+2]
			ip[i*4+2] = ipBytes[i*4+1]
			ip[i*4+3] = ipBytes[i*4+0]
		}
	default:
		return SocketAddr{}, fmt.Errorf("unexpected ip len: %d", len(ipBytes))
	}

	return SocketAddr{IP: ip, Port: uint16(port)}, nil
}

// MapInodesToPIDs обходит /proc/[pid]/fd: inode -> (PID, comm).
// Требует root для чужих процессов.
func MapInodesToPIDs() (map[uint64]SocketInfo, error) {
	result := make(map[uint64]SocketInfo)

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		comm := readComm(pid)
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			result[inode] = SocketInfo{Inode: inode, PID: pid, Comm: comm}
		}
	}
	return result, nil
}

func readComm(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}
