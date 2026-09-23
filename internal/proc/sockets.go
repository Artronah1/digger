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

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
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
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				continue
			}

			key := SocketKey{
				LocalIP:    local.IP.String(),
				LocalPort:  local.Port,
				RemoteIP:   remote.IP.String(),
				RemotePort: remote.Port,
			}
			result[key] = inode
		}
		f.Close()
	}
	return result, nil
}

// ScanSocketsByLocalPort — альтернативный индекс по локальному порту.
// Более надёжен для матчинга с pcap, т.к. локальный порт уникален
// для активного соединения и не меняется.
func ScanSocketsByLocalPort() (map[uint16]uint64, error) {
	result := make(map[uint16]uint64)

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			local, err := parseHexAddr(fields[1])
			if err != nil {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				continue
			}
			result[local.Port] = inode
		}
		f.Close()
	}
	return result, nil
}

type SocketAddr struct {
	IP   net.IP
	Port uint16
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
		case 4:
			ip = net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])
		case 16:
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
