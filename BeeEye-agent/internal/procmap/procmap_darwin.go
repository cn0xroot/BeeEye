//go:build darwin

package procmap

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// macOS 没有 /proc。这里用 `lsof -nP -i -F` 一次取得“本地地址:端口 → 进程”。
// 沿用 Linux 实现的 socket→inode→进程两段式接口:每个 socket 分配一个合成 id。
// 注意:非 root 只能看到当前用户的进程;sudo 运行时可看到全部。

func ownerUID(fi fs.FileInfo) string { return "" }

func netInterfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if v, ok := netip.AddrFromSlice(ipnet.IP); ok {
				out = append(out, v.Unmap())
			}
		}
	}
	return out, nil
}

var (
	lsofMu     sync.Mutex
	lsofOwners map[uint64]Process
)

func runLsof() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "lsof", "-nP", "-i", "-F", "pcLPn").Output()
}

// refreshLsof 重新执行 lsof,同时更新 socket 表与 owner 表(两者必须同一次快照,id 才对得上)。
func refreshLsof() (map[socketKey]uint64, map[uint64]Process) {
	out, err := runLsof()
	if err != nil && len(out) == 0 {
		return map[socketKey]uint64{}, map[uint64]Process{}
	}
	return parseLsof(out)
}

func platformSockets() map[socketKey]uint64 {
	socks, owners := refreshLsof()
	lsofMu.Lock()
	lsofOwners = owners
	lsofMu.Unlock()
	return socks
}

func platformOwners(force bool) map[uint64]Process {
	lsofMu.Lock()
	defer lsofMu.Unlock()
	if lsofOwners == nil {
		return map[uint64]Process{}
	}
	return lsofOwners
}

// parseLsof 解析 `lsof -F pcLPn` 输出。字段以首字符区分:
// p=pid c=命令 L=登录名 P=协议 n=地址("本地->远端" 或 "*:port")。
func parseLsof(data []byte) (map[socketKey]uint64, map[uint64]Process) {
	socks := map[socketKey]uint64{}
	owners := map[uint64]Process{}
	var (
		cur   Process
		proto string
		next  uint64
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		val := line[1:]
		switch line[0] {
		case 'p':
			pid, _ := strconv.Atoi(val)
			cur = Process{PID: pid}
			proto = ""
		case 'c':
			cur.Comm = val
		case 'L':
			cur.User = val
		case 'P':
			proto = strings.ToLower(val)
		case 'n':
			if proto != "tcp" && proto != "udp" {
				continue
			}
			local, _, _ := strings.Cut(val, "->")
			ap, ok := parseLsofAddr(local)
			if !ok {
				continue
			}
			next++
			socks[socketKey{proto, normalize(ap)}] = next
			owners[next] = cur
		}
	}
	return socks, owners
}

// parseLsofAddr 解析 "127.0.0.1:8080"、"[::1]:80"、"*:5353"。
func parseLsofAddr(s string) (netip.AddrPort, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}, false
	}
	host, portStr := s[:i], s[i+1:]
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil { // "*:*" 等无端口
		return netip.AddrPort{}, false
	}
	if host == "*" {
		return netip.AddrPortFrom(netip.IPv6Unspecified(), uint16(port)), true
	}
	host = strings.Trim(host, "[]")
	if z := strings.IndexByte(host, '%'); z >= 0 { // 去掉 IPv6 zone
		host = host[:z]
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}
