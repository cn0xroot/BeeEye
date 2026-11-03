//go:build darwin

package live

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AnyInterface 在 macOS 上表示“所有已启用的网卡”,每块网卡各开一个 /dev/bpf 设备。
const AnyInterface = "any"

const (
	dltNull  = 0 // 回环/utun:4 字节地址族头
	dltEN10  = 1 // 以太网
	afInet6D = 30
)

type bpfSource struct {
	iface     string
	ch        chan Packet
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	fds       []int

	idx      atomic.Int64
	captured atomic.Int64
	dropped  atomic.Int64
	bytes    atomic.Int64
}

func ioctlPtr(fd int, req uint, p unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}

func openBPFDev() (int, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		lastErr = err
		if err == unix.EBUSY {
			continue
		}
		if err == unix.ENOENT {
			break
		}
		if err == unix.EACCES || err == unix.EPERM {
			return -1, fmt.Errorf("没有权限打开 /dev/bpf*(请用 sudo 运行,或安装 Wireshark 的 ChmodBPF): %w", err)
		}
	}
	return -1, fmt.Errorf("无可用的 /dev/bpf 设备: %w", lastErr)
}

// OpenAFPacket 在 macOS 上用 BPF 设备实现同样的 Source 接口(名字沿用以保持调用方不变)。
func OpenAFPacket(iface string, snaplen int, promisc bool) (Source, error) {
	var names []string
	if iface == AnyInterface {
		ifs, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, i := range ifs {
			if i.Flags&net.FlagUp != 0 {
				names = append(names, i.Name)
			}
		}
	} else {
		if _, err := net.InterfaceByName(iface); err != nil {
			return nil, fmt.Errorf("interface %q: %w", iface, err)
		}
		names = []string{iface}
	}
	if len(names) == 0 {
		return nil, errors.New("没有可用网卡")
	}
	p := &bpfSource{iface: iface, ch: make(chan Packet, 4096), done: make(chan struct{})}
	for _, n := range names {
		fd, dlt, blen, err := openOne(n, promisc)
		if err != nil {
			if iface != AnyInterface {
				p.closeFDs()
				return nil, err
			}
			continue // any:跳过打不开的网卡
		}
		p.fds = append(p.fds, fd)
		p.wg.Add(1)
		go p.loop(fd, n, dlt, blen)
	}
	if len(p.fds) == 0 {
		return nil, errors.New("无法在任何网卡上开启 BPF 捕获(权限不足?请用 sudo 运行)")
	}
	go func() { p.wg.Wait(); close(p.ch) }()
	return p, nil
}

func openOne(name string, promisc bool) (fd, dlt, blen int, err error) {
	fd, err = openBPFDev()
	if err != nil {
		return
	}
	fail := func(what string, e error) (int, int, int, error) {
		unix.Close(fd)
		return -1, 0, 0, fmt.Errorf("%s %s: %w", name, what, e)
	}
	// 缓冲区必须在绑定网卡之前设置
	want := 1 << 20
	_ = ioctlPtr(fd, unix.BIOCSBLEN, unsafe.Pointer(&want))
	var ifr [32]byte
	copy(ifr[:15], name)
	if e := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr[0])); e != nil {
		return fail("BIOCSETIF", e)
	}
	one := 1
	_ = ioctlPtr(fd, unix.BIOCIMMEDIATE, unsafe.Pointer(&one))
	_ = ioctlPtr(fd, unix.BIOCSSEESENT, unsafe.Pointer(&one))
	if promisc {
		_ = ioctlPtr(fd, unix.BIOCPROMISC, nil)
	}
	var d uint32
	if e := ioctlPtr(fd, unix.BIOCGDLT, unsafe.Pointer(&d)); e != nil {
		return fail("BIOCGDLT", e)
	}
	if d != dltNull && d != dltEN10 {
		return fail("link type", fmt.Errorf("不支持的链路类型 %d", d))
	}
	var bl uint32
	if e := ioctlPtr(fd, unix.BIOCGBLEN, unsafe.Pointer(&bl)); e != nil {
		return fail("BIOCGBLEN", e)
	}
	// 读超时,便于及时响应 Close
	tv := unix.Timeval{Sec: 1}
	_ = ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv))
	return fd, int(d), int(bl), nil
}

func (p *bpfSource) loop(fd int, name string, dlt, blen int) {
	defer p.wg.Done()
	buf := make([]byte, blen)
	for {
		select {
		case <-p.done:
			return
		default:
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return
		}
		// struct bpf_hdr: tv_sec int32, tv_usec int32, caplen u32, datalen u32, hdrlen u16
		for off := 0; off+18 <= n; {
			sec := int64(*(*int32)(unsafe.Pointer(&buf[off])))
			usec := int64(*(*int32)(unsafe.Pointer(&buf[off+4])))
			caplen := int(*(*uint32)(unsafe.Pointer(&buf[off+8])))
			datalen := int(*(*uint32)(unsafe.Pointer(&buf[off+12])))
			hdrlen := int(*(*uint16)(unsafe.Pointer(&buf[off+16])))
			start, end := off+hdrlen, off+hdrlen+caplen
			if end > n {
				break
			}
			off = (end + 3) &^ 3
			data := buf[start:end]
			if dlt == dltNull {
				if len(data) < 4 {
					continue
				}
				af := *(*uint32)(unsafe.Pointer(&data[0]))
				et := [2]byte{0x08, 0x00}
				if af == afInet6D {
					et = [2]byte{0x86, 0xDD}
				}
				eth := make([]byte, 14, 10+len(data))
				eth[12], eth[13] = et[0], et[1]
				data = append(eth, data[4:]...)
				datalen += 10
			} else {
				data = append([]byte(nil), data...)
			}
			p.captured.Add(1)
			p.bytes.Add(int64(len(data)))
			pkt := Packet{
				Index: p.idx.Add(1), TS: time.Unix(sec, usec*1000), Iface: name,
				Data: data, CapLen: len(data), OrigLen: datalen,
			}
			select {
			case p.ch <- pkt:
			case <-p.done:
				return
			default:
				p.dropped.Add(1)
			}
		}
	}
}

func (p *bpfSource) Name() string           { return "bpf" }
func (p *bpfSource) Iface() string          { return p.iface }
func (p *bpfSource) Packets() <-chan Packet { return p.ch }
func (p *bpfSource) Stats() Stats {
	return Stats{Captured: p.captured.Load(), Dropped: p.dropped.Load(), Bytes: p.bytes.Load()}
}

func (p *bpfSource) closeFDs() {
	for _, fd := range p.fds {
		unix.Close(fd)
	}
}

func (p *bpfSource) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		p.wg.Wait() // 读超时 1s 内各 goroutine 退出后再关 fd,避免读到已复用的描述符
		p.closeFDs()
	})
	return nil
}

// LinkEvent / WatchLinks:macOS 无 netlink,不提供热插拔事件。
type LinkEvent struct {
	Name    string
	Removed bool
}

func WatchLinks(stop <-chan struct{}) (<-chan LinkEvent, error) {
	ch := make(chan LinkEvent)
	go func() { <-stop; close(ch) }()
	return ch, nil
}
