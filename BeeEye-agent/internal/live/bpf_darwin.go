//go:build darwin

package live

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
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
		parseBPFBuffer(buf[:n], dlt, name, func(ts time.Time, data []byte, origLen int) {
			p.captured.Add(1)
			p.bytes.Add(int64(len(data)))
			pkt := Packet{
				Index: p.idx.Add(1), TS: ts, Iface: name,
				Data: data, CapLen: len(data), OrigLen: origLen,
			}
			select {
			case p.ch <- pkt:
			case <-p.done:
			default:
				p.dropped.Add(1)
			}
		})
	}
}

// parseBPFBuffer 拆解一次 read() 返回的缓冲区:里面是若干条
// struct bpf_hdr{tv_sec,tv_usec int32; caplen,datalen u32; hdrlen u16} + 数据,
// 每条按 4 字节对齐。DLT_NULL(回环/utun)的 4 字节地址族头会被替换成
// 合成的以太网头,让下游解析器无需区分链路类型。
func parseBPFBuffer(b []byte, dlt int, _ string, emit func(ts time.Time, data []byte, origLen int)) {
	ne := binary.NativeEndian
	for off := 0; off+18 <= len(b); {
		sec := int64(int32(ne.Uint32(b[off:])))
		usec := int64(int32(ne.Uint32(b[off+4:])))
		caplen := int(ne.Uint32(b[off+8:]))
		datalen := int(ne.Uint32(b[off+12:]))
		hdrlen := int(ne.Uint16(b[off+16:]))
		start, end := off+hdrlen, off+hdrlen+caplen
		if hdrlen < 18 || end > len(b) {
			return // 截断或损坏的记录
		}
		off = (end + 3) &^ 3
		data := b[start:end]
		if dlt == dltNull {
			if len(data) < 4 {
				continue
			}
			et := [2]byte{0x08, 0x00}
			if ne.Uint32(data) == afInet6D {
				et = [2]byte{0x86, 0xDD}
			}
			eth := make([]byte, 14, 10+len(data))
			eth[12], eth[13] = et[0], et[1]
			data = append(eth, data[4:]...)
			datalen += 10
		} else {
			data = append([]byte(nil), data...)
		}
		emit(time.Unix(sec, usec*1000), data, datalen)
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

// LinkEvent 与 Linux 版同构。
type LinkEvent struct {
	Name    string
	Removed bool
}

// linkPollInterval:macOS 没有 netlink,改为轮询网卡列表(开销可忽略)。
const linkPollInterval = 2 * time.Second

// WatchLinks 轮询 net.Interfaces,网卡出现/变为 up 报告 NEWLINK,消失/变为 down 报告 DELLINK。
// stop 为 nil 时一直运行(与 Linux 版语义一致)。
func WatchLinks(stop <-chan struct{}) (<-chan LinkEvent, error) {
	prev, err := upSet()
	if err != nil {
		return nil, err
	}
	out := make(chan LinkEvent, 16)
	go func() {
		defer close(out)
		t := time.NewTicker(linkPollInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			cur, err := upSet()
			if err != nil {
				continue
			}
			for _, ev := range diffLinks(prev, cur) {
				select {
				case out <- ev:
				default: // 消费者落后:丢弃事件,下次状态差异仍会再次报告
				}
			}
			prev = cur
		}
	}()
	return out, nil
}

func upSet() (map[string]bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, i := range ifs {
		m[i.Name] = i.Flags&net.FlagUp != 0
	}
	return m, nil
}

// diffLinks 比较两次快照。顺序按名字排序,保证输出确定。
func diffLinks(prev, cur map[string]bool) []LinkEvent {
	var evs []LinkEvent
	for n, up := range cur {
		if up && !prev[n] {
			evs = append(evs, LinkEvent{Name: n})
		}
	}
	for n, up := range prev {
		if up && !cur[n] {
			evs = append(evs, LinkEvent{Name: n, Removed: true})
		}
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].Name < evs[j].Name })
	return evs
}
