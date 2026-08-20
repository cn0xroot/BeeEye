//go:build linux

package live

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// afPacket captures raw frames from a PF_PACKET socket. No CGO and no libpcap:
// the socket, the promiscuous-mode membership and the frame reads are all
// plain syscalls, which keeps the binary statically linkable and the container
// image small.
type afPacket struct {
	fd        int
	iface     string
	anyIface  bool
	ifindex   int
	snaplen   int
	ch        chan Packet
	done      chan struct{}
	closeOnce sync.Once

	nameMu  sync.Mutex
	ifNames map[int]string

	captured atomic.Int64
	dropped  atomic.Int64
	bytes    atomic.Int64
	skipped  atomic.Int64 // frames from non-Ethernet link layers
}

// ifName resolves an ifindex to a name, caching the answer. On "any" this is
// what keeps per-interface attribution (F17) intact.
func (p *afPacket) ifName(idx int) string {
	p.nameMu.Lock()
	defer p.nameMu.Unlock()
	if n, ok := p.ifNames[idx]; ok {
		return n
	}
	name := fmt.Sprintf("if%d", idx)
	if i, err := net.InterfaceByIndex(idx); err == nil {
		name = i.Name
	}
	p.ifNames[idx] = name
	return name
}

// Link-layer types whose frames start with an Ethernet header, which is what
// the dissector understands. Anything else (a TUN device, a PPP link) would be
// misparsed, so it is counted and skipped rather than decoded into nonsense.
const (
	arphrdEther    = 1
	arphrdLoopback = 772
)

// AnyInterface captures from every interface at once, the way `tcpdump -i any`
// does. Each packet still records the interface it actually arrived on, so the
// per-interface distinction F17 requires is preserved rather than lost.
const AnyInterface = "any"

// OpenAFPacket binds a raw socket to iface and starts reading frames.
//
// promisc additionally joins the interface's promiscuous multicast group so
// frames not addressed to this host are delivered too — which is the whole
// point on a gateway, where the interesting traffic belongs to other devices.
func OpenAFPacket(iface string, snaplen int, promisc bool) (Source, error) {
	anyIface := iface == AnyInterface

	var ifi *net.Interface
	if !anyIface {
		var err error
		ifi, err = net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("live: interface %q: %w", iface, err)
		}
	}

	// ETH_P_ALL must be in network byte order in the socket protocol field.
	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			return nil, fmt.Errorf("%w (interface %s)", ErrNoPermission, iface)
		}
		return nil, fmt.Errorf("live: socket(AF_PACKET): %w", err)
	}

	// An unbound AF_PACKET socket receives from every interface, which is
	// exactly what "any" means. Binding is what narrows it to one.
	if !anyIface {
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{
			Protocol: uint16(proto),
			Ifindex:  ifi.Index,
		}); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("live: bind to %s: %w", iface, err)
		}
	}

	if promisc {
		targets := []int{}
		if anyIface {
			// Promiscuous mode is per-interface, so "any" has to join each one.
			if all, err := net.Interfaces(); err == nil {
				for _, i := range all {
					if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
						targets = append(targets, i.Index)
					}
				}
			}
		} else {
			targets = append(targets, ifi.Index)
		}
		for _, idx := range targets {
			mreq := unix.PacketMreq{Ifindex: int32(idx), Type: unix.PACKET_MR_PROMISC}
			// Not fatal: without promiscuous mode we still see broadcast,
			// multicast and anything routed through this host.
			_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
		}
	}

	// A read timeout is what makes Close() responsive: the reader loop wakes
	// up regularly and can notice the done channel instead of blocking in
	// recvfrom forever.
	tv := unix.Timeval{Sec: 0, Usec: 200000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// A generous receive buffer absorbs bursts; the kernel drop counter tells
	// us honestly when it was not enough.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)

	p := &afPacket{
		fd:       fd,
		iface:    iface,
		anyIface: anyIface,
		snaplen:  snaplen,
		ch:       make(chan Packet, 4096),
		done:     make(chan struct{}),
		ifNames:  map[int]string{},
	}
	if ifi != nil {
		p.ifindex = ifi.Index
		p.ifNames[ifi.Index] = ifi.Name
	}
	go p.loop()
	return p, nil
}

func (p *afPacket) loop() {
	defer close(p.ch)
	buf := make([]byte, p.snaplen)
	var idx int64
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, from, err := unix.Recvfrom(p.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue // read timeout — loop back and re-check done
			}
			return // socket closed
		}
		if n <= 0 {
			continue
		}
		iface := p.iface
		if sll, ok := from.(*unix.SockaddrLinklayer); ok {
			if sll.Hatype != arphrdEther && sll.Hatype != arphrdLoopback {
				p.skipped.Add(1)
				continue
			}
			if p.anyIface {
				iface = p.ifName(sll.Ifindex)
			}
		}

		idx++
		p.captured.Add(1)
		p.bytes.Add(int64(n))

		pkt := Packet{
			Index:   idx,
			TS:      time.Now(),
			Iface:   iface,
			Data:    append([]byte(nil), buf[:n]...),
			CapLen:  n,
			OrigLen: n,
		}
		select {
		case p.ch <- pkt:
		case <-p.done:
			return
		default:
			// The UI is slower than the wire. Dropping the newest frame is
			// preferable to stalling the reader, which would push the loss
			// into the kernel where we cannot attribute it.
			p.dropped.Add(1)
		}
	}
}

func (p *afPacket) Name() string           { return "af_packet" }
func (p *afPacket) Iface() string          { return p.iface }
func (p *afPacket) Packets() <-chan Packet { return p.ch }

// Stats merges our own drop count with the kernel's socket statistics, so the
// status bar distinguishes "the UI fell behind" from "the kernel ran out of
// buffer" instead of blaming one for the other.
func (p *afPacket) Stats() Stats {
	dropped := p.dropped.Load()
	if st, err := unix.GetsockoptTpacketStats(p.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		dropped += int64(st.Drops)
	}
	return Stats{
		Captured: p.captured.Load(),
		Dropped:  dropped,
		Bytes:    p.bytes.Load(),
	}
}

func (p *afPacket) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		err = unix.Close(p.fd)
	})
	return err
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
