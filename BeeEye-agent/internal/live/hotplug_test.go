package live

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// buildLinkMsg hand-assembles one nlmsghdr + ifinfomsg + IFLA_IFNAME rtattr,
// exactly as the kernel would send it, so parseLinkMessages can be tested
// without a real netlink socket or root.
func buildLinkMsg(msgType uint16, ifIndex int32, name string) []byte {
	nameBytes := append([]byte(name), 0) // NUL-terminated, per IFLA_IFNAME
	rtaLen := 4 + len(nameBytes)
	rtaAligned := (rtaLen + 3) &^ 3

	msgLen := rtmHdrLen + ifiHdrLen + rtaAligned
	buf := make([]byte, msgLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(buf[4:6], msgType)
	// flags(2) seq(4) pid(4) left zero

	ifi := buf[rtmHdrLen:]
	binary.LittleEndian.PutUint32(ifi[4:8], uint32(ifIndex))
	binary.LittleEndian.PutUint32(ifi[8:12], unix.IFF_UP)

	attr := buf[rtmHdrLen+ifiHdrLen:]
	binary.LittleEndian.PutUint16(attr[0:2], uint16(rtaLen))
	binary.LittleEndian.PutUint16(attr[2:4], unix.IFLA_IFNAME)
	copy(attr[4:], nameBytes)

	return buf
}

func TestParseLinkMessagesNewAndDel(t *testing.T) {
	msg := buildLinkMsg(unix.RTM_NEWLINK, 7, "wlx00c0ca9701f2")
	events := parseLinkMessages(msg)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Name != "wlx00c0ca9701f2" || events[0].Removed {
		t.Errorf("event = %+v, want Name=wlx00c0ca9701f2 Removed=false", events[0])
	}

	msg = buildLinkMsg(unix.RTM_DELLINK, 7, "wlx00c0ca9701f2")
	events = parseLinkMessages(msg)
	if len(events) != 1 || !events[0].Removed {
		t.Fatalf("delete event = %+v, want Removed=true", events)
	}
}

func TestParseLinkMessagesMultipleInOneDatagram(t *testing.T) {
	a := buildLinkMsg(unix.RTM_NEWLINK, 3, "eth0")
	b := buildLinkMsg(unix.RTM_NEWLINK, 4, "wlan0")
	events := parseLinkMessages(append(a, b...))
	if len(events) != 2 || events[0].Name != "eth0" || events[1].Name != "wlan0" {
		t.Fatalf("events = %+v, want [eth0 wlan0]", events)
	}
}

func TestParseLinkMessagesTruncatedIsIgnored(t *testing.T) {
	full := buildLinkMsg(unix.RTM_NEWLINK, 3, "eth0")
	for n := 0; n < len(full); n++ {
		// A truncated datagram must never panic — it should just yield
		// nothing (or, at the boundary, the ordinary case), same guarantee
		// the dissector's truncation tests enforce.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %d-byte truncated netlink message: %v", n, r)
				}
			}()
			parseLinkMessages(full[:n])
		}()
	}
}

func TestParseLinkMessagesIgnoresOtherTypes(t *testing.T) {
	msg := buildLinkMsg(unix.RTM_NEWLINK, 3, "eth0")
	// Flip the message type to something uninteresting (RTM_NEWADDR).
	binary.LittleEndian.PutUint16(msg[4:6], unix.RTM_NEWADDR)
	if events := parseLinkMessages(msg); len(events) != 0 {
		t.Errorf("expected no events for a non-link message, got %+v", events)
	}
}
