// Interface hot-plug auto-discovery (F20): watches RTNETLINK for link
// add/remove notifications so a USB Wi-Fi dongle plugged in after startup —
// or one unplugged — is noticed without a restart or a polling loop. This
// uses a raw AF_NETLINK socket, the same low-dependency style as the
// AF_PACKET capture source in afpacket.go: no CGO, no third-party netlink
// library.
package live

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// LinkEvent is one interface add or remove notification. Only the name and
// whether it disappeared are carried — callers that care whether the
// interface is actually up re-check via net.InterfaceByName, since that is
// authoritative and the netlink flags snapshot in the message can already be
// stale by the time it's read.
type LinkEvent struct {
	Name    string
	Removed bool // true for RTM_DELLINK, false for RTM_NEWLINK
}

const rtmHdrLen = 16 // sizeof(struct nlmsghdr)
const ifiHdrLen = 16 // sizeof(struct ifinfomsg)

// WatchLinks opens an RTNETLINK socket subscribed to link-change
// notifications and streams parsed events on the returned channel until stop
// is closed, at which point the channel is closed too. A malformed or
// truncated netlink message is skipped rather than treated as fatal — a
// missed hot-plug notification only delays auto-discovery by one event, it
// never corrupts state.
func WatchLinks(stop <-chan struct{}) (<-chan LinkEvent, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	// A short receive timeout lets the read loop notice stop being closed
	// instead of blocking in Recvfrom forever — the same pattern
	// afpacket.go uses for a responsive Close.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	out := make(chan LinkEvent, 16)
	go func() {
		defer close(out)
		defer unix.Close(fd)
		buf := make([]byte, 8192)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue // timeout (expected every ~1s) or a transient error
			}
			for _, ev := range parseLinkMessages(buf[:n]) {
				select {
				case out <- ev:
				case <-stop:
					return
				}
			}
		}
	}()
	return out, nil
}

// parseLinkMessages decodes zero or more nlmsghdr-framed RTM_NEWLINK/
// RTM_DELLINK messages out of one netlink datagram. Field layout follows
// linux/rtnetlink.h; everything is read with explicit offsets rather than an
// unsafe struct cast, so a short or corrupt buffer just stops the loop
// instead of reading out of bounds.
func parseLinkMessages(buf []byte) []LinkEvent {
	var events []LinkEvent
	for len(buf) >= rtmHdrLen {
		msgLen := int(binary.LittleEndian.Uint32(buf[0:4]))
		msgType := binary.LittleEndian.Uint16(buf[4:6])
		if msgLen < rtmHdrLen || msgLen > len(buf) {
			break
		}
		if msgType == unix.RTM_NEWLINK || msgType == unix.RTM_DELLINK {
			if name, ok := parseIfname(buf[rtmHdrLen:msgLen]); ok {
				events = append(events, LinkEvent{Name: name, Removed: msgType == unix.RTM_DELLINK})
			}
		}
		aligned := (msgLen + 3) &^ 3 // NLMSG_ALIGNTO
		if aligned <= 0 || aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return events
}

// parseIfname walks the rtattr list following a struct ifinfomsg to find
// IFLA_IFNAME.
func parseIfname(body []byte) (string, bool) {
	if len(body) < ifiHdrLen {
		return "", false
	}
	attrs := body[ifiHdrLen:]
	for len(attrs) >= 4 {
		attrLen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		attrType := binary.LittleEndian.Uint16(attrs[2:4])
		if attrLen < 4 || attrLen > len(attrs) {
			break
		}
		if attrType == unix.IFLA_IFNAME {
			data := attrs[4:attrLen]
			if i := bytes.IndexByte(data, 0); i >= 0 {
				data = data[:i]
			}
			if len(data) > 0 {
				return string(data), true
			}
			return "", false
		}
		aligned := (attrLen + 3) &^ 3 // RTA_ALIGNTO
		if aligned <= 0 || aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	return "", false
}
