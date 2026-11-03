//go:build !linux && !darwin

package live

import "errors"

var errUnsupported = errors.New("live capture requires Linux (AF_PACKET); offline pcap import still works")

// OpenAFPacket is unavailable off Linux.
func OpenAFPacket(iface string, snaplen int, promisc bool) (Source, error) {
	return nil, errUnsupported
}

// LinkEvent mirrors the Linux type.
type LinkEvent struct {
	Name    string
	Removed bool
}

// WatchLinks returns a channel that closes when stop does; no events off Linux.
func WatchLinks(stop <-chan struct{}) (<-chan LinkEvent, error) {
	ch := make(chan LinkEvent)
	go func() { <-stop; close(ch) }()
	return ch, nil
}

// AnyInterface 与 Linux 版同名常量保持一致。
const AnyInterface = "any"
