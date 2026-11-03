//go:build !linux

package procmap

import (
	"io/fs"
	"net/netip"
)

func ownerUID(fi fs.FileInfo) string { return "" }

func netInterfaceAddrs() ([]netip.Addr, error) { return nil, nil }
