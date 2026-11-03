//go:build !linux && !darwin

package procmap

import (
	"io/fs"
	"net/netip"
)

func ownerUID(fi fs.FileInfo) string { return "" }

func netInterfaceAddrs() ([]netip.Addr, error) { return nil, nil }

func platformSockets() map[socketKey]uint64  { return map[socketKey]uint64{} }
func platformOwners(bool) map[uint64]Process { return map[uint64]Process{} }
