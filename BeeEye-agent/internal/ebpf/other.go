//go:build !linux

package ebpf

import (
	"errors"

	"BeeEye/internal/live"
)

// OpenEBPF 仅 Linux 可用。
func OpenEBPF(iface string) (live.Source, error) {
	return nil, errors.New("eBPF requires Linux")
}
