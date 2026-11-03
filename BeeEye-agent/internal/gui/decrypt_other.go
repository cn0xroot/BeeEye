//go:build !linux

package gui

// 非 Linux 平台:TLS 明文捕获依赖 eBPF uprobe,不可用,接口保持一致但始终禁用。

type PlaintextChunk struct {
	TimeMS    int64  `json:"ts_ms"`
	PID       int    `json:"pid"`
	Comm      string `json:"comm"`
	Direction string `json:"dir"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	Preview   string `json:"preview"`
}

type DecryptStatus struct {
	Enabled   bool   `json:"enabled"`
	Running   bool   `json:"running"`
	Attached  int    `json:"attached"`
	Error     string `json:"error,omitempty"`
	Keylogged int    `json:"keylogged"`
}

type Decryptor struct{}

func NewDecryptor() *Decryptor { return &Decryptor{} }

func (d *Decryptor) Enabled() bool { return false }
func (d *Decryptor) Status() DecryptStatus {
	return DecryptStatus{Error: "HTTPS 明文捕获仅支持 Linux (eBPF)"}
}
func (d *Decryptor) Keylog() []string                       { return nil }
func (d *Decryptor) Enable()                                {}
func (d *Decryptor) Disable()                               {}
func (d *Decryptor) Recent(pid, limit int) []PlaintextChunk { return nil }
func (d *Decryptor) Close()                                 {}
