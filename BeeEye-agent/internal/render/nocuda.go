//go:build !cuda

package render

// NewRenderer returns the software backend.
//
// This build was produced without the `cuda` tag, so no CUDA code is linked in
// at all — the binary runs on hosts with no NVIDIA driver, which is the normal
// case for a gateway. Build with `make gui-cuda` (or `-tags cuda`) on a machine
// with the CUDA toolkit to get the GPU path.
func NewRenderer() Renderer { return NewCPURenderer() }
