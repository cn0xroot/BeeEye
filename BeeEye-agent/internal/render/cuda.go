//go:build cuda

package render

/*
#cgo CFLAGS: -I/usr/local/cuda/include
#cgo LDFLAGS: -L${SRCDIR}/../../cuda -lBeeEyeRender -L/usr/local/cuda/lib64 -lcudart -Wl,-rpath,${SRCDIR}/../../cuda -Wl,-rpath,/usr/local/cuda/lib64
#include <stdlib.h>

int  BeeEyeRenderAvailable(void);
int  BeeEyeRenderDeviceName(char *buf, int buflen);
int  BeeEyeRenderFrame(const float *intensity, const float *channel_rgb,
                       int channels, int width, int height, float time_s,
                       unsigned char *out);
void BeeEyeRenderShutdown(void);
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// cudaRenderer drives cuda/BeeEye_render.cu.
//
// Calls are serialized: the C side keeps one set of device buffers and reuses
// them across frames, which is the right trade for a ~1 MB frame rendered a
// few times a second — but it means two concurrent Render calls would race on
// those buffers.
type cudaRenderer struct {
	mu     sync.Mutex
	device string
}

func newCUDARenderer() (Renderer, bool) {
	if C.BeeEyeRenderAvailable() == 0 {
		return nil, false
	}
	buf := make([]byte, 128)
	name := ""
	if n := C.BeeEyeRenderDeviceName((*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf))); n > 0 {
		name = string(buf[:n])
	}
	return &cudaRenderer{device: name}, true
}

func (r *cudaRenderer) Name() string   { return "cuda" }
func (r *cudaRenderer) Device() string { return r.device }

func (r *cudaRenderer) Render(intensity, channelRGB []float32, channels, width, height int, timeS float32, out []byte) error {
	if channels <= 0 || width <= 0 || height <= 0 ||
		len(intensity) < channels*width || len(out) < width*height*4 ||
		len(channelRGB) < channels*3 {
		return errBadGeometry
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	rc := C.BeeEyeRenderFrame(
		(*C.float)(unsafe.Pointer(&intensity[0])),
		(*C.float)(unsafe.Pointer(&channelRGB[0])),
		C.int(channels), C.int(width), C.int(height), C.float(timeS),
		(*C.uchar)(unsafe.Pointer(&out[0])))
	if rc != 0 {
		// Every failure code maps to a specific CUDA call in the .cu file;
		// keeping the number makes a driver problem diagnosable from a log.
		return fmt.Errorf("render: CUDA frame failed (code %d)", int(rc))
	}
	return nil
}

func (r *cudaRenderer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	C.BeeEyeRenderShutdown()
	return nil
}

// NewRenderer prefers the GPU and falls back to software.
func NewRenderer() Renderer {
	if r, ok := newCUDARenderer(); ok {
		return r
	}
	return NewCPURenderer()
}
