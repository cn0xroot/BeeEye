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
int  BeeEyeRenderCurveFrame(const float *tx_values, const float *rx_values,
                            int width, int height, float time_s,
                            float tx_r, float tx_g, float tx_b,
                            float rx_r, float rx_g, float rx_b,
                            float hot_r, float hot_g, float hot_b,
                            float base_r, float base_g, float base_b,
                            unsigned char *out);
int  BeeEyeRenderBarsFrame(const float *values, const float *colors_rgb,
                           int count, int width, int height,
                           float hot_r, float hot_g, float hot_b,
                           float base_r, float base_g, float base_b,
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

func (r *cudaRenderer) RenderCurve(txValues, rxValues []float32, width, height int, timeS float32, txRGB, rxRGB, hotRGB, baseRGB [3]float32, out []byte) error {
	if width <= 0 || height <= 0 || len(txValues) < width || len(rxValues) < width || len(out) < width*height*4 {
		return errBadGeometry
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	rc := C.BeeEyeRenderCurveFrame(
		(*C.float)(unsafe.Pointer(&txValues[0])),
		(*C.float)(unsafe.Pointer(&rxValues[0])),
		C.int(width), C.int(height), C.float(timeS),
		C.float(txRGB[0]), C.float(txRGB[1]), C.float(txRGB[2]),
		C.float(rxRGB[0]), C.float(rxRGB[1]), C.float(rxRGB[2]),
		C.float(hotRGB[0]), C.float(hotRGB[1]), C.float(hotRGB[2]),
		C.float(baseRGB[0]), C.float(baseRGB[1]), C.float(baseRGB[2]),
		(*C.uchar)(unsafe.Pointer(&out[0])))
	if rc != 0 {
		return fmt.Errorf("render: CUDA curve frame failed (code %d)", int(rc))
	}
	return nil
}

func (r *cudaRenderer) RenderBars(values, colorsRGB []float32, count, width, height int, hotRGB, baseRGB [3]float32, out []byte) error {
	if count <= 0 || width <= 0 || height <= 0 ||
		len(values) < count || len(colorsRGB) < count*3 || len(out) < width*height*4 {
		return errBadGeometry
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	rc := C.BeeEyeRenderBarsFrame(
		(*C.float)(unsafe.Pointer(&values[0])),
		(*C.float)(unsafe.Pointer(&colorsRGB[0])),
		C.int(count), C.int(width), C.int(height),
		C.float(hotRGB[0]), C.float(hotRGB[1]), C.float(hotRGB[2]),
		C.float(baseRGB[0]), C.float(baseRGB[1]), C.float(baseRGB[2]),
		(*C.uchar)(unsafe.Pointer(&out[0])))
	if rc != 0 {
		return fmt.Errorf("render: CUDA bars frame failed (code %d)", int(rc))
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
