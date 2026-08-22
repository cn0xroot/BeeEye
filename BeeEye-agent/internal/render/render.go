// Package render produces the live analyzer's traffic colour field.
//
// Two backends compute the identical image:
//
//	cuda — a CUDA kernel (cuda/BeeEye_render.cu) doing the per-pixel colour
//	       work on the GPU, selected when a device is present and the binary
//	       was built with the `cuda` tag
//	cpu  — the same maths in pure Go, always available
//
// The CPU path is not a stub. A host with no NVIDIA GPU — which is most
// gateways — must still get the full picture, so the fallback renders the same
// frame, just slower. TestBackendsAgree keeps the two from drifting apart.
package render

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
)

// Frame geometry. Small enough to push over HTTP many times a second, large
// enough that the waterfall reads as a continuous field rather than blocks.
const (
	DefaultWidth  = 1024
	DefaultHeight = 288
)

// ChannelColors are the per-channel hues, in the same fixed slot order the
// analyzer's packet list uses. Hue means identity here: a row of the field and
// a row of the list are the same colour because they are the same protocol.
//
// These are the validated categorical slots — colour-vision-deficiency checked
// against the dark surface they are drawn on, and never cycled: an unmapped
// channel falls into "other" rather than borrowing a colour that already means
// something else.
//
// They are the high-chroma versions of those slots. The hues and their spacing
// around the wheel are unchanged, so the CVD separation the slots were picked
// for still holds; only saturation and value went up, because the field is
// drawn on a near-black ground where the muted variants read as grey-blue
// mush rather than as eight distinguishable protocols.
var ChannelColors = [][3]float32{
	{0.180, 0.616, 1.000}, // #2e9dff blue         — tls
	{1.000, 0.416, 0.122}, // #ff6a1f orange        — http
	{0.000, 0.851, 0.573}, // #00d992 aqua          — dns
	{1.000, 0.765, 0.102}, // #ffc31a yellow        — mqtt
	{0.737, 1.000, 0.149}, // #bcff26 chartreuse    — sip
	{0.098, 0.941, 1.000}, // #19f0ff cyan          — sctp
	{0.149, 0.216, 1.000}, // #2637ff indigo        — gtp
	{0.980, 0.200, 1.000}, // #fa33ff pink-violet   — sim (also gsmtap)
	{1.000, 0.302, 0.616}, // #ff4d9d magenta       — arp
	{0.369, 0.941, 0.290}, // #5ef04a green         — icmp
	{0.671, 0.447, 1.000}, // #ab72ff violet        — tcp
	{1.000, 0.322, 0.322}, // #ff5252 red           — other
}

// ChannelRGB flattens the palette for a renderer, repeating the last slot if a
// caller declares more channels than there are colours.
func ChannelRGB(channels int) []float32 {
	out := make([]float32, channels*3)
	for i := 0; i < channels; i++ {
		c := ChannelColors[min(i, len(ChannelColors)-1)]
		out[i*3+0], out[i*3+1], out[i*3+2] = c[0], c[1], c[2]
	}
	return out
}

// Renderer computes one RGBA8 frame.
type Renderer interface {
	// Name reports the backend actually in use: "cuda" or "cpu". The UI shows
	// this, because claiming GPU rendering that is not happening would be a
	// lie of exactly the kind F43 exists to prevent.
	Name() string
	// Device is a human-readable device description, empty for the CPU path.
	Device() string
	// Render writes width*height*4 RGBA bytes into out. channelRGB carries
	// one RGB triplet per channel; see ChannelRGB.
	Render(intensity, channelRGB []float32, channels, width, height int, timeS float32, out []byte) error
	// RenderCurve draws a mirrored two-series line-chart frame: txValues
	// filled upward from a centre baseline, rxValues filled downward from
	// the same baseline, one already-normalized [0,1] sample per pixel
	// column each — upload/download over time the way a bandwidth monitor
	// shows it, as opposed to Render's per-channel colour field. Same
	// reasoning for having a GPU path at all: a wide curve redrawn several
	// times a second is exactly the kind of per-pixel work a GPU does far
	// more cheaply than a Go loop.
	//
	// The boundary and its glow are computed from the line SEGMENT joining
	// each pair of adjacent columns (point-to-segment distance), not just
	// the current column's own height — a flat per-column distance is what
	// made an earlier version of this read as a stepped bar chart with blur
	// around each step rather than one continuous anti-aliased line; a
	// diagonal run between two differing samples needs a diagonal glow.
	// hotRGB is a shared bloom colour both series ride toward on a burst,
	// baseRGB is the ground/panel colour a fill fades to as it nears the
	// baseline and the flat colour outside both filled regions.
	RenderCurve(txValues, rxValues []float32, width, height int, timeS float32, txRGB, rxRGB, hotRGB, baseRGB [3]float32, out []byte) error
	// RenderBars draws a ranked horizontal bar chart: one glowing bar per
	// row, stacked top to bottom, each already normalized to [0,1] of the
	// chart's own max (values[i]) and coloured with colorsRGB[i*3:i*3+3].
	// Built for the analyzer's ported capture-report view (protocol share,
	// top talkers, top conversations) so those panels share Render/
	// RenderCurve's glow-and-bloom visual language instead of reading as a
	// plainer tool bolted onto the analyzer — see program.md's Pcap-Analyzer
	// acknowledgment for what this is replacing the look of. No sweep/time
	// parameter: unlike the live field and traffic curve, a report's bars
	// describe a capture that has already finished, so there is nothing live
	// left to animate.
	RenderBars(values, colorsRGB []float32, count, width, height int, hotRGB, baseRGB [3]float32, out []byte) error
	Close() error
}

// History accumulates per-channel traffic intensity over a sliding set of time
// buckets — one pixel column each.
type History struct {
	mu       sync.Mutex
	channels []string
	index    map[string]int
	width    int
	data     []float32 // [channel*width + bucket], bucket 0 is the oldest
	peak     float32
}

// NewHistory creates the ring. channels are fixed at construction: a colour
// field whose rows change meaning underneath the viewer is unreadable.
func NewHistory(channels []string, width int) *History {
	if width <= 0 {
		width = DefaultWidth
	}
	h := &History{
		channels: append([]string(nil), channels...),
		index:    make(map[string]int, len(channels)),
		width:    width,
		data:     make([]float32, len(channels)*width),
		peak:     1,
	}
	for i, c := range channels {
		h.index[c] = i
	}
	return h
}

func (h *History) Channels() []string { return h.channels }
func (h *History) Width() int         { return h.width }

// Add credits weight to a channel's newest bucket. Unknown channel names land
// in the last channel, which callers should name "other".
func (h *History) Add(channel string, weight float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ci, ok := h.index[channel]
	if !ok {
		ci = len(h.channels) - 1
	}
	if ci < 0 {
		return
	}
	i := ci*h.width + h.width - 1
	h.data[i] += float32(weight)
	if h.data[i] > h.peak {
		h.peak = h.data[i]
	}
}

// Rotate shifts every channel one bucket into the past and opens a fresh one.
func (h *History) Rotate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := 0; c < len(h.channels); c++ {
		row := h.data[c*h.width : (c+1)*h.width]
		copy(row, row[1:])
		row[h.width-1] = 0
	}
	// Decay the peak so a single historic burst does not flatten the scale
	// forever, but keep a floor so an idle network is not amplified into noise.
	h.peak *= 0.985
	if h.peak < 1 {
		h.peak = 1
	}
}

// RawSnapshot returns the accumulated per-bucket values as-is — real bytes,
// not the log1p-normalized [0,1] Snapshot gives a Renderer. For a client-side
// chart that wants to print an actual "40 KB" axis label rather than draw a
// picture, the normalized version has already thrown away the number a label
// needs.
func (h *History) RawSnapshot() []float32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]float32, len(h.data))
	copy(out, h.data)
	return out
}

// Snapshot returns normalized intensities in [0,1], ready for a renderer.
func (h *History) Snapshot() []float32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]float32, len(h.data))
	// A log scale, because traffic is heavy-tailed: without it one large
	// transfer would wash out every small but interesting flow around it.
	scale := float32(math.Log1p(float64(h.peak)))
	if scale <= 0 {
		scale = 1
	}
	for i, v := range h.data {
		out[i] = float32(math.Log1p(float64(v))) / scale
		if out[i] > 1 {
			out[i] = 1
		}
	}
	return out
}

// EncodePNG wraps an RGBA buffer as a PNG for delivery to the browser.
func EncodePNG(rgba []byte, width, height int) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	copy(img.Pix, rgba)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ground and hot mirror c_ground / c_hot in cuda/BeeEye_render.cu. Both sides
// must change together; TestBackendsAgree fails loudly if they do not.
var (
	ground = [3]float32{0.043, 0.062, 0.118}
	hot    = [3]float32{1.000, 0.976, 0.929}
)

// chromaBoost is the saturation applied to a channel's hue before it is mixed
// with the ground. Mixing toward a dark navy desaturates as it darkens, so
// without this everything below a full burst drifts toward the ground's own
// colour and the field reads as one blue-grey wash.
const chromaBoost = 1.35

// PaletteCSS exposes the channel hues to the frontend, so the UI chrome and
// legend are drawn from the palette the field itself is rendered in rather
// than a second hand-picked set that almost matches.
func PaletteCSS() []string {
	out := make([]string, len(ChannelColors))
	for i, s := range ChannelColors {
		out[i] = "#" + hex2(s[0]) + hex2(s[1]) + hex2(s[2])
	}
	return out
}

func hex2(v float32) string {
	c := color.RGBA{R: uint8(clamp01(v)*255 + 0.5)}
	const digits = "0123456789abcdef"
	return string([]byte{digits[c.R>>4], digits[c.R&0x0f]})
}

func clamp01(v float32) float32 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
