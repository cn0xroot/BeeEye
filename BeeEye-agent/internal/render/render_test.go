package render

import (
	"math"
	"math/rand"
	"testing"
)

func testIntensity(channels, width int) []float32 {
	rng := rand.New(rand.NewSource(7))
	in := make([]float32, channels*width)
	for c := 0; c < channels; c++ {
		for x := 0; x < width; x++ {
			// A couple of bursts plus a noise floor, so the glow and the
			// palette are both actually exercised.
			v := float32(rng.Float64()) * 0.15
			if x > width/3 && x < width/3+20 && c == 2 {
				v = 0.95
			}
			if x > width/2 && x < width/2+6 {
				v += 0.6
			}
			in[c*width+x] = clamp01(v)
		}
	}
	return in
}

func TestCPURenderProducesAColourfulField(t *testing.T) {
	const ch, w, h = 8, 256, 128
	out := make([]byte, w*h*4)
	if err := NewCPURenderer().Render(testIntensity(ch, w), ChannelRGB(ch), ch, w, h, 1.5, out); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Every pixel opaque.
	for i := 3; i < len(out); i += 4 {
		if out[i] != 255 {
			t.Fatalf("pixel %d is not opaque", i/4)
		}
	}

	// The requirement is specifically a colourful field, not a grayscale one,
	// so assert that channels actually diverge rather than tracking together.
	maxSpread := 0
	for i := 0; i < len(out); i += 4 {
		r, g, b := int(out[i]), int(out[i+1]), int(out[i+2])
		spread := max(r, max(g, b)) - min(r, min(g, b))
		if spread > maxSpread {
			maxSpread = spread
		}
	}
	if maxSpread < 60 {
		t.Errorf("max channel spread %d: the frame is nearly grayscale", maxSpread)
	}
}

func testCurveValues(width int) []float32 {
	rng := rand.New(rand.NewSource(11))
	out := make([]float32, width)
	for x := 0; x < width; x++ {
		v := float32(rng.Float64()) * 0.2
		if x > width/2 && x < width/2+10 {
			v = 0.9 // a spike, to exercise the stroke and fill at a real height
		}
		out[x] = clamp01(v)
	}
	return out
}

func TestCPURenderCurveDrawsGroundStrokeAndFill(t *testing.T) {
	const w, h = 256, 128
	const half = h / 2
	tx := testCurveValues(w)
	rx := make([]float32, w) // idle rx: baseline flat, isolates the tx half for this check
	out := make([]byte, w*h*4)
	txRGB := [3]float32{0.3, 0.6, 1}
	rxRGB := [3]float32{1, 0.5, 0.2}
	hot := [3]float32{1, 1, 1}
	base := [3]float32{0.02, 0.05, 0.1}
	if err := NewCPURenderer().RenderCurve(tx, rx, w, h, 0, txRGB, rxRGB, hot, base, out); err != nil {
		t.Fatalf("RenderCurve: %v", err)
	}

	for i := 3; i < len(out); i += 4 {
		if out[i] != 255 {
			t.Fatalf("pixel %d is not opaque", i/4)
		}
	}

	// At the spike column (tx half, rows 0..half-1), the pixel just above the
	// curve height should be ground (dark) and the pixel just below should
	// be the fill (brighter, tinted toward the fill colour) — otherwise the
	// "area under the curve" is not actually being drawn.
	x := w/2 + 5
	var spikeHeight float32 = 0.9
	curveY := int(float32(half) * (1 - spikeHeight))
	above := (max(curveY-4, 0)*w + x) * 4
	below := (min(curveY+4, half-1)*w + x) * 4
	aboveBrightness := int(out[above]) + int(out[above+1]) + int(out[above+2])
	belowBrightness := int(out[below]) + int(out[below+1]) + int(out[below+2])
	if belowBrightness <= aboveBrightness {
		t.Errorf("fill (brightness %d) is not brighter than ground (brightness %d) below the curve", belowBrightness, aboveBrightness)
	}
}

func TestRenderCurveRejectsBadGeometry(t *testing.T) {
	r := NewCPURenderer()
	line := [3]float32{1, 1, 1}
	if err := r.RenderCurve(make([]float32, 4), make([]float32, 4), 256, 128, 0, line, line, line, line, make([]byte, 10)); err == nil {
		t.Error("accepted an undersized output buffer")
	}
	if err := r.RenderCurve(make([]float32, 4), make([]float32, 4), 256, 128, 0, line, line, line, line, make([]byte, 256*128*4)); err == nil {
		t.Error("accepted an undersized values buffer")
	}
}

func TestRenderRejectsBadGeometry(t *testing.T) {
	r := NewCPURenderer()
	out := make([]byte, 10)
	if err := r.Render(make([]float32, 4), ChannelRGB(2), 2, 2, 2, 0, out); err == nil {
		t.Error("accepted an undersized output buffer")
	}
	if err := r.Render(make([]float32, 1), ChannelRGB(8), 8, 256, 128, 0, make([]byte, 256*128*4)); err == nil {
		t.Error("accepted an undersized intensity buffer")
	}
}

func TestHistoryNormalizesAndAges(t *testing.T) {
	h := NewHistory([]string{"tls", "dns", "other"}, 8)
	h.Add("tls", 1000)
	h.Add("dns", 10)
	h.Add("nosuchchannel", 5) // must land in the last channel, not panic

	snap := h.Snapshot()
	if len(snap) != 3*8 {
		t.Fatalf("snapshot length %d, want 24", len(snap))
	}
	tls := snap[0*8+7]
	dns := snap[1*8+7]
	other := snap[2*8+7]
	if tls <= dns || dns <= 0 {
		t.Errorf("expected tls(%v) > dns(%v) > 0", tls, dns)
	}
	if other <= 0 {
		t.Error("unknown channel name did not fall through to the last channel")
	}
	// Log scaling must keep the small flow visible next to the large one —
	// on a linear scale dns would be 1% and invisible.
	if dns < 0.2 {
		t.Errorf("dns intensity %v is too compressed; log scaling is not working", dns)
	}

	h.Rotate()
	snap = h.Snapshot()
	if snap[0*8+7] != 0 {
		t.Error("Rotate did not open a fresh bucket")
	}
	if snap[0*8+6] <= 0 {
		t.Error("Rotate lost the previous bucket instead of shifting it")
	}
}

func TestPaletteCSSMatchesChannels(t *testing.T) {
	css := PaletteCSS()
	if len(css) != len(ChannelColors) {
		t.Fatalf("got %d css stops, want %d", len(css), len(ChannelColors))
	}

	// Check every slot against the float the renderer actually draws with,
	// rather than only the two endpoints: the frontend copies these hex values
	// into its own swatches, so a slot that rounds to a different colour than
	// it is rendered in makes the packet list disagree with the field.
	for i, c := range ChannelColors {
		want := "#" + hex2(c[0]) + hex2(c[1]) + hex2(c[2])
		if css[i] != want {
			t.Errorf("slot %d css = %s, want %s", i, css[i], want)
		}
	}

	// The endpoints are pinned as well, so reordering or replacing the palette
	// is a deliberate edit here and not a silent one.
	if css[0] != "#2e9dff" || css[len(css)-1] != "#ff5252" {
		t.Errorf("palette endpoints = %s .. %s, want #2e9dff .. #ff5252", css[0], css[len(css)-1])
	}
}

// TestBackendsAgree only has something to compare when the binary was built
// with the cuda tag and a device is present. It is the guard against the CUDA
// kernel and the Go fallback drifting apart as either is edited.
func TestBackendsAgree(t *testing.T) {
	gpu := NewRenderer()
	if gpu.Name() != "cuda" {
		t.Skip("not built with -tags cuda, or no CUDA device present")
	}
	defer gpu.Close()

	const ch, w, h = 8, 256, 128
	in := testIntensity(ch, w)
	gpuOut := make([]byte, w*h*4)
	cpuOut := make([]byte, w*h*4)

	if err := gpu.Render(in, ChannelRGB(ch), ch, w, h, 1.5, gpuOut); err != nil {
		t.Fatalf("cuda render: %v", err)
	}
	if err := NewCPURenderer().Render(in, ChannelRGB(ch), ch, w, h, 1.5, cpuOut); err != nil {
		t.Fatalf("cpu render: %v", err)
	}

	// Float maths differs slightly between the two; a couple of levels of
	// tolerance per channel is expected, a visible difference is not.
	var worst, total float64
	for i := range gpuOut {
		d := math.Abs(float64(gpuOut[i]) - float64(cpuOut[i]))
		total += d
		if d > worst {
			worst = d
		}
	}
	mean := total / float64(len(gpuOut))
	if worst > 3 {
		t.Errorf("worst per-channel difference %v (mean %.4f) — the kernels have diverged", worst, mean)
	}
	t.Logf("cuda device %q, worst channel delta %v, mean %.5f", gpu.Device(), worst, mean)
}

// TestCurveBackendsAgree is TestBackendsAgree's counterpart for RenderCurve —
// same skip-unless-cuda guard, same job of catching the kernel and the Go
// fallback drifting apart.
func TestCurveBackendsAgree(t *testing.T) {
	gpu := NewRenderer()
	if gpu.Name() != "cuda" {
		t.Skip("not built with -tags cuda, or no CUDA device present")
	}
	defer gpu.Close()

	const w, h = 256, 128
	tx := testCurveValues(w)
	rx := make([]float32, w) // a distinct series, not just tx again, so both halves get real coverage
	for i, v := range tx {
		rx[w-1-i] = v
	}
	txRGB := [3]float32{0.3, 0.6, 1}
	rxRGB := [3]float32{1, 0.5, 0.2}
	hot := [3]float32{1.0, 0.976, 0.929}
	base := [3]float32{0.02, 0.05, 0.1}
	gpuOut := make([]byte, w*h*4)
	cpuOut := make([]byte, w*h*4)

	if err := gpu.RenderCurve(tx, rx, w, h, 1.5, txRGB, rxRGB, hot, base, gpuOut); err != nil {
		t.Fatalf("cuda render: %v", err)
	}
	if err := NewCPURenderer().RenderCurve(tx, rx, w, h, 1.5, txRGB, rxRGB, hot, base, cpuOut); err != nil {
		t.Fatalf("cpu render: %v", err)
	}

	var worst, total float64
	for i := range gpuOut {
		d := math.Abs(float64(gpuOut[i]) - float64(cpuOut[i]))
		total += d
		if d > worst {
			worst = d
		}
	}
	mean := total / float64(len(gpuOut))
	if worst > 3 {
		t.Errorf("worst per-channel difference %v (mean %.4f) — the kernels have diverged", worst, mean)
	}
	t.Logf("cuda device %q, worst channel delta %v, mean %.5f", gpu.Device(), worst, mean)
}

// TestBarsBackendsAgree is TestBackendsAgree's counterpart for RenderBars —
// same skip-unless-cuda guard, same job of catching the kernel and the Go
// fallback drifting apart.
func TestBarsBackendsAgree(t *testing.T) {
	gpu := NewRenderer()
	if gpu.Name() != "cuda" {
		t.Skip("not built with -tags cuda, or no CUDA device present")
	}
	defer gpu.Close()

	const count, w, h = 8, 256, 128
	values := make([]float32, count)
	for i := range values {
		// A descending ranked bar chart, the shape this is actually used for
		// (top talkers / protocol share sorted by size), plus one zero-length
		// row to exercise the "nothing past x=0" edge.
		values[i] = clamp01(1 - float32(i)/float32(count))
	}
	values[count-1] = 0
	colors := ChannelRGB(count)
	hot := [3]float32{1.0, 0.976, 0.929}
	base := [3]float32{0.043, 0.062, 0.118}
	gpuOut := make([]byte, w*h*4)
	cpuOut := make([]byte, w*h*4)

	if err := gpu.RenderBars(values, colors, count, w, h, hot, base, gpuOut); err != nil {
		t.Fatalf("cuda render: %v", err)
	}
	if err := NewCPURenderer().RenderBars(values, colors, count, w, h, hot, base, cpuOut); err != nil {
		t.Fatalf("cpu render: %v", err)
	}

	var worst, total float64
	for i := range gpuOut {
		d := math.Abs(float64(gpuOut[i]) - float64(cpuOut[i]))
		total += d
		if d > worst {
			worst = d
		}
	}
	mean := total / float64(len(gpuOut))
	if worst > 3 {
		t.Errorf("worst per-channel difference %v (mean %.4f) — the kernels have diverged", worst, mean)
	}
	t.Logf("cuda device %q, worst channel delta %v, mean %.5f", gpu.Device(), worst, mean)
}
