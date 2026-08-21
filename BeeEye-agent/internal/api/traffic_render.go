package api

import (
	"net/http"
	"time"

	"BeeEye/internal/render"
)

// trafficRate turns raw captured bytes into an "instantaneous rate over
// time" curve for the overview's traffic-trend panel — rendered on the GPU
// when one is available, via the same render.Renderer the analyzer's colour
// field already uses (F7 asked for the overview to feel as live as the
// analyzer does; this is the same mechanism, not a second one).
//
// It reuses render.History exactly as internal/gui/session.go does for the
// analyzer's field, just with two channels rather than eight: "tx" (this
// gateway sending) and "rx" (this gateway receiving), mirrored above/below a
// centre baseline the way a bandwidth monitor shows upload/download — a
// single combined-throughput line was what conky draws, but conky was
// reference material for "show the shape of the traffic changing", not a
// spec to copy; splitting direction is what actually shows more of that
// shape, since upload and download bursts rarely coincide.
type trafficRate struct {
	hist     *render.History
	renderer render.Renderer
	t0       time.Time // drives the scan sweep, same trick as the analyzer's own render loop
}

// trafficRateWidth is how many buckets (pixel columns) the curve holds.
// trafficRateTick × trafficRateWidth is the visible time span — 1s × 280 ≈
// 4.7 minutes, long enough to show a real trend, short enough that a burst a
// minute ago hasn't scrolled off by the time someone glances at it.
// trafficCurveHeight is taller relative to the width than a single-line
// chart would need, since each direction only gets half of it.
const (
	trafficRateWidth   = 280
	trafficRateTick    = time.Second
	trafficCurveHeight = 260
)

func newTrafficRate() *trafficRate {
	return &trafficRate{
		hist:     render.NewHistory([]string{"tx", "rx"}, trafficRateWidth),
		renderer: render.NewRenderer(),
		t0:       time.Now(),
	}
}

// Add credits bytes to the current, still-open bucket for whichever
// direction they moved — this gateway sending (tx) or receiving (rx). Safe
// to call from the capture pipeline's own goroutine — render.History has its
// own lock, same as the analyzer's session.hist.Add does from its consume()
// loop.
func (t *trafficRate) Add(tx, rx int64) {
	if t == nil {
		return
	}
	if tx > 0 {
		t.hist.Add("tx", float64(tx))
	}
	if rx > 0 {
		t.hist.Add("rx", float64(rx))
	}
}

// run rotates the bucket window once per tick, forever — call as `go
// rate.run()`. There is no stop channel because, like every other
// background goroutine main.go starts (tiStore.Start, hotplugSupervisor.watch),
// it runs for the life of the process.
func (t *trafficRate) run() {
	ticker := time.NewTicker(trafficRateTick)
	defer ticker.Stop()
	for range ticker.C {
		t.hist.Rotate()
	}
}

// smoothRadius controls how much the raw per-second samples are blurred
// before rendering. Each bucket is "how many bytes landed in this one
// second", which is inherently spiky — a download either had a packet in a
// given second or it didn't — and RenderCurve draws each column's height
// independently, so undoing that here is what turns a column-by-column bar
// chart into something that reads as a continuous curve. A triangular
// weighting was chosen over a flat box average because it keeps a real
// burst's peak from being flattened as badly as an unweighted mean would.
const smoothRadius = 5

func smoothCurve(values []float32) []float32 {
	out := make([]float32, len(values))
	for i := range values {
		var sum, wsum float32
		for k := -smoothRadius; k <= smoothRadius; k++ {
			j := i + k
			if j < 0 || j >= len(values) {
				continue
			}
			w := float32(smoothRadius + 1 - absInt(k))
			sum += values[j] * w
			wsum += w
		}
		if wsum > 0 {
			out[i] = sum / wsum
		}
	}
	return out
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// frame renders the current window as a PNG. tx keeps the product's amber
// brand accent (the same gradient the desktop app's icon and hexagon motif
// use — see BeeEye-desktop/src-tauri/icons); rx gets the field's own "tls"
// blue (render.ChannelColors[0]) — already validated for contrast against
// the dark ground and already meaning "the other direction" nowhere else in
// this UI, so borrowing it does not collide with an existing meaning the
// way inventing a fresh hue here would risk.
func (t *trafficRate) frame() ([]byte, error) {
	snap := t.hist.Snapshot() // [tx(width) | rx(width)], per render.History's layout
	txValues := smoothCurve(snap[0:trafficRateWidth])
	rxValues := smoothCurve(snap[trafficRateWidth : 2*trafficRateWidth])
	out := make([]byte, trafficRateWidth*trafficCurveHeight*4)
	timeS := float32(time.Since(t.t0).Seconds())
	txRGB := [3]float32{1.0, 0.784, 0.239}   // #ffc83d, the brand accent
	rxRGB := [3]float32{0.180, 0.616, 1.000} // #2e9dff, render.ChannelColors[0] ("tls" blue)
	hot := [3]float32{1.000, 0.976, 0.929}   // render.hot — a burst blooms toward this, same as the field
	base := [3]float32{0.043, 0.062, 0.118}  // render.ground — fades into the panel
	if err := t.renderer.RenderCurve(txValues, rxValues, trafficRateWidth, trafficCurveHeight, timeS, txRGB, rxRGB, hot, base, out); err != nil {
		return nil, err
	}
	return render.EncodePNG(out, trafficRateWidth, trafficCurveHeight)
}

func (s *Server) trafficFrame(w http.ResponseWriter, r *http.Request) {
	png, err := s.rate.frame()
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) trafficRenderInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"backend": s.rate.renderer.Name(),
		"device":  s.rate.renderer.Device(),
		"width":   trafficRateWidth,
		"height":  trafficCurveHeight,
		"tick_ms": trafficRateTick.Milliseconds(),
	})
}

// trafficSeries hands the window over as real byte-per-second numbers rather
// than a rendered picture, for a client-side chart that draws its own axis
// labels/gridlines — a PNG has already thrown away the numbers a "40 KB"
// label needs, only the picture. Values are the same triangular-smoothed
// estimate the GPU/CPU curve draws (see smoothCurve's own comment on why:
// raw per-second buckets are inherently spiky), not an exact per-second
// count, so this is "the rate", not a byte-accounting ledger.
func (t *trafficRate) series() ([]float64, []float64) {
	snap := t.hist.RawSnapshot()
	tx := smoothCurve(snap[0:trafficRateWidth])
	rx := smoothCurve(snap[trafficRateWidth : 2*trafficRateWidth])
	txOut := make([]float64, len(tx))
	rxOut := make([]float64, len(rx))
	for i, v := range tx {
		txOut[i] = float64(v)
	}
	for i, v := range rx {
		rxOut[i] = float64(v)
	}
	return txOut, rxOut
}

func (s *Server) trafficSeries(w http.ResponseWriter, r *http.Request) {
	tx, rx := s.rate.series()
	writeJSON(w, map[string]any{
		"tx":      tx,
		"rx":      rx,
		"tick_ms": trafficRateTick.Milliseconds(),
	})
}
