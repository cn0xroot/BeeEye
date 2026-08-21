package render

import "math"

// cpuRenderer is the portable implementation. It computes exactly what
// beeeye_render_waterfall computes in cuda/BeeEye_render.cu — same palette,
// same glow kernel, same grid and sweep — so switching backends changes the
// speed and nothing else.
type cpuRenderer struct{}

// NewCPURenderer returns the software backend. Callers normally use
// NewRenderer, which picks CUDA when it is available.
func NewCPURenderer() Renderer { return cpuRenderer{} }

func (cpuRenderer) Name() string   { return "cpu" }
func (cpuRenderer) Device() string { return "" }
func (cpuRenderer) Close() error   { return nil }

const glowRadius = 6

// glowCrossChannelPenalty inflates a cross-channel glow step's effective
// distance before it goes into the same Gaussian the in-channel (dx-only)
// taps use — mirrors cuda/BeeEye_render.cu's GLOW_CROSS_CHANNEL_PENALTY, see
// that comment for why 49.0 (not the original 9.0): a wide, busy row must
// not visibly bleed into a completely idle neighbour (mqtt or http with zero
// traffic next to a loud tls or tcp row) and read as faintly lit rather than
// the flat dark the absence of data actually is.
const glowCrossChannelPenalty = 49.0

func (cpuRenderer) Render(intensity, channelRGB []float32, channels, width, height int, timeS float32, out []byte) error {
	if channels <= 0 || width <= 0 || height <= 0 {
		return errBadGeometry
	}
	if len(intensity) < channels*width || len(out) < width*height*4 ||
		len(channelRGB) < channels*3 {
		return errBadGeometry
	}

	bandH := float32(height) / float32(channels)

	// Precompute the glow weights once: the kernel is separable in nothing
	// useful here, but the weights repeat for every pixel.
	type tap struct {
		dx, dc int
		w      float32
	}
	var taps []tap
	var wsumFull float32
	for dx := -glowRadius; dx <= glowRadius; dx++ {
		for dc := -1; dc <= 1; dc++ {
			d := math.Sqrt(float64(dx*dx) + float64(dc*dc)*glowCrossChannelPenalty)
			w := float32(math.Exp(-d * d / (2.0 * 3.2 * 3.2)))
			taps = append(taps, tap{dx, dc, w})
			wsumFull += w
		}
	}
	_ = wsumFull

	for y := 0; y < height; y++ {
		ch := int(float32(y) / bandH)
		if ch >= channels {
			ch = channels - 1
		}
		bandPos := (float32(y) - float32(ch)*bandH) / bandH

		centre := 1 - abs32(bandPos-0.5)*2
		ridge := float32(math.Pow(float64(clamp01(centre)), 0.65))

		bandEdge := float32(0)
		if bandPos < 0.012 || bandPos > 0.988 {
			bandEdge = 1
		}

		for x := 0; x < width; x++ {
			base := intensity[ch*width+x]

			var glow, wsum float32
			for _, t := range taps {
				sx, sc := x+t.dx, ch+t.dc
				if sx < 0 || sx >= width || sc < 0 || sc >= channels {
					continue
				}
				glow += intensity[sc*width+sx] * t.w
				wsum += t.w
			}
			if wsum > 0 {
				glow /= wsum
			}

			v := clamp01(base*0.95+glow*0.85) * ridge
			// Perceptual gamma, mirroring the kernel: a quiet network would
			// otherwise sit at the bottom of the range and read as flat ground.
			v = float32(math.Pow(float64(clamp01(v)), 0.45))

			// Hue carries identity (which channel), brightness carries
			// magnitude — see the note in cuda/BeeEye_render.cu.
			hr := channelRGB[ch*3+0]
			hg := channelRGB[ch*3+1]
			hb := channelRGB[ch*3+2]

			// Saturate the hue before it is mixed down toward the ground.
			lum := 0.299*hr + 0.587*hg + 0.114*hb
			hr = clamp01(lum + (hr-lum)*chromaBoost)
			hg = clamp01(lum + (hg-lum)*chromaBoost)
			hb = clamp01(lum + (hb-lum)*chromaBoost)

			r := ground[0] + (hr-ground[0])*v
			g := ground[1] + (hg-ground[1])*v
			b := ground[2] + (hb-ground[2])*v
			if v > 0.62 {
				h := (v - 0.62) / 0.38 * 0.80
				r += (hot[0] - r) * h
				g += (hot[1] - g) * h
				b += (hot[2] - b) * h
			}

			timeTick := float32(0)
			if x%64 == 0 {
				timeTick = 1
			}
			grid := clamp01(bandEdge*0.35 + timeTick*0.12)
			r += (0.42 - r) * grid
			g += (0.90 - g) * grid
			b += (1.00 - b) * grid

			sweepX := float32(math.Mod(float64(timeS)/6.0, 1.0)) * float32(width)
			sd := abs32(float32(x) - sweepX)
			sweep := float32(math.Exp(-float64(sd*sd)/(2.0*26.0*26.0))) * 0.22
			r = clamp01(r + sweep*0.55)
			g = clamp01(g + sweep*0.95)
			b = clamp01(b + sweep)

			o := (y*width + x) * 4
			out[o+0] = uint8(clamp01(r)*255 + 0.5)
			out[o+1] = uint8(clamp01(g)*255 + 0.5)
			out[o+2] = uint8(clamp01(b)*255 + 0.5)
			out[o+3] = 255
		}
	}
	return nil
}

func abs32(v float32) float32 {
	if v < 0 {
		return -v
	}
	return v
}

// curveGlowSigma is the standard deviation, in pixels, of the glow bleeding
// off the stroke in both directions — the curve's counterpart to Render's
// own neighbourhood glow (see glowRadius above), so the two panels share a
// visual language instead of one looking hand-drawn next to the other.
const curveGlowSigma = 3.2

// curveHotLow/curveHotHigh bound the smoothstep a burst's height rides from
// the plain stroke colour toward hotRGB — mirrors Render's v > 0.62 bloom,
// just expressed as a soft ramp instead of a hard threshold so it does not
// flicker in and out as a value hovers near the edge.
const (
	curveHotLow  = 0.55
	curveHotHigh = 0.92
)

func smoothstep01(edge0, edge1, x float32) float32 {
	t := clamp01((x - edge0) / (edge1 - edge0))
	return t * t * (3 - 2*t)
}

// segPointDist is the distance from a pixel's centre, (0.5, fy) in the local
// coordinates of a one-pixel-wide column, to the line segment joining that
// column's own sample, (0, y0), to the next column's, (1, y1). Anti-aliasing
// a curve from each column's OWN flat height independently — what an
// earlier version of this did — reads as a stepped bar chart with blur
// pasted around each step: a diagonal run between two differing heights
// needs a diagonal glow, which only a real point-to-segment distance gives.
func segPointDist(fy, y0, y1 float32) float32 {
	abY := y1 - y0
	denom := 1 + abY*abY // |ab|^2 with ab = (1, abY)
	t := clamp01((0.5 + (fy-y0)*abY) / denom)
	dx := 0.5 - t
	dy := fy - (y0 + t*abY)
	return float32(math.Sqrt(float64(dx*dx + dy*dy)))
}

// RenderCurve is the portable implementation, computing exactly what
// beeeye_render_curve computes in cuda/BeeEye_render.cu — same glow, bloom
// and scan sweep — so switching backends changes only the speed.
func (cpuRenderer) RenderCurve(txValues, rxValues []float32, width, height int, timeS float32, txRGB, rxRGB, hotRGB, baseRGB [3]float32, out []byte) error {
	if width <= 0 || height <= 0 {
		return errBadGeometry
	}
	if len(txValues) < width || len(rxValues) < width || len(out) < width*height*4 {
		return errBadGeometry
	}
	half := height / 2
	sweepX := float32(math.Mod(float64(timeS)/6.0, 1.0)) * float32(width)

	for x := 0; x < width; x++ {
		nx := x + 1
		if nx >= width {
			nx = x
		}
		htx0, htx1 := clamp01(txValues[x]), clamp01(txValues[nx])
		hrx0, hrx1 := clamp01(rxValues[x]), clamp01(rxValues[nx])

		// tx grows upward from the baseline (row `half`) toward row 0; rx
		// grows downward from the same baseline toward row height-1.
		txY0, txY1 := float32(half)*(1-htx0), float32(half)*(1-htx1)
		rxSpan := float32(height - 1 - half)
		rxY0, rxY1 := float32(half)+hrx0*rxSpan, float32(half)+hrx1*rxSpan
		txYMid, rxYMid := (txY0+txY1)/2, (rxY0+rxY1)/2

		hotTtx := smoothstep01(curveHotLow, curveHotHigh, htx0)
		ltx := [3]float32{
			txRGB[0] + (hotRGB[0]-txRGB[0])*hotTtx,
			txRGB[1] + (hotRGB[1]-txRGB[1])*hotTtx,
			txRGB[2] + (hotRGB[2]-txRGB[2])*hotTtx,
		}
		hotTrx := smoothstep01(curveHotLow, curveHotHigh, hrx0)
		lrx := [3]float32{
			rxRGB[0] + (hotRGB[0]-rxRGB[0])*hotTrx,
			rxRGB[1] + (hotRGB[1]-rxRGB[1])*hotTrx,
			rxRGB[2] + (hotRGB[2]-rxRGB[2])*hotTrx,
		}

		grid := float32(0)
		if x%64 == 0 {
			grid = 0.10
		}
		sd := abs32(float32(x) - sweepX)
		sweep := float32(math.Exp(-float64(sd*sd)/(2.0*26.0*26.0))) * 0.15

		for y := 0; y < height; y++ {
			fy := float32(y)
			var r, g, b float32
			if y < half {
				glow := gaussGlow(segPointDist(fy, txY0, txY1))
				if fy < txYMid {
					// Above the tx curve: ground (+ faint ruler grid) with
					// the stroke's glow bleeding up off it.
					r, g, b = baseRGB[0]+grid*0.30, baseRGB[1]+grid*0.60, baseRGB[2]+grid*0.90
					gw := glow * 0.85
					r += (ltx[0] - r) * gw
					g += (ltx[1] - g) * gw
					b += (ltx[2] - b) * gw
				} else {
					// Filled: brightest right under the stroke, fading to
					// baseRGB as it nears the baseline.
					t := float32(0)
					if span := float32(half) - txYMid; span > 1e-4 {
						t = clamp01((fy - txYMid) / span)
					}
					r = txRGB[0] + (baseRGB[0]-txRGB[0])*t
					g = txRGB[1] + (baseRGB[1]-txRGB[1])*t
					b = txRGB[2] + (baseRGB[2]-txRGB[2])*t
					r += (ltx[0] - r) * glow
					g += (ltx[1] - g) * glow
					b += (ltx[2] - b) * glow
				}
			} else {
				glow := gaussGlow(segPointDist(fy, rxY0, rxY1))
				if fy > rxYMid {
					r, g, b = baseRGB[0]+grid*0.30, baseRGB[1]+grid*0.60, baseRGB[2]+grid*0.90
					gw := glow * 0.85
					r += (lrx[0] - r) * gw
					g += (lrx[1] - g) * gw
					b += (lrx[2] - b) * gw
				} else {
					t := float32(0)
					if span := rxYMid - float32(half); span > 1e-4 {
						t = clamp01((rxYMid - fy) / span)
					}
					r = rxRGB[0] + (baseRGB[0]-rxRGB[0])*t
					g = rxRGB[1] + (baseRGB[1]-rxRGB[1])*t
					b = rxRGB[2] + (baseRGB[2]-rxRGB[2])*t
					r += (lrx[0] - r) * glow
					g += (lrx[1] - g) * glow
					b += (lrx[2] - b) * glow
				}
			}

			// A thin baseline hairline anchors the eye at the tx/rx split —
			// without it, a quiet moment (both series near zero) is just a
			// flat field with no visible centre.
			if y == half-1 || y == half {
				r, g, b = r+0.05, g+0.05, b+0.06
			}

			// Scan sweep, matching Render's own "reads as live" touch.
			r = clamp01(r + sweep*0.5)
			g = clamp01(g + sweep*0.85)
			b = clamp01(b + sweep)

			o := (y*width + x) * 4
			out[o+0] = uint8(clamp01(r)*255 + 0.5)
			out[o+1] = uint8(clamp01(g)*255 + 0.5)
			out[o+2] = uint8(clamp01(b)*255 + 0.5)
			out[o+3] = 255
		}
	}
	return nil
}

func gaussGlow(dist float32) float32 {
	return float32(math.Exp(-float64(dist*dist) / (2.0 * curveGlowSigma * curveGlowSigma)))
}
