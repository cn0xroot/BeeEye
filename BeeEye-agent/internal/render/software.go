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
			d := math.Sqrt(float64(dx*dx) + float64(dc*dc)*9.0)
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
