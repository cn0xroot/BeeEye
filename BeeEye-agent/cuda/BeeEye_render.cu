// 蜂眼 BeeEye — CUDA color-field renderer for the live analyzer GUI.
//
// This computes the analyzer's traffic waterfall per pixel on the GPU: the
// intensity history (channels × time buckets) is uploaded each frame, and the
// kernel maps it through a palette with a neighborhood glow, a grid overlay
// and a moving scan sweep, writing RGBA8 out.
//
// Why on the GPU at all: the glow term is a gather over a 13-tap neighborhood
// in both axes for every pixel, so a 1024×288 frame is ~4.9M texture-ish reads
// per frame. That is exactly the shape a GPU is built for and a per-pixel loop
// in Go is not.
//
// The Go side keeps a CPU implementation of the identical math
// (internal/render/software.go) so a host with no NVIDIA GPU still gets the
// same picture — slower, but never a blank panel. render_test.go compares the
// two outputs to keep them from drifting apart.
//
// Build: make cuda   (nvcc -O3 --shared -Xcompiler -fPIC)

#include <cuda_runtime.h>
#include <math.h>

// Colour model: HUE CARRIES IDENTITY, BRIGHTNESS CARRIES MAGNITUDE.
//
// Each protocol channel owns a hue, supplied per frame by the caller and taken
// from the same eight-slot palette the packet list colours its rows with — so
// a row of the field and a row of the list mean the same thing in the same
// colour. Intensity then interpolates that hue up from the dark ground, and
// the very top of the range blooms toward a warm white so bursts still read as
// "hot" rather than merely "more saturated".
//
// A single magnitude ramp was tried first and rejected: with hue spent on
// magnitude, a quiet network rendered as eight indistinguishable navy stripes.
__constant__ float c_ground[3] = {0.043f, 0.062f, 0.118f};
__constant__ float c_hot[3] = {1.000f, 0.976f, 0.929f};

// Saturation applied to a channel's hue before it is mixed with the ground.
// Mixing toward a dark navy desaturates as it darkens, so without this
// everything below a full burst drifts toward the ground's own colour and the
// field reads as one blue-grey wash. Mirrors render.chromaBoost.
#define CHROMA_BOOST 1.35f

__device__ __forceinline__ float clamp01(float v) {
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
}

#define GLOW_RADIUS 6

// beeeye_render_waterfall renders one frame.
//
//   intensity : [channels * width] row-major, values already normalized 0..1
//   width     : time buckets, one pixel column each
//   height    : output rows; each channel gets height/channels rows
//   time_s    : wall time, drives the scan sweep so the panel reads as live
//   out       : RGBA8, width * height * 4 bytes
extern "C" __global__ void beeeye_render_waterfall(
    const float *__restrict__ intensity,
    const float *__restrict__ channel_rgb, /* [channels * 3], 0..1 */
    int channels, int width, int height,
    float time_s,
    unsigned char *__restrict__ out)
{
    int x = blockIdx.x * blockDim.x + threadIdx.x;
    int y = blockIdx.y * blockDim.y + threadIdx.y;
    if (x >= width || y >= height || channels <= 0) return;

    float band_h = (float)height / (float)channels;
    int ch = (int)((float)y / band_h);
    if (ch >= channels) ch = channels - 1;

    // Position within this channel's band, 0 at the top edge, 1 at the bottom.
    float band_pos = ((float)y - (float)ch * band_h) / band_h;

    float base = intensity[ch * width + x];

    // Neighborhood glow: a separable-ish gather over time (x) and across the
    // two adjacent channels, weighted by distance. This is what makes a burst
    // bloom outward instead of appearing as a hard rectangle.
    float glow = 0.0f;
    float wsum = 0.0f;
    for (int dx = -GLOW_RADIUS; dx <= GLOW_RADIUS; ++dx) {
        int sx = x + dx;
        if (sx < 0 || sx >= width) continue;
        for (int dc = -1; dc <= 1; ++dc) {
            int sc = ch + dc;
            if (sc < 0 || sc >= channels) continue;
            float d = sqrtf((float)(dx * dx) + (float)(dc * dc) * 9.0f);
            float w = expf(-d * d / (2.0f * 3.2f * 3.2f));
            glow += intensity[sc * width + sx] * w;
            wsum += w;
        }
    }
    if (wsum > 0.0f) glow /= wsum;

    // The band's vertical profile: brightest at the centre line, falling off
    // toward the edges, so each channel reads as its own ridge.
    float centre = 1.0f - fabsf(band_pos - 0.5f) * 2.0f;
    float ridge = powf(clamp01(centre), 0.65f);

    float v = clamp01(base * 0.95f + glow * 0.85f) * ridge;

    // Perceptual gamma. Without it a quiet network sits at the bottom of the
    // range and the whole panel reads as flat ground — technically accurate,
    // but it hides the small flows that are the interesting ones.
    v = powf(clamp01(v), 0.45f);

    float hr = channel_rgb[ch * 3 + 0];
    float hg = channel_rgb[ch * 3 + 1];
    float hb = channel_rgb[ch * 3 + 2];

    /* Saturate the hue before it is mixed down toward the ground. */
    float lum = 0.299f * hr + 0.587f * hg + 0.114f * hb;
    hr = clamp01(lum + (hr - lum) * CHROMA_BOOST);
    hg = clamp01(lum + (hg - lum) * CHROMA_BOOST);
    hb = clamp01(lum + (hb - lum) * CHROMA_BOOST);

    /* Ground → this channel's hue, then bloom toward warm white at the top. */
    float r = c_ground[0] + (hr - c_ground[0]) * v;
    float g = c_ground[1] + (hg - c_ground[1]) * v;
    float b = c_ground[2] + (hb - c_ground[2]) * v;

    if (v > 0.62f) {
        float hot = (v - 0.62f) / 0.38f * 0.80f;
        r += (c_hot[0] - r) * hot;
        g += (c_hot[1] - g) * hot;
        b += (c_hot[2] - b) * hot;
    }

    // Grid: a hairline between channel bands and a time ruler every 64 columns.
    float band_edge = (band_pos < 0.012f || band_pos > 0.988f) ? 1.0f : 0.0f;
    float time_tick = (x % 64 == 0) ? 1.0f : 0.0f;
    float grid = clamp01(band_edge * 0.35f + time_tick * 0.12f);
    r = r + (0.42f - r) * grid;
    g = g + (0.90f - g) * grid;
    b = b + (1.00f - b) * grid;

    // Scan sweep: a soft highlight travelling left to right once every 6s.
    float sweep_x = fmodf(time_s / 6.0f, 1.0f) * (float)width;
    float sd = fabsf((float)x - sweep_x);
    float sweep = expf(-sd * sd / (2.0f * 26.0f * 26.0f)) * 0.22f;
    r = clamp01(r + sweep * 0.55f);
    g = clamp01(g + sweep * 0.95f);
    b = clamp01(b + sweep);

    int o = (y * width + x) * 4;
    out[o + 0] = (unsigned char)(clamp01(r) * 255.0f + 0.5f);
    out[o + 1] = (unsigned char)(clamp01(g) * 255.0f + 0.5f);
    out[o + 2] = (unsigned char)(clamp01(b) * 255.0f + 0.5f);
    out[o + 3] = 255;
}

// ---------------------------------------------------------------- host API
//
// A tiny C surface so CGO does not have to know about CUDA types. Device
// buffers are allocated once and reused; reallocating per frame would dominate
// the runtime of a kernel this small.

static float *d_intensity = 0;
static float *d_hue = 0;
static unsigned char *d_out = 0;
static size_t d_intensity_cap = 0;
static size_t d_hue_cap = 0;
static size_t d_out_cap = 0;

extern "C" int BeeEyeRenderAvailable(void) {
    int count = 0;
    if (cudaGetDeviceCount(&count) != cudaSuccess) return 0;
    return count > 0 ? 1 : 0;
}

extern "C" int BeeEyeRenderDeviceName(char *buf, int buflen) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) return -1;
    int i = 0;
    for (; i < buflen - 1 && prop.name[i]; ++i) buf[i] = prop.name[i];
    buf[i] = 0;
    return i;
}

extern "C" int BeeEyeRenderFrame(const float *intensity, const float *channel_rgb,
                                 int channels, int width, int height,
                                 float time_s, unsigned char *out)
{
    if (channels <= 0 || width <= 0 || height <= 0) return -1;

    size_t in_bytes = (size_t)channels * (size_t)width * sizeof(float);
    size_t hue_bytes = (size_t)channels * 3 * sizeof(float);
    size_t out_bytes = (size_t)width * (size_t)height * 4;

    if (in_bytes > d_intensity_cap) {
        if (d_intensity) cudaFree(d_intensity);
        if (cudaMalloc((void **)&d_intensity, in_bytes) != cudaSuccess) return -2;
        d_intensity_cap = in_bytes;
    }
    if (hue_bytes > d_hue_cap) {
        if (d_hue) cudaFree(d_hue);
        if (cudaMalloc((void **)&d_hue, hue_bytes) != cudaSuccess) return -2;
        d_hue_cap = hue_bytes;
    }
    if (out_bytes > d_out_cap) {
        if (d_out) cudaFree(d_out);
        if (cudaMalloc((void **)&d_out, out_bytes) != cudaSuccess) return -3;
        d_out_cap = out_bytes;
    }

    if (cudaMemcpy(d_intensity, intensity, in_bytes, cudaMemcpyHostToDevice) != cudaSuccess)
        return -4;
    if (cudaMemcpy(d_hue, channel_rgb, hue_bytes, cudaMemcpyHostToDevice) != cudaSuccess)
        return -4;

    dim3 block(16, 16);
    dim3 grid((width + block.x - 1) / block.x, (height + block.y - 1) / block.y);
    beeeye_render_waterfall<<<grid, block>>>(d_intensity, d_hue, channels, width, height, time_s, d_out);

    if (cudaGetLastError() != cudaSuccess) return -5;
    if (cudaDeviceSynchronize() != cudaSuccess) return -6;
    if (cudaMemcpy(out, d_out, out_bytes, cudaMemcpyDeviceToHost) != cudaSuccess) return -7;
    return 0;
}

extern "C" void BeeEyeRenderShutdown(void) {
    if (d_intensity) { cudaFree(d_intensity); d_intensity = 0; d_intensity_cap = 0; }
    if (d_hue) { cudaFree(d_hue); d_hue = 0; d_hue_cap = 0; }
    if (d_out) { cudaFree(d_out); d_out = 0; d_out_cap = 0; }
}
