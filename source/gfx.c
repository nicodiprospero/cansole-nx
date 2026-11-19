// CANsole NX - tiny anti-aliased software renderer
#include "gfx.h"
#include <math.h>
#include <string.h>

static inline void blend(uint32_t *d, uint32_t col, int a) {
    if (a <= 0) return;
    if (a >= 255) { *d = col; return; }
    uint32_t s = *d;
    int sr = s & 255, sg = (s >> 8) & 255, sb = (s >> 16) & 255;
    int cr = col & 255, cg = (col >> 8) & 255, cb = (col >> 16) & 255;
    sr += ((cr - sr) * a) >> 8;
    sg += ((cg - sg) * a) >> 8;
    sb += ((cb - sb) * a) >> 8;
    *d = (uint32_t)sr | ((uint32_t)sg << 8) | ((uint32_t)sb << 16) | 0xFF000000u;
}

static inline void plot(Canvas *c, int x, int y, uint32_t col, int a) {
    if ((unsigned)x >= (unsigned)c->w || (unsigned)y >= (unsigned)c->h) return;
    blend(&c->px[y * c->stride + x], col, a);
}

static inline float clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }

uint32_t gfx_lerp(uint32_t a, uint32_t b, float t) {
    t = clampf(t, 0, 1);
    int ar = a & 255, ag = (a >> 8) & 255, ab = (a >> 16) & 255;
    int br = b & 255, bg = (b >> 8) & 255, bb = (b >> 16) & 255;
    return COL(ar + (int)((br - ar) * t), ag + (int)((bg - ag) * t), ab + (int)((bb - ab) * t));
}

void gfx_clear(Canvas *c, uint32_t col) {
    for (int y = 0; y < c->h; y++) {
        uint32_t *row = c->px + y * c->stride;
        for (int x = 0; x < c->w; x++) row[x] = col;
    }
}

void gfx_fill_a(Canvas *c, int x, int y, int w, int h, uint32_t col, int alpha) {
    int x0 = x < 0 ? 0 : x, y0 = y < 0 ? 0 : y;
    int x1 = x + w > c->w ? c->w : x + w, y1 = y + h > c->h ? c->h : y + h;
    if (x1 <= x0 || y1 <= y0) return;
    for (int yy = y0; yy < y1; yy++) {
        uint32_t *row = c->px + yy * c->stride;
        if (alpha >= 255)
            for (int xx = x0; xx < x1; xx++) row[xx] = col;
        else
            for (int xx = x0; xx < x1; xx++) blend(&row[xx], col, alpha);
    }
}

void gfx_fill(Canvas *c, int x, int y, int w, int h, uint32_t col) { gfx_fill_a(c, x, y, w, h, col, 255); }

void gfx_rrect(Canvas *c, int x, int y, int w, int h, int r, uint32_t col) {
    if (w <= 0 || h <= 0) return;
    if (r * 2 > w) r = w / 2;
    if (r * 2 > h) r = h / 2;
    if (r <= 0) { gfx_fill(c, x, y, w, h, col); return; }
    gfx_fill(c, x, y + r, w, h - 2 * r, col);
    gfx_fill(c, x + r, y, w - 2 * r, r, col);
    gfx_fill(c, x + r, y + h - r, w - 2 * r, r, col);
    for (int j = 0; j < r; j++)
        for (int i = 0; i < r; i++) {
            float dx = r - (i + 0.5f), dy = r - (j + 0.5f);
            float cov = clampf(r - sqrtf(dx * dx + dy * dy) + 0.5f, 0, 1);
            int a = (int)(cov * 255);
            if (!a) continue;
            plot(c, x + i, y + j, col, a);
            plot(c, x + w - 1 - i, y + j, col, a);
            plot(c, x + i, y + h - 1 - j, col, a);
            plot(c, x + w - 1 - i, y + h - 1 - j, col, a);
        }
}

void gfx_rrect_line(Canvas *c, int x, int y, int w, int h, int r, int t, uint32_t col) {
    if (w <= 0 || h <= 0) return;
    if (r * 2 > w) r = w / 2;
    if (r * 2 > h) r = h / 2;
    if (r < t) r = t;
    gfx_fill(c, x + r, y, w - 2 * r, t, col);
    gfx_fill(c, x + r, y + h - t, w - 2 * r, t, col);
    gfx_fill(c, x, y + r, t, h - 2 * r, col);
    gfx_fill(c, x + w - t, y + r, t, h - 2 * r, col);
    for (int j = 0; j < r; j++)
        for (int i = 0; i < r; i++) {
            float dx = r - (i + 0.5f), dy = r - (j + 0.5f);
            float d = sqrtf(dx * dx + dy * dy);
            float cov = clampf(r - d + 0.5f, 0, 1) - clampf((r - t) - d + 0.5f, 0, 1);
            int a = (int)(clampf(cov, 0, 1) * 255);
            if (!a) continue;
            plot(c, x + i, y + j, col, a);
            plot(c, x + w - 1 - i, y + j, col, a);
            plot(c, x + i, y + h - 1 - j, col, a);
            plot(c, x + w - 1 - i, y + h - 1 - j, col, a);
        }
}

void gfx_ring(Canvas *c, float cx, float cy, float ro, float ri, uint32_t col) {
    int y0 = (int)floorf(cy - ro - 1), y1 = (int)ceilf(cy + ro + 1);
    int x0 = (int)floorf(cx - ro - 1), x1 = (int)ceilf(cx + ro + 1);
    if (y0 < 0) y0 = 0;
    if (x0 < 0) x0 = 0;
    if (y1 > c->h) y1 = c->h;
    if (x1 > c->w) x1 = c->w;
    float ri2 = (ri - 1) > 0 ? (ri - 1) * (ri - 1) : 0;
    for (int y = y0; y < y1; y++) {
        float dy = y + 0.5f - cy;
        for (int x = x0; x < x1; x++) {
            float dx = x + 0.5f - cx;
            float d2 = dx * dx + dy * dy;
            if (d2 > (ro + 1) * (ro + 1)) continue;
            if (ri > 0 && d2 < ri2) continue;
            float d = sqrtf(d2);
            float cov = clampf(ro - d + 0.5f, 0, 1);
            if (ri > 0) cov -= clampf(ri - d + 0.5f, 0, 1);
            if (cov > 0) plot(c, x, y, col, (int)(cov * 255));
        }
    }
}

void gfx_circle(Canvas *c, float cx, float cy, float r, uint32_t col) { gfx_ring(c, cx, cy, r, 0, col); }

static float g_cov[4096];

void gfx_poly(Canvas *c, const float *xy, int n, uint32_t col) {
    if (n < 3) return;
    float miny = xy[1], maxy = xy[1];
    for (int i = 1; i < n; i++) {
        if (xy[i * 2 + 1] < miny) miny = xy[i * 2 + 1];
        if (xy[i * 2 + 1] > maxy) maxy = xy[i * 2 + 1];
    }
    int ys = (int)floorf(miny), ye = (int)ceilf(maxy);
    if (ys < 0) ys = 0;
    if (ye > c->h) ye = c->h;
    for (int py = ys; py < ye; py++) {
        int xmin = 1 << 30, xmax = -1;
        for (int s = 0; s < 4; s++) {
            float sy = py + (s + 0.5f) / 4.0f;
            float xl = 1e9f, xr = -1e9f;
            for (int i = 0; i < n; i++) {
                float ax = xy[i * 2], ay = xy[i * 2 + 1];
                float bx = xy[((i + 1) % n) * 2], by = xy[((i + 1) % n) * 2 + 1];
                if ((ay <= sy && by > sy) || (by <= sy && ay > sy)) {
                    float x = ax + (sy - ay) * (bx - ax) / (by - ay);
                    if (x < xl) xl = x;
                    if (x > xr) xr = x;
                }
            }
            if (xr <= xl) continue;
            if (xl < 0) xl = 0;
            if (xr > c->w) xr = (float)c->w;
            int pa = (int)floorf(xl), pb = (int)ceilf(xr);
            for (int px = pa; px < pb && px < 4096; px++) {
                float lo = px > xl ? px : xl;
                float hi = (px + 1) < xr ? (px + 1) : xr;
                if (hi > lo) g_cov[px] += (hi - lo) * 0.25f;
            }
            if (pa < xmin) xmin = pa;
            if (pb > xmax) xmax = pb;
        }
        for (int px = xmin; px < xmax && px < 4096; px++) {
            if (g_cov[px] > 0) plot(c, px, py, col, (int)(clampf(g_cov[px], 0, 1) * 255));
            g_cov[px] = 0;
        }
    }
}

void gfx_line(Canvas *c, float x0, float y0, float x1, float y1, float th, uint32_t col) {
    float dx = x1 - x0, dy = y1 - y0, len = sqrtf(dx * dx + dy * dy);
    if (len < 0.001f) return;
    float nx = -dy / len * th * 0.5f, ny = dx / len * th * 0.5f;
    float q[8] = {x0 + nx, y0 + ny, x1 + nx, y1 + ny, x1 - nx, y1 - ny, x0 - nx, y0 - ny};
    gfx_poly(c, q, 4, col);
}

int gfx_text_w(const Font *f, const char *s) { return (int)strlen(s) * f->cw; }

Rect gfx_text(Canvas *c, const Font *f, const char *s, int x, int y, uint32_t col, int anchor) {
    int w = gfx_text_w(f, s), h = f->ch;
    int ax = anchor % 3, ay = anchor / 3;
    if (ax == 1) x -= w / 2;
    else if (ax == 2) x -= w;
    if (ay == 1) y -= h / 2;
    else if (ay == 2) y -= h;
    Rect r = {x, y, w, h};
    for (const unsigned char *p = (const unsigned char *)s; *p; p++, x += f->cw) {
        int g = *p - f->first;
        if (g < 0 || g >= f->count) continue;
        const unsigned char *gd = f->data + (size_t)g * f->cw * f->ch;
        for (int j = 0; j < f->ch; j++) {
            int yy = y + j;
            if ((unsigned)yy >= (unsigned)c->h) continue;
            uint32_t *row = c->px + yy * c->stride;
            const unsigned char *gr = gd + j * f->cw;
            for (int i = 0; i < f->cw; i++) {
                int xx = x + i;
                if (gr[i] && (unsigned)xx < (unsigned)c->w) blend(&row[xx], col, gr[i]);
            }
        }
    }
    return r;
}

void gfx_blit(Canvas *dst, const Canvas *src, int x, int y) {
    for (int j = 0; j < src->h; j++) {
        int yy = y + j;
        if ((unsigned)yy >= (unsigned)dst->h) continue;
        int i0 = x < 0 ? -x : 0;
        int i1 = (x + src->w > dst->w) ? dst->w - x : src->w;
        if (i1 <= i0) continue;
        memcpy(dst->px + yy * dst->stride + x + i0, src->px + j * src->stride + i0, (size_t)(i1 - i0) * 4);
    }
}
