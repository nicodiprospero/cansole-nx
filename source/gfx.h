// CANsole NX - tiny software renderer (RGBA8888, little-endian: R | G<<8 | B<<16 | A<<24)
#pragma once
#include <stdint.h>

typedef struct {
    uint32_t *px;
    int w, h;
    int stride;  // in pixels
} Canvas;

#define COL(r, g, b) ((uint32_t)(r) | ((uint32_t)(g) << 8) | ((uint32_t)(b) << 16) | 0xFF000000u)

typedef struct {
    int cw, ch;     // monospace cell size
    int first;      // first char code
    int count;      // number of glyphs
    const unsigned char *data;  // count * cw * ch alpha bytes
} Font;

extern const Font FONT_XS, FONT_S, FONT_M, FONT_B, FONT_MID, FONT_BIG, FONT_HUGE;

enum { A_TL, A_TC, A_TR, A_ML, A_C, A_MR, A_BL, A_BC, A_BR };

typedef struct { int x, y, w, h; } Rect;

void gfx_clear(Canvas *c, uint32_t col);
void gfx_fill(Canvas *c, int x, int y, int w, int h, uint32_t col);
void gfx_fill_a(Canvas *c, int x, int y, int w, int h, uint32_t col, int alpha);
void gfx_rrect(Canvas *c, int x, int y, int w, int h, int r, uint32_t col);
void gfx_rrect_line(Canvas *c, int x, int y, int w, int h, int r, int t, uint32_t col);
void gfx_circle(Canvas *c, float cx, float cy, float r, uint32_t col);
void gfx_ring(Canvas *c, float cx, float cy, float r_out, float r_in, uint32_t col);
void gfx_poly(Canvas *c, const float *xy, int n, uint32_t col);  // convex, anti-aliased
void gfx_line(Canvas *c, float x0, float y0, float x1, float y1, float thick, uint32_t col);
Rect gfx_text(Canvas *c, const Font *f, const char *s, int x, int y, uint32_t col, int anchor);
int gfx_text_w(const Font *f, const char *s);
void gfx_blit(Canvas *dst, const Canvas *src, int x, int y);
uint32_t gfx_lerp(uint32_t a, uint32_t b, float t);
static inline int rect_hit(Rect r, int x, int y) { return x >= r.x && y >= r.y && x < r.x + r.w && y < r.y + r.h; }
