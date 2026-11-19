// CANsole NX - Nintendo Switch CAN bus console: cluster, sniffer, attacks, IDS, NFC, IR
// Platform independent core. Only transmit on buses you own or have permission to test.
#include "app.h"
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define W APP_W
#define H APP_H

// ------------------------------------------------------------------ palette
#define BG COL(9, 11, 15)
#define PANEL COL(20, 24, 31)
#define PANEL2 COL(30, 35, 46)
#define LINE COL(52, 60, 76)
#define FG COL(232, 234, 238)
#define DIM COL(120, 128, 144)
#define RED COL(240, 62, 48)
#define DARKRED COL(150, 32, 26)
#define AMBER COL(255, 176, 32)
#define GREEN COL(52, 214, 120)
#define CYAN COL(70, 196, 255)
#define WHITE COL(255, 255, 255)
#define BLACKISH COL(20, 20, 20)

// ------------------------------------------------- fake car "DBC" (sim)
#define ID_WHEELS 0x0B4
#define ID_ENGINE 0x120
#define ID_LIGHTS 0x188
#define ID_SPEED 0x1A0
#define ID_STEER 0x2C1
#define ID_WARN 0x2F0
#define ID_BODY 0x394
#define ID_DOORS 0x3E0
#define ID_VIN 0x4F0
#define ID_BATT 0x5A8

static const char *sim_name(uint32_t id) {
    switch (id) {
        case ID_WHEELS: return "wheel speeds";
        case ID_ENGINE: return "engine";
        case ID_LIGHTS: return "lights";
        case ID_SPEED: return "vehicle speed";
        case ID_STEER: return "steering";
        case ID_WARN: return "warnings";
        case ID_BODY: return "body ctrl";
        case ID_DOORS: return "door locks";
        case ID_VIN: return "vin/ident";
        case ID_BATT: return "battery";
    }
    return "";
}

// ------------------------------------------------------------------ utils
static uint32_t rng = 0x12345678u;
static uint32_t rnd(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}
static float rndf(void) { return (rnd() & 0xFFFFFF) / (float)0x1000000; }
static float gauss(void) { return (rndf() + rndf() + rndf() + rndf() - 2.0f) * 1.7f; }

// ---------------------------------------------------------- rate buckets
// 10 x 100 ms buckets -> frames per second over the last ~1 s
typedef struct {
    uint16_t b[10];
    int64_t bi;
} Rate;

static void rate_adv(Rate *r, double t) {
    int64_t i = (int64_t)(t * 10.0);
    if (i <= r->bi) return;
    if (i - r->bi >= 10) memset(r->b, 0, sizeof(r->b));
    else
        for (int64_t k = r->bi + 1; k <= i; k++) r->b[k % 10] = 0;
    r->bi = i;
}
static void rate_add(Rate *r, double t) {
    rate_adv(r, t);
    r->b[r->bi % 10]++;
}
static int rate_get(Rate *r, double t) {
    rate_adv(r, t);
    int s = 0;
    for (int i = 0; i < 10; i++) s += r->b[i];
    return s;
}

// --------------------------------------------------------------- bus state
#define MAXIDS 160
typedef struct {
    uint32_t id;
    uint8_t ext, len, data[8];
    double changed[8];
    uint32_t count;
    double first, last;
    Rate rate;
    int base;  // IDS baseline Hz, -1 = unknown
} IdInfo;

static IdInfo ids[MAXIDS];
static int nids;
static Rate rx_rate, ctr_rate;
static int ctr_last = -1;
static FILE *log_fp;
static char log_path[256];
static double wall0, t0;

static IdInfo *find_id(uint32_t id) {
    for (int i = 0; i < nids; i++)
        if (ids[i].id == id) return &ids[i];
    return NULL;
}

static void bus_reset(void) {
    nids = 0;
    memset(&rx_rate, 0, sizeof(rx_rate));
    memset(&ctr_rate, 0, sizeof(ctr_rate));
    ctr_last = -1;
}

static void ingest(const CanFrame *f, double t) {
    IdInfo *e = find_id(f->id);
    if (!e) {
        if (nids >= MAXIDS) return;
        int pos = 0;
        while (pos < nids && ids[pos].id < f->id) pos++;
        memmove(&ids[pos + 1], &ids[pos], (size_t)(nids - pos) * sizeof(IdInfo));
        nids++;
        e = &ids[pos];
        memset(e, 0, sizeof(*e));
        e->id = f->id;
        e->ext = f->ext;
        e->first = t;
        e->base = -1;
    }
    int len = f->len > 8 ? 8 : f->len;
    for (int i = 0; i < len; i++)
        if (i >= e->len || e->data[i] != f->data[i]) e->changed[i] = t;
    memcpy(e->data, f->data, (size_t)len);
    e->len = (uint8_t)len;
    e->count++;
    e->last = t;
    rate_add(&e->rate, t);
    rate_add(&rx_rate, t);
    if (f->id == ID_SPEED && len >= 3) {
        int c = f->data[2] & 0x0F;
        if (ctr_last >= 0 && c != ((ctr_last + 1) & 0x0F)) rate_add(&ctr_rate, t);
        ctr_last = c;
    }
    if (log_fp) {
        char hex[20];
        for (int i = 0; i < len; i++) sprintf(hex + i * 2, "%02X", f->data[i]);
        hex[len * 2] = 0;
        if (f->ext)
            fprintf(log_fp, "(%.6f) can0 %08X#%s\n", wall0 + (t - t0), (unsigned)f->id, hex);
        else
            fprintf(log_fp, "(%.6f) can0 %03X#%s\n", wall0 + (t - t0), (unsigned)f->id, hex);
    }
}

// ----------------------------------------------------------------- app state
enum { SRC_SIM, SRC_USB };
enum { TAB_CLUSTER, TAB_SNIFF, TAB_IDS, TAB_NFC, TAB_IR, NTABS };
static const char *TAB_NAMES[NTABS] = {"CLUSTER", "SNIFFER", "IDS", "NFC", "IR CAM"};

static int src = SRC_SIM;
static int tab = TAB_CLUSTER;
static bool tx_armed = true;
static bool show_help;
static bool quit_req;
static char toast_msg[160];
static double toast_until;
static double plus_t = -1;
static double last_input;
static bool attract_on;
static double attract_t0;
static uint32_t touch_hold_bits;
static bool prev_touch;
static float stick_y;
static uint32_t held_bits;
static double now_t, last_t;

static void toast(double t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void toast(double t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(toast_msg, sizeof(toast_msg), fmt, ap);
    va_end(ap);
    toast_until = t + 2.4;
}

// --------------------------------------------------------------- fake car
typedef struct {
    float throttle, brake, speed, rpm, coolant;
    bool bl, br;
    int ctr, body_ctr;
    uint8_t doors;
    double last[10];
} Car;
static Car car;
static const uint32_t SCHED_ID[10] = {ID_WHEELS, ID_ENGINE, ID_SPEED, ID_STEER, ID_LIGHTS,
                                      ID_BODY, ID_WARN, ID_BATT, ID_DOORS, ID_VIN};
static const double SCHED_P[10] = {0.02, 0.02, 0.02, 0.02, 0.1, 0.1, 0.2, 0.2, 0.5, 1.0};

static void car_reset(double t) {
    memset(&car, 0, sizeof(car));
    car.rpm = 800;
    car.coolant = 62;
    car.doors = 0x0F;
    for (int i = 0; i < 10; i++) car.last[i] = t;
}

static void car_physics(float dt) {
    float acc = car.throttle * 16.0f - car.brake * 38.0f - (0.5f + car.speed * 0.010f);
    car.speed += acc * dt;
    if (car.speed < 0) car.speed = 0;
    if (car.speed > 232) car.speed = 232;
    static const float lim[6] = {20, 42, 68, 98, 135, 999}, k[6] = {118, 74, 52, 40, 32, 26};
    float ratio = 118;
    for (int i = 0; i < 6; i++)
        if (car.speed < lim[i]) { ratio = k[i]; break; }
    float target = car.speed < 3 ? 800 + car.throttle * 3200 : fmaxf(900.0f, car.speed * ratio) + car.throttle * 400;
    if (target > 7400) target = 7400;
    float a = dt * 7;
    if (a > 1) a = 1;
    car.rpm += (target - car.rpm) * a;
    car.coolant += (90 - car.coolant) * dt * 0.02f;
}

static void car_frame(uint32_t id, double t, CanFrame *f) {
    memset(f, 0, sizeof(*f));
    f->id = id;
    uint8_t *d = f->data;
    switch (id) {
        case ID_ENGINE: {
            int r = (int)car.rpm;
            d[0] = r >> 8; d[1] = r & 255; d[2] = (uint8_t)(car.throttle * 100);
            d[3] = (uint8_t)((int)car.coolant + 40); d[4] = car.ctr & 15;
            f->len = 8;
        } break;
        case ID_SPEED: {
            car.ctr = (car.ctr + 1) & 15;
            int v = (int)(car.speed * 100);
            d[0] = v >> 8; d[1] = v & 255; d[2] = (uint8_t)car.ctr; d[3] = (uint8_t)(d[0] + d[1] + d[2]);
            f->len = 4;
        } break;
        case ID_WHEELS:
            for (int i = 0; i < 4; i++) {
                int v = car.speed > 0.5f ? (int)(car.speed * 100) + (int)(rnd() % 17) - 8 : 0;
                if (v < 0) v = 0;
                d[i * 2] = v >> 8; d[i * 2 + 1] = v & 255;
            }
            f->len = 8;
            break;
        case ID_LIGHTS: {
            bool on = fmod(t * 1.5, 1.0) < 0.5;
            d[0] = (car.bl && on ? 1 : 0) | (car.br && on ? 2 : 0);
            f->len = 2;
        } break;
        case ID_WARN: f->len = 4; break;
        case ID_DOORS: d[0] = car.doors; f->len = 2; break;
        case ID_STEER: {
            int a = (int)(gauss() * 6) & 0xFFFF;
            d[0] = a >> 8; d[1] = a & 255;
            f->len = 6;
        } break;
        case ID_BODY:
            car.body_ctr = (car.body_ctr + 1) & 255;
            d[0] = (uint8_t)car.body_ctr; d[1] = 0x5A; d[3] = (uint8_t)(car.body_ctr * 7);
            f->len = 4;
            break;
        case ID_VIN: memcpy(d, "CANSOLE1", 8); f->len = 8; break;
        case ID_BATT: {
            int v = 1410 + (int)(rnd() % 13) - 6;
            d[0] = v >> 8; d[1] = v & 255;
            f->len = 3;
        } break;
    }
}

static void car_tick(double t, float dt) {
    car_physics(dt);
    for (int i = 0; i < 10; i++) {
        if (t - car.last[i] > 0.5) car.last[i] = t - SCHED_P[i];
        while (t - car.last[i] >= SCHED_P[i]) {
            car.last[i] += SCHED_P[i];
            CanFrame f;
            car_frame(SCHED_ID[i], t, &f);
            ingest(&f, t);
        }
    }
}

// ---------------------------------------------------------------- attacker
enum { ATK_SPEED, ATK_RPM, ATK_DOORS, ATK_MIL, ATK_FUZZ, ATK_OMAX, ATK_OMIN, ATK_N };
static bool atk_hold[ATK_N];
static double atk_until[ATK_N];
static double atk_acc;
static uint32_t atk_sent;
static uint32_t fuzz_id = ID_SPEED;
static int fuzz_len = 8;
static CanFrame ovr_max, ovr_min;
static bool ovr_ok;

static bool atk_active(int a, double t) { return atk_hold[a] || atk_until[a] > t; }
static void atk_clear(void) {
    memset(atk_hold, 0, sizeof(atk_hold));
    memset(atk_until, 0, sizeof(atk_until));
}

static void emit_tx(const CanFrame *f, double t) {
    if (src == SRC_SIM) {
        ingest(f, t);
        atk_sent++;
    } else if (tx_armed) {
        if (plat_usb_send(f)) atk_sent++;
    }
}

static void atk_build(int a, CanFrame *f) {
    memset(f, 0, sizeof(*f));
    switch (a) {
        case ATK_SPEED: f->id = ID_SPEED; f->len = 4; f->data[0] = 0x5D; f->data[1] = 0xC0; break;  // 240 km/h, ctr 0
        case ATK_RPM: {
            static const uint8_t r[8] = {0x1E, 0x78, 100, 130, 0, 0, 0, 0};
            f->id = ID_ENGINE; f->len = 8; memcpy(f->data, r, 8);
        } break;
        case ATK_DOORS: f->id = ID_DOORS; f->len = 2; break;
        case ATK_MIL: f->id = ID_WARN; f->len = 4; f->data[0] = 7; break;
        case ATK_FUZZ:
            f->id = fuzz_id; f->ext = fuzz_id > 0x7FF; f->len = (uint8_t)fuzz_len;
            for (int i = 0; i < 8; i++) f->data[i] = (uint8_t)rnd();
            break;
        case ATK_OMAX: *f = ovr_max; break;
        case ATK_OMIN: *f = ovr_min; break;
    }
}

static void atk_tick(double t, float dt) {
    bool any = false;
    for (int a = 0; a < ATK_N; a++) any |= atk_active(a, t);
    if (!any) { atk_acc = 0; return; }
    atk_acc += dt * 200.0;
    int n = (int)atk_acc;
    atk_acc -= n;
    if (n > 8) n = 8;
    for (int k = 0; k < n; k++)
        for (int a = 0; a < ATK_N; a++) {
            if (!atk_active(a, t)) continue;
            if ((a == ATK_OMAX || a == ATK_OMIN) && !ovr_ok) continue;
            CanFrame f;
            atk_build(a, &f);
            emit_tx(&f, t);
        }
}

// --------------------------------------------------------------------- IDS
#define IDS_LEARN 6.0
typedef struct { double ts; int sev; char text[80]; } Alert;
enum { SEV_INFO, SEV_WARN, SEV_CRIT };
static bool ids_on = true, ids_learning = true;
static double ids_start, ids_last_eval, ids_last_hit;
static char ids_last_msg[80];
static Alert alerts[16];
static int nalerts;
static struct { uint32_t key; double t; } cool[64];
static int ncool;

static void ids_reset(double t) {
    ids_start = t;
    ids_learning = true;
    nalerts = 0;
    ncool = 0;
    ids_last_hit = -100;
    for (int i = 0; i < nids; i++) ids[i].base = -1;
}

static void ids_alert(uint32_t key, int sev, const char *txt, double t) {
    for (int i = 0; i < ncool; i++)
        if (cool[i].key == key) {
            if (t - cool[i].t < 2.5) return;
            cool[i].t = t;
            goto add;
        }
    if (ncool < 64) { cool[ncool].key = key; cool[ncool].t = t; ncool++; }
add:
    memmove(&alerts[1], &alerts[0], sizeof(Alert) * 15);
    alerts[0].ts = t - ids_start;
    alerts[0].sev = sev;
    snprintf(alerts[0].text, sizeof(alerts[0].text), "%s", txt);
    if (nalerts < 16) nalerts++;
    if (sev != SEV_INFO) {
        ids_last_hit = t;
        snprintf(ids_last_msg, sizeof(ids_last_msg), "%s", txt);
    }
}

static void ids_eval(double t) {
    if (!ids_on || t - ids_last_eval < 0.25) return;
    ids_last_eval = t;
    char buf[96];
    if (ids_learning) {
        if (t - ids_start >= IDS_LEARN) {
            for (int i = 0; i < nids; i++) {
                int r = rate_get(&ids[i].rate, t);
                ids[i].base = r < 1 ? 1 : r;
            }
            ids_learning = false;
            snprintf(buf, sizeof(buf), "Baseline learned: %d IDs. Monitoring.", nids);
            ids_alert(0xFFFFFFFF, SEV_INFO, buf, t);
        }
        return;
    }
    for (int i = 0; i < nids; i++) {
        int r = rate_get(&ids[i].rate, t);
        if (ids[i].base < 0) {
            if (r > 0) {
                snprintf(buf, sizeof(buf), "UNKNOWN ID 0x%03X appeared (%d Hz)", (unsigned)ids[i].id, r);
                ids_alert(0x10000000 | ids[i].id, SEV_WARN, buf, t);
            }
        } else if (r > ids[i].base * 1.6 + 4) {
            snprintf(buf, sizeof(buf), "RATE SPIKE 0x%03X: %d Hz vs %d Hz -> injection", (unsigned)ids[i].id, r, ids[i].base);
            ids_alert(0x20000000 | ids[i].id, SEV_CRIT, buf, t);
        }
    }
    int ce = rate_get(&ctr_rate, t);
    if (ce > 5) {
        snprintf(buf, sizeof(buf), "COUNTER BREAK 0x1A0: %d/s -> spoofed frames", ce);
        ids_alert(0x30000000, SEV_CRIT, buf, t);
    }
}

// -------------------------------------------------------------- sniffer/pins
static uint32_t sel_id;
static bool have_sel;
static int byte_cur;
static int scroll_top;
typedef struct {
    bool on;
    uint32_t cid;
    int off, w;
    bool have;
    uint32_t lo, hi, raw;
} Pin;
static Pin pins[2];
static int next_slot;
static uint32_t bit_prev_id;
static uint8_t bit_prev[8];
static double bit_t[8][8];

static int sel_index(void) {
    for (int i = 0; i < nids; i++)
        if (have_sel && ids[i].id == sel_id) return i;
    return 0;
}

static bool pin_pct(Pin *p, double t, float *pct) {
    IdInfo *e = find_id(p->cid);
    if (!e || t - e->last > 1.5 || e->len < p->off + p->w) return false;
    uint32_t raw = 0;
    for (int i = 0; i < p->w; i++) raw = (raw << 8) | e->data[p->off + i];
    p->raw = raw;
    if (!p->have) { p->lo = p->hi = raw; p->have = true; }
    if (raw < p->lo) p->lo = raw;
    if (raw > p->hi) p->hi = raw;
    uint32_t span = p->hi - p->lo;
    *pct = span ? (float)(raw - p->lo) * 100.0f / span : 0.0f;
    return true;
}

static void pin_selected(double t) {
    if (!have_sel) return;
    IdInfo *e = find_id(sel_id);
    if (!e) return;
    int off = byte_cur;
    if (off >= e->len) { toast(t, "That ID has no byte %d", off); return; }
    for (int k = 0; k < 2; k++)
        if (pins[k].on && pins[k].cid == e->id && pins[k].off == off) {
            pins[k].on = false;
            toast(t, "Unpinned 0x%03X", (unsigned)e->id);
            return;
        }
    int w = (off + 1 < e->len && e->changed[off + 1] > e->first + 0.5) ? 2 : 1;
    int slot = !pins[0].on ? 0 : (!pins[1].on ? 1 : next_slot);
    next_slot = 1 - slot;
    memset(&pins[slot], 0, sizeof(Pin));
    pins[slot].on = true;
    pins[slot].cid = e->id;
    pins[slot].off = off;
    pins[slot].w = w;
    toast(t, "Pinned 0x%03X bytes[%d:%d] -> %s gauge (auto-scaled)", (unsigned)e->id, off, off + w, slot ? "RIGHT" : "LEFT");
}

static bool build_override(void) {
    Pin *p = pins[0].on ? &pins[0] : (pins[1].on ? &pins[1] : NULL);
    uint32_t cid;
    int off, w;
    if (p) { cid = p->cid; off = p->off; w = p->w; }
    else if (have_sel) { cid = sel_id; off = byte_cur; w = 1; }
    else return false;
    IdInfo *e = find_id(cid);
    if (!e || off + w > e->len) return false;
    memset(&ovr_max, 0, sizeof(CanFrame));
    ovr_max.id = cid;
    ovr_max.ext = e->ext;
    ovr_max.len = e->len;
    memcpy(ovr_max.data, e->data, 8);
    ovr_min = ovr_max;
    for (int i = off; i < off + w; i++) { ovr_max.data[i] = 0xFF; ovr_min.data[i] = 0x00; }
    return true;
}

// ---------------------------------------------------------------- gauges
typedef struct {
    float cx, cy, r, vmin, vmax;
    Canvas bg;
    float disp;
} Gauge;
static Gauge g_rpm, g_spd, g_pin[2];
static Canvas bg_rpm, bg_spd, bg_pin;

static float g_ang(const Gauge *g, float v) {
    float tt = (v - g->vmin) / (g->vmax - g->vmin);
    if (tt < 0) tt = 0;
    if (tt > 1) tt = 1;
    return (225.0f - 270.0f * tt) * 3.14159265f / 180.0f;
}

static void make_gauge_bg(Canvas *bg, float r, float vmin, float vmax, float major, int minors, float label_div, float red_from) {
    int size = (int)(r * 2 + 8);
    bg->w = bg->h = bg->stride = size;
    bg->px = (uint32_t *)malloc((size_t)size * size * 4);
    gfx_clear(bg, BG);
    float c = size / 2.0f;
    Gauge tmp = {c, c, r, vmin, vmax, {0}, 0};
    gfx_circle(bg, c, c, r, PANEL);
    gfx_ring(bg, c, c, r, r - 3, LINE);
    if (red_from >= vmin) {
        int steps = 48;
        for (int i = 0; i < steps; i++) {
            float v0 = red_from + (vmax - red_from) * i / steps, v1 = red_from + (vmax - red_from) * (i + 1) / steps;
            float a0 = g_ang(&tmp, v0), a1 = g_ang(&tmp, v1);
            float q[8] = {c + cosf(a0) * (r - 6), c - sinf(a0) * (r - 6), c + cosf(a1) * (r - 6), c - sinf(a1) * (r - 6),
                          c + cosf(a1) * (r - 18), c - sinf(a1) * (r - 18), c + cosf(a0) * (r - 18), c - sinf(a0) * (r - 18)};
            gfx_poly(bg, q, 4, DARKRED);
        }
    }
    float step = major / minors;
    int n = (int)roundf((vmax - vmin) / step);
    for (int i = 0; i <= n; i++) {
        float v = vmin + i * step;
        float a = g_ang(&tmp, v);
        bool maj = i % minors == 0;
        float r0 = r - (maj ? 30 : 18);
        gfx_line(bg, c + cosf(a) * r0, c - sinf(a) * r0, c + cosf(a) * (r - 6), c - sinf(a) * (r - 6), maj ? 3.0f : 1.4f, maj ? FG : DIM);
        if (maj) {
            char lab[16];
            snprintf(lab, sizeof(lab), "%d", (int)(v / label_div));
            gfx_text(bg, &FONT_B, lab, (int)(c + cosf(a) * (r - 50)), (int)(c - sinf(a) * (r - 50)), FG, A_C);
        }
    }
}

static void gauge_init(Gauge *g, float cx, float cy, Canvas *bg, float r, float vmin, float vmax) {
    g->cx = cx; g->cy = cy; g->r = r; g->vmin = vmin; g->vmax = vmax; g->bg = *bg; g->disp = vmin;
}

static void gauge_draw(Canvas *c, Gauge *g, float value, bool alive) {
    float target = alive ? value : g->vmin;
    g->disp += (target - g->disp) * 0.45f;
    gfx_blit(c, &g->bg, (int)(g->cx - g->r - 4), (int)(g->cy - g->r - 4));
    float a = g_ang(g, g->disp);
    float cx = g->cx, cy = g->cy, rr = g->r - 22;
    float pa = a + 1.5707963f, pb = a - 1.5707963f;
    float q[8] = {cx + cosf(a) * rr, cy - sinf(a) * rr, cx + cosf(pa) * 6, cy - sinf(pa) * 6,
                  cx - cosf(a) * 20, cy + sinf(a) * 20, cx + cosf(pb) * 6, cy - sinf(pb) * 6};
    gfx_poly(c, q, 4, alive ? RED : LINE);
    gfx_circle(c, cx, cy, 14, PANEL2);
    gfx_ring(c, cx, cy, 14, 12, LINE);
}

// ---------------------------------------------------------------- touch map
enum { HT_TAB, HT_QUIT, HT_HELP, HT_HOLD, HT_TAP, HT_ROW, HT_BYTE, HT_IRMODE };
typedef struct { Rect r; int type; uint32_t a, b; } Hit;
static Hit hits[96];
static int nhits;
static void hit_add(Rect r, int type, uint32_t a, uint32_t b) {
    if (nhits < 96) { hits[nhits].r = r; hits[nhits].type = type; hits[nhits].a = a; hits[nhits].b = b; nhits++; }
}

// ------------------------------------------------------------------ NFC/IR
static NfcInfo nfc;
static uint32_t nfc_seen_seq;
typedef struct { double t; uint8_t uid[10]; int uid_len; uint32_t proto, type; } NfcHist;
static NfcHist nfc_hist[10];
static int n_nfc_hist;
static bool nfc_enabled, ir_enabled;
static bool ir_thermal = true;

// ---------------------------------------------------------------- logging
static void toggle_log(double t) {
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
        toast(t, "Saved %s", log_path);
        return;
    }
    time_t now = time(NULL);
    struct tm *tmv = localtime(&now);
    char stamp[32] = "log";
    if (tmv) strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", tmv);
    snprintf(log_path, sizeof(log_path), "%scansole_%s.log", plat_data_dir(), stamp);
    log_fp = fopen(log_path, "w");
    if (!log_fp) { toast(t, "Could not open %s", log_path); return; }
    wall0 = (double)now;
    t0 = t;
    toast(t, "REC -> %s", log_path);
}

// ------------------------------------------------------------------ input
static bool can_tx(double t) {
    if (src == SRC_SIM || tx_armed) return true;
    toast(t, "TX locked (read-only). Hold + for 2 s to arm - ask the bus owner first");
    return false;
}

static void fuzz_start(uint32_t id, bool have, double t) {
    if (!have) { toast(t, "Select an ID first"); return; }
    if (!can_tx(t)) return;
    IdInfo *e = find_id(id);
    fuzz_id = id;
    fuzz_len = (e && e->len) ? e->len : 8;
    atk_until[ATK_FUZZ] = t + 2.0;
    toast(t, "Fuzzing 0x%03X for 2 s", (unsigned)id);
}

static void stop_attract(void) {
    if (attract_on) {
        attract_on = false;
        atk_clear();
        car.bl = car.br = false;
    }
}

static void press(uint32_t b, double t) {
    held_bits |= b;
    last_input = t;
    stop_attract();
    if (show_help && b != B_MINUS) { show_help = false; return; }
    if (b == B_MINUS) {
        if (held_bits & B_PLUS) quit_req = true;
        else show_help = !show_help;
        return;
    }
    if (b == B_PLUS) {
        if (held_bits & B_MINUS) quit_req = true;
        plus_t = t;
        return;
    }
    if (b == B_L) { tab = (tab + NTABS - 1) % NTABS; return; }
    if (b == B_R) { tab = (tab + 1) % NTABS; return; }
    if (b == B_LSTICK) { toggle_log(t); return; }
    if (b == B_X && tab <= TAB_IDS) {
        ids_on = !ids_on;
        if (ids_on) { ids_reset(t); toast(t, "IDS on - learning baseline for 6 s"); }
        else toast(t, "IDS off");
        return;
    }
    if ((b == B_ZR || b == B_ZL) && tab <= TAB_IDS) {
        if (src == SRC_SIM) {
            atk_hold[b == B_ZR ? ATK_SPEED : ATK_RPM] = true;
        } else {
            if (!can_tx(t)) return;
            if (!build_override()) { toast(t, "Pin a signal in SNIFFER first (A on a byte)"); return; }
            ovr_ok = true;
            atk_hold[b == B_ZR ? ATK_OMAX : ATK_OMIN] = true;
        }
        return;
    }
    if (tab == TAB_SNIFF) {
        if (nids == 0) return;
        int i = sel_index();
        if (b == B_UP) { sel_id = ids[(i + nids - 1) % nids].id; have_sel = true; }
        else if (b == B_DOWN) { sel_id = ids[(i + 1) % nids].id; have_sel = true; }
        else if (b == B_LEFT) { if (byte_cur > 0) byte_cur--; }
        else if (b == B_RIGHT) { if (byte_cur < 7) byte_cur++; }
        else if (b == B_A) pin_selected(t);
        else if (b == B_B) { memset(pins, 0, sizeof(pins)); next_slot = 0; toast(t, "Pins cleared - gauges back to default"); }
        else if (b == B_Y) fuzz_start(sel_id, have_sel, t);
    } else if (tab == TAB_CLUSTER) {
        if (b == B_LEFT && src == SRC_SIM) { car.bl = !car.bl; car.br = false; }
        else if (b == B_RIGHT && src == SRC_SIM) { car.br = !car.br; car.bl = false; }
        else if (b == B_A) {
            if (src == SRC_SIM) { atk_until[ATK_DOORS] = t + 1.5; toast(t, "Spoofing 0x3E0: unlock all doors"); }
            else tab = TAB_SNIFF;
        } else if (b == B_B && src == SRC_SIM) {
            atk_until[ATK_MIL] = t + 3.0;
            toast(t, "Spoofing 0x2F0: warning lights");
        } else if (b == B_Y) {
            if (src == SRC_SIM) fuzz_start(ID_SPEED, true, t);
            else fuzz_start(sel_id, have_sel, t);
        }
    } else if (tab == TAB_IDS) {
        if (b == B_A) { ids_reset(t); toast(t, "Re-learning baseline"); }
        else if (b == B_B) nalerts = 0;
    } else if (tab == TAB_NFC) {
        if (b == B_B) n_nfc_hist = 0;
    } else if (tab == TAB_IR) {
        if (b == B_Y || b == B_A) ir_thermal = !ir_thermal;
    }
}

static void release(uint32_t b) {
    held_bits &= ~b;
    if (b == B_ZR) { atk_hold[ATK_SPEED] = false; atk_hold[ATK_OMAX] = false; }
    if (b == B_ZL) { atk_hold[ATK_RPM] = false; atk_hold[ATK_OMIN] = false; }
    if (b == B_PLUS) plus_t = -1;
}

static void tap(int x, int y, double t) {
    last_input = t;
    stop_attract();
    for (int i = nhits - 1; i >= 0; i--) {
        if (!rect_hit(hits[i].r, x, y)) continue;
        Hit *h = &hits[i];
        switch (h->type) {
            case HT_TAB: tab = (int)h->a; break;
            case HT_QUIT: quit_req = true; break;
            case HT_HELP: show_help = !show_help; break;
            case HT_HOLD: press(h->a, t); touch_hold_bits |= h->a; break;
            case HT_TAP: press(h->a, t); release(h->a); break;
            case HT_ROW: sel_id = h->a; have_sel = true; break;
            case HT_BYTE: sel_id = h->a; have_sel = true; byte_cur = (int)h->b; break;
            case HT_IRMODE: ir_thermal = !ir_thermal; break;
        }
        return;
    }
    if (show_help) show_help = false;
}

// -------------------------------------------------------------- attract mode
static void attract(double t) {
    double p = fmod(t - attract_t0, 40.0);
    car.throttle = p < 9 ? 0.85f : p < 20 ? 0.35f : p < 30 ? 0.15f : p < 36 ? 0.6f : 0.0f;
    car.brake = p >= 36 ? 0.6f : 0.0f;
    car.bl = p >= 9 && p < 13;
    tab = p < 20 ? TAB_CLUSTER : p < 30 ? TAB_IDS : TAB_SNIFF;
    atk_hold[ATK_SPEED] = (p >= 12 && p < 16) || (p >= 23 && p < 26);
    atk_hold[ATK_RPM] = p >= 16 && p < 18;
    atk_hold[ATK_DOORS] = p >= 18 && p < 19.5;
    atk_hold[ATK_MIL] = p >= 19.5 && p < 21;
    if (tab == TAB_SNIFF && nids) {
        sel_id = ids[((int)(p - 30)) % nids].id;
        have_sel = true;
        byte_cur = 0;
    }
}

// ================================================================== drawing
static Canvas *C;

static void txt(const Font *f, const char *s, int x, int y, uint32_t col, int anchor) { gfx_text(C, f, s, x, y, col, anchor); }

static void draw_header(double t) {
    gfx_fill(C, 0, 0, W, 56, PANEL);
    gfx_fill(C, 0, 56, W, 1, LINE);
    Rect r = gfx_text(C, &FONT_MID, "CAN", 16, 12, RED, A_TL);
    r = gfx_text(C, &FONT_MID, "sole", r.x + r.w, 12, FG, A_TL);
    gfx_text(C, &FONT_XS, "NX", r.x + r.w + 4, 22, DIM, A_TL);
    for (int i = 0; i < NTABS; i++) {
        Rect tr = {182 + i * 122, 10, 116, 36};
        gfx_rrect(C, tr.x, tr.y, tr.w, tr.h, 8, i == tab ? RED : PANEL2);
        txt(&FONT_B, TAB_NAMES[i], tr.x + tr.w / 2, tr.y + tr.h / 2, i == tab ? WHITE : DIM, A_C);
        hit_add(tr, HT_TAB, (uint32_t)i, 0);
    }
    char line[96], l2[96];
    if (src == SRC_SIM) snprintf(line, sizeof(line), "SIM car  |  %s", plat_usb_label());
    else snprintf(line, sizeof(line), "%s", plat_usb_label());
    if ((int)strlen(line) > 36) line[36] = 0;
    txt(&FONT_S, line, 1170, 8, src == SRC_SIM ? CYAN : GREEN, A_TR);
    const char *tx = src == SRC_SIM ? "TX: SIM" : (tx_armed ? "TX ARMED" : "TX LOCKED");
    uint32_t txc = src == SRC_SIM ? AMBER : (tx_armed ? RED : GREEN);
    snprintf(l2, sizeof(l2), "%d msg/s  %d IDs  ", rate_get(&rx_rate, t), nids);
    int total = gfx_text_w(&FONT_S, l2) + gfx_text_w(&FONT_S, tx) + (log_fp ? gfx_text_w(&FONT_S, "  REC") : 0);
    Rect sr = gfx_text(C, &FONT_S, l2, 1170 - total, 32, DIM, A_TL);
    sr = gfx_text(C, &FONT_S, tx, sr.x + sr.w, 32, txc, A_TL);
    if (log_fp) gfx_text(C, &FONT_S, "  REC", sr.x + sr.w, 32, RED, A_TL);
    Rect qb = {W - 50, 10, 38, 36}, hb = {W - 96, 10, 38, 36};
    gfx_rrect(C, qb.x, qb.y, qb.w, qb.h, 8, PANEL2);
    txt(&FONT_B, "X", qb.x + 19, qb.y + 18, DIM, A_C);
    hit_add(qb, HT_QUIT, 0, 0);
    gfx_rrect(C, hb.x, hb.y, hb.w, hb.h, 8, PANEL2);
    txt(&FONT_B, "?", hb.x + 19, hb.y + 18, DIM, A_C);
    hit_add(hb, HT_HELP, 0, 0);
    if (plus_t >= 0) {
        float p = (float)((t - plus_t) / 2.0);
        if (p > 1) p = 1;
        gfx_fill(C, 0, 54, (int)(W * p), 4, RED);
    }
}

typedef struct {
    bool rpm_ok, spd_ok, blink_ok, warn_ok, doors_ok;
    int rpm, thr, cool;
    float spd;
    uint8_t blink, warn, doors;
} Sig;

static Sig signals(double t) {
    Sig s;
    memset(&s, 0, sizeof(s));
    IdInfo *e;
    if ((e = find_id(ID_ENGINE)) && t - e->last < 1.0 && e->len >= 4) {
        s.rpm_ok = true; s.rpm = (e->data[0] << 8) | e->data[1]; s.thr = e->data[2]; s.cool = e->data[3] - 40;
    }
    if ((e = find_id(ID_SPEED)) && t - e->last < 1.0 && e->len >= 2) { s.spd_ok = true; s.spd = ((e->data[0] << 8) | e->data[1]) / 100.0f; }
    if ((e = find_id(ID_LIGHTS)) && t - e->last < 1.0 && e->len >= 1) { s.blink_ok = true; s.blink = e->data[0]; }
    if ((e = find_id(ID_WARN)) && t - e->last < 1.0 && e->len >= 1) { s.warn_ok = true; s.warn = e->data[0]; }
    if ((e = find_id(ID_DOORS)) && t - e->last < 1.0 && e->len >= 1) { s.doors_ok = true; s.doors = e->data[0]; }
    return s;
}

static void arrow(int cx, int cy, bool left, bool on) {
    float s = left ? -1.0f : 1.0f;
    float head[6] = {cx + s * 30, (float)cy, cx + s * 6, cy - 24.0f, cx + s * 6, cy + 24.0f};
    float body[8] = {cx + s * 7, cy - 10.0f, cx - s * 26, cy - 10.0f, cx - s * 26, cy + 10.0f, cx + s * 7, cy + 10.0f};
    gfx_poly(C, head, 3, on ? GREEN : PANEL2);
    gfx_poly(C, body, 4, on ? GREEN : PANEL2);
}

static void draw_doors(int cx, int cy, bool ok, uint8_t mask) {
    gfx_rrect(C, cx - 43, cy - 75, 86, 150, 26, PANEL2);
    gfx_rrect_line(C, cx - 43, cy - 75, 86, 150, 26, 2, LINE);
    gfx_rrect(C, cx - 30, cy - 52, 60, 22, 6, LINE);
    static const int dx[4] = {-52, 52, -52, 52}, dy[4] = {-22, -22, 26, 26};
    for (int i = 0; i < 4; i++) {
        uint32_t col = !ok ? LINE : ((mask >> i) & 1 ? GREEN : RED);
        gfx_rrect(C, cx + dx[i] - 7, cy + dy[i] - 21, 14, 42, 4, col);
    }
    if (!ok) txt(&FONT_B, "DOORS --", cx, cy + 90, DIM, A_C);
    else if ((mask & 15) == 15) txt(&FONT_B, "LOCKED", cx, cy + 90, GREEN, A_C);
    else txt(&FONT_B, "UNLOCKED!", cx, cy + 90, RED, A_C);
}

static void button(Rect r, const char *label, const char *hint, bool on, uint32_t edge) {
    gfx_rrect(C, r.x, r.y, r.w, r.h, 12, on ? RED : PANEL2);
    gfx_rrect_line(C, r.x, r.y, r.w, r.h, 12, 2, edge);
    txt(&FONT_B, label, r.x + r.w / 2, r.y + 26, WHITE, A_C);
    if (hint) txt(&FONT_S, hint, r.x + r.w / 2, r.y + 54, on ? COL(255, 220, 210) : DIM, A_C);
}

static void draw_cluster(double t) {
    Sig s = signals(t);
    char buf[128];
    for (int side = 0; side < 2; side++) {
        Pin *p = &pins[side];
        Gauge *g = p->on ? &g_pin[side] : (side == 0 ? &g_rpm : &g_spd);
        int cx = (int)g->cx, cy = (int)g->cy;
        if (p->on) {
            float pct = 0;
            bool ok = pin_pct(p, t, &pct);
            gauge_draw(C, g, pct, ok);
            snprintf(buf, sizeof(buf), "0x%03X [%d:%d]", (unsigned)p->cid, p->off, p->off + p->w);
            txt(&FONT_B, buf, cx, cy + 70, AMBER, A_C);
            if (ok) snprintf(buf, sizeof(buf), "%u", (unsigned)p->raw);
            else snprintf(buf, sizeof(buf), "--");
            txt(&FONT_BIG, buf, cx, cy + 112, FG, A_C);
            if (p->have) {
                snprintf(buf, sizeof(buf), "min %u  max %u", (unsigned)p->lo, (unsigned)p->hi);
                txt(&FONT_S, buf, cx, cy + 150, DIM, A_C);
            }
        } else if (side == 0) {
            gauge_draw(C, g, (float)s.rpm, s.rpm_ok);
            txt(&FONT_S, "RPM x1000", cx, cy + 70, DIM, A_C);
            if (s.rpm_ok) snprintf(buf, sizeof(buf), "%d", s.rpm);
            else snprintf(buf, sizeof(buf), "--");
            txt(&FONT_BIG, buf, cx, cy + 112, FG, A_C);
        } else {
            gauge_draw(C, g, s.spd, s.spd_ok);
            txt(&FONT_S, "km/h", cx, cy + 70, DIM, A_C);
            if (s.spd_ok) snprintf(buf, sizeof(buf), "%.0f", s.spd);
            else snprintf(buf, sizeof(buf), "--");
            txt(&FONT_BIG, buf, cx, cy + 112, FG, A_C);
        }
    }
    int cx = W / 2;
    arrow(cx - 120, 104, true, s.blink_ok && (s.blink & 1));
    arrow(cx + 120, 104, false, s.blink_ok && (s.blink & 2));
    if (s.spd_ok) snprintf(buf, sizeof(buf), "%.0f", s.spd);
    else snprintf(buf, sizeof(buf), "--");
    txt(&FONT_HUGE, buf, cx, 180, FG, A_C);
    txt(&FONT_S, "km/h", cx, 252, DIM, A_C);
    if (s.rpm_ok) {
        snprintf(buf, sizeof(buf), "throttle %d%%   coolant %dC", s.thr, s.cool);
        txt(&FONT_S, buf, cx, 276, DIM, A_C);
    } else if (src == SRC_USB) {
        txt(&FONT_S, "Real bus: pin signals in SNIFFER", cx, 276, AMBER, A_C);
    }
    draw_doors(cx, 360, s.doors_ok, s.doors);
    static const char *wn[3] = {"ENGINE", "OIL", "BATT"};
    for (int i = 0; i < 3; i++) {
        int bx = cx - 116 + i * 116 - 52, by = 492 - 17;
        bool on = s.warn_ok && ((s.warn >> i) & 1);
        uint32_t col = i == 0 ? AMBER : RED;
        if (on) gfx_rrect(C, bx, by, 104, 34, 6, col);
        else gfx_rrect_line(C, bx, by, 104, 34, 6, 2, LINE);
        txt(&FONT_B, wn[i], bx + 52, by + 17, on ? BLACKISH : DIM, A_C);
    }
    if (ids_on && t - ids_last_hit < 3.0) {
        gfx_fill(C, 0, 516, W, 40, ((int)(t * 4)) % 2 ? COL(120, 18, 14) : RED);
        snprintf(buf, sizeof(buf), "!! INTRUSION DETECTED  -  %s", ids_last_msg);
        txt(&FONT_B, buf, W / 2, 536, WHITE, A_C);
    }
    int bw = 194;
    if (src == SRC_SIM) {
        const char *lab[5] = {"SPOOF SPEED", "REDLINE RPM", "UNLOCK DOORS", "WARN LIGHTS", "FUZZ 0x1A0"};
        const char *hint[5] = {"[ZR]", "[ZL]", "[A]", "[B]", "[Y]"};
        uint32_t bits[5] = {B_ZR, B_ZL, B_A, B_B, B_Y};
        int types[5] = {HT_HOLD, HT_HOLD, HT_TAP, HT_TAP, HT_TAP};
        bool on[5] = {atk_active(ATK_SPEED, t), atk_active(ATK_RPM, t), atk_active(ATK_DOORS, t), atk_active(ATK_MIL, t), atk_active(ATK_FUZZ, t)};
        for (int i = 0; i < 5; i++) {
            Rect r = {18 + i * (bw + 12), 568, bw, 74};
            button(r, lab[i], hint[i], on[i], RED);
            hit_add(r, types[i], bits[i], 0);
        }
    } else {
        const char *lab[4] = {"OVERRIDE MAX", "OVERRIDE MIN", "FUZZ SELECTED", "GO SNIFF"};
        const char *hint[4] = {"[ZR] hold", "[ZL] hold", "[Y]", "[A]"};
        uint32_t bits[4] = {B_ZR, B_ZL, B_Y, B_A};
        int types[4] = {HT_HOLD, HT_HOLD, HT_TAP, HT_TAP};
        bool on[4] = {atk_active(ATK_OMAX, t), atk_active(ATK_OMIN, t), atk_active(ATK_FUZZ, t), false};
        for (int i = 0; i < 4; i++) {
            Rect r = {18 + i * (bw + 12), 568, bw, 74};
            button(r, lab[i], hint[i], on[i], RED);
            hit_add(r, types[i], bits[i], 0);
        }
    }
    gfx_rrect(C, 1048, 568, 214, 74, 12, PANEL);
    snprintf(buf, sizeof(buf), "spoofed TX  %u", (unsigned)atk_sent);
    txt(&FONT_S, buf, 1062, 580, AMBER, A_TL);
    int ce = rate_get(&ctr_rate, t);
    snprintf(buf, sizeof(buf), "ctr errors  %d/s", ce);
    txt(&FONT_S, buf, 1062, 608, ce > 5 ? RED : DIM, A_TL);
}

static void draw_sniffer(double t) {
    char buf[64];
    const int top = 96, rh = 30, maxrows = (650 - top) / rh;
    int si = sel_index();
    if (si < scroll_top) scroll_top = si;
    if (si >= scroll_top + maxrows) scroll_top = si - maxrows + 1;
    if (scroll_top > nids - maxrows) scroll_top = nids - maxrows;
    if (scroll_top < 0) scroll_top = 0;
    static const int hx[6] = {24, 120, 170, 606, 664, 748};
    static const char *hn[6] = {"ID", "DLC", "DATA", "Hz", "COUNT", "NAME"};
    for (int i = 0; i < (src == SRC_SIM ? 6 : 5); i++) txt(&FONT_S, hn[i], hx[i], 68, DIM, A_TL);
    for (int k = 0; k < maxrows && scroll_top + k < nids; k++) {
        IdInfo *e = &ids[scroll_top + k];
        int y = top + k * rh;
        bool sel = have_sel && e->id == sel_id;
        Rect row = {12, y - 2, 870, rh - 2};
        if (sel) {
            gfx_rrect(C, row.x, row.y, row.w, row.h, 6, PANEL2);
            gfx_fill(C, 12, y - 2, 4, rh - 2, RED);
        }
        hit_add(row, HT_ROW, e->id, 0);
        bool stale = t - e->last > 2.0;
        if (e->ext) snprintf(buf, sizeof(buf), "%08X", (unsigned)e->id);
        else snprintf(buf, sizeof(buf), "%03X", (unsigned)e->id);
        txt(&FONT_B, buf, 24, y, stale ? DIM : FG, A_TL);
        snprintf(buf, sizeof(buf), "%d", e->len);
        txt(&FONT_M, buf, 128, y + 2, DIM, A_TL);
        for (int i = 0; i < 8; i++) {
            Rect cell = {170 + i * 54, y, 48, 24};
            if (i < e->len) {
                double age = t - e->changed[i];
                uint32_t col = age < 0.3 ? RED : (age < 1.5 ? gfx_lerp(RED, FG, (float)((age - 0.3) / 1.2)) : (stale ? DIM : FG));
                snprintf(buf, sizeof(buf), "%02X", e->data[i]);
                txt(&FONT_B, buf, cell.x + 24, cell.y + 12, col, A_C);
                hit_add(cell, HT_BYTE, e->id, (uint32_t)i);
                for (int pk = 0; pk < 2; pk++)
                    if (pins[pk].on && pins[pk].cid == e->id && i >= pins[pk].off && i < pins[pk].off + pins[pk].w)
                        gfx_fill(C, cell.x + 8, cell.y + 24, 32, 3, AMBER);
            }
            if (sel && i == byte_cur) gfx_rrect_line(C, cell.x, cell.y, cell.w, cell.h, 4, 2, CYAN);
        }
        snprintf(buf, sizeof(buf), "%d", rate_get(&e->rate, t));
        txt(&FONT_M, buf, 606, y + 2, FG, A_TL);
        snprintf(buf, sizeof(buf), "%u", (unsigned)e->count);
        txt(&FONT_M, buf, 664, y + 2, DIM, A_TL);
        if (src == SRC_SIM) txt(&FONT_S, sim_name(e->id), 748, y + 4, DIM, A_TL);
    }
    if (nids == 0) {
        txt(&FONT_MID, "Waiting for frames...", 450, 300, DIM, A_C);
        if (src == SRC_USB) txt(&FONT_M, "Check bus power, wiring and bitrate (500k)", 450, 340, DIM, A_C);
    }
    if (nids > maxrows) {
        snprintf(buf, sizeof(buf), "%d-%d of %d", scroll_top + 1, scroll_top + maxrows < nids ? scroll_top + maxrows : nids, nids);
        txt(&FONT_S, buf, 870, 652, DIM, A_TR);
    }
    // side panel
    gfx_rrect(C, 900, 66, 364, 610, 12, PANEL);
    IdInfo *e = have_sel ? find_id(sel_id) : NULL;
    if (!e) return;
    if (bit_prev_id != e->id) {
        memset(bit_t, 0, sizeof(bit_t));
        bit_prev_id = e->id;
        memcpy(bit_prev, e->data, 8);
    } else {
        for (int bi = 0; bi < 8; bi++) {
            uint8_t x = e->data[bi] ^ bit_prev[bi];
            for (int bit = 0; bit < 8; bit++)
                if (x & (0x80 >> bit)) bit_t[bi][bit] = t;
        }
        memcpy(bit_prev, e->data, 8);
    }
    snprintf(buf, sizeof(buf), "0x%03X", (unsigned)e->id);
    txt(&FONT_BIG, buf, 918, 76, FG, A_TL);
    if (src == SRC_SIM) txt(&FONT_M, sim_name(e->id), 1080, 94, DIM, A_TL);
    snprintf(buf, sizeof(buf), "%d Hz   %d bytes", rate_get(&e->rate, t), e->len);
    txt(&FONT_M, buf, 918, 132, DIM, A_TL);
    txt(&FONT_S, "bit view (red = flipping)", 918, 166, DIM, A_TL);
    for (int bi = 0; bi < 8; bi++) {
        int yy = 194 + bi * 26;
        snprintf(buf, sizeof(buf), "b%d", bi);
        txt(&FONT_S, buf, 918, yy + 2, bi == byte_cur ? CYAN : DIM, A_TL);
        for (int bit = 0; bit < 8; bit++) {
            int cx = 960 + bit * 24;
            if (bi >= e->len) { gfx_rrect_line(C, cx, yy, 20, 20, 3, 1, PANEL2); continue; }
            int v = (e->data[bi] >> (7 - bit)) & 1;
            bool hot = t - bit_t[bi][bit] < 0.8;
            gfx_rrect(C, cx, yy, 20, 20, 3, hot ? RED : (v ? FG : PANEL2));
        }
        if (bi < e->len) {
            snprintf(buf, sizeof(buf), "%3d", e->data[bi]);
            txt(&FONT_S, buf, 1160, yy + 2, DIM, A_TL);
        }
    }
    static const char *help[7] = {"Up/Down  select ID", "Left/Right  byte cursor", "A  pin byte(s) to a gauge",
                                  "B  clear pins", "Y  fuzz this ID (2 s)", "Tip: move a pedal/knob and", "watch which byte goes red"};
    for (int i = 0; i < 7; i++) txt(&FONT_S, help[i], 918, 414 + i * 24, i >= 5 ? AMBER : DIM, A_TL);
    Rect pb = {918, 602, 150, 54}, fb = {1090, 602, 150, 54};
    gfx_rrect(C, pb.x, pb.y, pb.w, pb.h, 10, PANEL2);
    gfx_rrect_line(C, pb.x, pb.y, pb.w, pb.h, 10, 2, AMBER);
    txt(&FONT_B, "PIN [A]", pb.x + 75, pb.y + 27, AMBER, A_C);
    hit_add(pb, HT_TAP, B_A, 0);
    gfx_rrect(C, fb.x, fb.y, fb.w, fb.h, 10, PANEL2);
    gfx_rrect_line(C, fb.x, fb.y, fb.w, fb.h, 10, 2, RED);
    txt(&FONT_B, "FUZZ [Y]", fb.x + 75, fb.y + 27, RED, A_C);
    hit_add(fb, HT_TAP, B_Y, 0);
}

static void draw_ids(double t) {
    char buf[96];
    if (!ids_on) txt(&FONT_B, "IDS OFF  (press X to enable)", 24, 70, DIM, A_TL);
    else if (ids_learning) {
        double rem = IDS_LEARN - (t - ids_start);
        snprintf(buf, sizeof(buf), "LEARNING BASELINE  %.1fs  - don't attack yet", rem > 0 ? rem : 0.0);
        txt(&FONT_B, buf, 24, 70, AMBER, A_TL);
    } else {
        int nb = 0;
        for (int i = 0; i < nids; i++) nb += ids[i].base >= 0;
        snprintf(buf, sizeof(buf), "MONITORING  %d IDs  |  rate + rolling-counter checks", nb);
        txt(&FONT_B, buf, 24, 70, GREEN, A_TL);
    }
    gfx_rrect(C, 12, 106, 640, 540, 12, PANEL);
    txt(&FONT_B, "ALERTS", 28, 118, FG, A_TL);
    static const uint32_t sevc[3] = {CYAN, AMBER, RED};
    for (int k = 0; k < nalerts && k < 13; k++) {
        int y = 156 + k * 37;
        gfx_fill(C, 28, y + 4, 6, 22, sevc[alerts[k].sev]);
        snprintf(buf, sizeof(buf), "+%6.1fs", alerts[k].ts);
        txt(&FONT_S, buf, 42, y + 6, DIM, A_TL);
        snprintf(buf, sizeof(buf), "%.50s", alerts[k].text);
        txt(&FONT_S, buf, 132, y + 6, FG, A_TL);
    }
    if (!nalerts) txt(&FONT_S, "No alerts yet. Hold ZR to attack and watch this list.", 28, 162, DIM, A_TL);
    gfx_rrect(C, 664, 106, 600, 540, 12, PANEL);
    txt(&FONT_B, "RATE vs BASELINE (Hz)", 680, 118, FG, A_TL);
    for (int k = 0; k < nids && k < 15; k++) {
        IdInfo *e = &ids[k];
        int r = rate_get(&e->rate, t), b = e->base;
        int y = 158 + k * 31;
        snprintf(buf, sizeof(buf), "%03X", (unsigned)e->id);
        txt(&FONT_M, buf, 680, y, FG, A_TL);
        float scale = (float)r;
        if (b * 2 > scale) scale = (float)(b * 2);
        if (scale < 60) scale = 60;
        int bx = 744, bw = 360;
        gfx_rrect(C, bx, y + 2, bw, 18, 4, PANEL2);
        bool anomal = b >= 0 && !ids_learning && r > b * 1.6 + 4;
        bool unknown = b < 0 && !ids_learning && ids_on;
        int fw = (int)(bw * (r / scale > 1 ? 1 : r / scale));
        if (fw > 0) gfx_rrect(C, bx, y + 2, fw, 18, 4, anomal ? RED : unknown ? AMBER : GREEN);
        if (b > 0) gfx_fill(C, bx + (int)(bw * (b / scale > 1 ? 1 : b / scale)), y - 1, 2, 24, FG);
        if (b >= 0) snprintf(buf, sizeof(buf), "%d/%d", r, b);
        else snprintf(buf, sizeof(buf), "%d/?", r);
        txt(&FONT_S, buf, bx + bw + 12, y + 2, anomal ? RED : DIM, A_TL);
    }
    int ce = rate_get(&ctr_rate, t);
    snprintf(buf, sizeof(buf), "0x1A0 counter errors: %d/s", ce);
    txt(&FONT_M, buf, 680, 610, ce > 5 ? RED : DIM, A_TL);
}

static const char *nfc_proto_name(uint32_t p) {
    if (p & 1) return "ISO 14443-A";
    if (p & 2) return "ISO 14443-B";
    if (p & 4) return "FeliCa (JIS X 6319-4)";
    return "unknown";
}
static const char *nfc_type_name(uint32_t ty) {
    if (ty & (1 << 6)) return "MIFARE Classic";
    if (ty & (1 << 1)) return "Type 2 (NTAG / Ultralight)";
    if (ty & (1 << 3)) return "Type 4A (DESFire / smart card)";
    if (ty & (1 << 4)) return "Type 4B";
    if (ty & (1 << 2)) return "Type 3 (FeliCa)";
    if (ty & (1 << 0)) return "Type 1 (Topaz)";
    if (ty & (1 << 5)) return "Type 5 (ISO 15693)";
    return "unknown";
}
static const char *nfc_insight(uint32_t ty, int uid_len) {
    if (ty & (1 << 6)) return "MIFARE Classic: Crypto-1 was broken in 2008. Don't trust it for access control.";
    if (ty & (1 << 1)) return uid_len == 7 ? "7-byte UID NTAG: amiibo, badges, smart posters. UID is public data." : "Type 2 tag: memory pages readable by anyone nearby.";
    if (ty & (1 << 3)) return "Type 4 / DESFire: real crypto (AES on EV1+). Much harder target.";
    if (uid_len == 4) return "4-byte UID - possibly random per read (privacy mode) or a cloneable card.";
    return "UID alone should never be used as an authenticator: it's trivially cloned.";
}

static void uid_str(const uint8_t *u, int n, char *out) {
    int k = 0;
    for (int i = 0; i < n && i < 10; i++) k += sprintf(out + k, i ? ":%02X" : "%02X", u[i]);
    if (!n) strcpy(out, "--");
}

static void draw_nfc(double t) {
    char buf[128];
    gfx_rrect(C, 12, 70, 760, 576, 12, PANEL);
    txt(&FONT_B, "JOY-CON NFC READER", 30, 84, FG, A_TL);
    uint32_t sc = nfc.state == NFC_TAG ? GREEN : nfc.state == NFC_ERROR ? RED : AMBER;
    txt(&FONT_M, nfc.status[0] ? nfc.status : "starting...", 30, 120, sc, A_TL);
    txt(&FONT_S, "Hold a card, badge, key fob or amiibo on the RIGHT stick of the Joy-Con.", 30, 152, DIM, A_TL);
    txt(&FONT_S, "Read-only: shows the tag's identity. Nothing is copied or written.", 30, 176, DIM, A_TL);
    if (n_nfc_hist > 0) {
        NfcHist *h = &nfc_hist[0];
        uid_str(h->uid, h->uid_len, buf);
        txt(&FONT_S, "LAST TAG UID", 30, 222, DIM, A_TL);
        txt(&FONT_BIG, buf, 30, 246, (t - h->t < 1.0) ? RED : FG, A_TL);
        snprintf(buf, sizeof(buf), "UID length  %d bytes", h->uid_len);
        txt(&FONT_M, buf, 30, 320, FG, A_TL);
        snprintf(buf, sizeof(buf), "Protocol    %s", nfc_proto_name(h->proto));
        txt(&FONT_M, buf, 30, 352, FG, A_TL);
        snprintf(buf, sizeof(buf), "Tag type    %s", nfc_type_name(h->type));
        txt(&FONT_M, buf, 30, 384, FG, A_TL);
        snprintf(buf, sizeof(buf), "raw: protocol=0x%X type=0x%X", (unsigned)h->proto, (unsigned)h->type);
        txt(&FONT_XS, buf, 30, 416, LINE, A_TL);
        gfx_rrect(C, 30, 448, 724, 70, 10, PANEL2);
        const char *ins = nfc_insight(h->type, h->uid_len);
        char l1[80], l2[80];
        int n = (int)strlen(ins), cut = n > 56 ? 56 : n;
        while (cut < n && cut > 30 && ins[cut] != ' ') cut--;
        snprintf(l1, sizeof(l1), "%.*s", cut, ins);
        snprintf(l2, sizeof(l2), "%s", n > cut ? ins + cut + 1 : "");
        txt(&FONT_M, l1, 44, 458, AMBER, A_TL);
        txt(&FONT_M, l2, 44, 486, AMBER, A_TL);
    } else {
        // pulsing reader icon
        float p = 0.5f + 0.5f * sinf((float)t * 4);
        gfx_ring(C, 390, 380, 60 + p * 20, 54 + p * 20, gfx_lerp(PANEL, CYAN, 1 - p));
        gfx_ring(C, 390, 380, 40, 34, CYAN);
        gfx_circle(C, 390, 380, 14, CYAN);
        txt(&FONT_M, "waiting for a tag...", 390, 500, DIM, A_C);
    }
    txt(&FONT_S, "B: clear history", 30, 612, DIM, A_TL);
    gfx_rrect(C, 784, 70, 480, 576, 12, PANEL);
    txt(&FONT_B, "HISTORY", 800, 84, FG, A_TL);
    for (int i = 0; i < n_nfc_hist; i++) {
        NfcHist *h = &nfc_hist[i];
        int y = 124 + i * 50;
        uid_str(h->uid, h->uid_len, buf);
        txt(&FONT_M, buf, 800, y, i == 0 ? FG : DIM, A_TL);
        txt(&FONT_XS, nfc_type_name(h->type), 800, y + 26, DIM, A_TL);
    }
    if (!n_nfc_hist) txt(&FONT_S, "Tags you scan will appear here.", 800, 124, DIM, A_TL);
}

static uint32_t thermal(int v) {
    // black -> purple -> red -> orange -> yellow -> white
    static const int st[6][3] = {{0, 0, 0}, {80, 0, 120}, {200, 20, 40}, {255, 120, 0}, {255, 220, 40}, {255, 255, 255}};
    float f = v / 255.0f * 5.0f;
    int i = (int)f;
    if (i >= 5) return COL(255, 255, 255);
    float k = f - i;
    return COL(st[i][0] + (int)((st[i + 1][0] - st[i][0]) * k), st[i][1] + (int)((st[i + 1][1] - st[i][1]) * k),
               st[i][2] + (int)((st[i + 1][2] - st[i][2]) * k));
}

static void draw_ir(double t) {
    (void)t;
    char status[96] = "";
    int iw = 0, ih = 0;
    const uint8_t *img = plat_ir_frame(&iw, &ih, status, sizeof(status));
    int ox = 24, oy = 76, dw = 640, dh = 480;
    gfx_fill(C, ox - 4, oy - 4, dw + 8, dh + 8, LINE);
    int maxv = 0, bright = 0;
    long sum = 0;
    if (img && iw > 0 && ih > 0) {
        for (int y = 0; y < dh; y++) {
            const uint8_t *srow = img + (size_t)(y * ih / dh) * iw;
            uint32_t *drow = C->px + (oy + y) * C->stride + ox;
            for (int x = 0; x < dw; x++) {
                int v = srow[x * iw / dw];
                drow[x] = ir_thermal ? thermal(v) : COL(v, v, v);
            }
        }
        for (int i = 0; i < iw * ih; i++) {
            int v = img[i];
            sum += v;
            if (v > maxv) maxv = v;
            if (v > 235) bright++;
        }
    } else {
        gfx_fill(C, ox, oy, dw, dh, BLACKISH);
        txt(&FONT_M, "no IR image", ox + dw / 2, oy + dh / 2 - 14, DIM, A_C);
        txt(&FONT_S, "Detach the right Joy-Con and hold it (wireless)", ox + dw / 2, oy + dh / 2 + 16, DIM, A_C);
    }
    Rect mode = {ox, oy + dh + 10, 200, 40};
    gfx_rrect(C, mode.x, mode.y, mode.w, mode.h, 8, PANEL2);
    txt(&FONT_S, ir_thermal ? "THERMAL view [Y]" : "GRAY view [Y]", mode.x + 100, mode.y + 20, FG, A_C);
    hit_add(mode, HT_IRMODE, 0, 0);
    gfx_rrect(C, 690, 70, 574, 576, 12, PANEL);
    txt(&FONT_B, "JOY-CON IR CAMERA", 708, 84, FG, A_TL);
    txt(&FONT_S, status[0] ? status : "starting...", 708, 118, img ? GREEN : AMBER, A_TL);
    char buf[96];
    if (img) {
        snprintf(buf, sizeof(buf), "max %d   mean %ld   hot px %d", maxv, (iw * ih) > 0 ? sum / (iw * ih) : 0L, bright);
        txt(&FONT_M, buf, 708, 152, FG, A_TL);
        bool hit = bright > 25;
        gfx_rrect(C, 708, 190, 538, 60, 10, hit ? RED : PANEL2);
        txt(&FONT_B, hit ? "IR SOURCE DETECTED" : "no strong IR source", 977, 220, hit ? WHITE : DIM, A_C);
    }
    static const char *tips[] = {"The Joy-Con R has a 320x240 infrared camera", "+ IR flood light. Point it at:",
                                 "", " - a TV remote while pressing a button",
                                 " - a phone's Face ID / face-unlock emitter", " - CCTV cameras (IR night-vision LEDs)",
                                 " - the sensor bar of a smart TV", "", "Humans can't see 850-940 nm IR,",
                                 "the Joy-Con can. Same trick spots hidden", "cameras in hotel rooms."};
    for (unsigned i = 0; i < sizeof(tips) / sizeof(tips[0]); i++) txt(&FONT_S, tips[i], 708, 276 + (int)i * 26, i >= 8 ? AMBER : DIM, A_TL);
}

static void draw_footer(void) {
    gfx_fill(C, 0, H - 34, W, 34, PANEL);
    const char *hint;
    if (attract_on) hint = "DEMO MODE - touch anything or press a button to take control";
    else if (tab == TAB_CLUSTER)
        hint = src == SRC_SIM ? "Stick gas/brake | D-pad blinkers | ZR spoof speed | ZL redline | A doors | B warnings | X IDS"
                              : "Pin a signal in SNIFFER | ZR/ZL override it (TX armed) | + hold 2s arm TX | X IDS";
    else if (tab == TAB_SNIFF) hint = "Up/Down ID | Left/Right byte | A pin to gauge | B clear | Y fuzz | L/R tabs | - help";
    else if (tab == TAB_IDS) hint = "X IDS on/off | A re-learn baseline | B clear alerts | L/R tabs | - help";
    else if (tab == TAB_NFC) hint = "Tap a tag on the right Joy-Con stick | B clear history | L/R tabs | - help";
    else hint = "Point the right Joy-Con at IR sources | Y thermal/gray | L/R tabs | - help";
    txt(&FONT_S, hint, 16, H - 27, attract_on ? AMBER : DIM, A_TL);
    txt(&FONT_XS, "v" APP_VERSION_STR, W - 14, H - 25, LINE, A_TR);
}

static void draw_help(void) {
    gfx_fill_a(C, 0, 0, W, H, COL(0, 0, 0), 215);
    txt(&FONT_BIG, "CANsole NX controls", W / 2, 70, FG, A_C);
    static const char *L[][2] = {{"L / R", "switch tab"}, {"Left stick", "gas / brake (sim car)"},
                                 {"ZR (hold)", "spoof speed | override MAX"}, {"ZL (hold)", "spoof RPM | override MIN"},
                                 {"A", "unlock doors | pin byte"}, {"B", "warning lights | clear"},
                                 {"X", "IDS on/off (re-learns)"}, {"Y", "fuzz selected ID 2 s"}};
    static const char *R[][2] = {{"D-pad", "blinkers | select ID/byte"}, {"+ (hold 2 s)", "arm TX on real bus"},
                                 {"-", "this help"}, {"- and +", "quit"}, {"L-stick click", "candump log on SD"},
                                 {"Touchscreen", "tabs, buttons, rows"}, {"USB-C", "RAMN / CANable (slcan)"}};
    for (int i = 0; i < 8; i++) {
        txt(&FONT_B, L[i][0], 70, 140 + i * 46, RED, A_TL);
        txt(&FONT_M, L[i][1], 260, 142 + i * 46, FG, A_TL);
    }
    for (int i = 0; i < 7; i++) {
        txt(&FONT_B, R[i][0], 740, 140 + i * 46, RED, A_TL);
        txt(&FONT_M, R[i][1], 958, 142 + i * 46, FG, A_TL);
    }
    txt(&FONT_M, "Only transmit on buses you own or have permission to test.", W / 2, 600, AMBER, A_C);
    txt(&FONT_S, "press any button to close", W / 2, 650, DIM, A_C);
}

// ===================================================================== API
void app_init(void) {
    make_gauge_bg(&bg_rpm, 190, 0, 8000, 1000, 4, 1000, 6500);
    make_gauge_bg(&bg_spd, 190, 0, 260, 20, 2, 1, -1);
    make_gauge_bg(&bg_pin, 190, 0, 100, 10, 2, 1, 90);
    gauge_init(&g_rpm, 230, 300, &bg_rpm, 190, 0, 8000);
    gauge_init(&g_spd, 1050, 300, &bg_spd, 190, 0, 260);
    gauge_init(&g_pin[0], 230, 300, &bg_pin, 190, 0, 100);
    gauge_init(&g_pin[1], 1050, 300, &bg_pin, 190, 0, 100);
    car_reset(0);
    bus_reset();
    ids_reset(0);
    attract_on = false;
    last_input = 0;
    last_t = -1;
}

void app_shutdown(void) {
    if (log_fp) fclose(log_fp);
    log_fp = NULL;
    plat_nfc_enable(false);
    plat_ir_enable(false);
    free(bg_rpm.px);
    free(bg_spd.px);
    free(bg_pin.px);
}

static void switch_source(int s, double t) {
    src = s;
    bus_reset();
    atk_clear();
    memset(pins, 0, sizeof(pins));
    have_sel = false;
    ids_reset(t);
    stop_attract();
    if (s == SRC_USB) {
        tx_armed = false;
        tab = TAB_SNIFF;
        toast(t, "USB-CAN connected - READ-ONLY. Move a knob, watch the red bytes, pin with A");
    } else {
        tx_armed = true;
        car_reset(t);
        toast(t, "USB-CAN disconnected - back to the virtual car");
    }
}

bool app_frame(Canvas *c, const Input *in, double t) {
    C = c;
    now_t = t;
    float dt = last_t < 0 ? 0.016f : (float)(t - last_t);
    if (dt > 0.1f) dt = 0.1f;
    last_t = t;

    // --- source switching (USB-CAN hotplug)
    int us = plat_usb_state();
    if (src == SRC_SIM && us == USB_CONNECTED) switch_source(SRC_USB, t);
    else if (src == SRC_USB && us != USB_CONNECTED) switch_source(SRC_SIM, t);

    // --- input
    stick_y = in->stick_y;
    if (fabsf(stick_y) > 0.15f) { last_input = t; stop_attract(); }
    for (int b = 0; b < 15; b++) {
        uint32_t bit = 1u << b;
        if (in->down & bit) press(bit, t);
        if (in->up & bit) release(bit);
    }
    if (in->touching && !prev_touch) tap(in->tx, in->ty, t);
    if (!in->touching && prev_touch) {
        for (int b = 0; b < 15; b++)
            if (touch_hold_bits & (1u << b)) release(1u << b);
        touch_hold_bits = 0;
    }
    prev_touch = in->touching;
    held_bits = (held_bits & ~0x7FFFu) | in->held | touch_hold_bits;

    // --- arm TX (hold + 2 s)
    if (plus_t >= 0 && t - plus_t >= 2.0) {
        plus_t = -1;
        if (src == SRC_SIM) toast(t, "SIM mode: TX is always on (virtual car)");
        else {
            tx_armed = !tx_armed;
            if (!tx_armed) atk_clear();
            toast(t, tx_armed ? "TX ARMED - you are transmitting on a real bus" : "TX disarmed - read-only");
        }
    }

    // --- simulation / bus
    if (src == SRC_SIM) {
        if (t - last_input > 45.0) {
            if (!attract_on) { attract_on = true; attract_t0 = t; }
            attract(t);
        } else {
            float gas = stick_y > 0.12f ? stick_y : 0, brk = stick_y < -0.12f ? -stick_y : 0;
            car.throttle = gas;
            car.brake = brk;
        }
        car_tick(t, dt);
    } else {
        CanFrame fr[256];
        int n, guard = 0;
        while ((n = plat_usb_poll(fr, 256)) > 0 && guard++ < 16)
            for (int i = 0; i < n; i++) ingest(&fr[i], t);
    }
    atk_tick(t, dt);
    ids_eval(t);
    if (!have_sel && nids) { sel_id = ids[0].id; have_sel = true; }

    // --- NFC / IR lifecycle
    bool want_nfc = tab == TAB_NFC, want_ir = tab == TAB_IR;
    if (want_nfc != nfc_enabled) { plat_nfc_enable(want_nfc); nfc_enabled = want_nfc; }
    if (want_ir != ir_enabled) { plat_ir_enable(want_ir); ir_enabled = want_ir; }
    if (nfc_enabled) {
        plat_nfc_info(&nfc);
        if (nfc.seq != nfc_seen_seq && nfc.uid_len > 0) {
            nfc_seen_seq = nfc.seq;
            memmove(&nfc_hist[1], &nfc_hist[0], sizeof(NfcHist) * 9);
            nfc_hist[0].t = t;
            memcpy(nfc_hist[0].uid, nfc.uid, 10);
            nfc_hist[0].uid_len = nfc.uid_len;
            nfc_hist[0].proto = nfc.protocol;
            nfc_hist[0].type = nfc.tag_type;
            if (n_nfc_hist < 10) n_nfc_hist++;
        }
    }

    // --- draw
    nhits = 0;
    gfx_clear(c, BG);
    draw_header(t);
    switch (tab) {
        case TAB_CLUSTER: draw_cluster(t); break;
        case TAB_SNIFF: draw_sniffer(t); break;
        case TAB_IDS: draw_ids(t); break;
        case TAB_NFC: draw_nfc(t); break;
        case TAB_IR: draw_ir(t); break;
    }
    draw_footer();
    if (show_help) draw_help();
    if (toast_msg[0] && t < toast_until) {
        int tw = gfx_text_w(&FONT_M, toast_msg) + 36;
        if (tw > W - 20) tw = W - 20;
        int tx = (W - tw) / 2, ty = H - 48 - 40;
        gfx_rrect(C, tx, ty, tw, 40, 10, PANEL2);
        gfx_rrect_line(C, tx, ty, tw, 40, 10, 2, CYAN);
        txt(&FONT_M, toast_msg, W / 2, ty + 20, FG, A_C);
    }
    return !quit_req;
}
