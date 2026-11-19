// Host test harness: stub platform + scripted input, writes PPM screenshots.
// The USB stub emulates a RAMN board (stock firmware framing: [signal BE][counter BE][CRC32 LE]),
// including ECU D computing its LEDs from the frames it receives - so forged frames light "LEDs".
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../source/app.h"
#include "../source/slcan.h"

static double T;
static int usb_state_v = USB_SEARCHING;
static char usb_label[64] = "USB: none";
static int usb_tx_mode;  // 0 listen-only, 1 normal
int plat_usb_state(void) { return usb_state_v; }
const char *plat_usb_label(void) { return usb_label; }
void plat_usb_set_tx(bool en) { usb_tx_mode = en; fprintf(stderr, "[usb] adapter mode %s\n", en ? "O (normal)" : "L (listen-only)"); }
void plat_log(const char *fmt, ...) { va_list ap; va_start(ap, fmt); fprintf(stderr, "[log] "); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap); }
bool plat_safe_mode(void) { return false; }
static int rumbles;
void plat_rumble(float amp, int ms) { rumbles++; }

static uint32_t crc32b(const uint8_t *p, int n) {
    uint32_t c = 0xFFFFFFFF;
    while (n--) { c ^= *p++; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u))); }
    return ~c;
}
// --- emulated RAMN
static uint16_t ctr[0x800];
static uint16_t turn_val, lights_val = 0x0001, pbrake_val;  // what ECU D last received
static double last_forged_turn = -10, last_forged_lights = -10, last_forged_pb = -10;
static int emit(char *buf, uint32_t id, uint16_t sig, int sig8) {
    uint8_t d[8];
    if (sig8) { d[0] = (uint8_t)sig; d[1] = 0xFF; } else { d[0] = sig >> 8; d[1] = sig & 255; }
    uint16_t c = ctr[id]++;
    d[2] = c >> 8; d[3] = c & 255;
    uint32_t crc = crc32b(d, 4);
    d[4] = crc; d[5] = crc >> 8; d[6] = crc >> 16; d[7] = crc >> 24;
    int n = sprintf(buf, "t%03X8", id);
    for (int i = 0; i < 8; i++) n += sprintf(buf + n, "%02X", d[i]);
    buf[n++] = '\r';
    buf[n] = 0;
    return n;
}
static SlcanParser P;
int plat_usb_poll(CanFrame *out, int max) {
    static double last_fast = 0, last_slow = 0;
    if (usb_state_v != USB_CONNECTED) return 0;
    char buf[4096];
    int n = 0;
    while (last_fast + 0.01 <= T && n < 3500) {
        last_fast += 0.01;
        n += emit(buf + n, 0x024, (uint16_t)(fmax(0, 900 * sin(last_fast * 0.9))), 0);          // brake
        n += emit(buf + n, 0x039, (uint16_t)(2048 + 2000 * sin(last_fast * 1.3)), 0);           // accel
        n += emit(buf + n, 0x062, (uint16_t)(2047 + 1500 * sin(last_fast * 0.5)), 0);           // steering
        n += emit(buf + n, 0x043, (uint16_t)(1200 + 800 * sin(last_fast)), 0);                  // rpm status
    }
    while (last_slow + 0.1 <= T && n < 3500) {
        last_slow += 0.1;
        n += emit(buf + n, 0x077, 3, 1);                                                    // gear 3
        n += emit(buf + n, 0x150, 0x0003, 0);                                               // light switch: LOW
        n += emit(buf + n, 0x1A7, 0x0000, 0);                                               // no turn signal
        n += emit(buf + n, 0x1B8, 3, 1);                                                    // key IGN
        n += emit(buf + n, 0x1D3, 0, 1);                                                    // park brake down
        // ECU D: LEDs from what it received last (forged frames win while attack runs)
        uint16_t tv = (T - last_forged_turn < 0.2) ? turn_val : 0;
        uint16_t lv = (T - last_forged_lights < 0.2) ? lights_val : 0x0003;
        uint8_t pb = (T - last_forged_pb < 0.2) ? (uint8_t)pbrake_val : 0;
        uint8_t led = 0x01;  // battery (key IGN)
        if (lv & 0xFF00) led |= 0x02;
        if (pb) led |= 0x04;
        int pos = lv & 0xFF;
        if (pos >= 2) led |= 0x08;
        if (pos >= 3) led |= 0x10;
        if (pos >= 4) led |= 0x20;
        bool blink = fmod(T, 1.0) >= 0.5;
        if ((tv & 0xFF00) && blink) led |= 0x40;
        if ((tv & 0x00FF) && blink) led |= 0x80;
        n += emit(buf + n, 0x1BB, led, 1);
    }
    return slcan_feed(&P, (const uint8_t *)buf, n, out, max);
}
static int sent;
bool plat_usb_send(const CanFrame *f) {
    char b[64];
    slcan_encode(f, b);
    if (!usb_tx_mode) { fprintf(stderr, "!! TX while listen-only: %s\n", b); return false; }
    sent++;
    if (sent <= 2) fprintf(stderr, "TX %s\n", b);
    // verify the forged CRC like an IDS would
    if (f->len == 8 && crc32b(f->data, 4) != ((uint32_t)f->data[4] | f->data[5] << 8 | f->data[6] << 16 | (uint32_t)f->data[7] << 24))
        fprintf(stderr, "!! bad forged CRC on %03X\n", f->id);
    if (f->id == 0x1A7) { turn_val = f->data[0] | f->data[1] << 8; last_forged_turn = T; }
    if (f->id == 0x150) { lights_val = f->data[0] << 8 | f->data[1]; last_forged_lights = T; }
    if (f->id == 0x1D3) { pbrake_val = f->data[0]; last_forged_pb = T; }
    return true;
}
static bool nfc_on;
void plat_nfc_enable(bool on) { nfc_on = on; }
void plat_nfc_info(NfcInfo *o) {
    memset(o, 0, sizeof(*o));
    if (!nfc_on) return;
    if (fmod(T, 6) > 2) {
        o->state = NFC_TAG; strcpy(o->status, "Tag detected");
        uint8_t u[7] = {0x04, 0xA2, 0x3F, 0x1C, 0x55, 0x80, 0x81}; memcpy(o->uid, u, 7); o->uid_len = 7;
        o->protocol = 1; o->tag_type = 2; o->seq = (uint32_t)(T / 6);
    } else { o->state = NFC_SEARCHING; strcpy(o->status, "Searching for a tag..."); }
}
static bool ir_on; static uint8_t irimg[320 * 240];
void plat_ir_enable(bool on) { ir_on = on; }
const uint8_t *plat_ir_frame(int *w, int *h, char *st, int n) {
    if (!ir_on) return NULL;
    for (int y = 0; y < 240; y++) for (int x = 0; x < 320; x++) {
        double d = hypot(x - 200, y - 110);
        int v = (int)(40 + 30 * sin(x * 0.05) + (d < 40 ? 215 - d * 2 : 0)); if (v > 255) v = 255; if (v < 0) v = 0;
        irimg[y * 320 + x] = (uint8_t)v;
    }
    *w = 320; *h = 240; snprintf(st, n, "IR camera running (handheld)"); return irimg;
}
const char *plat_data_dir(void) { return "/tmp/"; }

static uint32_t fb[1280 * 720];
static void save(const char *name) {
    char p[256]; snprintf(p, sizeof p, "%s/%s.ppm", getenv("OUT") ? getenv("OUT") : "/tmp", name);
    FILE *f = fopen(p, "wb"); fprintf(f, "P6 1280 720 255\n");
    for (int i = 0; i < 1280 * 720; i++) { uint32_t v = fb[i]; fputc(v & 255, f); fputc((v >> 8) & 255, f); fputc((v >> 16) & 255, f); }
    fclose(f);
}

typedef struct { double at; uint32_t held; float stick; int usb; const char *shot; } Step;

static int attract_test(void) {
    Canvas c = {fb, 1280, 720, 1280};
    app_init();
    Input in; memset(&in, 0, sizeof in);
    // idle 45 s -> attract starts at t=45 (p=0). Snap key moments of the 44 s story.
    double snaps[] = {45 + 9.5, 45 + 13.5, 45 + 21, 45 + 28, 45 + 33, 45 + 38};
    const char *names[] = {"A1_L1", "A2_L2", "A3_L3_blind", "A4_secoc", "A5_ids", "A6_sniffer"};
    int k = 0;
    for (T = 0; T < 45 + 39; T += 1.0 / 60) {
        app_frame(&c, &in, T);
        if (k < 6 && T >= snaps[k]) save(names[k++]);
    }
    app_shutdown();
    return 0;
}

int main(void) {
    if (getenv("ATTRACT")) return attract_test();
    Canvas c = {fb, 1280, 720, 1280};
    app_init();
    Input in; memset(&in, 0, sizeof in);
    uint32_t prev = 0;
    Step S[] = {
        {0.0, 0, 0.9f, 0, NULL},
        {8.0, 0, 0.9f, 0, "01_cluster_driving"},
        {9.0, B_ZR, 0.5f, 0, NULL},                      // L1 naive spoof
        {10.5, B_ZR, 0.5f, 0, "02_L1_spoof_caught"},
        {11.0, B_UP, 0.5f, 0, NULL}, {11.1, 0, 0.5f, 0, NULL},          // -> L2
        {12.0, B_ZR, 0.5f, 0, NULL},
        {13.5, B_ZR, 0.5f, 0, "03_L2_forged_caught"},
        {14.0, B_UP, 0.5f, 0, NULL}, {14.1, 0, 0.5f, 0, NULL},          // -> L3
        {17.5, B_ZR, 0.5f, 0, NULL},                     // after cooldown: masquerade
        {21.0, B_ZR, 0.5f, 0, "04_L3_ids_blind"},
        {21.5, B_DOWN, 0.5f, 0, NULL}, {21.6, 0, 0.5f, 0, NULL},        // SecOC ON (relearn 6s)
        {29.0, B_ZR, 0.5f, 0, NULL},
        {31.0, B_ZR, 0.5f, 0, "05_L3_secoc_blocks"},
        {31.5, B_R, 0.5f, 0, NULL}, {31.6, B_R, 0.5f, 0, NULL}, {31.7, 0, 0.5f, 0, NULL},
        {32.0, B_ZR, 0.5f, 0, NULL},
        {33.0, B_ZR, 0.5f, 0, "06_ids_secoc"},
        {33.5, B_L, 0.5f, 0, NULL}, {33.6, B_L, 0.5f, 0, NULL}, {33.7, 0, 0.0f, 0, NULL},  // back to cluster
        {34.0, 0, 0.0f, 1, NULL},                        // plug RAMN
        {38.0, 0, 0.0f, 1, "07_ramn_sniffer"},
        {38.1, B_L, 0.0f, 1, NULL}, {38.2, 0, 0.0f, 1, NULL},
        {39.0, 0, 0.0f, 1, "08_ramn_dash_readonly"},
        {39.2, B_A, 0.0f, 1, NULL}, {39.3, 0, 0.0f, 1, NULL},           // try hazards while locked -> toast
        {39.6, B_PLUS, 0.0f, 1, NULL},                   // arm (hold 2s)
        {41.8, 0, 0.0f, 1, NULL},
        {42.0, B_A, 0.0f, 1, NULL}, {42.1, 0, 0.0f, 1, NULL},           // hazards
        {42.3, B_B, 0.0f, 1, NULL}, {42.4, 0, 0.0f, 1, NULL},           // check engine
        {43.6, 0, 0.0f, 1, "09_ramn_hazards_check_engine"},
        {44.2, 0, 0.0f, 1, "10_ramn_hazards_blink_off"},
        {44.5, B_R, 0.0f, 1, NULL}, {44.6, B_R, 0.0f, 1, NULL}, {44.7, 0, 0.0f, 1, NULL},
        {45.0, 0, 0.0f, 1, "11_ramn_ids"},
        {45.2, 0, 0.0f, 0, NULL},
        {46.0, 0, 0.0f, 0, "12_unplugged"},
        {46.1, 0, 0.0f, 0, NULL},
    };
    int ns = sizeof S / sizeof S[0], si = 0, last_si = -1;
    for (T = 0; T < 46.2; T += 1.0 / 60) {
        while (si + 1 < ns && S[si + 1].at <= T) si++;
        usb_state_v = S[si].usb ? USB_CONNECTED : USB_SEARCHING;
        snprintf(usb_label, sizeof usb_label, S[si].usb ? "USB 0483:5740 slcan 500k" : "USB: none");
        in.held = S[si].held; in.down = in.held & ~prev; in.up = prev & ~in.held; prev = in.held;
        in.stick_y = S[si].stick; in.touching = false;
        if (!app_frame(&c, &in, T)) { printf("quit at %.2f\n", T); break; }
        if (S[si].shot && si != last_si) save(S[si].shot);
        last_si = si;
    }
    printf("sent=%d rumbles=%d\n", sent, rumbles);
    app_shutdown();
    return 0;
}
