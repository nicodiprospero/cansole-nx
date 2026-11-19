// Host test harness: stub platform + scripted input, writes PPM screenshots.
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../source/app.h"
#include "../source/slcan.h"

static double T;
static int usb_state_v = USB_SEARCHING;
static char usb_label[64] = "USB: none";
int plat_usb_state(void) { return usb_state_v; }
const char *plat_usb_label(void) { return usb_label; }
static SlcanParser P;
int plat_usb_poll(CanFrame *out, int max) {
    // emulate a RAMN-ish bus through the real slcan parser: pedal 0x039, steering 0x062, counter 0x150
    static double last = 0;
    if (usb_state_v != USB_CONNECTED) return 0;
    char buf[2048]; int n = 0;
    while (last + 0.01 <= T) {
        last += 0.01;
        int pedal = (int)(2048 + 2000 * sin(last * 1.3));
        int steer = (int)(1000 * sin(last * 0.4)) & 0xFFFF;
        static int c = 0; c = (c + 1) & 0xFF;
        n += sprintf(buf + n, "t0392%02X%02X\r", pedal >> 8, pedal & 255);
        n += sprintf(buf + n, "t0624%02X%02X%02X00\r", steer >> 8, steer & 255, c);
        if (c % 10 == 0) n += sprintf(buf + n, "T18DAF1108%02X1122334455667\r", c); // malformed tail ok
        if (c % 5 == 0) n += sprintf(buf + n, "t1503%02XAB01\r", c);
        if (n > 1800) break;
    }
    return slcan_feed(&P, (const uint8_t *)buf, n, out, max);
}
static int sent;
bool plat_usb_send(const CanFrame *f) { char b[64]; slcan_encode(f, b); sent++; if (sent < 3) fprintf(stderr, "TX %s\n", b); return true; }
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

int main(void) {
    Canvas c = {fb, 1280, 720, 1280};
    app_init();
    Input in; memset(&in, 0, sizeof in);
    uint32_t prev = 0;
    struct { double at; uint32_t held; float stick; int touch, tx, ty; int usb; const char *shot; } S[] = {
        {0.0, 0, 0.9f, 0, 0, 0, 0, NULL},
        {8.0, 0, 0.9f, 0, 0, 0, 0, "01_cluster_driving"},
        {9.0, B_ZR, 0.5f, 0, 0, 0, 0, NULL},
        {10.5, B_ZR, 0.5f, 0, 0, 0, 0, "02_cluster_spoof"},
        {11.0, B_A, 0.5f, 0, 0, 0, 0, NULL},
        {11.1, 0, 0.5f, 0, 0, 0, 0, NULL},
        {11.6, 0, 0.5f, 0, 0, 0, 0, "03_doors_unlocked"},
        {12.0, B_R, 0.5f, 0, 0, 0, 0, NULL},
        {12.1, B_DOWN, 0.5f, 0, 0, 0, 0, NULL},
        {12.2, 0, 0.5f, 0, 0, 0, 0, NULL},
        {14.0, 0, 0.5f, 0, 0, 0, 0, "04_sniffer"},
        {14.1, B_R, 0.5f, 0, 0, 0, 0, NULL},
        {14.2, B_ZR, 0.5f, 0, 0, 0, 0, NULL},
        {16.0, B_ZR, 0.5f, 0, 0, 0, 0, "05_ids"},
        {16.1, B_R, 0.0f, 0, 0, 0, 0, NULL},
        {16.2, 0, 0.0f, 0, 0, 0, 0, NULL},
        {19.0, 0, 0.0f, 0, 0, 0, 0, "06_nfc"},
        {19.1, B_R, 0.0f, 0, 0, 0, 0, NULL},
        {19.2, 0, 0.0f, 0, 0, 0, 0, NULL},
        {20.0, 0, 0.0f, 0, 0, 0, 0, "07_ir"},
        {20.1, 0, 0.0f, 1, 300, 28, 0, NULL},   // touch CLUSTER tab... (x=300 -> tab 0 at 182..298? tab1)
        {20.2, 0, 0.0f, 0, 0, 0, 1, NULL},      // plug USB
        {23.0, 0, 0.0f, 0, 0, 0, 1, "08_usb_sniffer"},
        {23.1, B_A, 0.0f, 0, 0, 0, 1, NULL},     // pin 0x039 byte0
        {23.2, 0, 0.0f, 0, 0, 0, 1, NULL},
        {23.3, B_L, 0.0f, 0, 0, 0, 1, NULL},
        {23.4, B_ZR, 0.0f, 0, 0, 0, 1, NULL},    // locked -> toast
        {26.0, B_ZR, 0.0f, 0, 0, 0, 1, "09_usb_cluster_pinned"},
        {26.1, B_PLUS, 0.0f, 0, 0, 0, 1, NULL},
        {28.3, 0, 0.0f, 0, 0, 0, 1, NULL},
        {28.4, B_ZR, 0.0f, 0, 0, 0, 1, NULL},
        {29.5, B_ZR, 0.0f, 0, 0, 0, 1, "10_usb_armed_override"},
        {29.6, B_MINUS, 0.0f, 0, 0, 0, 1, NULL},
        {29.8, B_MINUS, 0.0f, 0, 0, 0, 1, "11_help"},
        {30.0, 0, 0.0f, 0, 0, 0, 0, NULL},
        {31.0, 0, 0.0f, 0, 0, 0, 0, "12_unplugged"},
        {80.0, 0, 0.0f, 0, 0, 0, 0, "13_attract"},
        {80.1, 0, 0.0f, 0, 0, 0, 0, NULL},
    };
    int ns = sizeof S / sizeof S[0], si = 0;
    int frames = 0;
    for (T = 0; T < 80.2; T += 1.0 / 60) {
        while (si + 1 < ns && S[si + 1].at <= T) si++;
        usb_state_v = S[si].usb ? USB_CONNECTED : USB_SEARCHING;
        snprintf(usb_label, sizeof usb_label, S[si].usb ? "USB 0483:5740 slcan 500k" : "USB: none");
        in.held = S[si].held; in.down = in.held & ~prev; in.up = prev & ~in.held; prev = in.held;
        in.stick_y = S[si].stick; in.touching = S[si].touch; in.tx = S[si].tx; in.ty = S[si].ty;
        if (!app_frame(&c, &in, T)) { printf("quit at %.2f\n", T); break; }
        frames++;
        if (S[si].shot && fabs(T - S[si].at) < 1.0 / 120 + 1e-9) save(S[si].shot);
        static int last_si = -1;
        if (S[si].shot && si != last_si) { save(S[si].shot); }
        last_si = si;
    }
    printf("frames=%d sent=%d\n", frames, sent);
    app_shutdown();
    return 0;
}
