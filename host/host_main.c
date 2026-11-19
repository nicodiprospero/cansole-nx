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
static bool pwr[3] = {true, true, true};   // ECU B, C, D
static double reboot_until[3];
static char pending[8192];
static int pending_n;
bool plat_usb_raw(const char *cmd) {
    fprintf(stderr, "[usb] raw %s\n", cmd);
    if (cmd[0] == 'y' && cmd[1] >= 'B' && cmd[1] <= 'D') pwr[cmd[1] - 'B'] = cmd[2] == '1';
    if (cmd[0] == 'Y') for (int i = 0; i < 3; i++) pwr[i] = cmd[1] == '1';
    return true;
}
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
static bool ecu_up(int e) { return pwr[e] && T >= reboot_until[e]; }
static void queue_raw(uint32_t id, const uint8_t *d) {
    pending_n += sprintf(pending + pending_n, "t%03X8", id);
    for (int i = 0; i < 8; i++) pending_n += sprintf(pending + pending_n, "%02X", d[i]);
    pending[pending_n++] = '\r';
}
// ISO-TP multi-frame response state
static uint8_t mf_buf[64]; static int mf_len, mf_pos, mf_ecu = -1, mf_sn;
int plat_usb_poll(CanFrame *out, int max) {
    static double last_fast = 0, last_slow = 0;
    if (usb_state_v != USB_CONNECTED) return 0;
    char buf[4096];
    int n = 0;
    while (last_fast + 0.01 <= T && n < 3500) {
        last_fast += 0.01;
        if (ecu_up(1)) n += emit(buf + n, 0x024, (uint16_t)(fmax(0, 900 * sin(last_fast * 0.9))), 0);          // brake
        if (ecu_up(1)) n += emit(buf + n, 0x039, (uint16_t)(2048 + 2000 * sin(last_fast * 1.3)), 0);           // accel
        if (ecu_up(0)) n += emit(buf + n, 0x062, (uint16_t)(2047 + 1500 * sin(last_fast * 0.5)), 0);           // steering
        n += emit(buf + n, 0x043, (uint16_t)(1200 + 800 * sin(last_fast)), 0);                  // rpm status
    }
    while (last_slow + 0.1 <= T && n < 3500) {
        last_slow += 0.1;
        if (ecu_up(1)) n += emit(buf + n, 0x077, 3, 1);                                     // gear 3
        if (ecu_up(0)) n += emit(buf + n, 0x150, 0x0003, 0);                                // light switch: LOW
        if (ecu_up(1)) n += emit(buf + n, 0x1A7, 0x0000, 0);                                // no turn signal
        if (ecu_up(1)) n += emit(buf + n, 0x098, 0, 1);                                     // horn button
        if (ecu_up(2)) n += emit(buf + n, 0x1B8, 3, 1);                                     // key IGN
        if (ecu_up(0)) n += emit(buf + n, 0x1D3, 0, 1);                                     // park brake down
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
        if (ecu_up(2)) n += emit(buf + n, 0x1BB, led, 1);
    }
    if (pending_n && n + pending_n < (int)sizeof(buf)) { memcpy(buf + n, pending, (size_t)pending_n); n += pending_n; pending_n = 0; }
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
    if (f->len == 8 && !(f->id >= 0x7E0 && f->id <= 0x7EF) && crc32b(f->data, 4) != ((uint32_t)f->data[4] | f->data[5] << 8 | f->data[6] << 16 | (uint32_t)f->data[7] << 24))
        fprintf(stderr, "!! bad forged CRC on %03X\n", f->id);
    if (f->id >= 0x7E1 && f->id <= 0x7E3) {  // UDS to ECU B/C/D
        int e = f->id - 0x7E1;
        uint32_t rid = 0x7E9 + e;
        uint8_t r[8] = {0};
        if (!ecu_up(e)) return true;
        if ((f->data[0] >> 4) == 3 && mf_ecu == e) {  // flow control -> send consecutive frames
            while (mf_pos < mf_len) {
                memset(r, 0, 8);
                r[0] = 0x20 | (mf_sn++ & 15);
                for (int i = 1; i < 8 && mf_pos < mf_len; i++) r[i] = mf_buf[mf_pos++];
                queue_raw(rid, r);
            }
            mf_ecu = -1;
            return true;
        }
        uint8_t sid = f->data[1];
        if (sid == 0x3E) { r[0] = 2; r[1] = 0x7E; r[2] = 0; queue_raw(rid, r); }
        else if (sid == 0x11) { r[0] = 2; r[1] = 0x51; r[2] = 1; queue_raw(rid, r); reboot_until[e] = T + 0.8; }
        else if (sid == 0x22) {
            uint16_t did = f->data[2] << 8 | f->data[3];
            const char *val = did == 0xF190 ? "RAMNVIN0123456789AB" : did == 0xF184 ? "Nov  6 2026 16:06:58" : NULL;
            if (!val) { r[0] = 3; r[1] = 0x7F; r[2] = 0x22; r[3] = 0x31; queue_raw(rid, r); return true; }
            mf_len = 0;
            mf_buf[mf_len++] = 0x62; mf_buf[mf_len++] = f->data[2]; mf_buf[mf_len++] = f->data[3];
            for (const char *c = val; *c; c++) mf_buf[mf_len++] = (uint8_t)*c;
            r[0] = 0x10 | (mf_len >> 8); r[1] = mf_len & 255;
            for (int i = 0; i < 6; i++) r[2 + i] = mf_buf[i];
            mf_pos = 6; mf_sn = 1; mf_ecu = e;
            queue_raw(rid, r);
        } else { r[0] = 3; r[1] = 0x7F; r[2] = sid; r[3] = 0x11; queue_raw(rid, r); }
        return true;
    }
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
        {44.5, B_R, 0.0f, 1, NULL}, {44.6, 0, 0.0f, 1, NULL}, {44.7, B_R, 0.0f, 1, NULL}, {44.8, 0, 0.0f, 1, NULL},
        {45.0, 0, 0.0f, 1, "11_ramn_ids"},
        {45.2, B_R, 0.0f, 1, NULL}, {45.3, 0, 0.0f, 1, NULL},               // -> ECU tab
        {45.4, B_A, 0.0f, 1, NULL}, {45.5, 0, 0.0f, 1, NULL},               // ping B
        {45.8, B_Y, 0.0f, 1, NULL}, {45.9, 0, 0.0f, 1, NULL},               // VIN + date (multi-frame)
        {46.5, B_DOWN, 0.0f, 1, NULL}, {46.6, 0, 0.0f, 1, NULL},            // select C
        {46.7, B_A, 0.0f, 1, NULL}, {46.8, 0, 0.0f, 1, NULL},
        {47.0, B_DOWN, 0.0f, 1, NULL}, {47.1, 0, 0.0f, 1, NULL},            // select D
        {47.2, B_X, 0.0f, 1, NULL}, {47.3, 0, 0.0f, 1, NULL},               // reset D -> silent
        {49.0, 0, 0.0f, 1, "13_ecu_uds"},
        {49.2, B_B, 0.0f, 1, NULL}, {49.3, 0, 0.7f, 1, NULL},               // START TAKEOVER, gas
        {52.0, B_ZL, 0.4f, 1, NULL},                                     // gas + brake
        {53.0, 0, 0.9f, 1, "14_takeover"},
        {53.2, 0x80000000u | 0, 0.9f, 1, NULL}, {53.3, 0, 0.9f, 1, NULL},   // touch tab 0 (CLUSTER)
        {55.5, 0, 0.9f, 1, "15_takeover_dash"},
        {55.6, 0x80000000u | 3, 0.0f, 1, NULL}, {55.7, 0, 0.0f, 1, NULL},   // touch tab 3 (ECU)
        {56.3, B_B, 0.0f, 1, NULL}, {56.4, 0, 0.0f, 1, NULL},               // stop takeover
        {56.6, 0x80000000u | 2, 0.0f, 1, NULL}, {56.7, 0, 0.0f, 1, NULL},   // touch tab 2 (IDS)
        {58.5, 0, 0.0f, 1, "16_after_takeover_ids"},
        {58.7, 0, 0.0f, 0, NULL},
        {59.5, 0, 0.0f, 0, "12_unplugged"},
        {59.6, 0, 0.0f, 0, NULL},
    };
    int ns = sizeof S / sizeof S[0], si = 0, last_si = -1;
    for (T = 0; T < 59.7; T += 1.0 / 60) {
        while (si + 1 < ns && S[si + 1].at <= T) si++;
        usb_state_v = S[si].usb ? USB_CONNECTED : USB_SEARCHING;
        snprintf(usb_label, sizeof usb_label, S[si].usb ? "USB 0483:5740 slcan 500k" : "USB: none");
        uint32_t hb = S[si].held;
        in.touching = false;
        if (hb & 0x80000000u) { in.touching = true; in.tx = 172 + (int)(hb & 15) * 106 + 51; in.ty = 28; hb = 0; }
        in.held = hb; in.down = in.held & ~prev; in.up = prev & ~in.held; prev = in.held;
        in.stick_y = S[si].stick;
        in.rstick_x = (float)sin(T * 1.5);
        if (!app_frame(&c, &in, T)) { printf("quit at %.2f\n", T); break; }
        if (S[si].shot && si != last_si) save(S[si].shot);
        last_si = si;
    }
    printf("sent=%d rumbles=%d\n", sent, rumbles);
    app_shutdown();
    return 0;
}
