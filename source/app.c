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

// ------------------------------------------- CRC32 (same as RAMN firmware)
// RAMN default traffic: [signal 16b BE][freshness counter 16b BE][CRC32 of bytes 0-3, little-endian]
static uint32_t crc32_buf(const uint8_t *p, int n) {
    uint32_t crc = 0xFFFFFFFFu;
    while (n--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

// ------------------------------------------- SipHash-2-4 (SecOC MAC demo)
#define ROTL64(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0; v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32); } while (0)
static uint64_t rd64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint64_t siphash24(const uint8_t *in, int inlen, const uint8_t key[16]) {
    uint64_t k0 = rd64(key), k1 = rd64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = ((uint64_t)inlen) << 56;
    int left = inlen & 7, end = inlen - left;
    for (int i = 0; i < end; i += 8) { uint64_t m = rd64(in + i); v3 ^= m; SIPROUND; SIPROUND; v0 ^= m; }
    for (int i = 0; i < left; i++) b |= ((uint64_t)in[end + i]) << (8 * i);
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
// Secret key shared by the speed ECU and the cluster ECU only (the attacker does not have it).
static const uint8_t SECOC_KEY[16] = {0x4b, 0x1d, 0x9e, 0x37, 0xc2, 0x58, 0xa1, 0x0f, 0x6e, 0x93, 0x24, 0xd7, 0x7a, 0x05, 0xbc, 0xe8};
static uint32_t secoc_mac(uint32_t id, const uint8_t *d) {
    uint8_t m[6] = {(uint8_t)(id >> 8), (uint8_t)id, d[0], d[1], d[2], d[3]};  // id + signal + freshness + checksum
    return (uint32_t)siphash24(m, 6, SECOC_KEY);
}

// ------------------------------------------- RAMN (Toyota) signal table
// From ToyotaInfoTech/RAMN firmware: ramn_signal_defs.h / ramn_vehicle_specific.h / ramn_actuators.h
#define R_CMD_BRAKE 0x01A
#define R_CTL_BRAKE 0x024
#define R_CMD_ACCEL 0x02F
#define R_CTL_ACCEL 0x039
#define R_STATUS_RPM 0x043
#define R_CMD_STEER 0x058
#define R_CTL_STEER 0x062
#define R_CMD_SHIFT 0x06D
#define R_CTL_SHIFT 0x077
#define R_CMD_HORN 0x098
#define R_CTL_HORN 0x0A2
#define R_CMD_LIGHTS 0x150
#define R_CMD_TURN 0x1A7
#define R_CTL_KEY 0x1B8
#define R_CTL_LIGHTS 0x1BB
#define R_CMD_PBRAKE 0x1C9
#define R_CTL_PBRAKE 0x1D3
static const char *ramn_name(uint32_t id) {
    switch (id) {
        case R_CMD_BRAKE: return "cmd brake (A)";
        case R_CTL_BRAKE: return "brake pedal (C)";
        case R_CMD_ACCEL: return "cmd accel (A)";
        case R_CTL_ACCEL: return "accel pedal (C)";
        case R_STATUS_RPM: return "rpm status (A)";
        case R_CMD_STEER: return "cmd steer (A)";
        case R_CTL_STEER: return "steering (B)";
        case R_CMD_SHIFT: return "cmd shift (A)";
        case R_CTL_SHIFT: return "gear+joy (C)";
        case R_CMD_HORN: return "horn btn (C)";
        case R_CTL_HORN: return "horn ctl (A)";
        case R_CMD_LIGHTS: return "light switch (B)";
        case R_CMD_TURN: return "turn signal (C)";
        case R_CTL_KEY: return "engine key (D)";
        case R_CTL_LIGHTS: return "LED state (D)";
        case R_CMD_PBRAKE: return "cmd p-brake (A)";
        case R_CTL_PBRAKE: return "park brake (B)";
        case 0x7E0: case 0x7E1: case 0x7E2: case 0x7E3: return "UDS request";
        case 0x7E8: case 0x7E9: case 0x7EA: case 0x7EB: return "UDS response";
    }
    return "";
}

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
    // RAMN framing checks (real bus)
    uint16_t ctr_last;
    bool ctr_have;
    uint32_t crc_ok, crc_bad;
    Rate ctr_err, crc_err;
    double last_ext;  // last frame NOT sent by us (is the real ECU still talking?)
} IdInfo;

static IdInfo ids[MAXIDS];
// story mode (sim): attack level 1 naive, 2 forged counter+checksum, 3 bus-off masquerade; SecOC defense
static int atk_level = 1;
static bool secoc_on;
static float spd_acc;          // speed accepted by the cluster ECU (after SecOC check)
static double spd_acc_t = -10;
static Rate mac_fail;
static uint32_t mac_fail_total;
// real bus
static bool ramn_mode;
static bool own_tx;            // true while ingesting a frame we transmitted ourselves
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

static bool src_is_sim(void);
static void uds_on_frame(const CanFrame *f, double t);
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
    if (!own_tx) e->last_ext = t;
    rate_add(&e->rate, t);
    rate_add(&rx_rate, t);
    if (src_is_sim() && f->id == ID_SPEED && len >= 3) {
        int c = f->data[2] & 0x0F;
        if (ctr_last >= 0 && c != ((ctr_last + 1) & 0x0F)) rate_add(&ctr_rate, t);
        ctr_last = c;
        // the cluster ECU (receiver): with SecOC it only accepts frames carrying a valid MAC
        bool ok = true;
        if (secoc_on) {
            uint32_t mac = len >= 8 ? ((uint32_t)f->data[4] << 24 | (uint32_t)f->data[5] << 16 | (uint32_t)f->data[6] << 8 | f->data[7]) : 0;
            ok = len >= 8 && mac == secoc_mac(f->id, f->data);
        }
        if (ok) {
            spd_acc = ((f->data[0] << 8) | f->data[1]) / 100.0f;
            spd_acc_t = t;
        } else {
            rate_add(&mac_fail, t);
            mac_fail_total++;
        }
    }
    if (!src_is_sim() && !own_tx && f->id >= 0x7E9 && f->id <= 0x7EB) uds_on_frame(f, t);
    if (!src_is_sim() && len == 8 && !(f->id >= 0x7E0 && f->id <= 0x7EF)) {
        // RAMN framing: [signal][counter BE][CRC32 LE of bytes 0-3]
        uint32_t crc = crc32_buf(f->data, 4);
        uint32_t got = (uint32_t)f->data[4] | (uint32_t)f->data[5] << 8 | (uint32_t)f->data[6] << 16 | (uint32_t)f->data[7] << 24;
        if (crc == got) {
            e->crc_ok++;
            uint16_t c = (uint16_t)(f->data[2] << 8 | f->data[3]);
            if (e->ctr_have && c != (uint16_t)(e->ctr_last + 1)) rate_add(&e->ctr_err, t);
            e->ctr_last = c;
            e->ctr_have = true;
        } else if (e->crc_ok > 10) {
            e->crc_bad++;
            rate_add(&e->crc_err, t);
        }
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
enum { TAB_CLUSTER, TAB_SNIFF, TAB_IDS, TAB_ECU, TAB_NFC, TAB_IR, NTABS };
static const char *TAB_NAMES[NTABS] = {"CLUSTER", "SNIFFER", "IDS", "ECU", "NFC", "IR CAM"};

static int src = SRC_SIM;
static bool src_is_sim(void) { return src == SRC_SIM; }
static int ecu_sel;
static void ecu_press(uint32_t b, double t);
static void tko_release(uint32_t b);
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
            if (secoc_on) {
                uint32_t mac = secoc_mac(ID_SPEED, d);
                d[4] = mac >> 24; d[5] = mac >> 16; d[6] = mac >> 8; d[7] = mac;
                f->len = 8;
            }
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

static bool speed_ecu_busoff;
static void car_tick(double t, float dt) {
    car_physics(dt);
    for (int i = 0; i < 10; i++) {
        if (SCHED_ID[i] == ID_SPEED && speed_ecu_busoff) { car.last[i] = t; continue; }
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
enum { ATK_SPEED, ATK_RPM, ATK_DOORS, ATK_MIL, ATK_FUZZ, ATK_OMAX, ATK_OMIN,
       ATK_R_HAZARD, ATK_R_CHECK, ATK_R_HIBEAM, ATK_R_PBRAKE, ATK_N };
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
        if (plat_usb_send(f)) {
            atk_sent++;
            own_tx = true;
            ingest(f, t);  // we are a node on the bus: our frames are part of the traffic the IDS taps
            own_tx = false;
        }
    }
}

// Forge a RAMN frame: copy the real ECU's last frame, patch the signal, continue its freshness
// counter and recompute the CRC32. CRC is an integrity check, not authentication: anyone can compute it.
static void ramn_forge(uint32_t id, int off, const uint8_t *sig, int n, CanFrame *f) {
    IdInfo *e = find_id(id);
    memset(f, 0, sizeof(*f));
    f->id = id;
    f->len = 8;
    if (e && e->len == 8) memcpy(f->data, e->data, 8);
    memcpy(f->data + off, sig, (size_t)n);
    uint16_t c = (e && e->ctr_have) ? (uint16_t)(e->ctr_last + 1) : 0;
    f->data[2] = (uint8_t)(c >> 8);
    f->data[3] = (uint8_t)c;
    uint32_t crc = crc32_buf(f->data, 4);
    f->data[4] = (uint8_t)crc; f->data[5] = (uint8_t)(crc >> 8); f->data[6] = (uint8_t)(crc >> 16); f->data[7] = (uint8_t)(crc >> 24);
}

// Re-sign (well, re-checksum) an existing RAMN frame: next freshness counter + fresh CRC32.
static void ramn_fix(CanFrame *f) {
    IdInfo *e = find_id(f->id);
    uint16_t c = (e && e->ctr_have) ? (uint16_t)(e->ctr_last + 1) : 0;
    f->data[2] = (uint8_t)(c >> 8);
    f->data[3] = (uint8_t)c;
    uint32_t crc = crc32_buf(f->data, 4);
    f->data[4] = (uint8_t)crc; f->data[5] = (uint8_t)(crc >> 8); f->data[6] = (uint8_t)(crc >> 16); f->data[7] = (uint8_t)(crc >> 24);
}

static void atk_build(int a, CanFrame *f) {
    memset(f, 0, sizeof(*f));
    switch (a) {
        case ATK_SPEED:
            f->id = ID_SPEED; f->len = 4; f->data[0] = 0x5D; f->data[1] = 0xC0;  // 240.00 km/h
            if (atk_level >= 2) {  // forge a valid freshness counter + checksum
                f->data[2] = (uint8_t)((ctr_last + 1) & 0x0F);
                f->data[3] = (uint8_t)(f->data[0] + f->data[1] + f->data[2]);
            }
            if (secoc_on) {  // attacker has no key: right length, garbage MAC
                f->len = 8;
                uint32_t g = rnd();
                f->data[4] = g >> 24; f->data[5] = g >> 16; f->data[6] = g >> 8; f->data[7] = g;
            }
            break;
        case ATK_R_HAZARD: { uint8_t v[2] = {1, 1}; ramn_forge(R_CMD_TURN, 0, v, 2, f); } break;  // byte0 right, byte1 left
        case ATK_R_CHECK: {
            IdInfo *e = find_id(R_CMD_LIGHTS);
            uint8_t v[2] = {0xFF, (uint8_t)(e && e->len >= 2 ? e->data[1] : 1)};  // high byte = engine warning flags
            ramn_forge(R_CMD_LIGHTS, 0, v, 2, f);
        } break;
        case ATK_R_HIBEAM: {
            IdInfo *e = find_id(R_CMD_LIGHTS);
            uint8_t v[2] = {(uint8_t)(e && e->len >= 1 ? e->data[0] : 0), 4};  // light switch position 4 = high beam
            ramn_forge(R_CMD_LIGHTS, 0, v, 2, f);
        } break;
        case ATK_R_PBRAKE: { uint8_t v[1] = {1}; ramn_forge(R_CTL_PBRAKE, 0, v, 1, f); } break;
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

static double masq_acc;
static void atk_tick(double t, float dt) {
    bool masq = src == SRC_SIM && atk_level == 3 && atk_active(ATK_SPEED, t);
    speed_ecu_busoff = masq;
    if (masq) {  // bus-off'd the real speed ECU: now send at exactly its 50 Hz with a perfect counter chain
        masq_acc += dt * 50.0;
        int m = (int)masq_acc;
        masq_acc -= m;
        if (m > 4) m = 4;
        for (int k = 0; k < m; k++) {
            CanFrame f;
            atk_build(ATK_SPEED, &f);
            emit_tx(&f, t);
        }
    } else masq_acc = 0;
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
            if (a == ATK_SPEED && atk_level == 3) continue;  // masquerade runs on its own 50 Hz clock below
            CanFrame f;
            atk_build(a, &f);
            if ((a == ATK_OMAX || a == ATK_OMIN) && ramn_mode && f.len == 8) ramn_fix(&f);
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
        plat_rumble(sev == SEV_CRIT ? 0.9f : 0.5f, sev == SEV_CRIT ? 220 : 120);
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
            if (r > 0 && ids[i].id >= 0x7DF && ids[i].id <= 0x7EF) {
                snprintf(buf, sizeof(buf), "UDS diagnostic traffic on 0x%03X", (unsigned)ids[i].id);
                ids_alert(0x10000000 | ids[i].id, SEV_INFO, buf, t);
            } else if (r > 0) {
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
    int mf = rate_get(&mac_fail, t);
    if (mf > 0) {
        snprintf(buf, sizeof(buf), "SecOC MAC FAIL 0x1A0: forged frame rejected (%d/s)", mf);
        ids_alert(0x40000000, SEV_CRIT, buf, t);
    }
    for (int i = 0; i < nids; i++) {  // real bus: RAMN freshness counter + CRC32
        int cr = rate_get(&ids[i].ctr_err, t), kr = rate_get(&ids[i].crc_err, t);
        if (cr > 3) {
            snprintf(buf, sizeof(buf), "COUNTER BREAK 0x%03X: %d/s -> forged/replayed", (unsigned)ids[i].id, cr);
            ids_alert(0x50000000 | ids[i].id, SEV_CRIT, buf, t);
        }
        if (kr > 2) {
            snprintf(buf, sizeof(buf), "CRC32 FAIL 0x%03X: %d/s -> corrupted/fuzzed", (unsigned)ids[i].id, kr);
            ids_alert(0x60000000 | ids[i].id, SEV_CRIT, buf, t);
        }
        if (ids[i].base >= 5 && t - ids[i].last > 1.0) {
            snprintf(buf, sizeof(buf), "0x%03X SILENT %.0fs: ECU off / bus-off / reset?", (unsigned)ids[i].id, t - ids[i].last);
            ids_alert(0x70000000 | ids[i].id, SEV_WARN, buf, t);
        }
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
enum { HT_TAB, HT_QUIT, HT_HELP, HT_HOLD, HT_TAP, HT_ROW, HT_BYTE, HT_IRMODE, HT_ECU };
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
        atk_level = 1;
        secoc_on = false;
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
            plat_rumble(0.3f, 50);
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
    } else if (tab == TAB_CLUSTER && src == SRC_USB && ramn_mode) {
        int a = b == B_A ? ATK_R_HAZARD : b == B_B ? ATK_R_CHECK : b == B_Y ? ATK_R_HIBEAM : b == B_UP ? ATK_R_PBRAKE : -1;
        if (a >= 0) {
            if (!can_tx(t)) return;
            atk_until[a] = t + 4.0;
            plat_rumble(0.35f, 60);
            static const char *nm[4] = {"HAZARD LIGHTS (0x1A7)", "CHECK ENGINE (0x150 hi)", "HIGH BEAM (0x150 lo=4)", "PARKING BRAKE (0x1D3)"};
            toast(t, "Forging %s for 4 s - valid counter + CRC32", nm[a - ATK_R_HAZARD]);
        }
    } else if (tab == TAB_CLUSTER) {
        if (b == B_UP && src == SRC_SIM) {
            atk_level = atk_level % 3 + 1;
            static const char *lv[3] = {"L1 NAIVE: replay a fixed frame (counter 0, bad checksum)",
                                        "L2 FORGED: valid counter + checksum, but extra frames on the bus",
                                        "L3 MASQUERADE: bus-off the real ECU, then impersonate it perfectly"};
            toast(t, "%s", lv[atk_level - 1]);
            plat_rumble(0.25f, 40);
            return;
        }
        if (b == B_DOWN && src == SRC_SIM) {
            secoc_on = !secoc_on;
            toast(t, secoc_on ? "SecOC ON: speed frames carry a 32-bit MAC (SipHash, secret key)" : "SecOC OFF: frames are only checksummed");
            plat_rumble(0.25f, 40);
            return;
        }
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
    } else if (tab == TAB_ECU) {
        ecu_press(b, t);
    } else if (tab == TAB_NFC) {
        if (b == B_B) n_nfc_hist = 0;
    } else if (tab == TAB_IR) {
        if (b == B_Y || b == B_A) ir_thermal = !ir_thermal;
    }
}

static void release(uint32_t b) {
    held_bits &= ~b;
    tko_release(b);
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
            case HT_ECU:
                ecu_sel = (int)h->a;
                if (h->b) { press(h->b, t); release(h->b); }
                break;
        }
        return;
    }
    if (show_help) show_help = false;
}

// -------------------------------------------------------------- attract mode
static void attract(double t) {
    double p = fmod(t - attract_t0, 44.0);
    car.throttle = p < 8 ? 0.85f : p < 34 ? 0.3f : p < 41 ? 0.6f : 0.0f;
    car.brake = p >= 41 ? 0.6f : 0.0f;
    car.bl = p >= 4 && p < 7;
    atk_level = p < 11 ? 1 : p < 17 ? 2 : 3;
    secoc_on = p >= 24 && p < 40;
    tab = p < 30 ? TAB_CLUSTER : p < 35 ? TAB_IDS : TAB_SNIFF;
    atk_hold[ATK_SPEED] = (p >= 8 && p < 11) || (p >= 12 && p < 15) || (p >= 18.5 && p < 23) || (p >= 25 && p < 32);
    atk_hold[ATK_RPM] = false;
    atk_hold[ATK_DOORS] = p >= 5 && p < 6;
    atk_hold[ATK_MIL] = false;
    if (tab == TAB_SNIFF && nids) {
        sel_id = ids[((int)(p - 35)) % nids].id;
        have_sel = true;
        byte_cur = 0;
    }
}


// ===================================================== ECU tools (real RAMN)
// UDS over ISO-TP (ECU B/C/D: request 0x7E1-0x7E3, response 0x7E9-0x7EB), ECU power control
// through RAMN's USB command set (yX0/yX1/Y1), and the Joy-Con takeover (masquerade of ECU B + C).
typedef struct { char s[72]; uint32_t col; } LogLine;
static LogLine ulog[14];
static int nulog;
static void ulog_add(uint32_t col, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ulog_add(uint32_t col, const char *fmt, ...) {
    memmove(&ulog[1], &ulog[0], sizeof(LogLine) * 13);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ulog[0].s, sizeof(ulog[0].s), fmt, ap);
    va_end(ap);
    ulog[0].col = col;
    if (nulog < 14) nulog++;
}

static const char ECU_LETTER[3] = {'B', 'C', 'D'};
static const char *ECU_ROLE[3] = {"chassis: steering, park brake, lights", "powertrain: pedals, gear, horn, turn",
                                  "body: engine key, LEDs"};
static bool ecu_power[3] = {true, true, true};
static double ecu_alive_t[3] = {-100, -100, -100};
static char ecu_info[3][64];

typedef struct { int ecu; uint8_t p[7]; int n; } UdsReq;
static UdsReq uq[8];
static int uq_n;
static bool uds_wait;
static int uds_ecu;
static double uds_sent_t;
static uint8_t uds_buf[256];
static int uds_need, uds_got;
static uint8_t uds_req_sid;
static uint16_t uds_req_did;

static void uds_queue(int ecu, const uint8_t *p, int n) {
    if (uq_n < 8) { uq[uq_n].ecu = ecu; memcpy(uq[uq_n].p, p, (size_t)n); uq[uq_n].n = n; uq_n++; }
}

static const char *nrc_name(uint8_t c) {
    switch (c) {
        case 0x10: return "generalReject";
        case 0x11: return "serviceNotSupported";
        case 0x12: return "subFunctionNotSupported";
        case 0x13: return "incorrectLength";
        case 0x22: return "conditionsNotCorrect";
        case 0x31: return "requestOutOfRange";
        case 0x33: return "securityAccessDenied";
        case 0x35: return "invalidKey";
        case 0x78: return "responsePending";
        case 0x7E: return "subFnNotInSession";
        case 0x7F: return "serviceNotInSession";
    }
    return "?";
}

static void uds_complete(double t) {
    int e = uds_ecu;
    uint8_t *r = uds_buf;
    int n = uds_got < uds_need ? uds_got : uds_need;
    uds_wait = false;
    if (n < 1) return;
    if (r[0] == 0x7F && n >= 3) {
        if (r[2] == 0x78) { uds_wait = true; uds_sent_t = t; return; }  // pending: keep waiting
        ulog_add(AMBER, "<- %c  NRC 0x%02X %s (SID %02X)", ECU_LETTER[e], r[2], nrc_name(r[2]), r[1]);
        ecu_alive_t[e] = t;
        return;
    }
    ecu_alive_t[e] = t;
    if (r[0] == 0x7E) ulog_add(GREEN, "<- %c  TesterPresent OK: ECU alive", ECU_LETTER[e]);
    else if (r[0] == 0x50) ulog_add(GREEN, "<- %c  Session 0x%02X active", ECU_LETTER[e], n > 1 ? r[1] : 0);
    else if (r[0] == 0x51) {
        ulog_add(RED, "<- %c  ECUReset accepted: rebooting!", ECU_LETTER[e]);
        plat_rumble(0.7f, 200);
    } else if (r[0] == 0x62 && n >= 3) {
        uint16_t did = (uint16_t)(r[1] << 8 | r[2]);
        char asc[48];
        int k = 0;
        for (int i = 3; i < n && k < 40; i++) asc[k++] = (r[i] >= 32 && r[i] < 127) ? (char)r[i] : '.';
        asc[k] = 0;
        ulog_add(GREEN, "<- %c  DID %04X: %s", ECU_LETTER[e], did, asc);
        if (did == 0xF190) snprintf(ecu_info[e], sizeof(ecu_info[e]), "VIN %s", asc);
        else if (did == 0xF184 && !ecu_info[e][0]) snprintf(ecu_info[e], sizeof(ecu_info[e]), "built %s", asc);
    } else {
        char hx[64];
        int k = 0;
        for (int i = 0; i < n && i < 12; i++) k += sprintf(hx + k, "%02X ", r[i]);
        ulog_add(FG, "<- %c  %s", ECU_LETTER[e], hx);
    }
}

static void uds_on_frame(const CanFrame *f, double t) {
    if (!uds_wait || f->id != 0x7E9u + (uint32_t)uds_ecu || f->len < 1) return;
    const uint8_t *d = f->data;
    int pci = d[0] >> 4;
    if (pci == 0) {  // single frame
        uds_need = d[0] & 15;
        uds_got = 0;
        for (int i = 1; i < f->len && uds_got < uds_need; i++) uds_buf[uds_got++] = d[i];
        uds_complete(t);
    } else if (pci == 1 && f->len >= 2) {  // first frame -> send flow control
        uds_need = ((d[0] & 15) << 8) | d[1];
        if (uds_need > (int)sizeof(uds_buf)) uds_need = sizeof(uds_buf);
        uds_got = 0;
        for (int i = 2; i < f->len && uds_got < uds_need; i++) uds_buf[uds_got++] = d[i];
        CanFrame fc;
        memset(&fc, 0, sizeof(fc));
        fc.id = 0x7E1u + (uint32_t)uds_ecu;
        fc.len = 8;
        fc.data[0] = 0x30;  // continue to send, no block limit, STmin 0
        emit_tx(&fc, t);
    } else if (pci == 2) {  // consecutive frame
        for (int i = 1; i < f->len && uds_got < uds_need; i++) uds_buf[uds_got++] = d[i];
        if (uds_got >= uds_need) uds_complete(t);
    }
}

static void uds_tick(double t) {
    if (uds_wait && t - uds_sent_t > 1.2) {
        ulog_add(DIM, "<- %c  no reply (powered off? not a UDS ECU?)", ECU_LETTER[uds_ecu]);
        uds_wait = false;
    }
    if (uds_wait || uq_n == 0 || src != SRC_USB || !tx_armed) return;
    UdsReq q = uq[0];
    memmove(&uq[0], &uq[1], sizeof(UdsReq) * (size_t)(uq_n - 1));
    uq_n--;
    CanFrame f;
    memset(&f, 0, sizeof(f));
    f.id = 0x7E1u + (uint32_t)q.ecu;
    f.len = 8;
    f.data[0] = (uint8_t)q.n;
    memcpy(f.data + 1, q.p, (size_t)q.n);
    char hx[40];
    int k = 0;
    for (int i = 0; i <= q.n; i++) k += sprintf(hx + k, "%02X ", f.data[i]);
    ulog_add(CYAN, "-> %c  %03X  %s", ECU_LETTER[q.ecu], (unsigned)f.id, hx);
    uds_ecu = q.ecu;
    uds_req_sid = q.p[0];
    uds_req_did = q.n >= 3 ? (uint16_t)(q.p[1] << 8 | q.p[2]) : 0;
    uds_wait = true;
    uds_sent_t = t;
    uds_need = uds_got = 0;
    emit_tx(&f, t);
}

static bool ecu_power_set(int e, bool on, double t) {
    char cmd[8];
    snprintf(cmd, sizeof(cmd), "y%c%d\r", ECU_LETTER[e], on ? 1 : 0);
    if (!plat_usb_raw(cmd)) { toast(t, "ECU power control needs RAMN's USB serial (slcan)"); return false; }
    ecu_power[e] = on;
    ulog_add(on ? GREEN : RED, "-> USB  y%c%d  power %s ECU %c", ECU_LETTER[e], on, on ? "ON" : "OFF", ECU_LETTER[e]);
    return true;
}

// ---- Joy-Con takeover: impersonate every message of ECU B and C at their real periods
static const uint32_t TKO_ID[8] = {R_CTL_STEER, R_CTL_PBRAKE, R_CMD_LIGHTS, R_CTL_BRAKE, R_CTL_ACCEL, R_CTL_SHIFT, R_CMD_HORN, R_CMD_TURN};
static const double TKO_P[8] = {0.01, 0.1, 0.1, 0.01, 0.01, 0.1, 0.1, 0.1};
static bool tko_on;
static double tko_t0, tko_last[8];
static uint16_t tko_accel, tko_brake, tko_steer = 0x7FF;
static int tko_gear = 1, tko_blink;  // blink: 0 off, 1 left, 2 right, 3 hazard
static bool tko_horn;
static int tko_alerts0;

static void tko_start(double t) {
    if (!can_tx(t)) return;
    if (!ecu_power_set(0, false, t) || !ecu_power_set(1, false, t)) return;
    tko_on = true;
    tko_t0 = t;
    for (int i = 0; i < 8; i++) tko_last[i] = t;
    bool ok;
    IdInfo *e = find_id(R_CTL_SHIFT);
    (void)ok;
    if (e && e->len >= 1 && e->data[0] >= 1 && e->data[0] <= 6) tko_gear = e->data[0];
    tko_alerts0 = nalerts;
    toast(t, "TAKEOVER: ECU B + C powered off, your Joy-Cons ARE the steering wheel and pedals now");
    plat_rumble(0.9f, 300);
}

static void tko_stop(double t) {
    if (!tko_on) return;
    tko_on = false;
    ecu_power_set(0, true, t);
    ecu_power_set(1, true, t);
    toast(t, "Takeover ended - ECU B + C powered back on (watch the IDS: their counters restart at 0)");
    plat_rumble(0.5f, 150);
}

static void tko_tick(double t) {
    if (!tko_on) return;
    if (src != SRC_USB || !tx_armed) { tko_on = false; return; }
    for (int i = 0; i < 8; i++) {
        if (t - tko_last[i] > 0.3) tko_last[i] = t - TKO_P[i];
        int guard = 0;
        while (t - tko_last[i] >= TKO_P[i] && guard++ < 5) {
            tko_last[i] += TKO_P[i];
            uint8_t v[2] = {0, 0};
            int nb = 2;
            switch (TKO_ID[i]) {
                case R_CTL_STEER: v[0] = tko_steer >> 8; v[1] = tko_steer & 255; break;
                case R_CTL_BRAKE: v[0] = tko_brake >> 8; v[1] = tko_brake & 255; break;
                case R_CTL_ACCEL: v[0] = tko_accel >> 8; v[1] = tko_accel & 255; break;
                case R_CTL_SHIFT: v[0] = (uint8_t)tko_gear; v[1] = 1; break;  // joystick released
                case R_CMD_HORN: v[0] = tko_horn ? 1 : 0; nb = 1; break;
                case R_CMD_TURN: v[0] = (tko_blink & 2) ? 1 : 0; v[1] = (tko_blink & 1) ? 1 : 0; break;  // b0 right, b1 left
                case R_CTL_PBRAKE: v[0] = 0; nb = 1; break;
                case R_CMD_LIGHTS: {
                    IdInfo *e = find_id(R_CMD_LIGHTS);
                    v[0] = 0;
                    v[1] = (e && e->len >= 2) ? e->data[1] : 1;
                } break;
            }
            CanFrame f;
            ramn_forge(TKO_ID[i], 0, v, nb, &f);
            emit_tx(&f, t);
        }
    }
}

static void ecu_press(uint32_t b, double t) {
    if (src != SRC_USB) { toast(t, "Plug in a RAMN: the ECU tools talk to real ECUs over UDS"); return; }
    if (tko_on) {
        if (b == B_B) tko_stop(t);
        else if (b == B_UP) { if (tko_gear < 6) tko_gear++; }
        else if (b == B_DOWN) { if (tko_gear > 1) tko_gear--; }
        else if (b == B_LEFT) tko_blink = tko_blink == 1 ? 0 : 1;
        else if (b == B_RIGHT) tko_blink = tko_blink == 2 ? 0 : 2;
        else if (b == B_Y) tko_blink = tko_blink == 3 ? 0 : 3;
        else if (b == B_A) tko_horn = true;
        return;
    }
    if (b == B_UP) { ecu_sel = (ecu_sel + 2) % 3; return; }
    if (b == B_DOWN) { ecu_sel = (ecu_sel + 1) % 3; return; }
    if (b != B_A && b != B_Y && b != B_X && b != B_ZR && b != B_B && b != B_ZL) return;
    if (!can_tx(t)) return;
    if (b == B_A) { uint8_t p[2] = {0x3E, 0x00}; uds_queue(ecu_sel, p, 2); }
    else if (b == B_Y) {
        uint8_t p1[3] = {0x22, 0xF1, 0x90}, p2[3] = {0x22, 0xF1, 0x84};
        uds_queue(ecu_sel, p1, 3);
        uds_queue(ecu_sel, p2, 3);
    } else if (b == B_X) {
        uint8_t p[2] = {0x11, 0x01};
        uds_queue(ecu_sel, p, 2);
        toast(t, "UDS ECUReset (0x11 01) -> ECU %c. Watch its IDs go SILENT in the IDS", ECU_LETTER[ecu_sel]);
    } else if (b == B_ZR) ecu_power_set(ecu_sel, !ecu_power[ecu_sel], t);
    else if (b == B_B) tko_start(t);
    else if (b == B_ZL) {
        if (plat_usb_raw("Y1\r")) {
            for (int i = 0; i < 3; i++) ecu_power[i] = true;
            ulog_add(GREEN, "-> USB  Y1  power ON all ECUs (restore)");
            toast(t, "Restore: all ECUs powered on");
        }
    }
}

static void tko_release(uint32_t b) {
    if (b == B_A) tko_horn = false;
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
        Rect tr = {172 + i * 106, 10, 102, 36};
        gfx_rrect(C, tr.x, tr.y, tr.w, tr.h, 8, i == tab ? RED : PANEL2);
        txt(&FONT_B, TAB_NAMES[i], tr.x + tr.w / 2, tr.y + tr.h / 2, i == tab ? WHITE : DIM, A_C);
        hit_add(tr, HT_TAB, (uint32_t)i, 0);
    }
    char line[96], l2[96];
    if (src == SRC_SIM) snprintf(line, sizeof(line), "SIM car  |  %s", plat_usb_label());
    else snprintf(line, sizeof(line), "%s%s", ramn_mode ? "RAMN | " : "", plat_usb_label());
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
    if (src == SRC_SIM) {
        if (t - spd_acc_t < 1.0) { s.spd_ok = true; s.spd = spd_acc; }
    } else if ((e = find_id(ID_SPEED)) && t - e->last < 1.0 && e->len >= 2) { s.spd_ok = true; s.spd = ((e->data[0] << 8) | e->data[1]) / 100.0f; }
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
    if (src == SRC_SIM) {
        static const char *lvn[3] = {"ATTACK L1 naive", "ATTACK L2 forged", "ATTACK L3 masq."};
        Rect lr = {1048, 568, 214, 34}, sr2 = {1048, 608, 214, 34};
        gfx_rrect(C, lr.x, lr.y, lr.w, lr.h, 8, PANEL2);
        gfx_rrect_line(C, lr.x, lr.y, lr.w, lr.h, 8, 2, atk_level == 3 ? AMBER : LINE);
        txt(&FONT_S, lvn[atk_level - 1], lr.x + 10, lr.y + 8, atk_level == 3 ? AMBER : FG, A_TL);
        txt(&FONT_XS, "[Up]", lr.x + lr.w - 8, lr.y + 10, DIM, A_TR);
        hit_add(lr, HT_TAP, B_UP, 0);
        gfx_rrect(C, sr2.x, sr2.y, sr2.w, sr2.h, 8, secoc_on ? COL(20, 70, 45) : PANEL2);
        gfx_rrect_line(C, sr2.x, sr2.y, sr2.w, sr2.h, 8, 2, secoc_on ? GREEN : LINE);
        txt(&FONT_S, secoc_on ? "SecOC ON (MAC)" : "SecOC OFF", sr2.x + 10, sr2.y + 8, secoc_on ? GREEN : DIM, A_TL);
        txt(&FONT_XS, "[Down]", sr2.x + sr2.w - 8, sr2.y + 10, DIM, A_TR);
        hit_add(sr2, HT_TAP, B_DOWN, 0);
        // lesson strip (only when no intrusion banner)
        bool hit_now = ids_on && t - ids_last_hit < 3.0;
        bool attacking = atk_active(ATK_SPEED, t);
        if (!hit_now && attacking) {
            const char *msg; uint32_t col = AMBER;
            if (secoc_on) { msg = "SecOC: forged frames have no valid MAC -> the cluster rejects them"; col = GREEN; }
            else if (atk_level == 3) msg = "IDS BLIND: real ECU is bus-off, attacker matches rate + counter + checksum";
            else if (atk_level == 2) msg = "Forged counter + checksum pass... but the extra frames double the rate";
            else msg = "Naive replay: fixed frame, broken counter";
            gfx_fill(C, 0, 516, W, 40, COL(40, 32, 10));
            txt(&FONT_B, msg, W / 2, 536, col, A_C);
        }
    }
}

// ------------------------------------------------------------- RAMN dashboard
static uint16_t ramn_u16(uint32_t id, double t, bool *ok) {
    IdInfo *e = find_id(id);
    *ok = e && e->len >= 2 && t - e->last < 1.5;
    return *ok ? (uint16_t)(e->data[0] << 8 | e->data[1]) : 0;
}
static uint8_t ramn_u8(uint32_t id, int idx, double t, bool *ok) {
    IdInfo *e = find_id(id);
    *ok = e && e->len > idx && t - e->last < 1.5;
    return *ok ? e->data[idx] : 0;
}

static void pedal_bar(int x, int y, int w, int h, const char *lab, uint32_t id, uint16_t v, bool ok, uint32_t col) {
    char buf[32];
    gfx_rrect(C, x, y, w, h, 10, PANEL2);
    float f = ok ? v / 4095.0f : 0;
    if (f > 1) f = 1;
    int fh = (int)((h - 8) * f);
    if (fh > 0) gfx_rrect(C, x + 4, y + h - 4 - fh, w - 8, fh, 8, col);
    txt(&FONT_B, lab, x + w / 2, y + h + 18, FG, A_C);
    snprintf(buf, sizeof(buf), "0x%03X", (unsigned)id);
    txt(&FONT_XS, buf, x + w / 2, y + h + 40, DIM, A_C);
    snprintf(buf, sizeof(buf), ok ? "%u" : "--", (unsigned)v);
    txt(&FONT_M, buf, x + w / 2, y - 18, ok ? FG : DIM, A_C);
}

static void draw_ramn(double t) {
    char buf[96];
    bool ok;
    // --- steering wheel (ECU B potentiometer, 12-bit, center 0x7FF)
    uint16_t st = ramn_u16(R_CTL_STEER, t, &ok);
    float ang = ok ? ((float)st - 2047.0f) / 2047.0f * 2.356f : 0;  // +-135 deg
    static float sdisp;
    sdisp += (ang - sdisp) * 0.5f;
    float cx = 230, cy = 290, r = 150;
    gfx_ring(C, cx, cy, r, r - 24, ok ? COL(70, 76, 92) : LINE);
    gfx_circle(C, cx, cy, 34, PANEL2);
    for (int k = 0; k < 3; k++) {
        float a = sdisp + 1.5708f + k * 2.0944f + 3.14159f;
        if (k == 0) a = sdisp - 1.5708f + 3.14159f;  // bottom spoke
        if (k == 1) a = sdisp + 0.2f;
        if (k == 2) a = sdisp + 3.14159f - 0.2f;
        gfx_line(C, cx + cosf(a) * 30, cy + sinf(a) * 30, cx + cosf(a) * (r - 20), cy + sinf(a) * (r - 20), 16, ok ? COL(70, 76, 92) : LINE);
    }
    // top marker
    float ma = sdisp - 1.5708f;
    gfx_circle(C, cx + cosf(ma) * (r - 12), cy + sinf(ma) * (r - 12), 9, RED);
    txt(&FONT_B, "STEERING", (int)cx, 470, FG, A_C);
    snprintf(buf, sizeof(buf), ok ? "0x062  raw %u  (%+.0f deg)" : "0x062  --", (unsigned)st, ang * 57.3f);
    txt(&FONT_S, buf, (int)cx, 494, DIM, A_C);

    // --- center: gear, key, light switch, rpm
    int mx = 640;
    uint8_t gear = ramn_u8(R_CTL_SHIFT, 0, t, &ok);
    bool gok = ok;
    uint8_t joy = ramn_u8(R_CTL_SHIFT, 1, t, &ok);
    txt(&FONT_S, "GEAR (0x077)", mx, 76, DIM, A_C);
    snprintf(buf, sizeof(buf), gok ? "%u" : "-", gear);
    txt(&FONT_HUGE, buf, mx, 150, FG, A_C);
    static const char *jn[7] = {"?", "released", "up", "down", "right", "left", "push"};
    snprintf(buf, sizeof(buf), "joystick: %s", ok && joy < 7 ? jn[joy] : "--");
    txt(&FONT_S, buf, mx, 214, DIM, A_C);
    uint8_t key = ramn_u8(R_CTL_KEY, 0, t, &ok);
    static const char *kn[4] = {"--", "OFF", "ACC", "IGN"};
    snprintf(buf, sizeof(buf), "KEY %s", ok && key < 4 ? kn[key] : "--");
    gfx_rrect(C, mx - 150, 240, 140, 40, 8, ok && key == 3 ? COL(20, 70, 45) : PANEL2);
    txt(&FONT_B, buf, mx - 80, 260, ok && key == 3 ? GREEN : FG, A_C);
    bool lok;
    uint16_t lights = ramn_u16(R_CMD_LIGHTS, t, &lok);
    static const char *ln[5] = {"--", "OFF", "TAIL", "LOW", "HIGH"};
    int lp = lights & 0xFF;
    snprintf(buf, sizeof(buf), "LIGHTS %s", lok && lp < 5 ? ln[lp] : "--");
    gfx_rrect(C, mx + 10, 240, 140, 40, 8, PANEL2);
    txt(&FONT_B, buf, mx + 80, 260, FG, A_C);
    uint16_t rpm = ramn_u16(R_STATUS_RPM, t, &ok);
    snprintf(buf, sizeof(buf), ok ? "rpm status 0x043: %u" : "rpm status 0x043: --", (unsigned)rpm);
    txt(&FONT_S, buf, mx, 300, DIM, A_C);

    // --- LED mirror (ECU D reports its own LED state on 0x1BB = proof the attack landed)
    uint8_t led = ramn_u8(R_CTL_LIGHTS, 0, t, &ok);
    static const char *lname[8] = {"BATT", "CHECK", "P-BRK", "TAIL", "LOW", "HIGH", "LEFT", "RIGHT"};
    static const uint32_t lcol[8] = {RED, AMBER, RED, COL(200, 40, 40), CYAN, COL(80, 140, 255), GREEN, GREEN};
    txt(&FONT_S, "ECU D LEDs (0x1BB, reported by the board)", mx, 336, DIM, A_C);
    for (int i = 0; i < 8; i++) {
        int lx = mx - 4 * 46 + 23 + i * 46, ly = 382;
        bool on = ok && (led >> i) & 1;
        if (on) gfx_circle(C, (float)lx, (float)ly, 19, gfx_lerp(BG, lcol[i], 0.35f));
        gfx_circle(C, (float)lx, (float)ly, 14, on ? lcol[i] : PANEL2);
        txt(&FONT_XS, lname[i], lx, ly + 28, on ? FG : DIM, A_C);
    }
    // --- framing lesson
    IdInfo *te = find_id(R_CTL_ACCEL);
    if (te && te->len == 8) {
        snprintf(buf, sizeof(buf), "%02X %02X | %02X %02X | %02X %02X %02X %02X", te->data[0], te->data[1], te->data[2], te->data[3],
                 te->data[4], te->data[5], te->data[6], te->data[7]);
        txt(&FONT_M, buf, mx, 440, FG, A_C);
        txt(&FONT_XS, "signal       counter     CRC32 (not a MAC!)", mx, 462, DIM, A_C);
        snprintf(buf, sizeof(buf), "CRC ok %u   bad %u", (unsigned)te->crc_ok, (unsigned)te->crc_bad);
        txt(&FONT_XS, buf, mx, 480, te->crc_ok ? GREEN : DIM, A_C);
    }

    // --- pedals (ECU C sliders)
    bool aok, bok;
    uint16_t acc = ramn_u16(R_CTL_ACCEL, t, &aok), brk = ramn_u16(R_CTL_BRAKE, t, &bok);
    pedal_bar(940, 110, 110, 330, "ACCEL", R_CTL_ACCEL, acc, aok, GREEN);
    pedal_bar(1110, 110, 110, 330, "BRAKE", R_CTL_BRAKE, brk, bok, RED);

    if (ids_on && t - ids_last_hit < 3.0) {
        gfx_fill(C, 0, 516, W, 40, ((int)(t * 4)) % 2 ? COL(120, 18, 14) : RED);
        snprintf(buf, sizeof(buf), "!! IDS  -  %s", ids_last_msg);
        txt(&FONT_B, buf, W / 2, 536, WHITE, A_C);
    }
    // --- attack buttons (forged with valid counter + CRC32)
    const char *lab[5] = {"HAZARDS", "CHECK ENGINE", "HIGH BEAM", "PARK BRAKE", "OVERRIDE PIN"};
    const char *hint[5] = {"[A] 0x1A7", "[B] 0x150", "[Y] 0x150", "[Up] 0x1D3", "[ZR] hold"};
    uint32_t bits[5] = {B_A, B_B, B_Y, B_UP, B_ZR};
    int types[5] = {HT_TAP, HT_TAP, HT_TAP, HT_TAP, HT_HOLD};
    bool on[5] = {atk_active(ATK_R_HAZARD, t), atk_active(ATK_R_CHECK, t), atk_active(ATK_R_HIBEAM, t),
                  atk_active(ATK_R_PBRAKE, t), atk_active(ATK_OMAX, t)};
    int bw = 194;
    for (int i = 0; i < 5; i++) {
        Rect rr = {18 + i * (bw + 12), 568, bw, 74};
        button(rr, lab[i], hint[i], on[i], tx_armed ? RED : LINE);
        hit_add(rr, types[i], bits[i], 0);
    }
    gfx_rrect(C, 1048, 568, 214, 74, 12, tx_armed ? COL(70, 18, 14) : COL(16, 50, 32));
    txt(&FONT_B, tx_armed ? "TX ARMED" : "READ-ONLY", 1155, 590, tx_armed ? RED : GREEN, A_C);
    txt(&FONT_XS, tx_armed ? "adapter in normal mode (O)" : "adapter listen-only (L)", 1155, 616, DIM, A_C);
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
    for (int i = 0; i < ((src == SRC_SIM || ramn_mode) ? 6 : 5); i++) txt(&FONT_S, hn[i], hx[i], 68, DIM, A_TL);
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
                if (ramn_mode && e->len == 8 && e->crc_ok > 0 && i >= 2) col = i < 4 ? COL(60, 140, 180) : LINE;  // counter / CRC32
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
        else if (ramn_mode) txt(&FONT_XS, ramn_name(e->id), 748, y + 6, e->crc_ok ? DIM : LINE, A_TL);
    }
    if (ramn_mode && nids > 0) {
        txt(&FONT_XS, "RAMN framing: bytes 0-1 signal (red = changing) | 2-3 freshness counter | 4-7 CRC32", 24, 656, COL(60, 140, 180), A_TL);
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
    else if (ramn_mode) txt(&FONT_XS, ramn_name(e->id), 1066, 100, DIM, A_TL);
    snprintf(buf, sizeof(buf), "%d Hz   %d bytes", rate_get(&e->rate, t), e->len);
    txt(&FONT_M, buf, 918, 132, DIM, A_TL);
    if (src == SRC_USB && e->len == 8 && e->crc_ok > 0) {
        snprintf(buf, sizeof(buf), "ctr %u  CRC32 %s", (unsigned)e->ctr_last, e->crc_bad ? "ok/bad" : "valid");
        txt(&FONT_S, buf, 918, 166, GREEN, A_TL);
    } else
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
    if (src == SRC_SIM) {
        int ce = rate_get(&ctr_rate, t);
        snprintf(buf, sizeof(buf), "0x1A0 ctr err %d/s | SecOC %s | MAC fails %u", ce, secoc_on ? "ON" : "OFF", (unsigned)mac_fail_total);
        txt(&FONT_S, buf, 680, 612, ce > 5 || rate_get(&mac_fail, t) ? RED : DIM, A_TL);
    } else {
        txt(&FONT_S, "Checks: rate baseline + RAMN counter + CRC32", 680, 612, DIM, A_TL);
    }
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

static void draw_ecu(double t) {
    char buf[128];
    if (src != SRC_USB) {
        gfx_rrect(C, 12, 70, W - 24, 576, 12, PANEL);
        txt(&FONT_MID, "ECU TOOLS - plug in a RAMN", W / 2, 200, FG, A_C);
        static const char *l[] = {"UDS diagnostics over ISO-TP: TesterPresent, Read VIN / build date, ECU reset",
                                  "ECU power control through RAMN's USB command set",
                                  "JOY-CON TAKEOVER: power off ECU B + C, then impersonate all 8 of their",
                                  "messages at their exact periods, with continued freshness counters and",
                                  "valid CRC32 - your sticks become the steering wheel and pedals."};
        for (int i = 0; i < 5; i++) txt(&FONT_M, l[i], W / 2, 270 + i * 34, i >= 2 ? AMBER : DIM, A_C);
        return;
    }
    // --- ECU cards
    for (int e = 0; e < 3; e++) {
        int y = 70 + e * 160;
        Rect card = {12, y, 410, 150};
        bool sel = e == ecu_sel && !tko_on;
        gfx_rrect(C, card.x, card.y, card.w, card.h, 12, PANEL);
        if (sel) gfx_rrect_line(C, card.x, card.y, card.w, card.h, 12, 2, CYAN);
        hit_add(card, HT_ECU, (uint32_t)e, 0);
        snprintf(buf, sizeof(buf), "ECU %c", ECU_LETTER[e]);
        txt(&FONT_MID, buf, 28, y + 10, FG, A_TL);
        txt(&FONT_XS, ECU_ROLE[e], 28, y + 46, DIM, A_TL);
        bool alive = t - ecu_alive_t[e] < 30;
        // is the ECU itself talking? (its own messages, not ours)
        static const uint32_t probe[3] = {R_CTL_STEER, R_CTL_ACCEL, R_CTL_KEY};
        IdInfo *pe = find_id(probe[e]);
        bool talking = pe && t - pe->last_ext < 0.5;
        snprintf(buf, sizeof(buf), "power %s", ecu_power[e] ? "ON" : "OFF");
        txt(&FONT_S, buf, 160, y + 14, ecu_power[e] ? GREEN : RED, A_TL);
        txt(&FONT_S, talking ? "on bus" : "silent", 300, y + 14, talking ? GREEN : AMBER, A_TL);
        txt(&FONT_XS, alive ? "UDS: answered" : "UDS: not pinged yet", 28, y + 64, alive ? GREEN : DIM, A_TL);
        if (ecu_info[e][0]) txt(&FONT_XS, ecu_info[e], 180, y + 64, FG, A_TL);
        static const char *bl[4] = {"PING [A]", "INFO [Y]", "RESET [X]", "POWER [ZR]"};
        static const uint32_t bb[4] = {B_A, B_Y, B_X, B_ZR};
        for (int k = 0; k < 4; k++) {
            Rect r = {24 + k * 98, y + 92, 92, 44};
            gfx_rrect(C, r.x, r.y, r.w, r.h, 8, PANEL2);
            gfx_rrect_line(C, r.x, r.y, r.w, r.h, 8, 1, k == 2 || k == 3 ? RED : LINE);
            txt(&FONT_XS, bl[k], r.x + r.w / 2, r.y + 22, FG, A_C);
            hit_add(r, HT_ECU, (uint32_t)e, bb[k]);
        }
    }
    Rect rs = {12, 552, 410, 48};
    gfx_rrect(C, rs.x, rs.y, rs.w, rs.h, 10, COL(16, 50, 32));
    txt(&FONT_B, "RESTORE ALL (Y1) [ZL]", rs.x + rs.w / 2, rs.y + 24, GREEN, A_C);
    hit_add(rs, HT_TAP, B_ZL, 0);

    // --- takeover panel
    Rect tp = {434, 70, 420, 530};
    gfx_rrect(C, tp.x, tp.y, tp.w, tp.h, 12, tko_on ? COL(48, 14, 12) : PANEL);
    if (tko_on) gfx_rrect_line(C, tp.x, tp.y, tp.w, tp.h, 12, 3, ((int)(t * 3)) % 2 ? RED : AMBER);
    txt(&FONT_B, "JOY-CON TAKEOVER", tp.x + 18, tp.y + 14, tko_on ? RED : FG, A_TL);
    txt(&FONT_XS, "masquerade ECU B + C (8 message IDs)", tp.x + 18, tp.y + 44, DIM, A_TL);
    static const char *steps[3] = {"1 power off ECU B + C (yB0 yC0)", "2 send their 8 IDs at exact periods",
                                   "3 continue each counter + valid CRC32"};
    for (int i = 0; i < 3; i++) txt(&FONT_S, steps[i], tp.x + 18, tp.y + 70 + i * 24, tko_on ? AMBER : DIM, A_TL);
    IdInfo *eb = find_id(R_CTL_STEER), *ec = find_id(R_CTL_ACCEL);
    bool bs = !eb || t - eb->last_ext > 0.3, cs = !ec || t - ec->last_ext > 0.3;
    if (tko_on) {
        snprintf(buf, sizeof(buf), "ECU B %s   ECU C %s", bs ? "silent OK" : "STILL TALKING", cs ? "silent OK" : "STILL TALKING");
        txt(&FONT_S, buf, tp.x + 18, tp.y + 150, bs && cs ? GREEN : RED, A_TL);
        // live controls
        float fa = tko_accel / 4095.0f, fb = tko_brake / 4095.0f;
        gfx_rrect(C, tp.x + 18, tp.y + 180, 60, 166, 8, PANEL2);
        if (fa > 0) gfx_rrect(C, tp.x + 22, tp.y + 342 - (int)(158 * fa), 52, (int)(158 * fa), 6, GREEN);
        txt(&FONT_XS, "ACCEL", tp.x + 48, tp.y + 352, FG, A_TC);
        gfx_rrect(C, tp.x + 90, tp.y + 180, 60, 166, 8, PANEL2);
        if (fb > 0) gfx_rrect(C, tp.x + 94, tp.y + 342 - (int)(158 * fb), 52, (int)(158 * fb), 6, RED);
        txt(&FONT_XS, "BRAKE", tp.x + 120, tp.y + 352, FG, A_TC);
        float a = ((float)tko_steer - 2047.0f) / 2047.0f * 2.356f;
        float wx = tp.x + 290, wy = tp.y + 262;
        gfx_ring(C, wx, wy, 80, 66, COL(70, 76, 92));
        gfx_line(C, wx, wy, wx + cosf(a + 3.14159f) * 68, wy + sinf(a + 3.14159f) * 68, 11, COL(70, 76, 92));
        gfx_line(C, wx, wy, wx + cosf(a) * 68, wy + sinf(a) * 68, 11, COL(70, 76, 92));
        gfx_circle(C, wx + cosf(a - 1.5708f) * 73, wy + sinf(a - 1.5708f) * 73, 7, RED);
        snprintf(buf, sizeof(buf), "steer %u", (unsigned)tko_steer);
        txt(&FONT_XS, buf, (int)wx, (int)wy + 90, FG, A_TC);
        static const char *bn[4] = {"off", "LEFT", "RIGHT", "HAZARD"};
        snprintf(buf, sizeof(buf), "GEAR %d   BLINK %s   HORN %s", tko_gear, bn[tko_blink], tko_horn ? "ON" : "off");
        txt(&FONT_S, buf, tp.x + 18, tp.y + 376, FG, A_TL);
        int na = nalerts - tko_alerts0;
        snprintf(buf, sizeof(buf), "%.0fs | IDS alerts since start: %d", t - tko_t0, na < 0 ? 0 : na);
        txt(&FONT_S, buf, tp.x + 18, tp.y + 402, na > 0 ? AMBER : GREEN, A_TL);
        txt(&FONT_XS, "L-stick gas | ZL brake | R-stick steer | Up/Dn gear", tp.x + 18, tp.y + 428, DIM, A_TL);
        txt(&FONT_XS, "Left/Right blinker | Y hazard | A horn | B stop", tp.x + 18, tp.y + 444, DIM, A_TL);
    } else {
        static const char *why[] = {"Why it matters:", "a rate IDS sees normal periods,", "a counter check sees perfect sequences,",
                                    "a CRC check sees valid CRCs.", "Only authentication (SecOC) or", "ECU-silence monitoring catch it.",
                                    "", "Requires TX armed (hold + 2 s)."};
        for (int i = 0; i < 8; i++) txt(&FONT_S, why[i], tp.x + 18, tp.y + 160 + i * 26, i == 0 ? FG : (i == 7 ? AMBER : DIM), A_TL);
    }
    Rect tb = {tp.x + 18, tp.y + tp.h - 70, tp.w - 36, 56};
    gfx_rrect(C, tb.x, tb.y, tb.w, tb.h, 12, tko_on ? RED : COL(70, 18, 14));
    txt(&FONT_B, tko_on ? "STOP TAKEOVER [B]" : "START TAKEOVER [B]", tb.x + tb.w / 2, tb.y + 28, WHITE, A_C);
    hit_add(tb, HT_TAP, B_B, 0);

    // --- UDS log
    Rect lp = {866, 70, 398, 530};
    gfx_rrect(C, lp.x, lp.y, lp.w, lp.h, 12, PANEL);
    txt(&FONT_B, "UDS / COMMAND LOG", lp.x + 16, lp.y + 14, FG, A_TL);
    for (int i = 0; i < nulog; i++) txt(&FONT_XS, ulog[i].s, lp.x + 14, lp.y + 50 + i * 33, ulog[i].col, A_TL);
    if (!nulog) txt(&FONT_XS, "Arm TX (+ 2 s), select an ECU, press A to ping.", lp.x + 14, lp.y + 50, DIM, A_TL);
    if (uds_wait) txt(&FONT_XS, "waiting for reply...", lp.x + 14, lp.y + lp.h - 24, AMBER, A_TL);
}

static void draw_footer(void) {
    gfx_fill(C, 0, H - 34, W, 34, PANEL);
    const char *hint;
    if (attract_on) hint = "DEMO MODE - touch anything or press a button to take control";
    else if (tab == TAB_CLUSTER && src == SRC_USB && ramn_mode)
        hint = "A hazards | B check-engine | Y high beam | Up park brake | ZR override pin | + hold 2s arm TX | X IDS";
    else if (tab == TAB_CLUSTER)
        hint = src == SRC_SIM ? "Stick gas | ZR spoof | ZL redline | A doors | B warn | Up attack level | Down SecOC | X IDS"
                              : "Pin a signal in SNIFFER | ZR/ZL override it (TX armed) | + hold 2s arm TX | X IDS";
    else if (tab == TAB_SNIFF) hint = "Up/Down ID | Left/Right byte | A pin to gauge | B clear | Y fuzz | L/R tabs | - help";
    else if (tab == TAB_IDS) hint = "X IDS on/off | A re-learn baseline | B clear alerts | L/R tabs | - help";
    else if (tab == TAB_ECU && tko_on) hint = "TAKEOVER: L-stick gas | ZL brake | R-stick steer | Up/Dn gear | </> blink | Y hazard | A horn | B stop";
    else if (tab == TAB_ECU) hint = "Up/Dn ECU | A ping | Y read VIN+date | X reset | ZR power | B TAKEOVER | ZL restore | + arm";
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
                                 {"Touchscreen", "tabs, buttons, rows"}, {"USB-C", "RAMN/CANable: slcan, gs_usb"}};
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
    ramn_mode = false;
    tko_on = false;
    uds_wait = false;
    uq_n = 0;
    for (int i = 0; i < 3; i++) { ecu_power[i] = true; ecu_alive_t[i] = -100; ecu_info[i][0] = 0; }
    if (s == SRC_USB) {
        tx_armed = false;
        plat_usb_set_tx(false);
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
            if (!tx_armed) { atk_clear(); if (tko_on) tko_stop(t); }
            plat_usb_set_tx(tx_armed);
            plat_rumble(0.6f, 150);
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
    if (tko_on) {
        float g = in->stick_y > 0.08f ? in->stick_y : 0;
        tko_accel = (uint16_t)(g > 1 ? 4095 : g * 4095);
        float br = (held_bits & B_ZL) ? 1.0f : (in->stick_y < -0.2f ? -in->stick_y : 0);
        tko_brake = (uint16_t)(br > 1 ? 4095 : br * 4095);
        float sx = in->rstick_x;
        if (sx > 1) sx = 1;
        if (sx < -1) sx = -1;
        if (fabsf(sx) < 0.06f) sx = 0;
        tko_steer = (uint16_t)(2047 + sx * 2047);
    }
    tko_tick(t);
    uds_tick(t);
    atk_tick(t, dt);
    ids_eval(t);
    if (!have_sel && nids) { sel_id = ids[0].id; have_sel = true; }
    if (src == SRC_USB && !ramn_mode) {
        static const uint32_t sig[8] = {R_CTL_BRAKE, R_CTL_ACCEL, R_CTL_STEER, R_CTL_SHIFT, R_CMD_LIGHTS, R_CMD_TURN, R_CTL_KEY, R_CTL_LIGHTS};
        int hits_n = 0;
        for (int i = 0; i < 8; i++) {
            IdInfo *e = find_id(sig[i]);
            if (e && e->count > 5) hits_n++;
        }
        if (hits_n >= 3) {
            ramn_mode = true;
            plat_log("RAMN detected (%d signature IDs)", hits_n);
            toast(t, "RAMN detected! CLUSTER is now a live RAMN dashboard (signals from Toyota's DBC)");
            plat_rumble(0.5f, 120);
        }
    }
    static bool first = true;
    if (first) {
        first = false;
        plat_log("first frame ok");
        if (plat_safe_mode()) toast(t, "SAFE MODE: USB, NFC and IR disabled (launched holding ZL)");
    }

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
        case TAB_CLUSTER:
            if (src == SRC_USB && ramn_mode) draw_ramn(t);
            else draw_cluster(t);
            break;
        case TAB_SNIFF: draw_sniffer(t); break;
        case TAB_IDS: draw_ids(t); break;
        case TAB_ECU: draw_ecu(t); break;
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
