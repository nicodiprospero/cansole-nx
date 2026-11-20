// CANsole NX - Nintendo Switch platform layer (libnx)
//   framebuffer + Joy-Con/touch input, USB-CAN (slcan over CDC-ACM via usb:hs),
//   Joy-Con NFC (nfc:user) and Joy-Con IR camera (irs).
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <switch.h>

#include "app.h"
#include "slcan.h"

static PadState g_pad;
static bool g_safe_mode;
static u64 g_t0;

// ================================================================ boot log
// Every line goes to sdmc:/switch/cansole-nx/boot.log AND to an in-memory ring that the SYSTEM tab
// shows. At startup the tail of the previous session is loaded too, so a crash/reboot cause is
// visible on the console itself.
#define LOG_PATH "sdmc:/switch/cansole-nx/boot.log"
#define LOG_RING 240
static Mutex log_mtx;
static FILE *bootlog;
static char log_ring[LOG_RING][112];
static int log_n, log_head;  // count kept, index of the oldest
static int prev_clean = -1;  // -1 no previous session, 0 ended without "clean exit", 1 clean
static void ring_push(const char *line) {
    int idx = (log_head + log_n) % LOG_RING;
    if (log_n == LOG_RING) log_head = (log_head + 1) % LOG_RING;
    else log_n++;
    snprintf(log_ring[idx], sizeof(log_ring[idx]), "%s", line);
}
void plat_log(const char *fmt, ...) {
    char line[112], msg[100];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    snprintf(line, sizeof(line), "[%8.3f] %s", armTicksToNs(armGetSystemTick() - g_t0) / 1e9, msg);
    mutexLock(&log_mtx);
    if (!bootlog) {
        mkdir("sdmc:/switch", 0777);
        mkdir("sdmc:/switch/cansole-nx", 0777);
        bootlog = fopen(LOG_PATH, "a");
    }
    if (bootlog) {
        fputs(line, bootlog);
        fputc('\n', bootlog);
        fflush(bootlog);
    }
    ring_push(line);
    mutexUnlock(&log_mtx);
}
int plat_log_count(void) { return log_n; }
const char *plat_log_line(int i) {
    if (i < 0 || i >= log_n) return "";
    return log_ring[(log_head + i) % LOG_RING];
}
int plat_prev_session_clean(void) { return prev_clean; }

// Load the last session's lines (after the final "---- CANsole NX" marker) into the ring.
static void log_load_previous(void) {
    FILE *f = fopen(LOG_PATH, "r");
    if (!f) return;
    static char tail[48][112];
    int tn = 0, th = 0;
    bool seen = false, clean = false;
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        buf[strcspn(buf, "\r\n")] = 0;
        if (strstr(buf, "---- CANsole NX")) { tn = 0; th = 0; seen = true; clean = false; }
        if (strstr(buf, "clean exit")) clean = true;
        int idx = (th + tn) % 48;
        if (tn == 48) th = (th + 1) % 48;
        else tn++;
        snprintf(tail[idx], sizeof(tail[idx]), "prev %.100s", buf);
    }
    long size = ftell(f);
    fclose(f);
    if (!seen) return;
    prev_clean = clean ? 1 : 0;
    for (int i = 0; i < tn; i++) ring_push(tail[(th + i) % 48]);
    ring_push(clean ? "prev ===== previous session: CLEAN EXIT =====" : "prev ===== previous session: NO clean exit (last line above) =====");
    if (size > 256 * 1024) rename(LOG_PATH, "sdmc:/switch/cansole-nx/boot.old.log");  // keep the file small
}
bool plat_safe_mode(void) { return g_safe_mode; }

// ================================================================== rumble
static HidVibrationDeviceHandle vib_hh[2], vib_p1[2];
static bool vib_ok_hh, vib_ok_p1;
static u64 vib_stop;
static void rumble_send(float amp) {
    HidVibrationValue v[2];
    for (int i = 0; i < 2; i++) {
        v[i].amp_low = amp;
        v[i].freq_low = 160.0f;
        v[i].amp_high = amp;
        v[i].freq_high = 320.0f;
    }
    if (vib_ok_hh) hidSendVibrationValues(vib_hh, v, 2);
    if (vib_ok_p1) hidSendVibrationValues(vib_p1, v, 2);
}
void plat_rumble(float amp, int ms) {
    if (amp > 1) amp = 1;
    rumble_send(amp);
    vib_stop = armGetSystemTick() + armNsToTicks((u64)ms * 1000000ULL);
}
static void rumble_init(void) {
    vib_ok_hh = R_SUCCEEDED(hidInitializeVibrationDevices(vib_hh, 2, HidNpadIdType_Handheld, HidNpadStyleTag_NpadHandheld));
    vib_ok_p1 = R_SUCCEEDED(hidInitializeVibrationDevices(vib_p1, 2, HidNpadIdType_No1, HidNpadStyleTag_NpadJoyDual));
    plat_log("rumble handheld=%d p1=%d", vib_ok_hh, vib_ok_p1);
}
static void rumble_poll(void) {
    if (vib_stop && armGetSystemTick() >= vib_stop) {
        rumble_send(0);
        vib_stop = 0;
    }
}

// =================================================================== USB-CAN
// Two drivers on top of usb:hs:
//   1) slcan over CDC-ACM (RAMN ECU A 0483:5740, CANable slcan firmware)  <- primary
//   2) gs_usb / candleLight (1d50:606f)                                    <- fallback
// Safety: opened LISTEN-ONLY; normal mode only after the user arms TX.
// Robustness: auto-bitrate search (listen-only, so harmless), reopen watchdog if the stream stops.
#define RXQ 4096
enum { KIND_NONE, KIND_SLCAN, KIND_GSUSB };
static Mutex usb_mtx;
static CanFrame rxq[RXQ];
static int rxq_head, rxq_tail;
static char txq[8192];
static int txq_len;
static CanFrame gs_txq[256];
static int gs_txq_n;
static volatile int usb_state_v = USB_OFF;
static char usb_label_s[64] = "USB: off";
static Thread usb_thread;
static volatile bool usb_run;
static bool usb_hs_up;
static bool usb_thread_ok;
static UsbHsClientIfSession if_sess;
static UsbHsClientEpSession ep_in, ep_out;
static bool have_if, have_in, have_out;
static u8 *usb_inbuf, *usb_outbuf, *usb_ctrlbuf;
static SlcanParser slp;
static volatile int usb_mode_req;  // 0 none, 1 listen-only, 2 normal (TX)
static int usb_kind, usb_cur_mode = 1;
static u16 usb_vid, usb_pid, usb_ifnum;
static const int BR_CODES[6] = {6, 8, 5, 4, 7, 3};
static const int BR_KBPS[6] = {500, 1000, 250, 125, 800, 100};
static int br_idx;
static u64 last_rx_tick;
static bool ever_rx;
static u32 gs_echo;
static bool listen_fallback;  // adapter seems to ignore listen-only: open normally (UI still blocks TX until armed)

static void set_label(const char *s) {
    mutexLock(&usb_mtx);
    snprintf(usb_label_s, sizeof(usb_label_s), "%s", s);
    mutexUnlock(&usb_mtx);
}

static void update_label(void) {
    char lab[64];
    if (usb_kind == KIND_SLCAN)
        snprintf(lab, sizeof(lab), "%04X:%04X slcan %dk%s", usb_vid, usb_pid, BR_KBPS[br_idx], ever_rx ? "" : "?");
    else
        snprintf(lab, sizeof(lab), "%04X:%04X gs_usb %dk%s", usb_vid, usb_pid, BR_KBPS[br_idx], ever_rx ? "" : "?");
    set_label(lab);
}

static void usb_close_dev(void) {
    if (have_in) usbHsEpClose(&ep_in);
    if (have_out) usbHsEpClose(&ep_out);
    if (have_if) usbHsIfClose(&if_sess);
    have_in = have_out = have_if = false;
    usb_kind = KIND_NONE;
}

static bool usb_write(const void *s, int n) {
    if (!have_out || n <= 0) return false;
    const u8 *p = (const u8 *)s;
    while (n > 0) {
        int chunk = n > 0x1000 ? 0x1000 : n;
        memcpy(usb_outbuf, p, (size_t)chunk);
        u32 xfer = 0;
        if (R_FAILED(usbHsEpPostBuffer(&ep_out, usb_outbuf, (u32)chunk, &xfer))) return false;
        p += chunk;
        n -= chunk;
    }
    return true;
}

static void push_rx(const CanFrame *f, int n) {
    mutexLock(&usb_mtx);
    for (int i = 0; i < n; i++) {
        int nx = (rxq_head + 1) % RXQ;
        if (nx == rxq_tail) break;  // full: drop
        rxq[rxq_head] = f[i];
        rxq_head = nx;
    }
    mutexUnlock(&usb_mtx);
}

static bool open_bulk_eps(void) {
    for (int i = 0; i < 15; i++) {
        struct usb_endpoint_descriptor *d = &if_sess.inf.inf.input_endpoint_descs[i];
        if (!have_in && d->bLength && (d->bmAttributes & 3) == 2 && R_SUCCEEDED(usbHsIfOpenUsbEp(&if_sess, &ep_in, 1, 0x1000, d)))
            have_in = true;
        d = &if_sess.inf.inf.output_endpoint_descs[i];
        if (!have_out && d->bLength && (d->bmAttributes & 3) == 2 && R_SUCCEEDED(usbHsIfOpenUsbEp(&if_sess, &ep_out, 1, 0x1000, d)))
            have_out = true;
    }
    return have_in && have_out;
}

// ---- slcan
static void slcan_open_cmd(int mode) {
    char cmd[32];
    int eff = (mode == 1 && listen_fallback) ? 2 : mode;
    snprintf(cmd, sizeof(cmd), "\rC\rS%d\r%c\r", BR_CODES[br_idx], eff == 2 ? 'O' : 'L');
    usb_write(cmd, (int)strlen(cmd));
    usb_cur_mode = mode;
}

static bool try_slcan(void) {
    UsbHsInterfaceFilter filter;
    memset(&filter, 0, sizeof(filter));
    filter.Flags = UsbHsInterfaceFilterFlags_bInterfaceClass;
    filter.bInterfaceClass = 0x0A;  // CDC data
    static UsbHsInterface ifs[8];
    s32 total = 0;
    if (R_FAILED(usbHsQueryAvailableInterfaces(&filter, ifs, sizeof(ifs), &total)) || total <= 0) return false;
    if (R_FAILED(usbHsAcquireUsbIf(&if_sess, &ifs[0]))) return false;
    have_if = true;
    if (!open_bulk_eps()) { usb_close_dev(); return false; }
    usb_vid = ifs[0].device_desc.idVendor;
    usb_pid = ifs[0].device_desc.idProduct;
    usb_ifnum = if_sess.inf.inf.interface_desc.bInterfaceNumber;
    u16 ctrl_if = usb_ifnum ? usb_ifnum - 1 : 0;
    u8 *lc = usb_ctrlbuf;
    memset(lc, 0, 0x40);
    lc[0] = 0x00; lc[1] = 0xC2; lc[2] = 0x01; lc[3] = 0x00;  // 115200 8N1
    lc[6] = 8;
    u32 xfer = 0;
    Result r1 = usbHsIfCtrlXfer(&if_sess, 0x21, 0x20, 0, ctrl_if, 7, lc, &xfer);
    Result r2 = usbHsIfCtrlXfer(&if_sess, 0x21, 0x22, 0x03, ctrl_if, 0, lc, &xfer);  // DTR | RTS
    usb_kind = KIND_SLCAN;
    memset(&slp, 0, sizeof(slp));
    usb_write("\r\r\r", 3);
    slcan_open_cmd(1);
    plat_log("usb: slcan %04X:%04X if=%d ctrl_if=%d linecoding=0x%X dtr=0x%X -> listen-only %dk", usb_vid, usb_pid, usb_ifnum, ctrl_if,
             (unsigned)r1, (unsigned)r2, BR_KBPS[br_idx]);
    return true;
}

// ---- gs_usb (candleLight)
typedef struct { u32 echo_id, can_id; u8 can_dlc, channel, flags, reserved; u8 data[8]; } __attribute__((packed)) GsFrame;

static Result gs_ctrl_out(u8 req, u16 value, const void *data, u16 len) {
    memcpy(usb_ctrlbuf, data, len);
    u32 xfer = 0;
    return usbHsIfCtrlXfer(&if_sess, 0x41, req, value, usb_ifnum, len, usb_ctrlbuf, &xfer);
}

static void gs_set_mode(int mode) {
    u32 reset[2] = {0, 0};
    gs_ctrl_out(2, 0, reset, 8);
    // bit timing: find tq count 8..25 that divides the CAN clock exactly
    u32 fclk = 48000000;
    u32 xfer = 0;
    memset(usb_ctrlbuf, 0, 64);
    if (R_SUCCEEDED(usbHsIfCtrlXfer(&if_sess, 0xC1, 4, 0, usb_ifnum, 40, usb_ctrlbuf, &xfer)) && xfer >= 8) {
        u32 v;
        memcpy(&v, usb_ctrlbuf + 4, 4);
        if (v) fclk = v;
    }
    u32 rate = (u32)BR_KBPS[br_idx] * 1000, tq = 16, brp = fclk / (rate * 16);
    for (u32 q = 16; q >= 8; q--)
        if (fclk % (rate * q) == 0) { tq = q; brp = fclk / (rate * q); break; }
    u32 seg2 = tq / 8 > 1 ? tq / 8 : 2;  // ~87.5% sample point
    u32 bt[5] = {1, tq - 1 - 1 - seg2, seg2, 1, brp ? brp : 1};  // prop, phase1, phase2, sjw, brp
    gs_ctrl_out(1, 0, bt, 20);
    u32 start[2] = {1, (mode == 2 || listen_fallback) ? 0u : 1u};  // start, flags: LISTEN_ONLY
    Result rc = gs_ctrl_out(2, 0, start, 8);
    usb_cur_mode = mode;
    plat_log("usb: gs_usb fclk=%u tq=%u brp=%u %dk mode=%s rc=0x%X", (unsigned)fclk, (unsigned)tq, (unsigned)brp, BR_KBPS[br_idx],
             mode == 2 ? "normal" : "listen", (unsigned)rc);
}

static bool try_gsusb(void) {
    UsbHsInterfaceFilter filter;
    memset(&filter, 0, sizeof(filter));
    filter.Flags = UsbHsInterfaceFilterFlags_idVendor | UsbHsInterfaceFilterFlags_idProduct;
    filter.idVendor = 0x1D50;
    filter.idProduct = 0x606F;
    static UsbHsInterface ifs[4];
    s32 total = 0;
    if (R_FAILED(usbHsQueryAvailableInterfaces(&filter, ifs, sizeof(ifs), &total)) || total <= 0) return false;
    if (R_FAILED(usbHsAcquireUsbIf(&if_sess, &ifs[0]))) return false;
    have_if = true;
    if (!open_bulk_eps()) { usb_close_dev(); return false; }
    usb_vid = ifs[0].device_desc.idVendor;
    usb_pid = ifs[0].device_desc.idProduct;
    usb_ifnum = if_sess.inf.inf.interface_desc.bInterfaceNumber;
    u32 fmt = 0x0000BEEF;
    gs_ctrl_out(0, 1, &fmt, 4);  // HOST_FORMAT
    usb_kind = KIND_GSUSB;
    gs_set_mode(1);
    return true;
}

static void gs_parse(const u8 *buf, u32 n) {
    CanFrame tmp[64];
    int got = 0;
    for (u32 o = 0; o + sizeof(GsFrame) <= n && got < 64; o += sizeof(GsFrame)) {
        GsFrame g;
        memcpy(&g, buf + o, sizeof(g));
        if (g.echo_id != 0xFFFFFFFFu) continue;           // echo of our own TX
        if (g.can_id & 0x60000000u) continue;            // RTR / error frames
        CanFrame f;
        memset(&f, 0, sizeof(f));
        f.ext = (g.can_id & 0x80000000u) ? 1 : 0;
        f.id = g.can_id & (f.ext ? 0x1FFFFFFFu : 0x7FFu);
        f.len = g.can_dlc > 8 ? 8 : g.can_dlc;
        memcpy(f.data, g.data, 8);
        tmp[got++] = f;
    }
    if (got) push_rx(tmp, got);
}

static bool usb_still_there(void) {
    static UsbHsInterface acq[8];
    s32 total = 0;
    if (R_FAILED(usbHsQueryAcquiredInterfaces(acq, sizeof(acq), &total))) return false;
    return total > 0;
}

static void usb_reopen(void) {
    if (usb_kind == KIND_SLCAN) slcan_open_cmd(usb_cur_mode);
    else if (usb_kind == KIND_GSUSB) gs_set_mode(usb_cur_mode);
}

static void usb_main(void *arg) {
    (void)arg;
    bool posted = false;
    u64 last_check = armGetSystemTick();
    int fails = 0;
    while (usb_run) {
        if (!have_if) {
            usb_state_v = USB_SEARCHING;
            set_label("plug RAMN/CANable");
            if (!try_slcan() && !try_gsusb()) {
                svcSleepThread(500000000ULL);
                continue;
            }
            usb_state_v = USB_CONNECTED;
            posted = false;
            fails = 0;
            ever_rx = false;
            listen_fallback = false;
            last_rx_tick = armGetSystemTick();
            update_label();
        }
        // adapter mode change (listen-only <-> normal)
        int req = usb_mode_req;
        if (req) {
            usb_mode_req = 0;
            if (usb_kind == KIND_SLCAN) slcan_open_cmd(req);
            else gs_set_mode(req);
            plat_log("usb: mode %s", req == 2 ? "NORMAL (TX armed)" : "LISTEN-ONLY");
        }
        // flush pending TX
        mutexLock(&usb_mtx);
        static char out[sizeof(txq)];
        static CanFrame gsout[256];
        int n = txq_len, gn = gs_txq_n;
        if (n) memcpy(out, txq, (size_t)n);
        if (gn) memcpy(gsout, gs_txq, sizeof(CanFrame) * (size_t)gn);
        txq_len = 0;
        gs_txq_n = 0;
        mutexUnlock(&usb_mtx);
        if (n && !usb_write(out, n)) fails++;
        for (int i = 0; i < gn; i++) {
            GsFrame g;
            memset(&g, 0, sizeof(g));
            g.echo_id = gs_echo++ % 8;
            g.can_id = gsout[i].id | (gsout[i].ext ? 0x80000000u : 0);
            g.can_dlc = gsout[i].len;
            memcpy(g.data, gsout[i].data, 8);
            if (!usb_write(&g, sizeof(g))) fails++;
        }
        // RX
        if (!posted) {
            u32 xid = 0;
            if (R_SUCCEEDED(usbHsEpPostBufferAsync(&ep_in, usb_inbuf, 0x1000, 0, &xid))) posted = true;
            else fails++;
        }
        if (posted) {
            Event *ev = usbHsEpGetXferEvent(&ep_in);
            if (R_SUCCEEDED(eventWait(ev, 10000000ULL))) {
                eventClear(ev);
                UsbHsXferReport rep;
                u32 cnt = 0;
                memset(&rep, 0, sizeof(rep));
                posted = false;
                if (R_SUCCEEDED(usbHsEpGetXferReport(&ep_in, &rep, 1, &cnt)) && cnt > 0 && R_SUCCEEDED(rep.res)) {
                    if (usb_kind == KIND_SLCAN) {
                        CanFrame tmp[128];
                        int got = slcan_feed(&slp, usb_inbuf, (int)rep.transferredSize, tmp, 128);
                        if (got) {
                            push_rx(tmp, got);
                            last_rx_tick = armGetSystemTick();
                            if (!ever_rx) { ever_rx = true; update_label(); plat_log("usb: frames flowing at %dk", BR_KBPS[br_idx]); }
                        }
                    } else {
                        if (rep.transferredSize >= sizeof(GsFrame)) {
                            gs_parse(usb_inbuf, rep.transferredSize);
                            last_rx_tick = armGetSystemTick();
                            if (!ever_rx) { ever_rx = true; update_label(); plat_log("usb: gs_usb frames flowing"); }
                        }
                    }
                    fails = 0;
                } else {
                    fails++;
                }
            }
        } else {
            svcSleepThread(10000000ULL);
        }
        u64 nowt = armGetSystemTick();
        // silent bus: never got a frame -> try the next bitrate (listen-only, so it cannot disturb the bus);
        // got frames before -> the adapter probably closed the channel (RAMN does on USB overflow): reopen.
        if (armTicksToNs(nowt - last_rx_tick) > 2500000000ULL) {
            last_rx_tick = nowt;
            if (!ever_rx && usb_cur_mode == 1) {
                br_idx = (br_idx + 1) % 6;
                if (br_idx == 0) {
                    listen_fallback = !listen_fallback;
                    plat_log("usb: full bitrate cycle silent, listen-only fallback=%d", listen_fallback);
                }
                plat_log("usb: no frames, trying %dk", BR_KBPS[br_idx]);
            } else {
                plat_log("usb: stream stopped, reopening at %dk", BR_KBPS[br_idx]);
            }
            usb_reopen();
            update_label();
        }
        // disconnect detection
        if (fails > 20 || armTicksToNs(nowt - last_check) > 1000000000ULL) {
            last_check = nowt;
            if (fails > 20 || !usb_still_there()) {
                plat_log("usb: device lost (fails=%d)", fails);
                usb_close_dev();
                usb_state_v = USB_SEARCHING;
                posted = false;
                fails = 0;
                svcSleepThread(300000000ULL);
            }
        }
    }
    usb_close_dev();
}

void plat_usb_set_tx(bool enable) { usb_mode_req = enable ? 2 : 1; }

bool plat_usb_raw(const char *cmd) {
    if (usb_state_v != USB_CONNECTED || usb_kind != KIND_SLCAN) return false;
    int n = (int)strlen(cmd);
    bool ok = false;
    mutexLock(&usb_mtx);
    if (txq_len + n < (int)sizeof(txq)) {
        memcpy(txq + txq_len, cmd, (size_t)n);
        txq_len += n;
        ok = true;
    }
    mutexUnlock(&usb_mtx);
    plat_log("usb: raw cmd %s", cmd[0] == 'y' || cmd[0] == 'Y' ? cmd : "(other)");
    return ok;
}

static void usb_start(void) {
    mutexInit(&usb_mtx);
    if (g_safe_mode) {
        usb_state_v = USB_OFF;
        snprintf(usb_label_s, sizeof(usb_label_s), "USB off (safe mode)");
        return;
    }
    usb_inbuf = memalign(0x1000, 0x1000);
    usb_outbuf = memalign(0x1000, 0x1000);
    usb_ctrlbuf = memalign(0x1000, 0x1000);
    Result rc = usbHsInitialize();
    plat_log("usbHsInitialize rc=0x%X", (unsigned)rc);
    if (R_SUCCEEDED(rc)) usb_hs_up = true;
    if (R_FAILED(rc) || !usb_inbuf || !usb_outbuf || !usb_ctrlbuf) {
        usb_state_v = USB_ERROR;
        snprintf(usb_label_s, sizeof(usb_label_s), "USB err 0x%X", (unsigned)rc);
        return;
    }
    usb_run = true;
    if (R_SUCCEEDED(threadCreate(&usb_thread, usb_main, NULL, NULL, 0x10000, 0x2C, -2)) && R_SUCCEEDED(threadStart(&usb_thread)))
        usb_thread_ok = true;
    else {
        usb_state_v = USB_ERROR;
        snprintf(usb_label_s, sizeof(usb_label_s), "USB thread failed");
    }
}

static void usb_stop(void) {
    if (usb_thread_ok) {
        usb_run = false;
        plat_log("shutdown: joining usb thread");
        threadWaitForExit(&usb_thread);
        threadClose(&usb_thread);
        usb_thread_ok = false;
    }
    if (usb_hs_up) {
        plat_log("shutdown: usbHsExit");
        usbHsExit();
        usb_hs_up = false;
    }
}

int plat_usb_state(void) { return usb_state_v; }

const char *plat_usb_label(void) {
    static char copy[64];
    mutexLock(&usb_mtx);
    memcpy(copy, usb_label_s, sizeof(copy));
    mutexUnlock(&usb_mtx);
    return copy;
}

int plat_usb_poll(CanFrame *out, int max) {
    int n = 0;
    mutexLock(&usb_mtx);
    while (n < max && rxq_tail != rxq_head) {
        out[n++] = rxq[rxq_tail];
        rxq_tail = (rxq_tail + 1) % RXQ;
    }
    mutexUnlock(&usb_mtx);
    return n;
}

bool plat_usb_send(const CanFrame *f) {
    if (usb_state_v != USB_CONNECTED) return false;
    bool ok = false;
    mutexLock(&usb_mtx);
    if (usb_kind == KIND_GSUSB) {
        if (gs_txq_n < 256) { gs_txq[gs_txq_n++] = *f; ok = true; }
    } else {
        char line[48];
        int n = slcan_encode(f, line);
        if (txq_len + n < (int)sizeof(txq)) {
            memcpy(txq + txq_len, line, (size_t)n);
            txq_len += n;
            ok = true;
        }
    }
    mutexUnlock(&usb_mtx);
    return ok;
}

// ======================================================================= NFC
static bool nfc_inited, nfc_have_dev;
static NfcDeviceHandle nfc_dev;
static NfcInfo nfc_cur;
static int nfc_prev_state = -1;
static u64 nfc_restart_tick, nfc_info_tick;
static bool nfc_info_ok;

void plat_nfc_enable(bool on) {
    if (on && g_safe_mode) {
        nfc_cur.state = NFC_ERROR;
        snprintf(nfc_cur.status, sizeof(nfc_cur.status), "NFC disabled (safe mode)");
        return;
    }
    if (on && !nfc_inited) {
        memset(&nfc_cur, 0, sizeof(nfc_cur));
        Result rc = nfcInitialize(NfcServiceType_User);
        plat_log("nfcInitialize rc=0x%X", (unsigned)rc);
        if (R_FAILED(rc)) {
            nfc_cur.state = NFC_ERROR;
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "NFC service unavailable (0x%X)", (unsigned)rc);
            return;
        }
        nfc_inited = true;
        s32 total = 0;
        rc = nfcListDevices(&total, &nfc_dev, 1);
        if (R_FAILED(rc) || total < 1) {
            nfc_cur.state = NFC_ERROR;
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "No NFC reader found - attach the right Joy-Con");
            return;
        }
        nfc_have_dev = true;
        rc = nfcStartDetection(&nfc_dev, NfcProtocol_All);
        nfc_restart_tick = armGetSystemTick();
        plat_log("nfc: start detection rc=0x%X", (unsigned)rc);
        nfc_cur.state = R_SUCCEEDED(rc) ? NFC_SEARCHING : NFC_ERROR;
        if (R_SUCCEEDED(rc))
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
        else
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Could not start detection (0x%X)", (unsigned)rc);
    } else if (!on && nfc_inited) {
        plat_log("nfc: stop (dev=%d)", nfc_have_dev);
        if (nfc_have_dev) nfcStopDetection(&nfc_dev);
        nfcExit();
        plat_log("nfc: exited");
        nfc_inited = nfc_have_dev = false;
        nfc_prev_state = -1;
    }
}

void plat_nfc_info(NfcInfo *out) {
    if (nfc_inited && nfc_have_dev) {
        NfcDeviceState st;
        if (R_SUCCEEDED(nfcGetDeviceState(&nfc_dev, &st))) {
            if ((int)st != nfc_prev_state) plat_log("nfc: state %d", (int)st);
            if (st == NfcDeviceState_TagFound || st == NfcDeviceState_TagMounted) {
                u64 now = armGetSystemTick();
                if (nfc_prev_state != (int)st) nfc_info_ok = false;
                // read the tag info on arrival, and retry every 200 ms if the first read failed
                if (!nfc_info_ok && (nfc_prev_state != (int)st || armTicksToNs(now - nfc_info_tick) > 200000000ULL)) {
                    nfc_info_tick = now;
                    NfcTagInfo ti;
                    memset(&ti, 0, sizeof(ti));
                    Result irc = nfcGetTagInfo(&nfc_dev, &ti);
                    if (R_FAILED(irc)) {
                        plat_log("nfc: GetTagInfo rc=0x%X", (unsigned)irc);
                        snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Tag seen, info read failed (0x%X) - hold still", (unsigned)irc);
                    } else {
                        nfc_info_ok = true;
                        plat_log("nfc: tag uid_len=%d proto=0x%X type=0x%X", (int)ti.uid.uid_length, (unsigned)ti.protocol, (unsigned)ti.tag_type);
                        int n = ti.uid.uid_length > 10 ? 10 : ti.uid.uid_length;
                        memcpy(nfc_cur.uid, ti.uid.uid, (size_t)n);
                        nfc_cur.uid_len = n;
                        nfc_cur.protocol = ti.protocol;
                        nfc_cur.tag_type = ti.tag_type;
                        nfc_cur.seq++;
                    }
                }
                nfc_cur.state = NFC_TAG;
                if (nfc_info_ok) snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Tag detected");
            } else if (st == NfcDeviceState_TagRemoved || st == NfcDeviceState_Initialized) {
                // Re-arm detection, but never faster than every 1.5 s: the state machine is
                // asynchronous and restarting every frame keeps the reader from ever seeing a tag.
                u64 now = armGetSystemTick();
                if (armTicksToNs(now - nfc_restart_tick) > 1500000000ULL) {
                    nfc_restart_tick = now;
                    if (st == NfcDeviceState_TagRemoved) nfcStopDetection(&nfc_dev);
                    Result rc = nfcStartDetection(&nfc_dev, NfcProtocol_All);
                    plat_log("nfc: re-arm from state %d rc=0x%X", (int)st, (unsigned)rc);
                }
                nfc_cur.state = NFC_SEARCHING;
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
            } else if (st == NfcDeviceState_SearchingForTag) {
                nfc_cur.state = NFC_SEARCHING;
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
            } else {
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Reader state %d", (int)st);
            }
            nfc_prev_state = (int)st;
        }
    }
    *out = nfc_cur;
}

// ======================================================================== IR
// Follows the right Joy-Con: the handheld rail when attached, the wireless player-1 Joy-Con when
// detached. Re-acquires the camera when the Joy-Con is attached/detached mid-session and restarts
// the processor if data stops.
// Modes: 0 SHARP image 160x120, 1 FAST image 80x60, 2 TRACK = clustering processor (the Joy-Con
// finds the bright blobs itself and sends only their positions, so it runs at full camera rate).
static bool ir_inited, ir_running, ir_wireless, ir_have_data;
static int ir_mode, ir_run_mode;
static IrsIrCameraHandle ir_handle;
static HidNpadIdType ir_id;
static u8 *ir_buf;
static int ir_w = 160, ir_h = 120;
static u64 ir_retry_tick, ir_last_new_tick, ir_fps_tick;
static s64 ir_last_sample;
static int ir_fps, ir_fps_n;
static char ir_status[96] = "";
static IrBlob ir_blobs[16];
static int ir_nblobs;
// Safety: a Joy-Con whose IR/NFC chip stops answering makes every irs call slow. Never hammer it:
// after 2 stalls (or one call that blocks > 0.4 s) we stop talking to the camera until the user retries.
static int ir_fails;
static bool ir_gave_up;
static void ir_fail(const char *why) {
    ir_fails++;
    plat_log("ir: failure %d (%s)", ir_fails, why);
    if (ir_fails >= 2) {
        ir_gave_up = true;
        plat_log("ir: giving up until retry");
    }
}
void plat_ir_retry(void) {
    ir_fails = 0;
    ir_gave_up = false;
    ir_retry_tick = 0;
    plat_log("ir: retry requested");
}

static bool ir_find_joycon(HidNpadIdType *out, bool *wireless) {
    if (hidGetNpadStyleSet(HidNpadIdType_Handheld) & HidNpadStyleTag_NpadHandheld) {
        *out = HidNpadIdType_Handheld;
        *wireless = false;
        return true;
    }
    static const HidNpadIdType ids[4] = {HidNpadIdType_No1, HidNpadIdType_No2, HidNpadIdType_No3, HidNpadIdType_No4};
    for (int i = 0; i < 4; i++) {
        if (hidGetNpadStyleSet(ids[i]) & (HidNpadStyleTag_NpadJoyDual | HidNpadStyleTag_NpadJoyRight)) {
            *out = ids[i];
            *wireless = true;
            return true;
        }
    }
    return false;
}

static void ir_stop(void) {
    if (ir_running) irsStopImageProcessor(ir_handle);
    ir_running = false;
    ir_have_data = false;
    ir_nblobs = 0;
}

static void ir_start(HidNpadIdType id, bool wireless) {
    Result rc = irsGetIrCameraHandle(&ir_handle, id);
    if (R_SUCCEEDED(rc)) {
        if (ir_mode == 2) {
            IrsClusteringProcessorConfig cc;
            memset(&cc, 0, sizeof(cc));
            cc.exposure_time = 200000;  // 200 us
            cc.light_target = 0;        // all IR LEDs on: close objects (a hand) show up too
            cc.gain = 2;
            cc.window_of_interest.x = 0;
            cc.window_of_interest.y = 0;
            cc.window_of_interest.width = 320;
            cc.window_of_interest.height = 240;
            cc.object_pixel_count_min = 3;
            cc.object_pixel_count_max = 320 * 240;
            cc.object_intensity_min = 150;
            cc.is_external_light_filter_enabled = 0;  // keep external IR (remote LEDs)
            rc = irsRunClusteringProcessor(ir_handle, &cc);
        } else {
            IrsImageTransferProcessorConfig cfg;
            irsGetDefaultImageTransferProcessorConfig(&cfg);
            cfg.format = ir_mode == 1 ? IrsImageTransferProcessorFormat_80x60 : IrsImageTransferProcessorFormat_160x120;
            ir_w = ir_mode == 1 ? 80 : 160;
            ir_h = ir_mode == 1 ? 60 : 120;
            rc = irsRunImageTransferProcessor(ir_handle, &cfg, 0x100000);
        }
    }
    ir_running = R_SUCCEEDED(rc);
    if (!ir_running) ir_fail("start failed");
    ir_run_mode = ir_mode;
    ir_id = id;
    ir_wireless = wireless;
    ir_have_data = false;
    ir_nblobs = 0;
    ir_last_sample = 0;
    ir_last_new_tick = armGetSystemTick();
    plat_log("ir: start id=%d wireless=%d mode=%d rc=0x%X", (int)id, wireless, ir_mode, (unsigned)rc);
    if (!ir_running)
        snprintf(ir_status, sizeof(ir_status), "IR start failed (0x%X) - retrying", (unsigned)rc);
}

void plat_ir_enable(bool on) {
    if (on && g_safe_mode) {
        snprintf(ir_status, sizeof(ir_status), "IR disabled (safe mode)");
        return;
    }
    if (on && !ir_inited) {
        Result rc = irsInitialize();
        plat_log("irsInitialize rc=0x%X", (unsigned)rc);
        if (R_FAILED(rc)) {
            snprintf(ir_status, sizeof(ir_status), "IR service unavailable (0x%X)", (unsigned)rc);
            return;
        }
        ir_inited = true;
        if (!ir_buf) ir_buf = malloc(160 * 120);
        ir_retry_tick = 0;
        snprintf(ir_status, sizeof(ir_status), "looking for the right Joy-Con...");
    } else if (!on && ir_inited) {
        plat_log("ir: stop (running=%d)", ir_running);
        ir_stop();
        irsExit();
        ir_inited = false;
        plat_log("ir: exited");
    }
}

void plat_ir_set_mode(int mode) {
    if (mode < 0 || mode > 2 || mode == ir_mode) return;
    ir_mode = mode;
    if (ir_running) {
        ir_stop();
        ir_retry_tick = 0;
    }
}

// Shared housekeeping: find the Joy-Con, (re)start the processor. False = nothing to read yet.
static bool ir_service(u64 now, char *status, int status_len) {
    if (!ir_inited || !ir_buf) {
        snprintf(status, (size_t)status_len, "%s", ir_status);
        return false;
    }
    if (ir_gave_up) {
        if (ir_running) ir_stop();
        snprintf(status, (size_t)status_len, "IR not responding - reset the right Joy-Con, then A to retry");
        return false;
    }
    HidNpadIdType id;
    bool wl = false;
    if (!ir_find_joycon(&id, &wl)) {
        if (ir_running) {
            plat_log("ir: right Joy-Con gone");
            ir_stop();
        }
        snprintf(status, (size_t)status_len, "No right Joy-Con: attach it, or press a button on it");
        return false;
    }
    if (ir_running && (id != ir_id || ir_run_mode != ir_mode)) {
        plat_log("ir: controller/mode changed (%d -> %d)", (int)ir_id, (int)id);
        ir_stop();
        ir_retry_tick = 0;
    }
    if (!ir_running) {
        if (!ir_retry_tick || armTicksToNs(now - ir_retry_tick) > 1000000000ULL) {
            ir_retry_tick = now;
            ir_start(id, wl);
        }
        if (!ir_running) {
            snprintf(status, (size_t)status_len, "%s", ir_status);
            return false;
        }
    }
    return true;
}

static void ir_got_sample(u64 now) {
    ir_fails = 0;
    ir_last_new_tick = now;
    ir_have_data = true;
    ir_fps_n++;
}

// fps + stall watchdog; false if the processor was restarted
static bool ir_watchdog(u64 now, Result rc, char *status, int status_len) {
    if (armTicksToNs(now - ir_fps_tick) > 1000000000ULL) {
        ir_fps = ir_fps_n;
        ir_fps_n = 0;
        ir_fps_tick = now;
    }
    u64 limit = ir_wireless ? 6000000000ULL : 3000000000ULL;
    // in TRACK mode an empty scene still produces samples, so the same watchdog applies
    // ir_start() stamps ir_last_new_tick AFTER the caller read `now`; without this guard the unsigned
    // subtraction wrapped around and the watchdog killed the camera a few ms after every start.
    u64 elapsed = now > ir_last_new_tick ? armTicksToNs(now - ir_last_new_tick) : 0;
    if (elapsed > limit) {
        plat_log("ir: no new data for %llus (rc=0x%X) - restarting", (unsigned long long)(limit / 1000000000ULL), (unsigned)rc);
        ir_fail("stalled");
        ir_stop();
        ir_retry_tick = 0;
        snprintf(status, (size_t)status_len, "IR stalled - restarting...");
        return false;
    }
    if (!ir_have_data) {
        snprintf(status, (size_t)status_len, "IR starting on %s...", ir_wireless ? "wireless Joy-Con" : "handheld rail");
        return false;
    }
    return true;
}

const uint8_t *plat_ir_frame(int *w, int *h, char *status, int status_len) {
    u64 now = armGetSystemTick();
    if (!ir_service(now, status, status_len)) return NULL;
    if (ir_run_mode == 2) return NULL;
    IrsImageTransferProcessorState st;
    memset(&st, 0, sizeof(st));
    u64 c0 = armGetSystemTick();
    Result rc = irsGetImageTransferProcessorState(ir_handle, ir_buf, (size_t)(ir_w * ir_h), &st);
    if (armTicksToNs(armGetSystemTick() - c0) > 400000000ULL) {
        ir_fail("call blocked > 0.4 s");
        ir_stop();
        snprintf(status, (size_t)status_len, "IR camera is answering too slowly - stopped");
        return NULL;
    }
    if (R_SUCCEEDED(rc) && (s64)st.sampling_number != ir_last_sample) {
        ir_last_sample = (s64)st.sampling_number;
        ir_got_sample(now);
    }
    if (!ir_watchdog(now, rc, status, status_len)) return NULL;
    snprintf(status, (size_t)status_len, "IR live: %s  %dx%d  %d fps", ir_wireless ? "wireless Joy-Con" : "handheld",
             ir_w, ir_h, ir_fps);
    *w = ir_w;
    *h = ir_h;
    return ir_buf;
}

int plat_ir_blobs(IrBlob *out, int max, char *status, int status_len) {
    u64 now = armGetSystemTick();
    if (!ir_service(now, status, status_len)) return -1;
    if (ir_run_mode != 2) return -1;
    IrsClusteringProcessorState st;
    s32 total = 0;
    memset(&st, 0, sizeof(st));
    u64 c0 = armGetSystemTick();
    Result rc = irsGetClusteringProcessorStates(ir_handle, &st, 1, &total);
    if (armTicksToNs(armGetSystemTick() - c0) > 400000000ULL) {
        ir_fail("call blocked > 0.4 s");
        ir_stop();
        snprintf(status, (size_t)status_len, "IR camera is answering too slowly - stopped");
        return -1;
    }
    if (R_SUCCEEDED(rc) && total > 0 && st.sampling_number != ir_last_sample) {
        ir_last_sample = st.sampling_number;
        ir_got_sample(now);
        int n = st.object_count > 16 ? 16 : st.object_count;
        for (int i = 0; i < n; i++) {
            const IrsClusteringData *d = &st.data[i];
            ir_blobs[i].x = d->centroid_x;
            ir_blobs[i].y = d->centroid_y;
            ir_blobs[i].pixels = (int)d->pixel_count;
            ir_blobs[i].intensity = d->average_intensity;
            ir_blobs[i].bx = d->bound_x;
            ir_blobs[i].by = d->bound_y;
            ir_blobs[i].bw = d->boundt_width;
            ir_blobs[i].bh = d->bound_height;
        }
        ir_nblobs = n;
    }
    if (!ir_watchdog(now, rc, status, status_len)) return -1;
    snprintf(status, (size_t)status_len, "IR TRACK: %s  %d blobs  %d Hz", ir_wireless ? "wireless Joy-Con" : "handheld",
             ir_nblobs, ir_fps);
    int n = ir_nblobs < max ? ir_nblobs : max;
    memcpy(out, ir_blobs, (size_t)n * sizeof(IrBlob));
    return n;
}

// ============================================================ Wi-Fi CAN bridge
// cannelloni (https://github.com/mguentner/cannelloni) over UDP port 20000, so a Linux laptop sees
// the Switch as a normal SocketCAN interface:  cannelloni -I vcan0 -R <switch ip> -r 20000 -l 20000
// Until a laptop talks to us, frames are broadcast on the local network.
// Packet: [version=2][op=0 DATA][seq][count BE16] then per frame [id BE32 (+0x80000000 EFF)][len][data]
#define NET_PORT 20000
static bool net_on, net_nifm;
static int net_fd = -1;
static u32 net_ip;  // network byte order
static struct sockaddr_in net_peer;
static bool net_have_peer;
static u8 net_seq;
static u8 net_tx[1200];
static int net_txlen, net_txcount;
static unsigned net_ntx, net_nrx, net_nbad;
static char net_err[64];

static void net_close(void) {
    if (net_fd >= 0) close(net_fd);
    net_fd = -1;
    if (net_nifm) nifmExit();
    net_nifm = false;
    socketExit();
    net_on = false;
}

void plat_net_enable(bool on) {
    if (on && !net_on) {
        net_err[0] = 0;
        if (g_safe_mode) {
            snprintf(net_err, sizeof(net_err), "disabled in safe mode");
            return;
        }
        Result rc = socketInitializeDefault();
        plat_log("net: socketInitialize rc=0x%X", (unsigned)rc);
        if (R_FAILED(rc)) {
            snprintf(net_err, sizeof(net_err), "network stack unavailable (0x%X)", (unsigned)rc);
            return;
        }
        net_on = true;
        net_nifm = R_SUCCEEDED(nifmInitialize(NifmServiceType_User));
        net_ip = 0;
        if (net_nifm && R_FAILED(nifmGetCurrentIpAddress(&net_ip))) net_ip = 0;
        if (!net_ip) {
            snprintf(net_err, sizeof(net_err), "no Wi-Fi: connect the Switch to a network first");
            plat_log("net: no IP address");
            net_close();
            return;
        }
        net_fd = socket(AF_INET, SOCK_DGRAM, 0);
        int one = 1;
        if (net_fd >= 0) setsockopt(net_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(NET_PORT);
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        if (net_fd < 0 || bind(net_fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
            snprintf(net_err, sizeof(net_err), "UDP port %d unavailable (errno %d)", NET_PORT, errno);
            plat_log("net: socket/bind failed errno=%d", errno);
            net_close();
            return;
        }
        fcntl(net_fd, F_SETFL, fcntl(net_fd, F_GETFL, 0) | O_NONBLOCK);
        net_have_peer = false;
        net_txlen = net_txcount = 0;
        net_ntx = net_nrx = net_nbad = 0;
        struct in_addr ia = {.s_addr = net_ip};
        plat_log("net: bridge up on %s:%d", inet_ntoa(ia), NET_PORT);
    } else if (!on && net_on) {
        plat_log("net: bridge down (tx=%u rx=%u)", net_ntx, net_nrx);
        net_close();
    }
}

bool plat_net_on(void) { return net_on; }

static void net_flush(void) {
    if (!net_on || !net_txcount) return;
    net_tx[0] = 2;  // cannelloni frame version
    net_tx[1] = 0;  // DATA
    net_tx[2] = net_seq++;
    net_tx[3] = (u8)(net_txcount >> 8);
    net_tx[4] = (u8)net_txcount;
    struct sockaddr_in d;
    if (net_have_peer) d = net_peer;
    else {
        memset(&d, 0, sizeof(d));
        d.sin_family = AF_INET;
        d.sin_port = htons(NET_PORT);
        d.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    }
    if (sendto(net_fd, net_tx, (size_t)net_txlen, 0, (struct sockaddr *)&d, sizeof(d)) > 0) net_ntx += (unsigned)net_txcount;
    net_txlen = net_txcount = 0;
}

void plat_net_send(const CanFrame *f) {
    if (!net_on) return;
    if (net_txlen == 0) net_txlen = 5;
    if (net_txlen + 13 > (int)sizeof(net_tx)) {
        net_flush();
        net_txlen = 5;
    }
    u32 id = f->ext ? ((f->id & 0x1FFFFFFF) | 0x80000000u) : (f->id & 0x7FF);
    u8 *p = net_tx + net_txlen;
    p[0] = (u8)(id >> 24);
    p[1] = (u8)(id >> 16);
    p[2] = (u8)(id >> 8);
    p[3] = (u8)id;
    u8 len = f->len > 8 ? 8 : f->len;
    p[4] = len;
    memcpy(p + 5, f->data, len);
    net_txlen += 5 + len;
    net_txcount++;
}

int plat_net_poll(CanFrame *out, int max) {
    if (!net_on) return 0;
    net_flush();
    int n = 0;
    u8 buf[1500];
    for (int k = 0; k < 16 && n < max; k++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t r = recvfrom(net_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (r <= 0) break;
        if (from.sin_addr.s_addr == net_ip) continue;  // our own broadcast looping back
        if (r < 5 || buf[0] != 2 || buf[1] != 0) { net_nbad++; continue; }
        if (!net_have_peer || net_peer.sin_addr.s_addr != from.sin_addr.s_addr || net_peer.sin_port != from.sin_port) {
            struct in_addr ia = from.sin_addr;
            plat_log("net: peer %s:%d", inet_ntoa(ia), ntohs(from.sin_port));
        }
        net_peer = from;
        net_have_peer = true;
        int cnt = buf[3] << 8 | buf[4], pos = 5;
        for (int i = 0; i < cnt && n < max; i++) {
            if (pos + 5 > r) { net_nbad++; break; }
            u32 id = (u32)buf[pos] << 24 | (u32)buf[pos + 1] << 16 | (u32)buf[pos + 2] << 8 | buf[pos + 3];
            u8 lenb = buf[pos + 4];
            pos += 5;
            int len = lenb & 0x7F;
            if (lenb & 0x80) pos++;  // CAN-FD flags byte
            if (id & 0x40000000u) len = 0;  // RTR: no payload on the wire
            if (len > 64 || pos + len > r) { net_nbad++; break; }
            CanFrame *f = &out[n++];
            memset(f, 0, sizeof(*f));
            f->ext = (id & 0x80000000u) ? 1 : 0;
            f->id = f->ext ? (id & 0x1FFFFFFF) : (id & 0x7FF);
            f->len = (u8)(len > 8 ? 8 : len);
            memcpy(f->data, buf + pos, f->len);
            pos += len;
        }
    }
    net_nrx += (unsigned)n;
    return n;
}

void plat_net_info(char *l1, int n1, char *l2, int n2, unsigned *tx, unsigned *rx) {
    struct in_addr me = {.s_addr = net_ip};
    if (!net_on) {
        snprintf(l1, (size_t)n1, "%s", net_err[0] ? net_err : "off");
        l2[0] = 0;
    } else {
        snprintf(l1, (size_t)n1, "%s:%d", inet_ntoa(me), NET_PORT);
        if (net_have_peer) {
            struct in_addr ia = net_peer.sin_addr;
            snprintf(l2, (size_t)n2, "laptop %s:%d", inet_ntoa(ia), ntohs(net_peer.sin_port));
        } else
            snprintf(l2, (size_t)n2, "broadcasting - no laptop yet");
    }
    *tx = net_ntx;
    *rx = net_nrx;
}

// ===================================================================== files
const char *plat_data_dir(void) {
    mkdir("sdmc:/switch", 0777);
    mkdir("sdmc:/switch/cansole-nx", 0777);
    return "sdmc:/switch/cansole-nx/";
}

// ====================================================================== main
static uint32_t map_buttons(u64 k) {
    uint32_t b = 0;
    if (k & HidNpadButton_A) b |= B_A;
    if (k & HidNpadButton_B) b |= B_B;
    if (k & HidNpadButton_X) b |= B_X;
    if (k & HidNpadButton_Y) b |= B_Y;
    if (k & HidNpadButton_L) b |= B_L;
    if (k & HidNpadButton_R) b |= B_R;
    if (k & HidNpadButton_ZL) b |= B_ZL;
    if (k & HidNpadButton_ZR) b |= B_ZR;
    if (k & HidNpadButton_Plus) b |= B_PLUS;
    if (k & HidNpadButton_Minus) b |= B_MINUS;
    if (k & HidNpadButton_Up) b |= B_UP;
    if (k & HidNpadButton_Down) b |= B_DOWN;
    if (k & HidNpadButton_Left) b |= B_LEFT;
    if (k & HidNpadButton_Right) b |= B_RIGHT;
    if (k & HidNpadButton_StickL) b |= B_LSTICK;
    if (k & HidNpadButton_StickR) b |= B_RSTICK;
    return b;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    g_t0 = armGetSystemTick();
    mutexInit(&log_mtx);
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    padInitializeDefault(&g_pad);
    hidInitializeTouchScreen();
    for (int i = 0; i < 4; i++) {  // hold ZL while launching = safe mode
        padUpdate(&g_pad);
        if (padGetButtons(&g_pad) & HidNpadButton_ZL) g_safe_mode = true;
        svcSleepThread(15000000ULL);
    }
    log_load_previous();
    plat_log("---- CANsole NX " APP_VERSION_STR " start (safe_mode=%d, applet=%d)", g_safe_mode, (int)appletGetAppletType());
    rumble_init();
    appletSetMediaPlaybackState(true);  // keep the screen on in demo mode

    NWindow *win = nwindowGetDefault();
    Framebuffer fb;
    framebufferCreate(&fb, win, APP_W, APP_H, PIXEL_FORMAT_RGBA_8888, 2);
    framebufferMakeLinear(&fb);

    usb_start();
    app_init();
    u64 t_start = armGetSystemTick();

    plat_log("framebuffer + app init ok");
    while (appletMainLoop()) {
        rumble_poll();
        padUpdate(&g_pad);
        Input in;
        memset(&in, 0, sizeof(in));
        in.down = map_buttons(padGetButtonsDown(&g_pad));
        in.up = map_buttons(padGetButtonsUp(&g_pad));
        in.held = map_buttons(padGetButtons(&g_pad));
        HidAnalogStickState ls = padGetStickPos(&g_pad, 0);
        HidAnalogStickState rs = padGetStickPos(&g_pad, 1);
        in.stick_y = ls.y / 32767.0f;
        in.rstick_x = rs.x / 32767.0f;
        HidTouchScreenState ts = {0};
        if (hidGetTouchScreenStates(&ts, 1) && ts.count > 0) {
            in.touching = true;
            in.tx = (int)ts.touches[0].x;
            in.ty = (int)ts.touches[0].y;
        }
        double t = armTicksToNs(armGetSystemTick() - t_start) / 1e9;

        u32 stride = 0;
        u32 *px = (u32 *)framebufferBegin(&fb, &stride);
        Canvas c = {px, APP_W, APP_H, (int)(stride / sizeof(u32))};
        bool keep = app_frame(&c, &in, t);
        framebufferEnd(&fb);
        if (!keep) break;
    }

    plat_log("exit requested");
    rumble_send(0);
    plat_log("shutdown: app (nfc/ir off)");
    app_shutdown();
    if (net_on) plat_net_enable(false);
    usb_stop();
    plat_log("shutdown: framebuffer");
    framebufferClose(&fb);
    appletSetMediaPlaybackState(false);
    plat_log("clean exit");
    if (bootlog) fclose(bootlog);
    return 0;
}
