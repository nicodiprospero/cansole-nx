// CANsole NX - Nintendo Switch platform layer (libnx)
//   framebuffer + Joy-Con/touch input, USB-CAN (slcan over CDC-ACM via usb:hs),
//   Joy-Con NFC (nfc:user) and Joy-Con IR camera (irs).
#include <malloc.h>
#include <stdarg.h>
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
static Mutex log_mtx;
static FILE *bootlog;
void plat_log(const char *fmt, ...) {
    mutexLock(&log_mtx);
    if (!bootlog) {
        mkdir("sdmc:/switch", 0777);
        mkdir("sdmc:/switch/cansole-nx", 0777);
        bootlog = fopen("sdmc:/switch/cansole-nx/boot.log", "a");
    }
    if (bootlog) {
        va_list ap;
        va_start(ap, fmt);
        fprintf(bootlog, "[%8.3f] ", armTicksToNs(armGetSystemTick() - g_t0) / 1e9);
        vfprintf(bootlog, fmt, ap);
        fputc('\n', bootlog);
        fflush(bootlog);
        va_end(ap);
    }
    mutexUnlock(&log_mtx);
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
        snprintf(lab, sizeof(lab), "USB %04X:%04X slcan %dk%s", usb_vid, usb_pid, BR_KBPS[br_idx], ever_rx ? "" : "?");
    else
        snprintf(lab, sizeof(lab), "USB %04X:%04X gs_usb %dk%s", usb_vid, usb_pid, BR_KBPS[br_idx], ever_rx ? "" : "?");
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
            set_label("USB: plug RAMN/CANable");
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
    if (R_FAILED(rc) || !usb_inbuf || !usb_outbuf || !usb_ctrlbuf) {
        usb_state_v = USB_ERROR;
        snprintf(usb_label_s, sizeof(usb_label_s), "USB host unavailable (0x%X)", (unsigned)rc);
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
        threadWaitForExit(&usb_thread);
        threadClose(&usb_thread);
        usb_thread_ok = false;
    }
    if (usb_state_v != USB_ERROR && !g_safe_mode) usbHsExit();
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
        nfc_cur.state = R_SUCCEEDED(rc) ? NFC_SEARCHING : NFC_ERROR;
        if (R_SUCCEEDED(rc))
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
        else
            snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Could not start detection (0x%X)", (unsigned)rc);
    } else if (!on && nfc_inited) {
        if (nfc_have_dev) nfcStopDetection(&nfc_dev);
        nfcExit();
        nfc_inited = nfc_have_dev = false;
        nfc_prev_state = -1;
    }
}

void plat_nfc_info(NfcInfo *out) {
    if (nfc_inited && nfc_have_dev) {
        NfcDeviceState st;
        if (R_SUCCEEDED(nfcGetDeviceState(&nfc_dev, &st))) {
            if (st == NfcDeviceState_TagFound || st == NfcDeviceState_TagMounted) {
                if (nfc_prev_state != (int)st) {
                    NfcTagInfo ti;
                    memset(&ti, 0, sizeof(ti));
                    if (R_SUCCEEDED(nfcGetTagInfo(&nfc_dev, &ti))) {
                        int n = ti.uid.uid_length > 10 ? 10 : ti.uid.uid_length;
                        memcpy(nfc_cur.uid, ti.uid.uid, (size_t)n);
                        nfc_cur.uid_len = n;
                        nfc_cur.protocol = ti.protocol;
                        nfc_cur.tag_type = ti.tag_type;
                        nfc_cur.seq++;
                    }
                }
                nfc_cur.state = NFC_TAG;
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Tag detected");
            } else if (st == NfcDeviceState_TagRemoved || st == NfcDeviceState_Initialized) {
                nfcStopDetection(&nfc_dev);
                nfcStartDetection(&nfc_dev, NfcProtocol_All);
                nfc_cur.state = NFC_SEARCHING;
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
            } else if (st == NfcDeviceState_SearchingForTag) {
                nfc_cur.state = NFC_SEARCHING;
                snprintf(nfc_cur.status, sizeof(nfc_cur.status), "Searching for a tag...");
            }
            nfc_prev_state = (int)st;
        }
    }
    *out = nfc_cur;
}

// ======================================================================== IR
static bool ir_inited, ir_running;
static IrsIrCameraHandle ir_handle;
static u8 *ir_buf;
static char ir_status[96] = "";
#define IR_W 320
#define IR_H 240

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
        if (!ir_buf) ir_buf = malloc(IR_W * IR_H);
        HidNpadIdType id = padIsHandheld(&g_pad) ? HidNpadIdType_Handheld : HidNpadIdType_No1;
        rc = irsGetIrCameraHandle(&ir_handle, id);
        if (R_SUCCEEDED(rc)) {
            IrsImageTransferProcessorConfig cfg;
            irsGetDefaultImageTransferProcessorConfig(&cfg);
            rc = irsRunImageTransferProcessor(ir_handle, &cfg, 0x100000);
        }
        ir_running = R_SUCCEEDED(rc);
        plat_log("ir start rc=0x%X running=%d", (unsigned)rc, ir_running);
        if (ir_running)
            snprintf(ir_status, sizeof(ir_status), "IR camera running (%s)", id == HidNpadIdType_Handheld ? "handheld" : "player 1");
        else
            snprintf(ir_status, sizeof(ir_status), "IR start failed (0x%X) - try a detached Joy-Con", (unsigned)rc);
    } else if (!on && ir_inited) {
        if (ir_running) irsStopImageProcessor(ir_handle);
        irsExit();
        ir_inited = ir_running = false;
    }
}

const uint8_t *plat_ir_frame(int *w, int *h, char *status, int status_len) {
    snprintf(status, (size_t)status_len, "%s", ir_status);
    if (!ir_running || !ir_buf) return NULL;
    IrsImageTransferProcessorState st;
    if (R_FAILED(irsGetImageTransferProcessorState(ir_handle, ir_buf, IR_W * IR_H, &st))) return NULL;
    *w = IR_W;
    *h = IR_H;
    return ir_buf;
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
        in.stick_y = ls.y / 32767.0f;
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
    app_shutdown();
    usb_stop();
    framebufferClose(&fb);
    appletSetMediaPlaybackState(false);
    plat_log("clean exit");
    if (bootlog) fclose(bootlog);
    return 0;
}
