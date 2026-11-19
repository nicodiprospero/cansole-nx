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
#define RXQ 4096
static Mutex usb_mtx;
static CanFrame rxq[RXQ];
static int rxq_head, rxq_tail;
static char txq[8192];
static int txq_len;
static volatile int usb_state_v = USB_OFF;
static char usb_label_s[64] = "USB: off";
static Thread usb_thread;
static volatile bool usb_run;
static bool usb_thread_ok;
static UsbHsClientIfSession if_sess;
static UsbHsClientEpSession ep_in, ep_out;
static bool have_if, have_in, have_out;
static u8 *usb_inbuf, *usb_outbuf;
static SlcanParser slp;
static volatile int usb_mode_req;  // 0 none, 1 listen-only, 2 normal (TX)

static void set_label(const char *s) {
    mutexLock(&usb_mtx);
    snprintf(usb_label_s, sizeof(usb_label_s), "%s", s);
    mutexUnlock(&usb_mtx);
}

static void usb_close_dev(void) {
    if (have_in) usbHsEpClose(&ep_in);
    if (have_out) usbHsEpClose(&ep_out);
    if (have_if) usbHsIfClose(&if_sess);
    have_in = have_out = have_if = false;
}

static bool usb_write(const char *s, int n) {
    if (!have_out || n <= 0) return false;
    while (n > 0) {
        int chunk = n > 0x1000 ? 0x1000 : n;
        memcpy(usb_outbuf, s, (size_t)chunk);
        u32 xfer = 0;
        if (R_FAILED(usbHsEpPostBuffer(&ep_out, usb_outbuf, (u32)chunk, &xfer))) return false;
        s += chunk;
        n -= chunk;
    }
    return true;
}

static bool usb_try_open(void) {
    UsbHsInterfaceFilter filter;
    memset(&filter, 0, sizeof(filter));
    filter.Flags = UsbHsInterfaceFilterFlags_bInterfaceClass;
    filter.bInterfaceClass = 0x0A;  // CDC data interface (STM32/RAMN, CANable slcan firmware)
    static UsbHsInterface ifs[8];
    s32 total = 0;
    Result rc = usbHsQueryAvailableInterfaces(&filter, ifs, sizeof(ifs), &total);
    if (R_FAILED(rc) || total <= 0) return false;
    rc = usbHsAcquireUsbIf(&if_sess, &ifs[0]);
    if (R_FAILED(rc)) return false;
    have_if = true;
    for (int i = 0; i < 15; i++) {
        struct usb_endpoint_descriptor *d = &if_sess.inf.inf.input_endpoint_descs[i];
        if (!have_in && d->bLength && (d->bmAttributes & 3) == 2 && R_SUCCEEDED(usbHsIfOpenUsbEp(&if_sess, &ep_in, 1, 0x1000, d)))
            have_in = true;
        d = &if_sess.inf.inf.output_endpoint_descs[i];
        if (!have_out && d->bLength && (d->bmAttributes & 3) == 2 && R_SUCCEEDED(usbHsIfOpenUsbEp(&if_sess, &ep_out, 1, 0x1000, d)))
            have_out = true;
    }
    if (!have_in || !have_out) {
        usb_close_dev();
        return false;
    }
    // CDC-ACM: line coding 115200 8N1 + DTR/RTS on the control interface (usually data interface - 1)
    u16 ctrl_if = if_sess.inf.inf.interface_desc.bInterfaceNumber ? if_sess.inf.inf.interface_desc.bInterfaceNumber - 1 : 0;
    u8 *lc = usb_outbuf;
    memset(lc, 0, 0x40);
    lc[0] = 0x00; lc[1] = 0xC2; lc[2] = 0x01; lc[3] = 0x00;  // 115200
    lc[4] = 0; lc[5] = 0; lc[6] = 8;
    u32 xfer = 0;
    usbHsIfCtrlXfer(&if_sess, 0x21, 0x20, 0, ctrl_if, 7, lc, &xfer);
    usbHsIfCtrlXfer(&if_sess, 0x21, 0x22, 0x03, ctrl_if, 0, lc, &xfer);
    // slcan: close, 500 kbit/s, open LISTEN-ONLY (the adapter itself cannot transmit until armed)
    static const char init[] = "\r\r\rC\rS6\rL\r";
    usb_write(init, (int)sizeof(init) - 1);
    plat_log("usb: opened %04X:%04X if=%d ctrl_if=%d (listen-only)", ifs[0].device_desc.idVendor, ifs[0].device_desc.idProduct,
             if_sess.inf.inf.interface_desc.bInterfaceNumber, ctrl_if);
    char lab[64];
    snprintf(lab, sizeof(lab), "USB %04X:%04X slcan 500k", ifs[0].device_desc.idVendor, ifs[0].device_desc.idProduct);
    set_label(lab);
    memset(&slp, 0, sizeof(slp));
    return true;
}

static bool usb_still_there(void) {
    static UsbHsInterface acq[8];
    s32 total = 0;
    if (R_FAILED(usbHsQueryAcquiredInterfaces(acq, sizeof(acq), &total))) return false;
    return total > 0;
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
            if (!usb_try_open()) {
                svcSleepThread(500000000ULL);
                continue;
            }
            usb_state_v = USB_CONNECTED;
            posted = false;
            fails = 0;
        }
        // adapter mode change (listen-only <-> normal)
        int req = usb_mode_req;
        if (req) {
            usb_mode_req = 0;
            const char *cmd = req == 2 ? "C\rS6\rO\r" : "C\rS6\rL\r";
            usb_write(cmd, (int)strlen(cmd));
            plat_log("usb: mode %s", req == 2 ? "NORMAL (TX armed)" : "LISTEN-ONLY");
        }
        // flush pending TX
        mutexLock(&usb_mtx);
        static char out[sizeof(txq)];
        int n = txq_len;
        if (n) memcpy(out, txq, (size_t)n);
        txq_len = 0;
        mutexUnlock(&usb_mtx);
        if (n && !usb_write(out, n)) fails++;
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
                    CanFrame tmp[128];
                    int got = slcan_feed(&slp, usb_inbuf, (int)rep.transferredSize, tmp, 128);
                    if (got) {
                        mutexLock(&usb_mtx);
                        for (int i = 0; i < got; i++) {
                            int nx = (rxq_head + 1) % RXQ;
                            if (nx == rxq_tail) break;  // full: drop
                            rxq[rxq_head] = tmp[i];
                            rxq_head = nx;
                        }
                        mutexUnlock(&usb_mtx);
                    }
                    fails = 0;
                } else {
                    fails++;
                }
            }
        } else {
            svcSleepThread(10000000ULL);
        }
        // disconnect detection
        u64 nowt = armGetSystemTick();
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

static void usb_start(void) {
    mutexInit(&usb_mtx);
    if (g_safe_mode) {
        usb_state_v = USB_OFF;
        snprintf(usb_label_s, sizeof(usb_label_s), "USB off (safe mode)");
        return;
    }
    usb_inbuf = memalign(0x1000, 0x1000);
    usb_outbuf = memalign(0x1000, 0x1000);
    Result rc = usbHsInitialize();
    plat_log("usbHsInitialize rc=0x%X", (unsigned)rc);
    if (R_FAILED(rc) || !usb_inbuf || !usb_outbuf) {
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
    char line[48];
    int n = slcan_encode(f, line);
    bool ok = false;
    mutexLock(&usb_mtx);
    if (txq_len + n < (int)sizeof(txq)) {
        memcpy(txq + txq_len, line, (size_t)n);
        txq_len += n;
        ok = true;
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
