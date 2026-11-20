// CANsole NX - platform interface (Switch implementation in main.c, test stubs in host/)
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t id;
    uint8_t len;   // 0-8 (CAN-FD frames are truncated to 8 for display)
    uint8_t ext;   // 29-bit id
    uint8_t data[8];
} CanFrame;

// ---- USB-CAN adapter (slcan over USB CDC-ACM, e.g. RAMN ECU A / CANable)
enum { USB_OFF = 0, USB_SEARCHING = 1, USB_CONNECTED = 2, USB_ERROR = 3 };
int plat_usb_state(void);
const char *plat_usb_label(void);           // short human-readable status
int plat_usb_poll(CanFrame *out, int max);  // frames received since last call
bool plat_usb_send(const CanFrame *f);
// Bus-level safety: false = adapter opened listen-only ("L"), true = normal mode ("O") so we may transmit.
void plat_usb_set_tx(bool enable);
// Raw adapter command (slcan only), e.g. RAMN "yC0\r" = power off ECU C. Returns false if unsupported.
bool plat_usb_raw(const char *cmd);

// ---- Joy-Con NFC reader
enum { NFC_OFF = 0, NFC_ERROR = 1, NFC_SEARCHING = 2, NFC_TAG = 3 };
typedef struct {
    int state;
    char status[96];
    uint8_t uid[10];
    int uid_len;
    uint32_t protocol, tag_type;
    uint32_t seq;  // increments every time a new tag is read
} NfcInfo;
void plat_nfc_enable(bool on);
void plat_nfc_info(NfcInfo *out);

// ---- Joy-Con IR camera
void plat_ir_enable(bool on);
void plat_ir_retry(void);         // talk to the camera again after it was given up on
void plat_ir_set_mode(int mode);  // 0 SHARP 160x120 image, 1 FAST 80x60 image, 2 TRACK (blob clustering)
const uint8_t *plat_ir_frame(int *w, int *h, char *status, int status_len);  // 8-bit grayscale or NULL
typedef struct {
    float x, y;        // centroid in the 320x240 sensor space
    int pixels;        // blob size
    float intensity;   // average brightness 0-255
    int bx, by, bw, bh;
} IrBlob;
int plat_ir_blobs(IrBlob *out, int max, char *status, int status_len);  // TRACK mode: blob count, -1 = no data

// ---- files / diagnostics
const char *plat_data_dir(void);  // folder for candump logs, with trailing slash
void plat_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));  // boot.log on SD
bool plat_safe_mode(void);        // true if launched holding ZL: USB/NFC/IR disabled
int plat_log_count(void);         // in-memory log ring (this session + tail of the previous one)
const char *plat_log_line(int i); // 0 = oldest
int plat_prev_session_clean(void);  // -1 unknown, 0 previous session did not exit cleanly, 1 clean

// ---- Wi-Fi CAN bridge (cannelloni over UDP :20000 - a Linux laptop sees a SocketCAN interface)
void plat_net_enable(bool on);
bool plat_net_on(void);
void plat_net_send(const CanFrame *f);      // queued, sent once per frame
int plat_net_poll(CanFrame *out, int max);  // flushes the queue, returns frames received from the laptop
void plat_net_info(char *line1, int n1, char *line2, int n2, unsigned *tx, unsigned *rx);

// ---- haptics
void plat_rumble(float amp, int ms);  // Joy-Con HD rumble pulse (amp 0..1)
