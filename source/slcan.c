// CANsole NX - slcan (Lawicel ASCII) encoder/decoder
#include "slcan.h"
#include <stdio.h>
#include <string.h>

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hexn(const char *s, int n, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) {
        int h = hexv(s[i]);
        if (h < 0) return 0;
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return 1;
}

static const int FD_LEN[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64};

static int parse_line(const char *l, int n, CanFrame *f) {
    if (n < 1) return 0;
    char k = l[0];
    int idlen, fd = 0;
    switch (k) {
        case 't': idlen = 3; break;
        case 'T': idlen = 8; break;
        case 'd': case 'b': idlen = 3; fd = 1; break;   // CAN-FD (slcan extensions)
        case 'D': case 'B': idlen = 8; fd = 1; break;
        default: return 0;  // 'r'/'R' remote frames, acks, version strings...
    }
    if (n < 1 + idlen + 1) return 0;
    uint32_t id, dl;
    if (!hexn(l + 1, idlen, &id)) return 0;
    if (!hexn(l + 1 + idlen, 1, &dl)) return 0;
    int len = fd ? FD_LEN[dl & 15] : (int)(dl > 8 ? 8 : dl);
    const char *d = l + 2 + idlen;
    int avail = (n - 2 - idlen) / 2;
    if (avail < len) return 0;
    memset(f, 0, sizeof(*f));
    f->id = id;
    f->ext = idlen == 8;
    f->len = (uint8_t)(len > 8 ? 8 : len);
    for (int i = 0; i < f->len; i++) {
        uint32_t b;
        if (!hexn(d + i * 2, 2, &b)) return 0;
        f->data[i] = (uint8_t)b;
    }
    return 1;
}

int slcan_feed(SlcanParser *p, const uint8_t *buf, int len, CanFrame *out, int max) {
    int got = 0;
    for (int i = 0; i < len; i++) {
        char c = (char)buf[i];
        if (c == '\r' || c == '\n' || c == 7) {
            if (p->n > 0 && got < max && parse_line(p->line, p->n, &out[got])) got++;
            p->n = 0;
        } else if (p->n < (int)sizeof(p->line) - 1) {
            p->line[p->n++] = c;
        } else {
            p->n = 0;  // garbage, resync on next terminator
        }
    }
    return got;
}

int slcan_encode(const CanFrame *f, char *out) {
    int n;
    int len = f->len > 8 ? 8 : f->len;
    if (f->ext)
        n = sprintf(out, "T%08X%d", (unsigned)(f->id & 0x1FFFFFFF), len);
    else
        n = sprintf(out, "t%03X%d", (unsigned)(f->id & 0x7FF), len);
    for (int i = 0; i < len; i++) n += sprintf(out + n, "%02X", f->data[i]);
    out[n++] = '\r';
    out[n] = 0;
    return n;
}
