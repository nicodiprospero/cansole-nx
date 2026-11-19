// CANsole NX - slcan (Lawicel ASCII) encoder/decoder
#pragma once
#include "platform.h"

typedef struct {
    char line[200];
    int n;
} SlcanParser;

// Feed raw serial bytes; returns number of frames written to out (max `max`).
int slcan_feed(SlcanParser *p, const uint8_t *buf, int len, CanFrame *out, int max);
// Encode a classic CAN frame as "tIIILDD..\r" / "TIIIIIIIILDD..\r"; returns length.
int slcan_encode(const CanFrame *f, char *out);
