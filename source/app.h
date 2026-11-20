// CANsole NX - application core (platform independent)
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "gfx.h"
#include "platform.h"

#define APP_W 1280
#define APP_H 720
#define APP_VERSION_STR "1.4.0"

enum {
    B_A = 1 << 0, B_B = 1 << 1, B_X = 1 << 2, B_Y = 1 << 3,
    B_L = 1 << 4, B_R = 1 << 5, B_ZL = 1 << 6, B_ZR = 1 << 7,
    B_PLUS = 1 << 8, B_MINUS = 1 << 9,
    B_UP = 1 << 10, B_DOWN = 1 << 11, B_LEFT = 1 << 12, B_RIGHT = 1 << 13,
    B_LSTICK = 1 << 14, B_RSTICK = 1 << 15,
};

typedef struct {
    uint32_t held, down, up;  // button bitmasks
    float stick_y;            // left stick, +1 = up (gas), -1 = down (brake)
    float rstick_x;           // right stick, -1 left .. +1 right (takeover steering)
    bool touching;
    int tx, ty;               // touch position in 1280x720 space
} Input;

void app_init(void);
bool app_frame(Canvas *c, const Input *in, double t);  // false = quit requested
void app_shutdown(void);
