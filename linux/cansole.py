#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CANsole v1.0 - Nintendo Switch CAN bus console
================================================
Turns a Switch running Switchroot L4T Ubuntu into a car-hacking toy:

  CLUSTER  live gauges, blinkers, doors, warning lights, touch attack buttons
  SNIFFER  cansniffer-style view, changed bytes light up, bit view, pin any
           byte(s) to a big gauge (that's how you reverse-engineer a signal)
  IDS      rate + rolling-counter intrusion detection that catches the attacks

Interfaces:
  --iface sim        built-in virtual car, no hardware needed (default fallback)
  --iface slcan      USB-CAN in slcan mode, e.g. RAMN ECU A or CANable  (/dev/ttyACM0)
  --iface socketcan  can0 / vcan0 (candleLight, gs_usb, MCP2515 HAT ...)
  --iface auto       slcan if /dev/ttyACM* exists, else can0, else sim  (default)

Real buses start READ-ONLY. TX needs --allow-tx AND holding + for 2 seconds.
Only transmit on hardware you own or have explicit permission to touch.

Controls (Joy-Cons / keyboard):
  L / R  (Q / E)        switch tab                 - (H)    help
  Left stick (W / S)    gas / brake (sim car)      + (T)    hold 2 s: arm TX (real bus)
  ZR (Space)            spoof speed / override MAX
  ZL (L-Shift)          spoof RPM   / override MIN
  A (J)                 cluster: unlock doors      sniffer: pin bytes to gauge
  B (K)                 cluster: check-engine      sniffer: clear pins
  X (I)                 IDS on / off (re-learns baseline)
  Y (U)                 fuzz selected ID for 2 s
  D-pad (arrows)        sniffer: select ID / byte  cluster: blinkers
  Capture (F12)         screenshot to ~/Pictures/CANsole
  L-stick click (R)     start/stop candump log in ~/cansole_logs
  - and + together (Esc) quit.  Touchscreen works for tabs, buttons and rows.

Setup on Switchroot Ubuntu:
  sudo apt install -y python3-pygame python3-can python3-serial can-utils
  python3 cansole.py --install      # adds "CANsole" + "CANsole Demo" launchers
"""

import argparse
import glob
import math
import os
import random
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime

os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")
os.environ.setdefault("SDL_GAMECONTROLLER_USE_BUTTON_LABELS", "1")

try:
    import can
except ImportError:
    sys.exit("python-can missing ->  sudo apt install -y python3-can   (or: pip install python-can)")
try:
    import pygame
except ImportError:
    sys.exit("pygame missing ->  sudo apt install -y python3-pygame   (or: pip install pygame)")

try:
    from pygame._sdl2 import controller as sdl_controller
except Exception:  # older pygame
    sdl_controller = None

APP = "CANsole"
VERSION = "1.0"
W, H = 1280, 720
FPS = 30

# ---------------------------------------------------------------- palette ---
BG = (9, 11, 15)
PANEL = (20, 24, 31)
PANEL2 = (30, 35, 46)
LINE = (52, 60, 76)
FG = (232, 234, 238)
DIM = (120, 128, 144)
RED = (240, 62, 48)
AMBER = (255, 176, 32)
GREEN = (52, 214, 120)
CYAN = (70, 196, 255)

# ------------------------------------------------- fake car "DBC" (sim) ---
ID_WHEELS = 0x0B4   # 4x uint16 BE wheel speed km/h*100
ID_ENGINE = 0x120   # [rpm_hi, rpm_lo, throttle%, coolant+40, ctr, 0, 0, 0]
ID_LIGHTS = 0x188   # byte0 bit0 left blinker, bit1 right blinker
ID_SPEED = 0x1A0    # [spd_hi, spd_lo (km/h*100), counter 0-15, checksum]
ID_STEER = 0x2C1    # int16 BE steering angle *10
ID_WARN = 0x2F0     # byte0 bit0 check engine, bit1 oil, bit2 battery
ID_BODY = 0x394     # counter + magic + checksum
ID_DOORS = 0x3E0    # byte0 bit0-3 door locked FL FR RL RR
ID_VIN = 0x4F0      # ascii
ID_BATT = 0x5A8     # uint16 BE battery mV/10

NAMES = {
    ID_WHEELS: "wheel speeds", ID_ENGINE: "engine", ID_LIGHTS: "lights",
    ID_SPEED: "vehicle speed", ID_STEER: "steering", ID_WARN: "warnings",
    ID_BODY: "body ctrl", ID_DOORS: "door locks", ID_VIN: "vin/ident",
    ID_BATT: "battery",
}


def now():
    return time.monotonic()


def trim(dq, t, win=1.0):
    while dq and t - dq[0] > win:
        dq.popleft()


# ======================================================================
#  Bus state (filled by the reader thread, read by the UI)
# ======================================================================
class FrameInfo:
    __slots__ = ("data", "changed", "count", "times", "first", "last", "ext")

    def __init__(self, t):
        self.data = b""
        self.changed = [0.0] * 8
        self.count = 0
        self.times = deque()
        self.first = t
        self.last = t
        self.ext = False


class BusState:
    def __init__(self):
        self.lock = threading.Lock()
        self.frames = {}
        self.rx_times = deque()
        self.total = 0
        self.ctr_last = None
        self.ctr_err = deque()
        self.log_fp = None
        self.log_path = ""
        self.log_chan = "can0"

    def ingest(self, msg):
        t = now()
        cid = msg.arbitration_id
        data = bytes(msg.data)
        with self.lock:
            fi = self.frames.get(cid)
            if fi is None:
                fi = FrameInfo(t)
                fi.ext = bool(msg.is_extended_id)
                self.frames[cid] = fi
            old = fi.data
            for i, b in enumerate(data[:8]):
                if i >= len(old) or old[i] != b:
                    fi.changed[i] = t
            fi.data = data
            fi.count += 1
            fi.last = t
            fi.times.append(t)
            trim(fi.times, t)
            self.total += 1
            self.rx_times.append(t)
            trim(self.rx_times, t)
            if cid == ID_SPEED and len(data) >= 3:
                c = data[2] & 0x0F
                if self.ctr_last is not None and c != ((self.ctr_last + 1) & 0x0F):
                    self.ctr_err.append(t)
                self.ctr_last = c
            if self.log_fp:
                idtxt = f"{cid:08X}" if msg.is_extended_id else f"{cid:03X}"
                self.log_fp.write(f"({time.time():.6f}) {self.log_chan} {idtxt}#{data.hex().upper()}\n")

    def snapshot(self, t):
        rows = []
        with self.lock:
            for cid in sorted(self.frames):
                fi = self.frames[cid]
                trim(fi.times, t)
                rows.append((cid, fi.data, list(fi.changed), len(fi.times), fi.count, fi.last, fi.first, fi.ext))
            trim(self.rx_times, t)
            trim(self.ctr_err, t)
            return rows, len(self.rx_times), len(self.ctr_err)

    def toggle_log(self, chan):
        with self.lock:
            if self.log_fp:
                self.log_fp.close()
                self.log_fp = None
                return False, self.log_path
            d = os.path.expanduser("~/cansole_logs")
            os.makedirs(d, exist_ok=True)
            self.log_path = os.path.join(d, datetime.now().strftime("cansole_%Y%m%d_%H%M%S.log"))
            self.log_fp = open(self.log_path, "w", buffering=1)
            self.log_chan = chan
            return True, self.log_path


# ======================================================================
#  Threads: reader, simulated car, attacker
# ======================================================================
class Reader(threading.Thread):
    def __init__(self, bus, state):
        super().__init__(daemon=True)
        self.bus, self.state = bus, state
        self.running = True
        self.error = ""

    def run(self):
        while self.running:
            try:
                msg = self.bus.recv(0.1)
            except Exception as e:  # unplugged adapter etc.
                self.error = str(e)[:70]
                time.sleep(0.5)
                continue
            if msg is None or getattr(msg, "is_error_frame", False):
                continue
            self.error = ""
            self.state.ingest(msg)


def drain(bus, limit=2000):
    """Virtual buses queue every frame for every instance; drain the ones nobody reads."""
    try:
        for _ in range(limit):
            if bus.recv(0) is None:
                break
    except Exception:
        pass


class FakeCar(threading.Thread):
    """A small believable car: ECU frames at real-world-ish rates."""
    GEARS = [(0, 20, 118), (20, 42, 74), (42, 68, 52), (68, 98, 40), (98, 135, 32), (135, 999, 26)]
    SCHED = {ID_WHEELS: 0.02, ID_ENGINE: 0.02, ID_SPEED: 0.02, ID_STEER: 0.02,
             ID_LIGHTS: 0.1, ID_BODY: 0.1, ID_WARN: 0.2, ID_BATT: 0.2, ID_DOORS: 0.5, ID_VIN: 1.0}

    def __init__(self, bus):
        super().__init__(daemon=True)
        self.bus = bus
        self.throttle = 0.0
        self.brake = 0.0
        self.blink_l = False
        self.blink_r = False
        self.speed = 0.0
        self.rpm = 800.0
        self.coolant = 62.0
        self.ctr = 0
        self.body_ctr = 0
        self.doors = 0x0F
        self.running = True

    def physics(self, dt):
        acc = self.throttle * 16.0 - self.brake * 38.0 - (0.5 + self.speed * 0.010)
        self.speed = max(0.0, min(232.0, self.speed + acc * dt))
        ratio = 118
        for lo, hi, k in self.GEARS:
            if lo <= self.speed < hi:
                ratio = k
                break
        if self.speed < 3:
            target = 800 + self.throttle * 3200
        else:
            target = max(900.0, self.speed * ratio) + self.throttle * 400
        target = min(target, 7400)
        self.rpm += (target - self.rpm) * min(1.0, dt * 7)
        self.coolant += (90 - self.coolant) * dt * 0.02

    def frame(self, cid, t):
        if cid == ID_ENGINE:
            r = int(self.rpm)
            return [r >> 8, r & 255, int(self.throttle * 100), int(self.coolant) + 40, self.ctr & 0x0F, 0, 0, 0]
        if cid == ID_SPEED:
            self.ctr = (self.ctr + 1) & 0x0F
            v = int(self.speed * 100)
            hi, lo = v >> 8, v & 255
            return [hi, lo, self.ctr, (hi + lo + self.ctr) & 0xFF]
        if cid == ID_WHEELS:
            out = []
            for _ in range(4):
                v = max(0, int(self.speed * 100 + random.randint(-8, 8))) if self.speed > 0.5 else 0
                out += [v >> 8, v & 255]
            return out
        if cid == ID_LIGHTS:
            on = (t * 1.5) % 1.0 < 0.5
            return [(1 if self.blink_l and on else 0) | (2 if self.blink_r and on else 0), 0]
        if cid == ID_WARN:
            return [0, 0, 0, 0]
        if cid == ID_DOORS:
            return [self.doors, 0]
        if cid == ID_STEER:
            a = int(random.gauss(0, 6)) & 0xFFFF
            return [a >> 8, a & 255, 0, 0, 0, 0]
        if cid == ID_BODY:
            self.body_ctr = (self.body_ctr + 1) & 0xFF
            return [self.body_ctr, 0x5A, 0x00, (self.body_ctr * 7) & 0xFF]
        if cid == ID_VIN:
            return list(b"CANSOLE1")
        if cid == ID_BATT:
            v = 1410 + random.randint(-6, 6)
            return [v >> 8, v & 255, 0]
        return [0]

    def run(self):
        last = {k: 0.0 for k in self.SCHED}
        prev = now()
        while self.running:
            t = now()
            dt, prev = t - prev, t
            self.physics(dt)
            for cid, per in self.SCHED.items():
                if t - last[cid] >= per:
                    last[cid] = t
                    try:
                        self.bus.send(can.Message(arbitration_id=cid, data=bytes(self.frame(cid, t)),
                                                  is_extended_id=False))
                    except Exception:
                        pass
            drain(self.bus)
            time.sleep(0.004)


class Attacker(threading.Thread):
    """Sends spoofed frames at ~200 Hz while an attack is held or bursting."""

    def __init__(self, bus, allowed, drain_own):
        super().__init__(daemon=True)
        self.bus = bus
        self.allowed = allowed
        self.drain_own = drain_own
        self.lock = threading.Lock()
        self.holds = set()
        self.bursts = {}
        self.fuzz_id = ID_SPEED
        self.fuzz_len = 8
        self.override = None  # (cid, data_max, data_min, ext)
        self.sent = 0
        self.running = True

    def hold(self, name, on):
        with self.lock:
            if on:
                self.holds.add(name)
            else:
                self.holds.discard(name)

    def burst(self, name, secs):
        with self.lock:
            self.bursts[name] = now() + secs

    def clear(self):
        with self.lock:
            self.holds.clear()
            self.bursts.clear()

    def active(self, t=None):
        t = t or now()
        with self.lock:
            return set(self.holds) | {n for n, u in self.bursts.items() if u > t}

    def build(self, name):
        if name == "speed":   # 240.00 km/h, counter stuck at 0, wrong checksum
            return ID_SPEED, bytes([0x5D, 0xC0, 0x00, 0x00]), False
        if name == "rpm":
            return ID_ENGINE, bytes([0x1E, 0x78, 100, 130, 0, 0, 0, 0]), False
        if name == "doors":
            return ID_DOORS, bytes([0x00, 0x00]), False
        if name == "mil":
            return ID_WARN, bytes([0x07, 0, 0, 0]), False
        if name == "fuzz":
            n = max(1, min(8, self.fuzz_len))
            return self.fuzz_id, bytes(random.getrandbits(8) for _ in range(n)), self.fuzz_id > 0x7FF
        if name in ("ovr_max", "ovr_min") and self.override:
            cid, mx, mn, ext = self.override
            return cid, (mx if name == "ovr_max" else mn), ext
        return None

    def run(self):
        while self.running:
            act = self.active()
            if act and self.allowed():
                for name in act:
                    f = self.build(name)
                    if not f:
                        continue
                    try:
                        self.bus.send(can.Message(arbitration_id=f[0], data=f[1], is_extended_id=f[2]))
                        self.sent += 1
                    except Exception:
                        pass
            if self.drain_own:
                drain(self.bus)
            time.sleep(0.005)


# ======================================================================
#  Intrusion detection: frequency baseline + rolling counter check
# ======================================================================
class IDS:
    LEARN = 6.0

    def __init__(self):
        self.enabled = True
        self.reset()

    def reset(self):
        self.start = now()
        self.learning = True
        self.baseline = {}
        self.alerts = deque(maxlen=16)
        self.cool = {}
        self.last_eval = 0.0
        self.last_hit = 0.0
        self.last_msg = ""
        self.live = {}

    def alert(self, key, sev, text, t):
        if t - self.cool.get(key, -99) < 2.5:
            return
        self.cool[key] = t
        self.alerts.appendleft((t - self.start, sev, text))
        if sev != "info":
            self.last_hit = t
            self.last_msg = text

    def evaluate(self, rows, ctr_err, t):
        if not self.enabled or t - self.last_eval < 0.25:
            return
        self.last_eval = t
        rates = {r[0]: r[3] for r in rows}
        self.live = rates
        if self.learning:
            if t - self.start >= self.LEARN:
                self.baseline = {k: max(1, v) for k, v in rates.items()}
                self.learning = False
                self.alert(("learn",), "info", f"Baseline learned: {len(self.baseline)} IDs. Monitoring.", t)
            return
        for cid, r in rates.items():
            b = self.baseline.get(cid)
            if b is None:
                if r > 0:
                    self.alert(("new", cid), "warn", f"UNKNOWN ID 0x{cid:03X} appeared ({r} Hz)", t)
            elif r > b * 1.6 + 4:
                self.alert(("rate", cid), "crit", f"RATE SPIKE 0x{cid:03X}: {r} Hz vs {b} Hz -> injection", t)
        if ctr_err > 5:
            self.alert(("ctr",), "crit", f"COUNTER BREAK 0x{ID_SPEED:03X}: {ctr_err}/s -> spoofed frames", t)


# ======================================================================
#  Bus opening
# ======================================================================
def make_bus(**kw):
    try:
        return can.Bus(**kw)
    except TypeError:  # very old python-can
        kw["bustype"] = kw.pop("interface")
        return can.Bus(**kw)


def autodetect():
    acm = sorted(glob.glob("/dev/ttyACM*"))
    if acm:
        return "slcan", acm[0]
    if os.path.exists("/sys/class/net/can0"):
        return "socketcan", "can0"
    return "sim", None


def open_buses(args):
    iface, chan = args.iface, args.channel
    if iface == "auto":
        iface, auto_chan = autodetect()
        chan = chan or auto_chan
    fallback = None
    if iface != "sim":
        try:
            if iface == "slcan":
                chan = chan or "/dev/ttyACM0"
                bus = make_bus(interface="slcan", channel=chan, bitrate=args.bitrate)
                label = f"SLCAN {chan} @ {args.bitrate // 1000}k"
            else:
                chan = chan or "can0"
                bus = make_bus(interface="socketcan", channel=chan)
                label = f"SocketCAN {chan}"
            return {"kind": "real", "label": label, "rx": bus, "tx": bus, "car": None,
                    "chan": os.path.basename(chan)}
        except Exception as e:
            print(f"[{APP}] could not open {iface} {chan}: {e}  -> falling back to SIM", file=sys.stderr)
            fallback = f"SIM (no {iface} on {chan})"
    ch = f"cansole-{os.getpid()}"
    return {"kind": "sim", "label": fallback or "SIM - virtual car",
            "rx": make_bus(interface="virtual", channel=ch),
            "tx": make_bus(interface="virtual", channel=ch),
            "car": make_bus(interface="virtual", channel=ch),
            "chan": "vcan0"}


# ======================================================================
#  Drawing helpers
# ======================================================================
def mkfont(size, bold=False):
    f = None
    try:
        f = pygame.font.SysFont("dejavusansmono,liberationmono,menlo,consolas,couriernew", size, bold=bold)
    except Exception:
        f = None
    return f or pygame.font.Font(None, int(size * 1.3))


class Gauge:
    START, SWEEP = 225.0, 270.0

    def __init__(self, center, radius, vmin, vmax, major, minors, label_div=1, red_from=None, font=None):
        self.cx, self.cy = center
        self.r = radius
        self.vmin, self.vmax = vmin, vmax
        self.major, self.minors = major, minors
        self.label_div = label_div
        self.red_from = red_from
        self.font = font
        self.disp = vmin
        self.bg = self._render_bg()

    def ang(self, v):
        t = (v - self.vmin) / float(self.vmax - self.vmin)
        return math.radians(self.START - self.SWEEP * max(0.0, min(1.0, t)))

    @staticmethod
    def pt(c, a, rr):
        return (c[0] + math.cos(a) * rr, c[1] - math.sin(a) * rr)

    def _render_bg(self):
        size = self.r * 2 + 8
        s = pygame.Surface((size, size), pygame.SRCALPHA)
        c = (size // 2, size // 2)
        pygame.draw.circle(s, PANEL, c, self.r)
        pygame.draw.circle(s, LINE, c, self.r, 3)
        if self.red_from is not None:
            steps = 40
            span = self.vmax - self.red_from
            for i in range(steps):
                v0 = self.red_from + span * i / steps
                v1 = self.red_from + span * (i + 1) / steps
                a0, a1 = self.ang(v0), self.ang(v1)
                quad = [self.pt(c, a0, self.r - 6), self.pt(c, a1, self.r - 6),
                        self.pt(c, a1, self.r - 18), self.pt(c, a0, self.r - 18)]
                pygame.draw.polygon(s, (150, 32, 26), quad)
        step = self.major / self.minors
        n = int(round((self.vmax - self.vmin) / step))
        for i in range(n + 1):
            v = self.vmin + i * step
            a = self.ang(v)
            is_major = i % self.minors == 0
            r0 = self.r - (30 if is_major else 18)
            col = FG if is_major else DIM
            pygame.draw.line(s, col, self.pt(c, a, r0), self.pt(c, a, self.r - 6), 3 if is_major else 1)
            if is_major and self.font:
                lab = self.font.render(str(int(v / self.label_div)), True, FG)
                s.blit(lab, lab.get_rect(center=self.pt(c, a, self.r - 50)))
        return s

    def draw(self, surf, value, alive=True):
        target = value if (alive and value is not None) else self.vmin
        self.disp += (target - self.disp) * 0.45
        surf.blit(self.bg, (self.cx - self.r - 4, self.cy - self.r - 4))
        a = self.ang(self.disp)
        c = (self.cx, self.cy)
        tip = self.pt(c, a, self.r - 22)
        tail = self.pt(c, a + math.pi, 20)
        l = self.pt(c, a + math.pi / 2, 6)
        r = self.pt(c, a - math.pi / 2, 6)
        col = RED if alive else LINE
        pygame.draw.polygon(surf, col, [tip, l, tail, r])
        pygame.draw.aalines(surf, col, True, [tip, l, tail, r])
        pygame.draw.circle(surf, PANEL2, c, 14)
        pygame.draw.circle(surf, LINE, c, 14, 2)


# ======================================================================
#  The app
# ======================================================================
BTN_CONST = [("A", "CONTROLLER_BUTTON_A"), ("B", "CONTROLLER_BUTTON_B"), ("X", "CONTROLLER_BUTTON_X"),
             ("Y", "CONTROLLER_BUTTON_Y"), ("MINUS", "CONTROLLER_BUTTON_BACK"),
             ("HOME", "CONTROLLER_BUTTON_GUIDE"), ("PLUS", "CONTROLLER_BUTTON_START"),
             ("LSTICK", "CONTROLLER_BUTTON_LEFTSTICK"), ("RSTICK", "CONTROLLER_BUTTON_RIGHTSTICK"),
             ("L", "CONTROLLER_BUTTON_LEFTSHOULDER"), ("R", "CONTROLLER_BUTTON_RIGHTSHOULDER"),
             ("UP", "CONTROLLER_BUTTON_DPAD_UP"), ("DOWN", "CONTROLLER_BUTTON_DPAD_DOWN"),
             ("LEFT", "CONTROLLER_BUTTON_DPAD_LEFT"), ("RIGHT", "CONTROLLER_BUTTON_DPAD_RIGHT"),
             ("CAPTURE", "CONTROLLER_BUTTON_MISC1")]
CTRL_BTN = {getattr(pygame, c): n for n, c in BTN_CONST if hasattr(pygame, c)}

# Raw-joystick fallback (Linux hid-nintendo evdev order). Override with ~/.config/cansole/joymap.json
JOY_DEFAULT = {0: "B", 1: "A", 2: "X", 3: "Y", 4: "CAPTURE", 5: "L", 6: "R", 7: "ZL", 8: "ZR",
               9: "MINUS", 10: "PLUS", 11: "HOME", 12: "LSTICK", 13: "RSTICK",
               14: "UP", 15: "DOWN", 16: "LEFT", 17: "RIGHT"}

KEYMAP = {pygame.K_q: "L", pygame.K_e: "R", pygame.K_TAB: "R", pygame.K_LSHIFT: "ZL", pygame.K_SPACE: "ZR",
          pygame.K_j: "A", pygame.K_k: "B", pygame.K_i: "X", pygame.K_u: "Y",
          pygame.K_UP: "UP", pygame.K_DOWN: "DOWN", pygame.K_LEFT: "LEFT", pygame.K_RIGHT: "RIGHT",
          pygame.K_t: "PLUS", pygame.K_h: "MINUS", pygame.K_F12: "CAPTURE", pygame.K_r: "LSTICK"}


def load_joymap():
    p = os.path.expanduser("~/.config/cansole/joymap.json")
    m = dict(JOY_DEFAULT)
    try:
        import json
        with open(p) as fp:
            m.update({int(k): v for k, v in json.load(fp).items()})
    except Exception:
        pass
    return m


class App:
    TABS = ["CLUSTER", "SNIFFER", "IDS"]

    def __init__(self, args):
        self.args = args
        pygame.init()
        flags = pygame.SCALED | (0 if args.windowed else pygame.FULLSCREEN)
        try:
            self.screen = pygame.display.set_mode((W, H), flags)
        except pygame.error:
            self.screen = pygame.display.set_mode((W, H), 0 if args.windowed else pygame.FULLSCREEN)
        pygame.display.set_caption(f"{APP} {VERSION}")
        pygame.mouse.set_visible(bool(args.windowed))
        self.clock = pygame.time.Clock()

        self.f_xs = mkfont(14)
        self.f_s = mkfont(17)
        self.f = mkfont(20)
        self.f_b = mkfont(22, True)
        self.f_mid = mkfont(28, True)
        self.f_big = mkfont(46, True)
        self.f_huge = mkfont(112, True)
        self.tcache = {}

        self.state = BusState()
        self.ids = IDS()
        self.buses = open_buses(args)
        self.kind = self.buses["kind"]
        self.label = self.buses["label"]
        self.car = None
        if self.kind == "sim":
            self.car = FakeCar(self.buses["car"])
            self.car.start()
        self.reader = Reader(self.buses["rx"], self.state)
        self.reader.start()
        self.tx_armed = self.kind == "sim"
        self.attacker = Attacker(self.buses["tx"], lambda: self.tx_armed, drain_own=(self.kind == "sim"))
        self.attacker.start()

        gy = 300
        self.g_rpm = Gauge((230, gy), 190, 0, 8000, 1000, 4, 1000, 6500, self.f_b)
        self.g_spd = Gauge((1050, gy), 190, 0, 260, 20, 2, 1, None, self.f_b)
        self.g_pin = [Gauge((230, gy), 190, 0, 100, 10, 2, 1, 90, self.f_b),
                      Gauge((1050, gy), 190, 0, 100, 10, 2, 1, 90, self.f_b)]

        self.tab = 0
        self.sel_id = None
        self.byte_cur = 0
        self.scroll = 0
        self.pins = [None, None]
        self.next_slot = 0
        self.bit_prev = (None, b"")
        self.bit_times = [[0.0] * 8 for _ in range(8)]
        self.toast_msg, self.toast_until = "", 0.0
        self.help = False
        self.quit = False
        self.held = set()
        self.plus_t = None
        self.stick_y = 0.0
        self.kb_gas = self.kb_brake = False
        self.last_input = now() - (1e6 if args.attract else 0)
        self.attract_t0 = now()
        self.attract_active = False
        self.last_btn = ""
        self.mouse_holds = []
        self.hit = []           # (rect, action, arg) touch targets rebuilt every frame
        self.rows, self.rx_rate, self.ctr_err = [], 0, 0
        self.frames = {}
        self.ctrls, self.ctrl_ids, self.joys = {}, set(), {}
        self.joymap = load_joymap()
        if sdl_controller:
            try:
                sdl_controller.init()
            except Exception:
                pass
        if args.log:
            ok, path = self.state.toggle_log(self.buses["chan"])
            print(f"[{APP}] logging to {path}")
        print(f"[{APP}] interface: {self.label}")

    # ------------------------------------------------------------ text --
    def text(self, s, font, color, pos, anchor="topleft"):
        key = (id(font), s, color)
        surf = self.tcache.get(key)
        if surf is None:
            if len(self.tcache) > 4000:
                self.tcache.clear()
            surf = font.render(s, True, color)
            self.tcache[key] = surf
        r = surf.get_rect(**{anchor: pos})
        self.screen.blit(surf, r)
        return r

    def toast(self, msg, secs=2.2):
        self.toast_msg, self.toast_until = msg, now() + secs

    # ---------------------------------------------------------- input --
    def open_device(self, idx, as_ctrl):
        try:
            if as_ctrl and sdl_controller and sdl_controller.is_controller(idx):
                c = sdl_controller.Controller(idx)
                iid = c.as_joystick().get_instance_id()
                if iid not in self.ctrls:
                    self.ctrls[iid] = c
                    self.ctrl_ids.add(iid)
                    self.toast(f"Controller: {c.name}")
            elif not as_ctrl and not (sdl_controller and sdl_controller.is_controller(idx)):
                j = pygame.joystick.Joystick(idx)
                j.init()
                if j.get_instance_id() not in self.joys:
                    self.joys[j.get_instance_id()] = j
                    self.toast(f"Joystick: {j.get_name()}")
        except Exception as e:
            print(f"[{APP}] device {idx}: {e}", file=sys.stderr)

    def handle(self, ev):
        T = ev.type
        if T == pygame.QUIT:
            self.quit = True
        elif T == pygame.KEYDOWN:
            if ev.key == pygame.K_ESCAPE:
                self.quit = True
            elif ev.key == pygame.K_w:
                self.kb_gas = True
                self.touch()
            elif ev.key == pygame.K_s:
                self.kb_brake = True
                self.touch()
            elif ev.key in KEYMAP:
                self.press(KEYMAP[ev.key])
        elif T == pygame.KEYUP:
            if ev.key == pygame.K_w:
                self.kb_gas = False
            elif ev.key == pygame.K_s:
                self.kb_brake = False
            elif ev.key in KEYMAP:
                self.release(KEYMAP[ev.key])
        elif T == getattr(pygame, "CONTROLLERDEVICEADDED", -1):
            self.open_device(ev.device_index, True)
        elif T == getattr(pygame, "CONTROLLERDEVICEREMOVED", -1):
            iid = getattr(ev, "instance_id", None)
            self.ctrls.pop(iid, None)
            self.ctrl_ids.discard(iid)
        elif T == getattr(pygame, "CONTROLLERBUTTONDOWN", -1):
            n = CTRL_BTN.get(ev.button)
            if n:
                self.press(n)
        elif T == getattr(pygame, "CONTROLLERBUTTONUP", -1):
            n = CTRL_BTN.get(ev.button)
            if n:
                self.release(n)
        elif T == getattr(pygame, "CONTROLLERAXISMOTION", -1):
            v = ev.value / 32767.0
            if ev.axis == getattr(pygame, "CONTROLLER_AXIS_LEFTY", 1):
                self.stick(v)
            elif ev.axis in (getattr(pygame, "CONTROLLER_AXIS_TRIGGERLEFT", 4),
                             getattr(pygame, "CONTROLLER_AXIS_TRIGGERRIGHT", 5)):
                b = "ZL" if ev.axis == getattr(pygame, "CONTROLLER_AXIS_TRIGGERLEFT", 4) else "ZR"
                if v > 0.5 and b not in self.held:
                    self.press(b)
                elif v < 0.25 and b in self.held:
                    self.release(b)
        elif T == pygame.JOYDEVICEADDED:
            self.open_device(ev.device_index, False)
        elif T == pygame.JOYDEVICEREMOVED:
            self.joys.pop(getattr(ev, "instance_id", None), None)
        elif T in (pygame.JOYBUTTONDOWN, pygame.JOYBUTTONUP):
            if getattr(ev, "instance_id", None) in self.ctrl_ids:
                return
            n = self.joymap.get(ev.button)
            self.last_btn = f"raw btn {ev.button} -> {n}"
            if n:
                (self.press if T == pygame.JOYBUTTONDOWN else self.release)(n)
        elif T == pygame.JOYHATMOTION:
            if getattr(ev, "instance_id", None) in self.ctrl_ids:
                return
            x, y = ev.value
            for b, on in (("LEFT", x < 0), ("RIGHT", x > 0), ("UP", y > 0), ("DOWN", y < 0)):
                if on and b not in self.held:
                    self.press(b)
                elif not on and b in self.held:
                    self.release(b)
        elif T == pygame.JOYAXISMOTION:
            if getattr(ev, "instance_id", None) in self.ctrl_ids:
                return
            if ev.axis == 1:
                self.stick(ev.value)
        elif T == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            self.tap(ev.pos)
        elif T == pygame.MOUSEBUTTONUP and ev.button == 1:
            for b in self.mouse_holds:
                self.release(b)
            self.mouse_holds = []

    def touch(self):
        self.last_input = now()
        if self.attract_active:
            self.attract_active = False
            self.attacker.clear()
            if self.car:
                self.car.blink_l = self.car.blink_r = False

    def stick(self, v):
        if abs(v) > 0.15:
            self.touch()
        self.stick_y = v

    def tap(self, pos):
        self.touch()
        for rect, action, arg in reversed(self.hit):
            if rect.collidepoint(pos):
                if action == "tab":
                    self.tab = arg
                elif action == "quit":
                    self.quit = True
                elif action == "help":
                    self.help = not self.help
                elif action == "hold":
                    self.press(arg)
                    self.mouse_holds.append(arg)
                elif action == "tapbtn":
                    self.press(arg)
                    self.release(arg)
                elif action == "row":
                    self.sel_id = arg
                elif action == "byte":
                    self.sel_id, self.byte_cur = arg
                return
        if self.help:
            self.help = False

    def can_tx(self, quiet=False):
        if self.tx_armed:
            return True
        if not quiet:
            if self.args.allow_tx:
                self.toast("TX is locked - hold + for 2 s to arm (ask the bus owner first)")
            else:
                self.toast("Read-only bus. Relaunch with --allow-tx (and get permission) to transmit")
        return False

    def press(self, b):
        self.held.add(b)
        self.touch()
        self.last_btn = self.last_btn if self.last_btn.startswith("raw") else b
        if self.help and b not in ("MINUS",):
            self.help = False
            return
        if b == "MINUS":
            if "PLUS" in self.held:
                self.quit = True
            else:
                self.help = not self.help
            return
        if b == "PLUS":
            if "MINUS" in self.held:
                self.quit = True
            self.plus_t = now()
            return
        if b == "L":
            self.tab = (self.tab - 1) % 3
        elif b == "R":
            self.tab = (self.tab + 1) % 3
        elif b == "CAPTURE":
            self.screenshot()
        elif b == "LSTICK":
            on, path = self.state.toggle_log(self.buses["chan"])
            self.toast(("REC -> " if on else "Saved ") + path, 3)
        elif b in ("ZR", "ZL"):
            self.attack_hold(b, True)
        elif b == "X":
            self.ids.enabled = not self.ids.enabled
            if self.ids.enabled:
                self.ids.reset()
                self.toast("IDS on - learning baseline for 6 s")
            else:
                self.toast("IDS off")
        elif self.tab == 1:
            self.press_sniffer(b)
        elif self.tab == 0:
            self.press_cluster(b)
        elif self.tab == 2:
            if b == "A":
                self.ids.reset()
                self.toast("Re-learning baseline")
            elif b == "B":
                self.ids.alerts.clear()

    def release(self, b):
        self.held.discard(b)
        if b in ("ZR", "ZL"):
            self.attack_hold(b, False)
        if b == "PLUS":
            self.plus_t = None

    def attack_hold(self, b, on):
        if self.kind == "sim":
            self.attacker.hold("speed" if b == "ZR" else "rpm", on)
            return
        name = "ovr_max" if b == "ZR" else "ovr_min"
        if not on:
            self.attacker.hold(name, False)
            return
        if not self.can_tx():
            return
        tpl = self.override_template()
        if not tpl:
            self.toast("Pin a signal in SNIFFER first (A on a byte)")
            return
        self.attacker.override = tpl
        self.attacker.hold(name, True)

    def override_template(self):
        pin = self.pins[0] or self.pins[1]
        if pin:
            cid, off, w = pin["cid"], pin["off"], pin["w"]
        elif self.sel_id is not None:
            cid, off, w = self.sel_id, self.byte_cur, 1
        else:
            return None
        cur = self.frames.get(cid)
        if not cur:
            return None
        data = bytearray(cur[0])
        if off + w > len(data):
            return None
        mx, mn = bytearray(data), bytearray(data)
        for i in range(off, off + w):
            mx[i], mn[i] = 0xFF, 0x00
        return cid, bytes(mx), bytes(mn), cid > 0x7FF

    def fuzz(self, cid):
        if cid is None:
            self.toast("Select an ID first")
            return
        if not self.can_tx():
            return
        cur = self.frames.get(cid)
        self.attacker.fuzz_id = cid
        self.attacker.fuzz_len = len(cur[0]) if cur and cur[0] else 8
        self.attacker.burst("fuzz", 2.0)
        self.toast(f"Fuzzing 0x{cid:03X} for 2 s")

    def press_cluster(self, b):
        if b in ("LEFT", "RIGHT") and self.car:
            if b == "LEFT":
                self.car.blink_l, self.car.blink_r = not self.car.blink_l, False
            else:
                self.car.blink_r, self.car.blink_l = not self.car.blink_r, False
        elif b == "A":
            if self.kind == "sim":
                self.attacker.burst("doors", 1.5)
                self.toast("Spoofing 0x3E0: unlock all doors")
            else:
                self.tab = 1
        elif b == "B":
            if self.kind == "sim":
                self.attacker.burst("mil", 3.0)
                self.toast("Spoofing 0x2F0: warning lights")
        elif b == "Y":
            self.fuzz(ID_SPEED if self.kind == "sim" else self.sel_id)

    def press_sniffer(self, b):
        ids = [r[0] for r in self.rows]
        if not ids:
            return
        i = ids.index(self.sel_id) if self.sel_id in ids else 0
        if b == "UP":
            self.sel_id = ids[(i - 1) % len(ids)]
        elif b == "DOWN":
            self.sel_id = ids[(i + 1) % len(ids)]
        elif b == "LEFT":
            self.byte_cur = max(0, self.byte_cur - 1)
        elif b == "RIGHT":
            self.byte_cur = min(7, self.byte_cur + 1)
        elif b == "A":
            self.pin_selected()
        elif b == "B":
            self.pins = [None, None]
            self.next_slot = 0
            self.toast("Pins cleared - gauges back to default")
        elif b == "Y":
            self.fuzz(self.sel_id)

    def pin_selected(self):
        row = next((r for r in self.rows if r[0] == self.sel_id), None)
        if not row:
            return
        cid, data, changed, _, _, _, first, _ = row
        off = self.byte_cur
        if off >= len(data):
            self.toast("That ID has no byte there")
            return
        for k, p in enumerate(self.pins):
            if p and p["cid"] == cid and p["off"] == off:
                self.pins[k] = None
                self.toast(f"Unpinned 0x{cid:03X}")
                return
        w = 2 if off + 1 < len(data) and changed[off + 1] > first + 0.5 else 1
        if self.pins[0] is None:
            slot = 0
        elif self.pins[1] is None:
            slot = 1
        else:
            slot = self.next_slot
        self.next_slot = 1 - slot
        self.pins[slot] = {"cid": cid, "off": off, "w": w, "lo": None, "hi": None, "raw": None}
        side = "LEFT" if slot == 0 else "RIGHT"
        self.toast(f"Pinned 0x{cid:03X} bytes[{off}:{off + w}] -> {side} gauge (auto-scaled)")

    def screenshot(self):
        d = os.path.expanduser("~/Pictures/CANsole")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, datetime.now().strftime("cansole_%Y%m%d_%H%M%S.png"))
        pygame.image.save(self.screen, p)
        self.toast(f"Screenshot saved: {p}")

    # --------------------------------------------------------- update --
    def attract(self, t):
        p = (t - self.attract_t0) % 40
        car = self.car
        car.throttle = 0.85 if p < 9 else 0.35 if p < 20 else 0.15 if p < 30 else 0.6 if p < 36 else 0.0
        car.brake = 0.6 if p >= 36 else 0.0
        car.blink_l = 9 <= p < 13
        self.tab = 0 if p < 20 else 2 if p < 30 else 1
        self.attacker.hold("speed", 12 <= p < 16 or 23 <= p < 26)
        self.attacker.hold("rpm", 16 <= p < 18)
        self.attacker.hold("doors", 18 <= p < 19.5)
        self.attacker.hold("mil", 19.5 <= p < 21)
        if self.tab == 1 and self.rows:
            ids = [r[0] for r in self.rows]
            self.sel_id = ids[int(p - 30) % len(ids)]
            self.byte_cur = 0

    def update(self, t):
        self.rows, self.rx_rate, self.ctr_err = self.state.snapshot(t)
        self.frames = {r[0]: (r[1], r[5], r[3]) for r in self.rows}
        if self.sel_id is None and self.rows:
            self.sel_id = self.rows[0][0]

        idle = t - self.last_input
        if self.args.attract and self.car and idle > 30:
            if not self.attract_active:
                self.attract_active = True
                self.attract_t0 = t
            self.attract(t)
        elif self.car:
            gas = max(0.0, -self.stick_y)
            brk = max(0.0, self.stick_y)
            if self.kb_gas:
                gas = 1.0
            if self.kb_brake:
                brk = 1.0
            self.car.throttle = gas if gas > 0.12 else 0.0
            self.car.brake = brk if brk > 0.12 else 0.0

        if self.plus_t and t - self.plus_t >= 2.0:
            self.plus_t = None
            if self.kind == "sim":
                self.toast("SIM mode: TX is always on (it's a virtual car)")
            elif self.args.allow_tx:
                self.tx_armed = not self.tx_armed
                if not self.tx_armed:
                    self.attacker.clear()
                self.toast("TX ARMED - you are now transmitting on a real bus" if self.tx_armed
                           else "TX disarmed - read-only", 3)
            else:
                self.toast("Read-only bus. Relaunch with --allow-tx (and get permission) to transmit")

        self.ids.evaluate(self.rows, self.ctr_err, t)

        sel = self.frames.get(self.sel_id)
        if sel is not None:
            data = sel[0]
            pid, pdata = self.bit_prev
            if pid != self.sel_id:
                self.bit_times = [[0.0] * 8 for _ in range(8)]
            elif data != pdata:
                for bi in range(min(len(data), len(pdata), 8)):
                    x = data[bi] ^ pdata[bi]
                    for bit in range(8):
                        if x & (0x80 >> bit):
                            self.bit_times[bi][bit] = t
            self.bit_prev = (self.sel_id, data)

    def signals(self, t):
        s = {}

        def fresh(cid):
            f = self.frames.get(cid)
            return f[0] if f and t - f[1] < 1.0 else None

        d = fresh(ID_ENGINE)
        if d and len(d) >= 4:
            s["rpm"] = (d[0] << 8) | d[1]
            s["thr"] = d[2]
            s["cool"] = d[3] - 40
        d = fresh(ID_SPEED)
        if d and len(d) >= 2:
            s["spd"] = ((d[0] << 8) | d[1]) / 100.0
        d = fresh(ID_LIGHTS)
        if d:
            s["blink"] = d[0]
        d = fresh(ID_WARN)
        if d:
            s["warn"] = d[0]
        d = fresh(ID_DOORS)
        if d:
            s["doors"] = d[0]
        return s

    def pin_pct(self, pin, t):
        f = self.frames.get(pin["cid"])
        if not f or t - f[1] > 1.5:
            return None
        data = f[0]
        o, w = pin["off"], pin["w"]
        if len(data) < o + w:
            return None
        raw = int.from_bytes(data[o:o + w], "big")
        pin["raw"] = raw
        pin["lo"] = raw if pin["lo"] is None else min(pin["lo"], raw)
        pin["hi"] = raw if pin["hi"] is None else max(pin["hi"], raw)
        span = pin["hi"] - pin["lo"]
        return (raw - pin["lo"]) * 100.0 / span if span else 0.0

    # ----------------------------------------------------------- draw --
    def draw(self, t):
        self.screen.fill(BG)
        self.hit = []
        self.draw_header(t)
        [self.draw_cluster, self.draw_sniffer, self.draw_ids][self.tab](t)
        self.draw_footer(t)
        if self.help:
            self.draw_help()
        if self.toast_msg and t < self.toast_until:
            surf = self.f.render(self.toast_msg, True, FG)
            r = surf.get_rect(midbottom=(W // 2, H - 48)).inflate(36, 18)
            pygame.draw.rect(self.screen, PANEL2, r, border_radius=10)
            pygame.draw.rect(self.screen, CYAN, r, 2, border_radius=10)
            self.screen.blit(surf, surf.get_rect(center=r.center))

    def draw_header(self, t):
        pygame.draw.rect(self.screen, PANEL, (0, 0, W, 56))
        pygame.draw.line(self.screen, LINE, (0, 56), (W, 56))
        r = self.text("CAN", self.f_mid, RED, (18, 12))
        self.text("sole", self.f_mid, FG, (r.right, 12))
        for i, name in enumerate(self.TABS):
            rect = pygame.Rect(250 + i * 150, 10, 140, 36)
            on = i == self.tab
            pygame.draw.rect(self.screen, RED if on else PANEL2, rect, border_radius=8)
            self.text(name, self.f_b, (255, 255, 255) if on else DIM, rect.center, "center")
            self.hit.append((rect, "tab", i))
        err = self.reader.error
        self.text(self.label if not err else f"BUS ERROR: {err}", self.f_s, CYAN if not err else RED,
                  (1150, 8), "topright")
        tx = "TX: SIM" if self.kind == "sim" else ("TX ARMED" if self.tx_armed else "TX LOCKED (read-only)")
        txc = AMBER if self.kind == "sim" else (RED if self.tx_armed else GREEN)
        rec = "  REC" if self.state.log_fp else ""
        r = self.text(f"{self.rx_rate} msg/s   {len(self.rows)} IDs   ", self.f_s, DIM, (700, 32))
        r = self.text(tx, self.f_s, txc, (r.right, 32))
        if rec:
            self.text(rec, self.f_s, RED, (r.right, 32))
        qb = pygame.Rect(W - 50, 10, 38, 36)
        pygame.draw.rect(self.screen, PANEL2, qb, border_radius=8)
        self.text("X", self.f_b, DIM, qb.center, "center")
        self.hit.append((qb, "quit", None))
        hb = pygame.Rect(W - 96, 10, 38, 36)
        pygame.draw.rect(self.screen, PANEL2, hb, border_radius=8)
        self.text("?", self.f_b, DIM, hb.center, "center")
        self.hit.append((hb, "help", None))
        if self.plus_t:
            p = min(1.0, (t - self.plus_t) / 2.0)
            pygame.draw.rect(self.screen, RED, (0, 54, int(W * p), 4))

    # --- cluster
    def draw_cluster(self, t):
        s = self.signals(t)
        for side in (0, 1):
            pin = self.pins[side]
            g = self.g_pin[side] if pin else (self.g_rpm if side == 0 else self.g_spd)
            if pin:
                pct = self.pin_pct(pin, t)
                g.draw(self.screen, pct, pct is not None)
                self.text(f"0x{pin['cid']:03X} [{pin['off']}:{pin['off'] + pin['w']}]", self.f_b, AMBER,
                          (g.cx, g.cy + 70), "center")
                raw = pin["raw"]
                self.text("--" if pct is None else f"{raw}", self.f_big, FG, (g.cx, g.cy + 112), "center")
                if pin["lo"] is not None:
                    self.text(f"min {pin['lo']}  max {pin['hi']}", self.f_s, DIM, (g.cx, g.cy + 150), "center")
            elif side == 0:
                rpm = s.get("rpm")
                g.draw(self.screen, rpm, rpm is not None)
                self.text("RPM x1000", self.f_s, DIM, (g.cx, g.cy + 70), "center")
                self.text("--" if rpm is None else f"{rpm}", self.f_big, FG, (g.cx, g.cy + 112), "center")
            else:
                spd = s.get("spd")
                g.draw(self.screen, spd, spd is not None)
                self.text("km/h", self.f_s, DIM, (g.cx, g.cy + 70), "center")
                self.text("--" if spd is None else f"{spd:.0f}", self.f_big, FG, (g.cx, g.cy + 112), "center")

        cx = W // 2
        blink = s.get("blink", 0)
        self.arrow(cx - 120, 104, True, bool(blink & 1))
        self.arrow(cx + 120, 104, False, bool(blink & 2))
        spd = s.get("spd")
        self.text("--" if spd is None else f"{spd:.0f}", self.f_huge, FG, (cx, 180), "center")
        self.text("km/h", self.f_s, DIM, (cx, 246), "center")
        if "rpm" in s:
            self.text(f"throttle {s['thr']}%   coolant {s['cool']}C", self.f_s, DIM, (cx, 272), "center")
        elif self.kind == "real":
            self.text("Real bus: pin signals in SNIFFER", self.f_s, AMBER, (cx, 272), "center")
        self.draw_doors(cx, 356, s.get("doors"))
        warn = s.get("warn")
        for i, name in enumerate(("ENGINE", "OIL", "BATT")):
            rect = pygame.Rect(0, 0, 104, 34)
            rect.center = (cx - 116 + i * 116, 492)
            on = warn is not None and bool(warn & (1 << i))
            col = (AMBER if i == 0 else RED) if on else LINE
            pygame.draw.rect(self.screen, col if on else PANEL, rect, 0 if on else 2, border_radius=6)
            self.text(name, self.f_b, (20, 20, 20) if on else DIM, rect.center, "center")

        if self.ids.enabled and t - self.ids.last_hit < 3.0:
            band = pygame.Rect(0, 516, W, 40)
            pygame.draw.rect(self.screen, (120, 18, 14) if int(t * 4) % 2 else RED, band)
            self.text("!! INTRUSION DETECTED  -  " + self.ids.last_msg, self.f_b, (255, 255, 255),
                      band.center, "center")

        if self.kind == "sim":
            btns = [("SPOOF SPEED", "hold", "ZR", "ZR"), ("REDLINE RPM", "hold", "ZL", "ZL"),
                    ("UNLOCK DOORS", "tapbtn", "A", "A"), ("WARNING LIGHTS", "tapbtn", "B", "B"),
                    ("FUZZ 0x1A0", "tapbtn", "Y", "Y")]
        else:
            btns = [("OVERRIDE MAX", "hold", "ZR", "ZR"), ("OVERRIDE MIN", "hold", "ZL", "ZL"),
                    ("FUZZ SELECTED", "tapbtn", "Y", "Y"), ("GO SNIFF", "tapbtn", "A", "A")]
        active = self.attacker.active(t)
        live = {"ZR": {"speed", "ovr_max"}, "ZL": {"rpm", "ovr_min"}, "A": {"doors"},
                "B": {"mil"}, "Y": {"fuzz"}}
        bw = 194
        for i, (lab, kind, arg, hint) in enumerate(btns):
            rect = pygame.Rect(18 + i * (bw + 12), 568, bw, 74)
            on = bool(active & live.get(arg, set()))
            pygame.draw.rect(self.screen, RED if on else PANEL2, rect, border_radius=12)
            pygame.draw.rect(self.screen, RED, rect, 2, border_radius=12)
            self.text(lab, self.f_b, (255, 255, 255), (rect.centerx, rect.y + 26), "center")
            self.text(f"[{hint}]", self.f_s, (255, 220, 210) if on else DIM, (rect.centerx, rect.y + 54), "center")
            self.hit.append((rect, kind, arg))
        panel = pygame.Rect(1048, 568, 214, 74)
        pygame.draw.rect(self.screen, PANEL, panel, border_radius=12)
        self.text(f"spoofed TX  {self.attacker.sent}", self.f_s, AMBER, (panel.x + 14, panel.y + 12))
        self.text(f"ctr errors  {self.ctr_err}/s", self.f_s, RED if self.ctr_err > 5 else DIM,
                  (panel.x + 14, panel.y + 40))

    def arrow(self, cx, cy, left, on):
        s = -1 if left else 1
        pts = [(cx + s * 30, cy), (cx + s * 6, cy - 24), (cx + s * 6, cy - 10), (cx - s * 26, cy - 10),
               (cx - s * 26, cy + 10), (cx + s * 6, cy + 10), (cx + s * 6, cy + 24)]
        pygame.draw.polygon(self.screen, GREEN if on else PANEL2, pts)

    def draw_doors(self, cx, cy, mask):
        body = pygame.Rect(0, 0, 86, 150)
        body.center = (cx, cy)
        pygame.draw.rect(self.screen, PANEL2, body, border_radius=26)
        pygame.draw.rect(self.screen, LINE, body, 2, border_radius=26)
        pygame.draw.rect(self.screen, LINE, (cx - 30, cy - 52, 60, 22), border_radius=6)
        for i, (dx, dy) in enumerate(((-52, -22), (52, -22), (-52, 26), (52, 26))):
            r = pygame.Rect(0, 0, 14, 42)
            r.center = (cx + dx, cy + dy)
            col = LINE if mask is None else (GREEN if mask & (1 << i) else RED)
            pygame.draw.rect(self.screen, col, r, border_radius=4)
        if mask is None:
            lab, col = "DOORS --", DIM
        elif mask & 0x0F == 0x0F:
            lab, col = "LOCKED", GREEN
        else:
            lab, col = "UNLOCKED!", RED
        self.text(lab, self.f_b, col, (cx, cy + 90), "center")

    # --- sniffer
    def draw_sniffer(self, t):
        top, rh = 96, 30
        maxrows = (650 - top) // rh
        ids = [r[0] for r in self.rows]
        sel_i = ids.index(self.sel_id) if self.sel_id in ids else 0
        if sel_i < self.scroll:
            self.scroll = sel_i
        elif sel_i >= self.scroll + maxrows:
            self.scroll = sel_i - maxrows + 1
        self.scroll = max(0, min(self.scroll, max(0, len(ids) - maxrows)))
        for x, h in ((24, "ID"), (120, "DLC"), (170, "DATA"), (606, "Hz"), (664, "COUNT"), (748, "NAME")):
            self.text(h, self.f_s, DIM, (x, 68))
        pinned = {(p["cid"], o) for p in self.pins if p for o in range(p["off"], p["off"] + p["w"])}
        for k, row in enumerate(self.rows[self.scroll:self.scroll + maxrows]):
            cid, data, changed, rate, count, last, first, ext = row
            y = top + k * rh
            rect = pygame.Rect(12, y - 2, 870, rh - 2)
            selected = cid == self.sel_id
            if selected:
                pygame.draw.rect(self.screen, PANEL2, rect, border_radius=6)
                pygame.draw.rect(self.screen, RED, (12, y - 2, 4, rh - 2))
            self.hit.append((rect, "row", cid))
            stale = t - last > 2.0
            self.text(f"{cid:08X}" if ext else f"{cid:03X}", self.f_b, DIM if stale else FG, (24, y))
            self.text(str(len(data)), self.f, DIM, (128, y + 2))
            for i in range(8):
                cell = pygame.Rect(170 + i * 54, y, 48, 24)
                if i < len(data):
                    age = t - changed[i]
                    if age < 0.3:
                        col = RED
                    elif age < 1.5:
                        k2 = (age - 0.3) / 1.2
                        col = tuple(int(RED[j] + (FG[j] - RED[j]) * k2) for j in range(3))
                    else:
                        col = DIM if stale else FG
                    self.text(f"{data[i]:02X}", self.f_b, col, cell.center, "center")
                    self.hit.append((cell, "byte", (cid, i)))
                    if (cid, i) in pinned:
                        pygame.draw.line(self.screen, AMBER, (cell.x + 8, cell.bottom), (cell.right - 8, cell.bottom), 3)
                if selected and i == self.byte_cur:
                    pygame.draw.rect(self.screen, CYAN, cell, 2, border_radius=4)
            self.text(str(rate), self.f, FG, (606, y + 2))
            self.text(str(count), self.f, DIM, (664, y + 2))
            if self.kind == "sim":
                self.text(NAMES.get(cid, ""), self.f_s, DIM, (748, y + 4))
        if not self.rows:
            self.text("Waiting for frames...", self.f_mid, DIM, (450, 300), "center")
            if self.kind == "real":
                self.text("Check wiring, bitrate (--bitrate) and that the bus is powered", self.f, DIM,
                          (450, 340), "center")
        if len(ids) > maxrows:
            self.text(f"{self.scroll + 1}-{min(len(ids), self.scroll + maxrows)} of {len(ids)}", self.f_s, DIM,
                      (870, 652), "topright")

        p = pygame.Rect(900, 66, 364, 610)
        pygame.draw.rect(self.screen, PANEL, p, border_radius=12)
        sel = self.frames.get(self.sel_id)
        if sel is None:
            return
        data, last, rate = sel
        self.text(f"0x{self.sel_id:03X}", self.f_big, FG, (p.x + 18, p.y + 10))
        if self.kind == "sim":
            self.text(NAMES.get(self.sel_id, ""), self.f, DIM, (p.x + 160, p.y + 26))
        self.text(f"{rate} Hz   {len(data)} bytes", self.f, DIM, (p.x + 18, p.y + 66))
        self.text("bit view (red = flipping)", self.f_s, DIM, (p.x + 18, p.y + 100))
        for bi in range(8):
            yy = p.y + 128 + bi * 26
            self.text(f"b{bi}", self.f_s, CYAN if bi == self.byte_cur else DIM, (p.x + 18, yy + 2))
            for bit in range(8):
                cell = pygame.Rect(p.x + 60 + bit * 24, yy, 20, 20)
                if bi >= len(data):
                    pygame.draw.rect(self.screen, PANEL2, cell, 1, border_radius=3)
                    continue
                v = (data[bi] >> (7 - bit)) & 1
                hot = t - self.bit_times[bi][bit] < 0.8
                col = RED if hot else (FG if v else PANEL2)
                pygame.draw.rect(self.screen, col, cell, border_radius=3)
            if bi < len(data):
                self.text(f"{data[bi]:3d}", self.f_s, DIM, (p.x + 260, yy + 2))
        y0 = p.y + 348
        for line in ("Up/Down  select ID", "Left/Right  byte cursor", "A  pin byte(s) to a gauge",
                     "B  clear pins", "Y  fuzz this ID (2 s)", "Tip: move a pedal/knob and", "watch which byte goes red"):
            self.text(line, self.f_s, DIM if not line.startswith(("Tip", "watch")) else AMBER, (p.x + 18, y0))
            y0 += 24
        pb = pygame.Rect(p.x + 18, p.bottom - 74, 150, 54)
        pygame.draw.rect(self.screen, PANEL2, pb, border_radius=10)
        pygame.draw.rect(self.screen, AMBER, pb, 2, border_radius=10)
        self.text("PIN [A]", self.f_b, AMBER, pb.center, "center")
        self.hit.append((pb, "tapbtn", "A"))
        fb = pygame.Rect(p.x + 190, p.bottom - 74, 150, 54)
        pygame.draw.rect(self.screen, PANEL2, fb, border_radius=10)
        pygame.draw.rect(self.screen, RED, fb, 2, border_radius=10)
        self.text("FUZZ [Y]", self.f_b, RED, fb.center, "center")
        self.hit.append((fb, "tapbtn", "Y"))

    # --- IDS
    def draw_ids(self, t):
        ids = self.ids
        if not ids.enabled:
            st, col = "IDS OFF  (press X to enable)", DIM
        elif ids.learning:
            st, col = f"LEARNING BASELINE  {max(0.0, ids.LEARN - (t - ids.start)):.1f}s  - don't attack yet", AMBER
        else:
            st, col = f"MONITORING  {len(ids.baseline)} IDs  |  rate + rolling-counter checks", GREEN
        self.text(st, self.f_b, col, (24, 70))
        lp = pygame.Rect(12, 106, 640, 540)
        pygame.draw.rect(self.screen, PANEL, lp, border_radius=12)
        self.text("ALERTS", self.f_b, FG, (lp.x + 16, lp.y + 12))
        sevcol = {"info": CYAN, "warn": AMBER, "crit": RED}
        for k, (ts, sev, txt) in enumerate(list(ids.alerts)[:13]):
            y = lp.y + 50 + k * 37
            pygame.draw.rect(self.screen, sevcol[sev], (lp.x + 16, y + 4, 6, 22))
            self.text(f"+{ts:6.1f}s", self.f_s, DIM, (lp.x + 30, y + 6))
            self.text(txt[:52], self.f_s, FG, (lp.x + 120, y + 6))
        if not ids.alerts:
            self.text("No alerts yet. Hold ZR to attack and watch this list.", self.f_s, DIM,
                      (lp.x + 16, lp.y + 56))

        rp = pygame.Rect(664, 106, 600, 540)
        pygame.draw.rect(self.screen, PANEL, rp, border_radius=12)
        self.text("RATE vs BASELINE (Hz)", self.f_b, FG, (rp.x + 16, rp.y + 12))
        rows = self.rows[:15]
        for k, row in enumerate(rows):
            cid, rate = row[0], row[3]
            base = ids.baseline.get(cid)
            y = rp.y + 52 + k * 31
            self.text(f"{cid:03X}", self.f, FG, (rp.x + 16, y))
            scale = max(rate, (base or 0) * 2, 60)
            bar_w = 360
            bx = rp.x + 80
            pygame.draw.rect(self.screen, PANEL2, (bx, y + 2, bar_w, 18), border_radius=4)
            anomal = base is not None and not ids.learning and rate > base * 1.6 + 4
            unknown = base is None and not ids.learning and ids.enabled
            col = RED if anomal else AMBER if unknown else GREEN
            pygame.draw.rect(self.screen, col, (bx, y + 2, int(bar_w * min(1.0, rate / scale)), 18), border_radius=4)
            if base:
                x = bx + int(bar_w * min(1.0, base / scale))
                pygame.draw.line(self.screen, FG, (x, y - 1), (x, y + 23), 2)
            self.text(f"{rate}/{base if base else '?'}", self.f_s, RED if anomal else DIM, (bx + bar_w + 12, y + 2))
        self.text(f"0x1A0 counter errors: {self.ctr_err}/s", self.f, RED if self.ctr_err > 5 else DIM,
                  (rp.x + 16, rp.bottom - 36))

    def draw_footer(self, t):
        pygame.draw.rect(self.screen, PANEL, (0, H - 34, W, 34))
        if self.tab == 0:
            hint = ("Stick gas/brake | D-pad blinkers | ZR spoof speed | ZL redline | A doors | B warnings | X IDS"
                    if self.kind == "sim" else
                    "Pin a signal in SNIFFER | ZR/ZL override it (TX armed) | + hold 2s arm TX | X IDS")
        elif self.tab == 1:
            hint = "Up/Down ID | Left/Right byte | A pin to gauge | B clear | Y fuzz | L/R tabs | - help"
        else:
            hint = "X IDS on/off | A re-learn baseline | B clear alerts | L/R tabs | - help"
        if self.attract_active:
            hint = "DEMO MODE - touch anything or press a button to take control"
        self.text(hint, self.f_s, AMBER if self.attract_active else DIM, (16, H - 26))
        dbg = f"{self.last_btn}  {self.clock.get_fps():.0f} fps"
        self.text(dbg, self.f_xs, LINE, (W - 14, H - 24), "topright")

    def draw_help(self):
        ov = pygame.Surface((W, H), pygame.SRCALPHA)
        ov.fill((0, 0, 0, 215))
        self.screen.blit(ov, (0, 0))
        self.text("CANsole controls", self.f_big, FG, (W // 2, 70), "center")
        left = [("L / R", "switch tab"), ("Left stick", "gas / brake (sim car)"),
                ("ZR (hold)", "spoof speed  |  override MAX"), ("ZL (hold)", "spoof RPM  |  override MIN"),
                ("A", "unlock doors  |  pin byte to gauge"), ("B", "warning lights  |  clear pins"),
                ("X", "IDS on/off (re-learns)"), ("Y", "fuzz selected ID 2 s")]
        right = [("D-pad", "blinkers  |  select ID / byte"), ("+ (hold 2 s)", "arm TX on real bus"),
                 ("-", "this help"), ("- and +", "quit"), ("Capture", "screenshot"),
                 ("L-stick click", "candump log on/off"), ("Touchscreen", "tabs, buttons, rows")]
        for col, items in ((70, left), (740, right)):
            for i, (k, v) in enumerate(items):
                self.text(k, self.f_b, RED, (col, 140 + i * 46))
                self.text(v, self.f, FG, (col + (190 if col < 400 else 170), 142 + i * 46))
        self.text(f"Interface: {self.label}", self.f, CYAN, (W // 2, 560), "center")
        self.text("Only transmit on buses you own or have permission to test.", self.f, AMBER, (W // 2, 600), "center")
        self.text("press any button to close", self.f_s, DIM, (W // 2, 650), "center")

    # ------------------------------------------------------------ run --
    def run(self):
        t_end = now() + self.args.run_seconds if self.args.run_seconds else None
        snap_dir = self.args.snap
        next_snap = now() + 1.0
        snap_n = 0
        if snap_dir:
            os.makedirs(snap_dir, exist_ok=True)
        while not self.quit:
            for ev in pygame.event.get():
                self.handle(ev)
            t = now()
            self.update(t)
            self.draw(t)
            pygame.display.flip()
            if snap_dir and t >= next_snap:
                pygame.image.save(self.screen, os.path.join(snap_dir, f"snap_{snap_n:03d}_tab{self.tab}.png"))
                snap_n += 1
                next_snap = t + self.args.snap_every
            if t_end and t > t_end:
                break
            self.clock.tick(FPS)
        self.shutdown()

    def shutdown(self):
        for th in (self.reader, self.attacker, self.car):
            if th:
                th.running = False
        time.sleep(0.15)
        if self.state.log_fp:
            self.state.toggle_log("")
        seen = set()
        for k in ("rx", "tx", "car"):
            b = self.buses.get(k)
            if b is not None and id(b) not in seen:
                seen.add(id(b))
                try:
                    b.shutdown()
                except Exception:
                    pass
        pygame.quit()


# ======================================================================
#  Extras: probe mode, launcher installer, icon
# ======================================================================
def run_probe(args):
    """Shows raw Joy-Con events so you can fix ~/.config/cansole/joymap.json if needed."""
    pygame.init()
    screen = pygame.display.set_mode((W, H), 0 if args.windowed else pygame.FULLSCREEN)
    font = mkfont(22)
    if sdl_controller:
        sdl_controller.init()
    lines = deque(maxlen=24)
    devs = []
    clock = pygame.time.Clock()
    start = now()
    while True:
        for ev in pygame.event.get():
            n = pygame.event.event_name(ev.type)
            if ev.type == pygame.QUIT or (ev.type == pygame.KEYDOWN and ev.key == pygame.K_ESCAPE):
                pygame.quit()
                return
            if ev.type == pygame.MOUSEBUTTONDOWN and ev.pos[0] > W - 120 and ev.pos[1] < 80:
                pygame.quit()
                return
            if ev.type == pygame.JOYDEVICEADDED:
                j = pygame.joystick.Joystick(ev.device_index)
                j.init()
                devs.append(j)
                is_c = bool(sdl_controller and sdl_controller.is_controller(ev.device_index))
                lines.appendleft(f"ADDED: {j.get_name()}  buttons={j.get_numbuttons()} axes={j.get_numaxes()} "
                                 f"hats={j.get_numhats()} game_controller={is_c}")
                if is_c:
                    devs.append(sdl_controller.Controller(ev.device_index))
            elif ev.type in (pygame.JOYBUTTONDOWN,):
                lines.appendleft(f"JOY button {ev.button} DOWN  (current map: {load_joymap().get(ev.button)})")
            elif ev.type == pygame.JOYHATMOTION:
                lines.appendleft(f"JOY hat {ev.hat} = {ev.value}")
            elif ev.type == pygame.JOYAXISMOTION and abs(ev.value) > 0.6:
                lines.appendleft(f"JOY axis {ev.axis} = {ev.value:+.2f}")
            elif ev.type == getattr(pygame, "CONTROLLERBUTTONDOWN", -1):
                lines.appendleft(f"CONTROLLER button {ev.button} -> {CTRL_BTN.get(ev.button)}")
            elif ev.type == getattr(pygame, "CONTROLLERAXISMOTION", -1) and abs(ev.value) > 20000:
                lines.appendleft(f"CONTROLLER axis {ev.axis} = {ev.value}")
            elif n in ("FingerDown",):
                lines.appendleft(f"TOUCH {ev.x:.2f},{ev.y:.2f}")
        screen.fill(BG)
        screen.blit(font.render("CANsole input probe - press Joy-Con buttons. Esc / tap top-right to exit", True, RED),
                    (20, 16))
        q = font.render("[EXIT]", True, FG)
        screen.blit(q, (W - 110, 16))
        for i, l in enumerate(lines):
            screen.blit(font.render(l, True, FG if i == 0 else DIM), (20, 60 + i * 26))
        pygame.display.flip()
        clock.tick(30)
        if args.run_seconds and now() - start > args.run_seconds:
            pygame.quit()
            return


def make_icon(path):
    pygame.init()
    s = pygame.Surface((256, 256), pygame.SRCALPHA)
    pygame.draw.rect(s, BG, (0, 0, 256, 256), border_radius=48)
    g = Gauge((128, 140), 96, 0, 100, 25, 1, 1, 75, None)
    g.disp = 82
    g.draw(s, 82)
    f = mkfont(44, True)
    t1 = f.render("CAN", True, RED)
    s.blit(t1, t1.get_rect(center=(128, 222)))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pygame.image.save(s, path)


def install():
    me = os.path.abspath(__file__)
    os.chmod(me, 0o755)
    icon = os.path.expanduser("~/.local/share/icons/cansole.png")
    make_icon(icon)
    apps = os.path.expanduser("~/.local/share/applications")
    os.makedirs(apps, exist_ok=True)
    try:
        desk = subprocess.check_output(["xdg-user-dir", "DESKTOP"], text=True).strip()
    except Exception:
        desk = os.path.expanduser("~/Desktop")
    entries = {
        "cansole.desktop": ("CANsole", "CAN bus cluster, sniffer, attacks and IDS", f'python3 "{me}" --iface auto'),
        "cansole-demo.desktop": ("CANsole Demo", "Virtual car + attract mode (no hardware)",
                                 f'python3 "{me}" --iface sim --attract'),
    }
    for fname, (name, comment, cmd) in entries.items():
        body = (f"[Desktop Entry]\nType=Application\nName={name}\nComment={comment}\n"
                f"Exec={cmd}\nIcon={icon}\nTerminal=false\nCategories=Development;Utility;\n")
        for d in (apps, desk):
            if not os.path.isdir(d):
                continue
            p = os.path.join(d, fname)
            with open(p, "w") as fp:
                fp.write(body)
            os.chmod(p, 0o755)
            if d == desk and shutil.which("gio"):
                subprocess.call(["gio", "set", p, "metadata::trusted", "true"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"  installed {p}")
    print("Done. Tap 'CANsole' (auto-detects RAMN/USB-CAN, else sim) or 'CANsole Demo' (attract mode).")
    print("If GNOME shows 'Untrusted launcher': right-click the icon -> Allow Launching.")


def main():
    ap = argparse.ArgumentParser(description="CANsole - CAN bus cluster/sniffer/attack/IDS for Nintendo Switch")
    ap.add_argument("--iface", default="auto", choices=["auto", "sim", "slcan", "socketcan"])
    ap.add_argument("--channel", help="/dev/ttyACM0 for slcan, can0/vcan0 for socketcan")
    ap.add_argument("--bitrate", type=int, default=500000, help="slcan bitrate (default 500000)")
    ap.add_argument("--allow-tx", action="store_true", help="allow arming TX on a real bus (+ held 2 s)")
    ap.add_argument("--windowed", action="store_true", help="window + mouse cursor (laptops)")
    ap.add_argument("--attract", action="store_true", help="sim only: self-running demo after 30 s idle")
    ap.add_argument("--log", action="store_true", help="start candump logging immediately")
    ap.add_argument("--install", action="store_true", help="create desktop launchers + icon")
    ap.add_argument("--probe", action="store_true", help="show raw controller events")
    ap.add_argument("--run-seconds", type=float, default=0, help=argparse.SUPPRESS)
    ap.add_argument("--snap", help=argparse.SUPPRESS)
    ap.add_argument("--snap-every", type=float, default=1.5, help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.install:
        install()
        return
    if args.probe:
        run_probe(args)
        return
    App(args).run()


if __name__ == "__main__":
    main()
