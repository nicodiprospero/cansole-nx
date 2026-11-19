# CANsole: a Nintendo Switch CAN bus console

A Switch running Switchroot L4T Ubuntu becomes a car-hacking console:

| Tab | What it does |
|---|---|
| **CLUSTER** | Live RPM and speed gauges, blinkers, door locks and warning lights. Touch buttons let you attack the car. |
| **SNIFFER** | A cansniffer-style view. Changed bytes flash red and there's a per-bit flip view. Pin any byte or bytes to a big auto-scaled gauge, which is how you reverse-engineer a signal. |
| **IDS** | Frequency-baseline and rolling-counter intrusion detection. It catches every attack the app can launch. |

The pitch is "attack and defense on a game console". The built-in virtual car means it works with no hardware at all. Plug in a RAMN or a CANable and it reads a real bus.

---

## Tonight (about 1–2 h)

### 0. Ubuntu on the Switch
- **If L4T Ubuntu is still on your SD card**, you're set.
- **If you wiped it for game space**, restore your backup with hekate UMS and a laptop.
- **Fallback:** the same file runs on any laptop with `--windowed`.

### 1. Install the dependencies (Switch → Ubuntu → Terminal)
```bash
sudo apt update
sudo apt install -y python3-pygame python3-can python3-serial can-utils
sudo usermod -aG dialout $USER     # needed for /dev/ttyACM0 (RAMN/CANable); log out and back in
mkdir -p ~/cansole
```
Copy `cansole.py` into `~/cansole/`.

### 2. First run (virtual car, in a window)
```bash
cd ~/cansole
python3 cansole.py --iface sim --windowed
```
Drive with the left stick. Hold **ZR** to see the spoofed speed hit 240 and the red IDS banner. Press **L/R** to switch tabs.

### 3. If the Joy-Con buttons are wrong
```bash
python3 cansole.py --probe
```
Press each button and note the numbers. Then create `~/.config/cansole/joymap.json`, for example:
```json
{"0": "B", "1": "A", "2": "X", "3": "Y", "5": "L", "6": "R", "7": "ZL", "8": "ZR", "9": "MINUS", "10": "PLUS"}
```
(Joy-Cons normally go through SDL's GameController mapping, so you probably won't need this. The touchscreen always works.)

### 4. One-tap launchers
```bash
python3 cansole.py --install
```
This creates two desktop icons:
- **CANsole** auto-detects the interface: RAMN/CANable on `/dev/ttyACM*`, then `can0`, otherwise the virtual car.
- **CANsole Demo** runs the virtual car in **attract mode**. It plays itself after 30 s idle (driving, spoofing, IDS alerts, sniffer). Any touch or button press takes over.

If GNOME says "untrusted launcher", right-click the icon and choose **Allow Launching**.

---

## Tomorrow at the Car Hacking Village

### Demo A: no hardware (always works)
Tap **CANsole Demo** and hand it to people. The touch buttons on the cluster (SPOOF SPEED, REDLINE, UNLOCK DOORS, WARNING LIGHTS) are made for visitors.

### Demo B: the real RAMN bus (ask the crew first)
RAMN's ECU A can act as a USB-to-CAN adapter in slcan mode. Confirm with the village crew which mode their board is in.

1. Connect Switch USB-C to RAMN USB-C. If the RAMN doesn't power up, put the Switch in its dock and use a dock USB-A port.
2. Tap **CANsole**. The header should say `SLCAN /dev/ttyACM0 @ 500k`.
3. Open **SNIFFER**. Move a RAMN pedal or knob and watch which byte flashes red.
4. Use the D-pad to move to that byte and press **A**. It's now pinned to the big gauge, and the gauge follows the knob.
5. The bus stays **read-only** unless you start with `--allow-tx` **and** hold **+** for 2 s:
   ```bash
   python3 ~/cansole/cansole.py --iface slcan --channel /dev/ttyACM0 --allow-tx
   ```
   Only do this with the crew's OK. Holding **ZR** or **ZL** then overrides the pinned signal to max or min.

If the RAMN uses a different bitrate, add `--bitrate 250000` (or whatever they say).
For a SocketCAN adapter: `sudo ip link set can0 up type can bitrate 500000`, then run `--iface socketcan --channel can0`.

### Capture everything for your portfolio
- **Capture button** saves a screenshot to `~/Pictures/CANsole/`.
- **Left-stick click** starts or stops a candump-format log in `~/cansole_logs/`. You can replay it later with `canplayer -I file.log vcan0=can0`.

---

## 60-second pitch

1. *"This is a Nintendo Switch running Linux. Right now it's the instrument cluster of a virtual car on a CAN bus."* Drive with the stick.
2. *"Now I'm the attacker."* Hold **ZR**. *"I'm injecting speed frames at 200 Hz. The car is doing 80 and the dash says 240. CAN has no authentication, so whoever sends last wins."*
3. The red banner appears. *"The same Switch catches me. The IDS learned each ID's normal rate and checks the rolling counter in the speed frame, and my spoofed frames break both."* Flip to the **IDS** tab.
4. *"And this is how you find signals on a car you don't know."* Open **SNIFFER**, wiggle the input, watch the red bytes, pin one. *"That's how I'm reverse-engineering the gauges for my BMW E34 project."*

---

## Fake car signals (sim)

| ID | Signal | Encoding | Rate |
|---|---|---|---|
| 0x0B4 | wheel speeds | 4 × uint16 BE, km/h × 100 | 50 Hz |
| 0x120 | engine | RPM uint16 BE, throttle %, coolant + 40 | 50 Hz |
| 0x188 | lights | bit0 left blinker, bit1 right blinker | 10 Hz |
| 0x1A0 | vehicle speed | uint16 BE km/h × 100, counter 0–15, checksum | 50 Hz |
| 0x2C1 | steering | int16 BE | 50 Hz |
| 0x2F0 | warnings | bit0 engine, bit1 oil, bit2 battery | 5 Hz |
| 0x394 | body ctrl | counter + magic + checksum | 10 Hz |
| 0x3E0 | door locks | bits 0–3, 1 = locked | 2 Hz |
| 0x4F0 | ident | ASCII "CANSOLE1" | 1 Hz |
| 0x5A8 | battery | uint16 BE | 5 Hz |

## Controls

| Joy-Con | Keyboard | Action |
|---|---|---|
| L / R | Q / E | switch tab |
| Left stick | W / S | gas / brake (sim) |
| ZR (hold) | Space | spoof speed, or override pinned signal to MAX |
| ZL (hold) | L-Shift | spoof RPM, or override pinned signal to MIN |
| A | J | unlock doors, or pin byte to gauge (sniffer) |
| B | K | warning lights, or clear pins (sniffer) |
| X | I | IDS on/off (re-learns the baseline) |
| Y | U | fuzz the selected ID for 2 s |
| D-pad | arrows | blinkers, or select ID / byte (sniffer) |
| + (hold 2 s) | T | arm TX on a real bus (needs `--allow-tx`) |
| − | H | help |
| − and + | Esc | quit |
| Capture | F12 | screenshot |
| L-stick click | R | candump log on/off |
