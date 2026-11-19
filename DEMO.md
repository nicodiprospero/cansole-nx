# CANsole NX: Car Hacking Village demo script (Hardwear.io NL 2026)

## Before you start (5 min)
- [ ] Switch charged and **CANsole NX v1.2** opens. Hold **ZL** while launching for safe mode if anything misbehaves.
- [ ] Open it once on the virtual car: drive, press ZR, check the banner and rumble.
- [ ] Ask the crew for the RAMN board **and permission to transmit**. Write down the bitrate (default 500k).
- [ ] Cable: Switch USB-C → RAMN USB. If the RAMN doesn't power up, use the dock's USB-A port or a powered hub.
- [ ] If the crew has `candump` on the big screen on the same bus, ask them to leave it running. People will see your injected frames appear live.

---

## Act 1: "My game console is a car" (60 s, virtual car)
**Show:** CLUSTER tab. Drive with the left stick, blink with the D-pad.
**Say:** *"This is a native Switch homebrew app. Software renderer, no Linux. It simulates an ECU network: 10 message IDs at real periodic rates, a speed frame with a 4-bit rolling counter and a checksum."*

## Act 2: Attack L1 → L2 (90 s)
- **ZR (hold), level L1 naive:** needle to 240, red banner, rumble.
  *"No authentication on CAN, so whoever talks last wins. But my IDS learned each ID's rate in 6 seconds, and the counter breaks."*
- **D-pad Up → L2 forged**, then **ZR**: still caught.
  *"Now I forge a valid counter and checksum. The payload checks pass, but I'm sending frames on top of the real ECU, so the rate doubles and the sequences collide."*

## Act 3: L3, the IDS goes blind (60 s)
- **D-pad Up → L3 masquerade**, then **ZR**: the amber banner reads **"IDS BLIND"**.
  *"A real attacker would bus-off the speed ECU first, using error frames to push its TEC past 255 (Cho & Shin, 2016). Then they send at exactly 50 Hz with a perfect counter chain. Rate-based IDS sees nothing."*
- **IDS tab:** all bars green while the needle lies.

## Act 4: SecOC fixes it (60 s)
- **D-pad Down → SecOC ON**, then **ZR**: **"SecOC MAC FAIL, forged frame rejected"**, and the speed shows `--`.
  *"AUTOSAR SecOC: the sender adds a truncated MAC (SipHash-2-4 here) over ID, payload and freshness, using a key the attacker doesn't have. The cluster drops forged frames. Note the speed goes to `--`: SecOC stops spoofing, not denial of service. The bus-off'd ECU is still gone."*

## Act 5: Their RAMN, live (the money shot)
1. Plug in RAMN. The header shows **`RAMN | USB 0483:5740`**, auto-detected from its signal IDs.
2. **SNIFFER** (read-only; the adapter is opened in slcan **listen-only `L`** mode):
   *"Bytes 0–1 are the signal, 2–3 the freshness counter, 4–7 a CRC32. It's your firmware's framing, and I decode it."*
   Ask someone to move the **accelerator slider**: byte 0x039 goes red. Press **A** to pin it.
3. **CLUSTER** = RAMN dashboard: the steering wheel follows ECU B's pot, the pedal bars follow ECU C's sliders, and the LED row is **ECU D's own report (0x1BB)**.
4. **Arm TX:** hold **+** for 2 s. The adapter reopens in normal mode `O`.
   *"With your OK: forging."*
   - **A → HAZARDS:** both turn LEDs blink on the real board. *"Frame 0x1A7 with the next freshness counter and a recomputed CRC32. CRC is integrity, not authentication: anyone can compute it. And the receiving ECUs don't verify it anyway."*
   - **B → CHECK ENGINE**, **Y → HIGH BEAM**, **Up → PARK BRAKE** LED.
   - **IDS tab:** COUNTER BREAK alerts. *"The defender's view: my forged counters collide with ECU B and C's real sequence. That's exactly what a counter-aware IDS catches."*
5. Disarm: hold **+** again. Back to listen-only.

## Act 6: The takeover, the finale (the IDS goes blind on real hardware)
Go to the **ECU tab**. TX must be armed.
1. **Diagnostics first (shows depth):** select ECU B and press **A** (TesterPresent: "ECU alive"). Press **Y** to read the VIN and build date. That's a multi-frame ISO-TP response; the app sends the flow-control frame itself.
   *"This is UDS over ISO-TP, the same protocol a dealership tool speaks."*
2. **Optional:** select ECU D and press **X** (ECUReset 0x11 01). The board reboots that ECU. The IDS tab shows **"0x1BB SILENT"**.
3. **Press B: START TAKEOVER.**
   - The Switch powers off ECU B and C through RAMN's own USB commands (`yB0` / `yC0`). That stands in for a bus-off attack.
   - It then impersonates **all 8 of their messages at their exact periods** (10 ms and 100 ms), continuing every freshness counter with a valid CRC32.
   - **Left stick = accelerator, ZL = brake, right stick = steering, D-pad = gear and blinkers, Y = hazards, A = horn.**
   - ECU A's screen and the LEDs now follow *your Joy-Cons*.
   *"I just replaced two ECUs with a Nintendo controller."*
4. Show the **IDS tab: no alerts.** *"Rate normal, counters perfect, CRCs valid. A rate/counter IDS is blind to a clean masquerade. What catches it: authentication (SecOC), or noticing the ECU went silent/rebooted. That's why I powered them off before starting: there's no gap."*
5. **Press B to stop.** B and C power back on. Their counters restart at 0, and the IDS flags it. *"And that's the forensic trace a good IDS keeps."*
6. If anything looks off: **ZL = RESTORE ALL (`Y1`)** powers every ECU back on.

## Bonus (if time)
- **NFC tab:** tap someone's badge on the right stick: UID and chip type. If it's MIFARE Classic: *"Crypto-1 was broken in 2008."*
- **IR CAM tab:** point at a phone's face-unlock emitter or a TV remote. You can see the invisible IR.

## Lines that land
- *"It runs on hardware every kid has. Car security education shouldn't need a $500 adapter."*
- *"Everything is a tradeoff: rate IDS is cheap but blind to masquerade, SecOC needs keys and bandwidth (4 of 8 bytes here)."*
- *"Built in 24 h, open source on my GitHub."*

## If something breaks
- **App crashes on a tab:** stay on CLUSTER/SNIFFER/IDS. NFC and IR only start when their tab opens.
- **RAMN not detected:** the header says `USB: plug RAMN/CANable`. Re-plug it. Check `sdmc:/switch/cansole-nx/boot.log`.
- **Header shows `slcan 250k?`:** no frames yet, so the app is cycling bitrates (listen-only, harmless). It locks as soon as frames arrive.
- **Frames stop:** the app re-opens the channel after 2.5 s (RAMN closes slcan if USB overflows).
- **RAMN doesn't power from the Switch:** use a USB-C hub with power-delivery input, or ask the crew for a powered hub.
- **Nothing works:** the self-running demo starts after 45 s idle on the virtual car. Let it run and talk over it.
