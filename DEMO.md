# CANsole NX: Car Hacking Village demo script (Hardwear.io NL 2026)

## Before you start (5 min)
- [ ] Switch charged and **CANsole NX v1.1** opens. Hold **ZL** while launching for safe mode if anything misbehaves.
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
- **Nothing works:** the self-running demo starts after 45 s idle on the virtual car. Let it run and talk over it.
