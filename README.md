# SploitsHen — PS4 14.00 / 14.02 Jailbreak Host

> **For PS4 firmware 14.00 and 14.02 only.**  
> Run from your PC on the same network as the console. Nothing is installed on the PS4.

---

## What This Is

A local HTTP server that delivers the **afterglow** kernel exploit to your PS4's browser.  
Once the exploit runs, the kernel is left readable/writable with `uid 0` — standard payloads  
(ps4-hen, GoldHEN) load from there.

Custom additions on top of the base exploit:

- **Hacker theme** — black/red/green Matrix aesthetic, glitch-title, ASCII art dragon
- **Key authentication** — the PS4 URL requires a `?key=XXXX` token; the browser keeps  
  it via cookie, so CSS/JS assets load fine after the initial redirect
- **Admin panel** — web UI to generate labeled access keys, copy PS4-ready URLs, and  
  revoke keys; a fresh admin key prints to your terminal on every server start

---

## Requirements

- Windows PC (or any machine with Python 3)
- PS4 on firmware **14.00** or **14.02**, on the same Wi-Fi/LAN
- Python 3.6+ — download at <https://python.org/downloads>  
  *(tick "Add Python to PATH" during install)*

---

## Quick Start

1. Put the whole folder somewhere on your PC (e.g. `C:\AkatsukiAIM\14.02 Jailbreak\`)
2. Double-click **`serve.bat`**
3. The terminal prints two URLs — copy the **PS4 URL** (includes the key)
4. On your PS4: open the browser and enter that URL, and leave the page open; the exploit launch begins automatically
5. Done. GoldHEN / ps4-hen loads.

---

## Admin Panel

When the server starts it prints something like:

```
  Admin panel : http://192.168.1.x:8000/admin?ak=a1b2c3d4e5f6g7h8
  PS4 URL     : http://192.168.1.x:8000/?key=ab12cd34ef
```

Open the **Admin panel** URL in any browser on your PC. From there you can:

- Generate new access keys with a custom label (e.g. "living room PS4")
- Copy the full PS4 URL for each key (ready to type or scan as QR)
- Revoke keys you no longer need
- See how many times each key has been used

> **Note:** The admin key changes every time you restart the server.  
> Access keys persist until you revoke them or restart.

---

## Files

| File | Purpose |
|---|---|
| `serve.bat` | Windows launcher — detects Python, checks everything, starts the server |
| `server.py` | Custom Python HTTP server: key auth, cookie sessions, admin API |
| `index.html` | PS4 browser landing page (SploitsHen purple theme) |
| `style.css` | Purple neon SploitsHen theme |
| `matrix.js` | Matrix rain canvas animation |
| `launch.js` | PS4 exploit launcher (countdown → start button → fires exploit) |
| `afterglow-g.js` | Afterglow exploit — GoldHEN path |
| `core.js` / `mem.js` | Exploit primitives |
| `int64.js` | 64-bit integer helpers |
| `ps4_offsets.js` | Firmware 14.00/14.02 kernel offsets |
| `hen.bin` | ps4-hen (patched — wrong `sceSblPfsSetKeys` fixed for 14.00) |
| `goldhen.bin` | GoldHEN |
| `patchset.bin` | Kernel patches GoldHEN expects |
| `kernel_1402.bin` | 14.02-specific kernel payload |
| `binloader.bin` | FW-independent payload receiver: listens on TCP 9020 after the jailbreak, takes **raw** payloads (first byte `E9`, e.g. `hen.bin`) AND **ELF64** payloads (magic `7F 45 4C 46`), shows a popup, beacons every event to the server log, re-listens after each payload |
| `hello.elf` / `hello.bin` | ELF64 / raw test payload: shows a `hello, world!` popup and beacons `[hw] 1..5` to the server log — use it to verify the binloader end to end |
| `serve.sh` | Linux/macOS alternative to serve.bat |

---

## Binloader — push payloads over TCP (no page reloads)

1. On the PS4 open `go-b.html` (or the PS4 URL + `&binloader=1`) and run the exploit.
   A popup says **binloader listening on port 9020** when it is ready.
2. From the PC:

```bat
nc --send-only <PS4-IP> 9020 < hen.bin      :: Ncat: raw HEN installer
nc --send-only <PS4-IP> 9020 < hello.elf    :: Ncat: ELF64 test payload (hello, world! popup)
nc -q0 <PS4-IP> 9020 < payload.bin          :: OpenBSD nc
```

- The stub takes **raw** payloads (`E9` first byte) and **ELF64** payloads (`7F 45 4C 46`).
  ELF64 must be self-contained (no PT_INTERP): scene toolchains (ps4-payload-sdk, OpenOrbis,
  tutorial builds) emit exactly that. A plain Linux `gcc` hello world will be refused with an
  honest `[bld] x! interp` beacon — it cannot run on a PS4 anyway.
- Every event lands in the server log (`[bld] ...`, `[hen] ...`, `[hw] ...`) — run
  `python watch_beacons.py` in a second terminal to see them live.
- The stub **re-listens** after each payload: iterate without reloading the page.
  If a payload kills the browser, reboot the console and send a different one.

---

## Hosting Note

> GitHub Pages serves **static files only** — `server.py` does not run there.  
> The key-auth and admin panel require a real Python server on a local PC.  
>
> **To jailbreak your PS4, run `serve.bat` on a PC on the same network.**  
>
> This repo is for backup, version control, and easy re-download.

---

## ps4-hen Patch Note

Upstream `hen.bin` has a wrong `sceSblPfsSetKeys` address on 14.00 — unpatched,  
every app launch after jailbreak freezes the console. The copy here is already fixed.  
See `TECHNICAL.md` for details.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `serve.bat` opens and closes instantly | Python not on PATH | Install Python 3, tick "Add Python to PATH", restart |
| PS4 page loads but looks plain | Stale cookie / browser cache | Close and reopen PS4 browser, re-enter URL with key |
| `exploit failed — please retry` | Normal — no damage done | Reopen browser, go again |
| `the handles are NOT defused` | Chain got far, couldn't clean up | **Cold-start the console** (don't just close browser) |
| Console dies with no message | Heap race — normal failure rate | Cold start and retry |

---

## Credits

- **raw13g** — exploit substrate  
- **jordyidk** — [slopkit](https://github.com/jordyidk/slopkit)  
- **al-azif** — <https://github.com/al-azif/>  
- **SiSTRo** — GoldHEN  
- **TheFlow, ChendoChap, abc, AlAzif, LightningMods, @egycnq** — kernel exploit lineage  
- **iDntUseModz** — SploitsHen purple theme, key auth system, admin panel

## Legal

Security research on hardware we own. No Sony code redistributed.  
Licensed under the GNU Affero General Public License v3.0 or later.
