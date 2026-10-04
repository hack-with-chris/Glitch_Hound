# Building Glitch Hound as a Windows .exe

You do **not** need to change anything about the database for this — MongoDB
Atlas works fine in a packaged desktop app. (The Firebase discussion earlier
was specific to the *Android* version of this project; Android has no real
MongoDB driver and MongoDB retired the Atlas Data API in Sept 2025. None of
that applies to a Python desktop app.)

## 1. Install dependencies + PyInstaller

```bash
pip install -r requirements.txt
pip install pyinstaller
```

## 2. Build

Easiest: double-click `build.bat` (Windows), or run manually:

```bash
pyinstaller glitchhound.spec --clean
```

This produces `dist/GlitchHound.exe`. It's a **onefile** build — a single
executable that self-extracts to a temp folder each time it launches (a
couple seconds slower to start than a `--onedir` build, but only one file
to hand someone).

## 3. Give it its own `.env`

Copy your `.env` file into the **same folder as `GlitchHound.exe`** —
`config.py` looks for it right next to the executable when running as a
packaged build (not the temp folder PyInstaller extracts to, which gets
wiped every launch).

⚠️ **Before sharing this exe with anyone else**: don't ship your real
`MONGODB_URI` / `RAZORPAY_KEY_SECRET` / etc. in that `.env` — anyone with
the file (or who runs `strings GlitchHound.exe`) could extract them. For
a personal build that's fine; for handing the exe to other people, either
give each install its own restricted Atlas DB user, or don't distribute
`.env` at all and have each person set up their own.

## 4. Test it

Run the exe on a machine that does **not** have Python installed, to make
sure nothing was missed. Confirm login, a scan, and the subscription page
(mock payment mode) all work.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Blank/broken-looking window, missing fonts or theme colors | customtkinter's bundled theme/font files weren't included | Already handled in `glitchhound.spec` via `collect_data_files("customtkinter")` — if you edited the spec, make sure that line is still there |
| Exe closes instantly, no window, no error | It crashed on startup and the windowed build hides the traceback | In `glitchhound.spec`, temporarily set `console=True`, rebuild, run from a terminal to see the real error, then switch back to `False` |
| `Could not connect to MongoDB Atlas` | `.env` isn't next to the exe, or Atlas Network Access doesn't allow this machine's IP | Confirm `.env` is in `dist/` next to the exe; in Atlas, Network Access → allow `0.0.0.0/0` for testing across devices |
| Windows Defender / antivirus flags it | Common false-positive with PyInstaller onefile builds (unsigned exe that self-extracts) | Expected for an unsigned build; code-signing (a paid certificate) is the real fix if you're distributing this widely |

## Optional next step: a proper installer

Right now this is just a standalone `.exe`. For a "real" Windows installer
(Start Menu shortcut, uninstaller, Add/Remove Programs entry), wrap the
PyInstaller output with [Inno Setup](https://jrsoftware.org/isinfo.php) —
happy to generate that `.iss` script too if you want to go that far.
