# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for Glitch Hound.

Build with (from the project root, same folder as main.py):
    pyinstaller glitchhound.spec --clean

Output lands in dist/GlitchHound.exe (single file).

Three things in here exist specifically because of gotchas this project's
dependencies hit with PyInstaller's default static analysis:
  1. customtkinter ships .json theme files + font files it loads by path
     at runtime — collect_data_files() bundles those in.
  2. pymongo's `mongodb+srv://` URIs are resolved via dnspython, which
     imports its rdata-type modules dynamically (importlib), so PyInstaller
     can't "see" them by scanning imports — collect_submodules() forces
     them all in.
  3. reportlab (used for PDF report export) can need its AFM font metric
     files at runtime for some fonts — collected defensively.

If you've pip-installed the optional Easebuzz or razorpay SDKs (for
PAYMENT_GATEWAY_MODE=easebuzz / razorpay), PyInstaller picks them up
automatically as long as they're installed in the same environment you run
`pyinstaller` from — no extra config needed here.
"""
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = []
datas += collect_data_files("customtkinter")
datas += collect_data_files("reportlab")

hiddenimports = []
hiddenimports += collect_submodules("dns")   # dnspython's import name is "dns", not "dnspython"
hiddenimports += ["pymongo", "bson"]

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="GlitchHound",
    debug=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # Set console=True temporarily if the exe closes instantly with no
    # window — that means it crashed on startup and this is the only way
    # to see the traceback. Switch back to False once it's working.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Put a .ico file in the project root and point this at it for a
    # custom taskbar/exe icon, e.g. icon="icon.ico"
    icon=None,
)
