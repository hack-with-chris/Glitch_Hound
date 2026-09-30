"""
Reusable animated widgets for the hacker theme.

MatrixRain       — the falling-character background used on the login/
                    register screens, and (embedded smaller) as a "scan in
                    progress" animation. Pure tkinter Canvas, driven by
                    .after(), so it doesn't depend on any extra libraries.
TerminalSpinner  — drives a spinner + cycling status text on a CTkLabel
                    while a background thread (the actual scan) is running.
                    Purely cosmetic — it never reads real scan progress,
                    since the scanner functions are intentionally left
                    untouched and don't expose incremental progress.
labeled_entry    — an entry field with a small caption label stacked above
                    it, instead of relying only on a placeholder that
                    disappears the moment you start typing.
labeled_password_entry — same, plus a show/hide eye toggle.
"""
import random
import tkinter as tk

import customtkinter as ctk

from gui import theme

_RAIN_CHARS = list("アイウエオカキクケコサシスセソ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<>/\\$#@%&")


class MatrixRain(tk.Canvas):
    def __init__(self, parent, font_size=15, speed_ms=55, **kwargs):
        kwargs.setdefault("bg", theme.BLACK)
        kwargs.setdefault("highlightthickness", 0)
        super().__init__(parent, **kwargs)
        self.font_size = font_size
        self.speed_ms = speed_ms
        self._col_width = font_size
        self._columns = []
        self._running = False
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        if event.width < 2 or event.height < 2:
            return
        num_cols = max(1, event.width // self._col_width)
        self._columns = [random.randint(-40, 0) for _ in range(num_cols)]

    def start(self):
        if not self._running:
            self._running = True
            self._tick()

    def stop(self):
        self._running = False

    def _tick(self):
        if not self._running:
            return
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w > 2 and h > 2 and self._columns:
            for i, head in enumerate(self._columns):
                x = i * self._col_width + self._col_width // 2
                trail_len = 16
                for j in range(trail_len):
                    y = (head - j) * self.font_size
                    if 0 <= y <= h:
                        char = random.choice(_RAIN_CHARS)
                        if j == 0:
                            color = "#D9FFDA"
                        else:
                            fade = max(0.0, 1 - j / trail_len)
                            g = int(50 + fade * 190)
                            color = f"#00{g:02x}00"
                        self.create_text(x, y, text=char, fill=color,
                                          font=(theme.FONT, self.font_size), anchor="n")
                self._columns[i] += 1
                if (head - trail_len) * self.font_size > h and random.random() < 0.04:
                    self._columns[i] = random.randint(-30, 0)
        self.after(self.speed_ms, self._tick)


_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class TerminalSpinner:
    """
    label.configure(text=...) is called repeatedly to show a spinner glyph
    plus a cycling status phrase, e.g. "⠹  Probing ports...". Start it right
    before launching the scan thread, stop it the moment results come back.
    """

    def __init__(self, label, phases, interval_ms=120, phase_every=6):
        self.label = label
        self.phases = phases
        self.interval_ms = interval_ms
        self.phase_every = phase_every
        self._running = False
        self._frame_idx = 0
        self._phase_idx = 0
        self._tick_count = 0
        self._job = None

    def start(self):
        self._running = True
        self._frame_idx = 0
        self._phase_idx = 0
        self._tick_count = 0
        self.label.configure(text_color=theme.GREEN)
        self._tick()

    def stop(self, final_text=None, color=None):
        self._running = False
        if self._job:
            try:
                self.label.after_cancel(self._job)
            except Exception:
                pass
            self._job = None
        if final_text is not None:
            self.label.configure(text=final_text, text_color=color or theme.GREEN_DIM)

    def _tick(self):
        if not self._running:
            return
        frame = _SPINNER_FRAMES[self._frame_idx % len(_SPINNER_FRAMES)]
        phase = self.phases[self._phase_idx % len(self.phases)]
        self.label.configure(text=f"{frame}  {phase}")
        self._frame_idx += 1
        self._tick_count += 1
        if self._tick_count % self.phase_every == 0:
            self._phase_idx += 1
        self._job = self.label.after(self.interval_ms, self._tick)


def labeled_entry(parent, label_text, **entry_kwargs):
    """
    Returns (wrapper_frame, entry). The wrapper stacks a small green caption
    (e.g. "USERNAME") above a CTkEntry, so the field's purpose stays visible
    even once you've typed into it — a plain inside placeholder vanishes the
    moment you start typing, which gets confusing on forms with several
    fields, especially masked password fields where you can't just glance
    at the content to remember which box is which.

    Pack/grid the returned wrapper (not the entry) into your layout.
    entry_kwargs are passed straight through to CTkEntry — do NOT pass
    placeholder_text here, the label above replaces that role.
    """
    width = entry_kwargs.get("width", 320)
    wrapper = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkLabel(wrapper, text=label_text.upper(), font=theme.F_SMALL, text_color=theme.GREEN_DIM,
                 anchor="w", width=width).pack(fill="x", pady=(0, 4))
    entry = ctk.CTkEntry(wrapper, **entry_kwargs)
    entry.pack()
    return wrapper, entry


def labeled_password_entry(parent, label_text, **entry_kwargs):
    """
    Same idea as labeled_entry, but for password fields: adds a small eye
    toggle on the right edge of the box to show/hide the typed characters.
    Masked (•) by default; the icon brightens green while text is visible
    as a state cue. Returns (wrapper_frame, entry) — entry.get() etc. work
    exactly like a normal CTkEntry.
    """
    entry_kwargs = dict(entry_kwargs)  # don't mutate the caller's shared kwargs dict
    entry_kwargs.pop("show", None)     # masking is managed by the toggle below
    width = entry_kwargs.pop("width", 320)
    height = entry_kwargs.pop("height", 42)
    fg_color = entry_kwargs.pop("fg_color", theme.PANEL_ALT)
    border_color = entry_kwargs.pop("border_color", theme.BORDER)
    border_width = entry_kwargs.pop("border_width", 1)

    wrapper = ctk.CTkFrame(parent, fg_color="transparent")
    ctk.CTkLabel(wrapper, text=label_text.upper(), font=theme.F_SMALL, text_color=theme.GREEN_DIM,
                 anchor="w", width=width).pack(fill="x", pady=(0, 4))

    box = ctk.CTkFrame(wrapper, width=width, height=height, fg_color=fg_color,
                        border_color=border_color, border_width=border_width, corner_radius=6)
    box.pack()
    box.pack_propagate(False)

    entry = ctk.CTkEntry(box, show="•", fg_color="transparent", border_width=0, **entry_kwargs)
    entry.pack(side="left", fill="both", expand=True, padx=(10, 2), pady=4)

    state = {"visible": False}

    def toggle():
        state["visible"] = not state["visible"]
        entry.configure(show="" if state["visible"] else "•")
        toggle_btn.configure(text_color=theme.GREEN if state["visible"] else theme.GREEN_DIM)

    toggle_btn = ctk.CTkButton(
        box, text="👁", width=34, height=max(height - 10, 20), font=(theme.FONT, 15),
        fg_color="transparent", text_color=theme.GREEN_DIM, hover_color=theme.PANEL,
        command=toggle,
    )
    toggle_btn.pack(side="right", padx=(0, 4))

    return wrapper, entry
