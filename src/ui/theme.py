
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

BG = "#0f1318"
BG_CARD = "#161c24"
BG_INPUT = "#1c2430"
BG_HOVER = "#263140"

BORDER = "#2b3542"
SURFACE = "#121821"
OVERLAY = "#374353"

FG = "#dfe6dc"
FG_DIM = "#a0ab9d"
FG_SUBTLE = "#72807e"

ACCENT = "#d8ae67"
GREEN = "#79bb92"
YELLOW = "#d8a65d"
RED = "#c97c74"
PURPLE = "#9286a4"
TEAL = "#75a89f"
CYAN = "#a7c0b9"

COPY_FLASH = GREEN

FONT_UI = ("Bahnschrift", 10)
FONT_UI_SM = ("Bahnschrift", 9)
FONT_UI_XS = ("Bahnschrift", 8)
FONT_UI_BOLD = ("Bahnschrift", 10, "bold")
FONT_UI_LG = ("Bahnschrift", 11)
FONT_TITLE = ("Bahnschrift", 24, "bold")

FONT_MONO = ("Cascadia Mono", 10)
FONT_MONO_SM = ("Cascadia Mono", 9)
FONT_MONO_XS = ("Cascadia Mono", 8)
FONT_MONO_BOLD = ("Cascadia Mono", 10, "bold")
FONT_MONO_SM_BOLD = ("Cascadia Mono", 9, "bold")
FONT_MONO_LG_BOLD = ("Cascadia Mono", 13, "bold")

BUTTON_STYLES = {
    "primary": {"bg": "#31404d", "fg": FG, "hover": "#3a4d5d", "active": "#476072"},
    "accent": {"bg": ACCENT, "fg": "#1f170c", "hover": "#e4be80", "active": "#c5964f"},
    "success": {"bg": GREEN, "fg": "#0d1511", "hover": "#8cc6a4", "active": "#68a680"},
    "danger": {"bg": RED, "fg": "#1d1110", "hover": "#d88e87", "active": "#b66b63"},
    "ghost": {"bg": BG_CARD, "fg": FG_DIM, "hover": BG_HOVER, "active": OVERLAY},
    "secondary": {"bg": "#2a3643", "fg": FG, "hover": "#324252", "active": "#3f5368"},
}

_UI_SCALE = 1.0

def set_ui_scale(scale: float):
    global _UI_SCALE
    try:
        factor = float(scale)
    except (TypeError, ValueError):
        factor = 1.0
    _UI_SCALE = max(0.8, min(2.0, round(factor, 2)))

def get_ui_scale() -> float:
    return _UI_SCALE

def _scaled_px(scale, value, minimum=1):
    try:
        factor = _UI_SCALE if scale is None else float(scale)
    except (TypeError, ValueError):
        factor = 1.0
    return max(minimum, int(round(float(value) * max(0.8, factor))))

def _scaled_padding(value, scale=None):
    if isinstance(value, (tuple, list)):
        return tuple(_scaled_px(scale, item, minimum=0) for item in value)
    return _scaled_px(scale, value, minimum=0)

def _rounded_points(x1, y1, x2, y2, radius):
    radius = max(0, min(radius, int((x2 - x1) / 2), int((y2 - y1) / 2)))
    return [
        x1 + radius, y1,
        x1 + radius, y1,
        x2 - radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1 + radius,
        x1, y1,
    ]

def _hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[index:index + 2], 16) for index in (0, 2, 4))

def _rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*rgb)

class GradientRule(tk.Canvas):

    def __init__(self, parent, colors, height=2):
        scaled_height = _scaled_px(None, height)
        super().__init__(
            parent,
            bg=parent.cget("bg"),
            height=scaled_height,
            bd=0,
            highlightthickness=0,
            relief=tk.FLAT,
        )
        self._colors = list(colors)
        self._height = scaled_height
        self.bind("<Configure>", lambda _event: self._draw())
        self._draw()

    def _draw(self):
        self.delete("all")
        width = max(1, self.winfo_width())
        height = max(1, self._height)
        if len(self._colors) < 2:
            self.create_rectangle(0, 0, width, height, fill=self._colors[0] if self._colors else BORDER, outline="")
            return

        segments = len(self._colors) - 1
        for x in range(width):
            pos = x / max(1, width - 1)
            segment = min(segments - 1, int(pos * segments))
            local = (pos * segments) - segment
            start = _hex_to_rgb(self._colors[segment])
            end = _hex_to_rgb(self._colors[segment + 1])
            rgb = tuple(int(start[idx] + (end[idx] - start[idx]) * local) for idx in range(3))
            self.create_line(x, 0, x, height, fill=_rgb_to_hex(rgb))

class PillButton(tk.Frame):

    def __init__(
        self, parent, text, command, style="primary", font=None,
        padx=16, pady=8, radius=8, min_width=0,
    ):
        super().__init__(parent, bg=parent.cget("bg"), bd=0, highlightthickness=0)
        self.command = command
        self._text = text
        self._style_name = style
        self._palette = BUTTON_STYLES.get(style, BUTTON_STYLES["primary"]).copy()
        self._font = tkfont.Font(font=font or FONT_UI_BOLD)
        self._padx = _scaled_px(None, padx, minimum=0)
        self._pady = _scaled_px(None, pady, minimum=0)
        self._radius = _scaled_px(None, radius, minimum=0)
        self._min_width = _scaled_px(None, min_width, minimum=0)
        self._state = tk.NORMAL
        self._bg_override = None
        self._fg_override = None
        self._hover = False
        self._pressed = False

        self.canvas = tk.Canvas(
            self,
            bg=self.cget("background"),
            bd=0,
            highlightthickness=0,
            relief=tk.FLAT,
            cursor="hand2",
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        for widget in (self, self.canvas):
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)
            widget.bind("<ButtonPress-1>", self._on_press)
            widget.bind("<ButtonRelease-1>", self._on_release)

        self._draw()

    def _colors(self):
        if self._state == tk.DISABLED:
            return BG_INPUT, FG_SUBTLE

        bg = self._palette["bg"]
        fg = self._palette["fg"]
        if self._pressed:
            bg = self._palette["active"]
        elif self._hover:
            bg = self._palette["hover"]

        return self._bg_override or bg, self._fg_override or fg

    def _draw(self):
        bg, fg = self._colors()
        text_width = self._font.measure(self._text)
        line_height = self._font.metrics("linespace")
        width = max(self._min_width, text_width + self._padx * 2)
        height = line_height + self._pady * 2

        self.canvas.configure(
            width=width,
            height=height,
            bg=super().cget("bg"),
            cursor="hand2" if self._state != tk.DISABLED else "arrow",
        )
        self.canvas.delete("all")
        self.canvas.create_polygon(
            _rounded_points(1, 1, width - 1, height - 1, self._radius),
            smooth=True,
            splinesteps=24,
            fill=bg,
            outline=BORDER if self._style_name == "ghost" else bg,
        )
        self.canvas.create_text(
            width // 2,
            height // 2,
            text=self._text,
            fill=fg,
            font=self._font,
        )

    def _on_enter(self, _event=None):
        if self._state == tk.DISABLED:
            return
        self._hover = True
        self._draw()

    def _on_leave(self, _event=None):
        self._hover = False
        self._pressed = False
        self._draw()

    def _on_press(self, _event=None):
        if self._state == tk.DISABLED:
            return
        self._pressed = True
        self._draw()

    def _on_release(self, event=None):
        if self._state == tk.DISABLED:
            return
        was_pressed = self._pressed
        self._pressed = False
        self._draw()
        if not was_pressed or not self.command:
            return
        x = event.x if event else 0
        y = event.y if event else 0
        if 0 <= x <= self.canvas.winfo_width() and 0 <= y <= self.canvas.winfo_height():
            self.command()

    def configure(self, cnf=None, **kw):
        if "text" in kw:
            self._text = kw.pop("text")
        if "command" in kw:
            self.command = kw.pop("command")
        if "state" in kw:
            self._state = kw.pop("state")
        if "bg" in kw:
            self._bg_override = kw.pop("bg")
        if "fg" in kw:
            self._fg_override = kw.pop("fg")
        if "font" in kw:
            self._font = tkfont.Font(font=kw.pop("font"))
        if "style" in kw:
            self._style_name = kw.pop("style")
            self._palette = BUTTON_STYLES.get(self._style_name, BUTTON_STYLES["primary"]).copy()
        result = super().configure(cnf, **kw)
        self._draw()
        return result

    config = configure

    def cget(self, key):
        if key == "bg":
            return self._bg_override or self._palette["bg"]
        if key == "fg":
            return self._fg_override or self._palette["fg"]
        if key == "text":
            return self._text
        if key == "state":
            return self._state
        return super().cget(key)

class MinimalScrollbar(tk.Canvas):

    def __init__(self, parent, command=None, orient=tk.VERTICAL, width=14, min_thumb=34):
        scaled_width = _scaled_px(None, width, minimum=8)
        dimension_kwargs = {"width": scaled_width} if orient == tk.VERTICAL else {"height": scaled_width}
        super().__init__(
            parent,
            bg=BG_CARD,
            bd=0,
            highlightthickness=0,
            relief=tk.FLAT,
            cursor="hand2",
            **dimension_kwargs,
        )
        self.command = command
        self.orient = orient
        self._first = 0.0
        self._last = 1.0
        self._drag_offset = None
        self._hover = False
        self._min_thumb = _scaled_px(None, min_thumb, minimum=28)

        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Button-1>", self._on_press)
        self.bind("<B1-Motion>", self._on_drag)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self._draw()

    def _thumb_bounds(self):
        width = max(self.winfo_width(), 12)
        height = max(self.winfo_height(), 12)
        inset = 2 if max(width, height) >= 14 else 3
        min_thumb = self._min_thumb

        if self.orient == tk.HORIZONTAL:
            left = 2 + int((width - 4) * self._first)
            right = 2 + int((width - 4) * self._last)
            if right - left < min_thumb:
                right = min(width - 2, left + min_thumb)
                if right - left < min_thumb:
                    left = max(2, right - min_thumb)
            return left, inset, right, height - inset

        top = 2 + int((height - 4) * self._first)
        bottom = 2 + int((height - 4) * self._last)
        if bottom - top < min_thumb:
            bottom = min(height - 2, top + min_thumb)
            if bottom - top < min_thumb:
                top = max(2, bottom - min_thumb)
        return inset, top, width - inset, bottom

    def _draw(self):
        self.delete("all")
        width = max(self.winfo_width(), 12)
        height = max(self.winfo_height(), 12)
        self.create_rectangle(0, 0, width, height, fill=BG_CARD, outline="")
        self.create_rectangle(1, 1, width - 1, height - 1, fill=SURFACE, outline=BORDER)
        x1, y1, x2, y2 = self._thumb_bounds()
        thumb_fill = ACCENT if self._drag_offset is not None else ("#5a7188" if self._hover else "#465465")
        self.create_polygon(
            _rounded_points(x1, y1, x2, y2, 5),
            smooth=True,
            splinesteps=18,
            fill=thumb_fill,
            outline="",
        )

    def set(self, first, last):
        self._first = max(0.0, min(1.0, float(first)))
        self._last = max(self._first, min(1.0, float(last)))
        self._draw()

    def configure(self, cnf=None, **kw):
        if "command" in kw:
            self.command = kw.pop("command")
        return super().configure(cnf, **kw)

    config = configure

    def _move_to(self, fraction):
        if not self.command:
            return
        self.command("moveto", max(0.0, min(1.0, fraction)))

    def _on_press(self, event):
        x1, y1, x2, y2 = self._thumb_bounds()
        if self.orient == tk.HORIZONTAL:
            if x1 <= event.x <= x2:
                self._drag_offset = event.x - x1
            else:
                self._drag_offset = (x2 - x1) / 2
                self._on_drag(event)
        else:
            if y1 <= event.y <= y2:
                self._drag_offset = event.y - y1
            else:
                self._drag_offset = (y2 - y1) / 2
                self._on_drag(event)
        self.grab_set()
        self._draw()

    def _on_drag(self, event):
        if self._drag_offset is None:
            return
        span = max(1, (self.winfo_width() if self.orient == tk.HORIZONTAL else self.winfo_height()) - 4)
        thumb_len = max(1, int(span * max(self._last - self._first, 0.05)))
        movable = max(1, span - thumb_len)
        position = event.x if self.orient == tk.HORIZONTAL else event.y
        fraction = (position - self._drag_offset - 2) / movable
        self._move_to(fraction)

    def _on_release(self, _event):
        self._drag_offset = None
        try:
            self.grab_release()
        except Exception:
            pass
        self._draw()

    def _on_enter(self, _event=None):
        self._hover = True
        self._draw()

    def _on_leave(self, _event=None):
        self._hover = False
        if self._drag_offset is None:
            self._draw()

def make_button(parent, text, command, style="primary", **kwargs):
    return PillButton(
        parent,
        text=text,
        command=command,
        style=style,
        font=kwargs.get("font", FONT_UI_BOLD),
        padx=kwargs.get("padx", 16),
        pady=kwargs.get("pady", 8),
        radius=kwargs.get("radius", 8),
        min_width=kwargs.get("min_width", 0),
    )

def make_card(parent, **kwargs):
    return tk.Frame(
        parent,
        bg=BG_CARD,
        bd=0,
        highlightbackground=BORDER,
        highlightthickness=1,
        padx=_scaled_px(None, kwargs.get("padx", 16), minimum=0),
        pady=_scaled_px(None, kwargs.get("pady", 12), minimum=0),
    )

def make_gradient_rule(parent, colors, height=2):
    return GradientRule(parent, colors=colors, height=height)

def make_label(parent, text, fg=FG, bg=BG, font=None, **kw):
    return tk.Label(parent, text=text, fg=fg, bg=bg, font=font or FONT_UI_SM, **kw)

def make_entry(parent, var, w=20, fg=FG, font=None, **kw):
    return tk.Entry(
        parent,
        textvariable=var,
        width=w,
        bg=BG_INPUT,
        fg=fg,
        insertbackground=fg,
        disabledbackground=BG_INPUT,
        disabledforeground=FG_SUBTLE,
        relief=tk.FLAT,
        bd=0,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        font=font or FONT_MONO_SM,
        **kw,
    )

def make_scrollbar(parent, command=None, width=14, min_thumb=34, orient=tk.VERTICAL):
    return MinimalScrollbar(parent, command=command, width=width, min_thumb=min_thumb, orient=orient)

class MinimalDropdown(tk.Frame):

    def __init__(self, parent, variable, values, width=180, command=None, font=None):
        super().__init__(parent, bg=BG_INPUT, highlightbackground=BORDER, highlightthickness=1)
        self.variable = variable
        self.values = list(values)
        self.command = command
        self._virtual_handler = None
        self._popup = None
        self._listbox = None
        width_px = _scaled_px(None, width, minimum=90)
        label_padx = _scaled_px(None, 10, minimum=4)
        label_pady = _scaled_px(None, 5, minimum=2)
        arrow_padx = _scaled_px(None, 8, minimum=3)
        popup_margin = _scaled_px(None, 4, minimum=2)
        self._popup_margin = popup_margin
        self._popup_row_height = _scaled_px(None, 24, minimum=18)

        self._label = tk.Label(
            self,
            textvariable=self.variable,
            bg=BG_INPUT,
            fg=FG,
            font=font or FONT_MONO_SM,
            anchor="w",
            padx=label_padx,
            pady=label_pady,
            width=max(6, width_px // max(8, _scaled_px(None, 10, minimum=8))),
        )
        self._label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._arrow = tk.Label(
            self,
            text="v",
            bg=BG_INPUT,
            fg=FG_DIM,
            font=FONT_UI_SM,
            padx=arrow_padx,
            pady=label_pady,
            cursor="hand2",
        )
        self._arrow.pack(side=tk.RIGHT)

        for widget in (self, self._label, self._arrow):
            widget.bind("<Button-1>", self._toggle_popup)

    def set(self, value):
        self.variable.set(value)

    def get(self):
        return self.variable.get()

    def bind(self, sequence=None, func=None, add=None):
        if sequence == "<<ComboboxSelected>>":
            self._virtual_handler = func
            return str(id(func))
        return super().bind(sequence, func, add)

    def configure(self, cnf=None, **kw):
        if "values" in kw:
            self.values = list(kw.pop("values"))
        return super().configure(cnf, **kw)

    config = configure

    def _toggle_popup(self, _event=None):
        if self._popup and self._popup.winfo_exists():
            self._close_popup()
        else:
            self._open_popup()

    def _open_popup(self):
        if self._popup and self._popup.winfo_exists():
            return

        popup = tk.Toplevel(self)
        popup.overrideredirect(True)
        popup.configure(bg=BG_CARD)
        popup.attributes("-topmost", True)

        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height() + self._popup_margin
        width = max(self.winfo_width(), _scaled_px(None, 160, minimum=120))
        visible_rows = min(max(len(self.values), 1), 8)
        height = visible_rows * self._popup_row_height + _scaled_px(None, 6, minimum=4)
        popup.geometry(f"{width}x{height}+{x}+{y}")

        shell = tk.Frame(popup, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        shell.pack(fill=tk.BOTH, expand=True)

        list_frame = tk.Frame(shell, bg=BG_CARD)
        list_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=_scaled_px(None, 2, minimum=0),
            pady=_scaled_px(None, 2, minimum=0),
        )

        listbox = tk.Listbox(
            list_frame,
            bg=BG_CARD,
            fg=FG,
            selectbackground=OVERLAY,
            selectforeground=FG,
            highlightthickness=0,
            relief=tk.FLAT,
            bd=0,
            font=FONT_UI_SM,
            activestyle="none",
            exportselection=False,
        )
        scrollbar = make_scrollbar(list_frame, listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        if len(self.values) > visible_rows:
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        for idx, value in enumerate(self.values):
            listbox.insert(tk.END, value)
            if value == self.variable.get():
                listbox.selection_set(idx)
                listbox.see(idx)

        listbox.bind("<ButtonRelease-1>", self._select_from_popup)
        listbox.bind("<Return>", self._select_from_popup)
        popup.bind("<FocusOut>", lambda _e: self._close_popup())
        popup.bind("<Escape>", lambda _e: self._close_popup())
        popup.after(0, popup.focus_force)

        self._popup = popup
        self._listbox = listbox

    def _select_from_popup(self, _event=None):
        if not self._listbox:
            return
        selection = self._listbox.curselection()
        if not selection:
            return
        value = self.values[selection[0]]
        self.variable.set(value)
        self._close_popup()
        if self._virtual_handler:
            self._virtual_handler(None)
        elif self.command:
            self.command(value)

    def _close_popup(self):
        if self._popup and self._popup.winfo_exists():
            self._popup.destroy()
        self._popup = None
        self._listbox = None

def configure_treeview_style(style: ttk.Style, scale: float = 1.0):
    style.theme_use("clam")
    style.configure(
        "Treeview",
        background=BG_HOVER,
        foreground=FG,
        fieldbackground=BG_HOVER,
        rowheight=_scaled_px(scale, 28, minimum=24),
        borderwidth=0,
        bordercolor=BG_HOVER,
        lightcolor=BG_HOVER,
        darkcolor=BG_HOVER,
        relief="flat",
        font=FONT_UI_SM,
    )
    style.configure(
        "Treeview.Heading",
        background=SURFACE,
        foreground=FG_DIM,
        font=FONT_MONO_SM_BOLD,
        relief="flat",
    )
    style.map("Treeview", background=[("selected", "#31404d")])
    style.map("Treeview.Heading", background=[("active", BG_HOVER)])
    style.configure("TSeparator", background=BORDER)

    style.configure(
        "SteamAudit.Treeview",
        background="#1a2230",
        foreground=FG,
        fieldbackground="#1a2230",
        rowheight=_scaled_px(scale, 32, minimum=28),
        borderwidth=0,
        bordercolor="#1a2230",
        lightcolor="#1a2230",
        darkcolor="#1a2230",
        relief="flat",
        font=FONT_UI_SM,
    )
    style.configure(
        "SteamAudit.Treeview.Heading",
        background="#141c28",
        foreground=FG_SUBTLE,
        font=("Bahnschrift", 8, "bold"),
        relief="flat",
        padding=(_scaled_px(scale, 8), _scaled_px(scale, 6)),
    )
    style.map(
        "SteamAudit.Treeview",
        background=[("selected", "#293a4d")],
    )
    style.map(
        "SteamAudit.Treeview.Heading",
        background=[("active", "#1c2836")],
    )

def configure_combobox_style(style: ttk.Style, root: tk.Tk, scale: float = 1.0):
    style.configure(
        "TCombobox",
        fieldbackground=BG_INPUT,
        background=BG_INPUT,
        foreground=FG,
        selectbackground=BG_INPUT,
        selectforeground=FG,
        bordercolor=BORDER,
        arrowcolor=ACCENT,
        insertcolor=FG,
        padding=_scaled_px(scale, 6),
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG_INPUT), ("disabled", BG_INPUT), ("active", BG_INPUT)],
        foreground=[("readonly", FG), ("disabled", FG_DIM), ("active", FG)],
        selectbackground=[("readonly", BG_INPUT)],
        selectforeground=[("readonly", FG)],
        background=[("readonly", BG_INPUT), ("active", BG_INPUT)],
    )
    root.option_add("*TCombobox*Listbox.background", BG_INPUT)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.selectBackground", OVERLAY)
    root.option_add("*TCombobox*Listbox.selectForeground", FG)

def configure_progressbar_style(style: ttk.Style, scale: float = 1.0):
    style.configure(
        "TProgressbar",
        troughcolor="#24303c",
        background="#7fb3a1",
        bordercolor="#24303c",
        lightcolor="#95c5b4",
        darkcolor="#679686",
        thickness=_scaled_px(scale, 10, minimum=8),
    )

def configure_entry_style(style: ttk.Style, scale: float = 1.0):
    style.configure(
        "TEntry",
        fieldbackground=BG_INPUT,
        foreground=FG,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        insertcolor=FG,
        padding=_scaled_px(scale, 8),
    )
