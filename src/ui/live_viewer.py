import argparse, json, os, struct, sys, tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.ui.theme import (
    BG, BG_CARD, BG_INPUT, BG_HOVER, BORDER, OVERLAY,
    FG, FG_DIM, FG_SUBTLE,
    ACCENT, GREEN, RED, YELLOW,
    FONT_MONO_SM, FONT_MONO_SM_BOLD, FONT_MONO_XS,
    FONT_MONO_BOLD, FONT_MONO_LG_BOLD, FONT_UI_SM,
    make_button, make_label, make_entry,
    configure_treeview_style,
)

C_BG     = BG
C_PANEL  = BG_CARD
C_ROW    = BG_HOVER
C_HDR    = BG_CARD
C_ACCENT = ACCENT
C_GREEN  = GREEN
C_RED    = RED
C_DIM    = FG_DIM
C_FG     = FG
C_SEP    = BORDER

_F9   = FONT_MONO_SM
_F9B  = FONT_MONO_SM_BOLD
_F8B  = FONT_MONO_XS
_F8   = FONT_MONO_XS
_F10B = FONT_MONO_BOLD
_F13B = FONT_MONO_LG_BOLD

def load_dump_data(dump_dir: str) -> Dict[str, dict]:
    classes = {}
    for fname in ("ClassesInfo.json", "StructsInfo.json"):
        for d in [dump_dir,
                  os.path.join(dump_dir, "Offsets"),
                  os.path.join(os.path.dirname(dump_dir), "Offsets")]:
            fp = os.path.join(d, fname)
            if not os.path.isfile(fp):
                continue
            with open(fp, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for entry in raw.get("data", []):
                if not isinstance(entry, dict) or not entry:
                    continue
                name  = next(iter(entry))
                items = entry[name]
                members, inherit, size = [], [], 0
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    k0 = next(iter(item))
                    if k0 == "__MDKClassSize":
                        size = item[k0]
                        continue
                    if k0 in ("__InheritInfo", "__SuperChain"):
                        inherit = item[k0] or []
                        continue
                    if k0.startswith("__"):
                        continue
                    val = item[k0]
                    if (isinstance(val, list) and len(val) == 3
                            and isinstance(val[0], list)
                            and isinstance(val[1], int)):
                        type_str = val[0][0] if val[0] else "unknown"
                        members.append({
                            "name":   k0,
                            "type":   type_str,
                            "offset": val[1],
                            "size":   val[2],
                        })
                    elif isinstance(val, dict):
                        n = val.get("name") or k0
                        if n:
                            members.append({
                                "name":   n,
                                "type":   val.get("type", ""),
                                "offset": val.get("offset", 0),
                                "size":   val.get("size", 0),
                            })
                members.sort(key=lambda m: m["offset"])
                classes[name] = {"members": members, "inherit": inherit, "size": size}
            break
    return classes

class Reader:
    def __init__(self):
        self.handle = 0
        self.pid    = 0
        self.ok     = False

    def attach(self, name: str) -> bool:
        try:
            from src.core.memory import get_pid_by_name, attach
            self.pid    = get_pid_by_name(name)
            self.handle = attach(self.pid) if self.pid else 0
            self.ok     = bool(self.handle)
        except Exception:
            self.ok = False
        return self.ok

    def detach(self):
        try:
            if self.handle:
                from src.core.memory import detach
                detach(self.handle)
        except Exception:
            pass
        self.handle = 0; self.ok = False

    def read(self, addr: int, size: int) -> Optional[bytes]:
        if not self.ok or not addr:
            return None
        try:
            from src.core.memory import read_bytes
            return read_bytes(self.handle, addr, size)
        except Exception:
            return None

    def fmt(self, addr: int, size: int) -> str:
        b = self.read(addr, min(size, 8))
        if not b or len(b) < min(size, 1):
            return "?"
        try:
            if size == 1:
                v = b[0]; return f"{v}  (0x{v:02X})"
            if size == 2:
                v = struct.unpack_from("<H", b)[0]; return f"{v}  (0x{v:04X})"
            if size == 4:
                i = struct.unpack_from("<i", b)[0]
                u = struct.unpack_from("<I", b)[0]
                f = struct.unpack_from("<f", b)[0]
                return f"int {i}   uint {u}   float {f:.3f}"
            if size >= 8:
                p = struct.unpack_from("<Q", b)[0]
                i = struct.unpack_from("<q", b)[0]
                return f"0x{p:016X}   ({i})"
        except Exception:
            pass
        return b[:8].hex()

    def ptr(self, addr: int) -> int:
        b = self.read(addr, 8)
        if b and len(b) >= 8:
            try: return struct.unpack_from("<Q", b)[0]
            except Exception: pass
        return 0

class LiveViewerApp:
    POLL_MS = 500

    def __init__(self, root: tk.Tk, dump_data: Dict[str, dict], process_name: str = ""):
        self.root       = root
        self.data       = dump_data
        self.reader     = Reader()
        self.cur_class  = ""
        self.cur_addr   = 0
        self.pinned: List[Tuple[str,str,int,int]] = []
        self.history: List[Tuple[str,int]] = []
        self.hist_pos   = -1
        self._names     = sorted(dump_data.keys())
        self._poll_id   = None

        self._build()
        self._fill_list("")

        if process_name:
            self.proc_var.set(process_name)
            self.root.after(200, self._auto_attach)

        self._poll()

    def _auto_attach(self):
        proc = self.proc_var.get().strip()
        if proc and not self.reader.ok:
            self._attach()

    def _build(self):
        r = self.root
        r.title("Live Struct Viewer")
        r.geometry("1200x740")
        r.configure(bg=C_BG)
        r.option_add("*Font", "Consolas 9")

        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview",
                    background=C_ROW, foreground=C_FG,
                    fieldbackground=C_ROW, rowheight=21,
                    borderwidth=0)
        s.configure("Treeview.Heading",
                    background=C_HDR, foreground=C_ACCENT,
                    font=_F9B, relief="flat")
        s.map("Treeview", background=[("selected", "#3b4068")])
        s.configure("TSeparator", background=C_SEP)

        def lbl(parent, text, fg=C_FG, bg=C_BG, font=_F9, **kw):
            return tk.Label(parent, text=text, fg=fg, bg=bg, font=font, **kw)

        def btn(parent, text, cmd, fg=C_FG, bg=C_ROW, font=_F9,
                padx=8, pady=3, **kw):
            return tk.Button(parent, text=text, command=cmd,
                             fg=fg, bg=bg, activeforeground=fg,
                             activebackground=C_PANEL,
                             font=font, relief=tk.FLAT,
                             cursor="hand2", padx=padx, pady=pady, **kw)

        def entry(parent, var, w=20, fg=C_FG, font=_F9, **kw):
            return tk.Entry(parent, textvariable=var, width=w,
                            bg=C_PANEL, fg=fg, insertbackground=fg,
                            relief=tk.FLAT, bd=4, font=font, **kw)

        title_bar = tk.Frame(r, bg=C_HDR, pady=6, padx=12)
        title_bar.pack(fill=tk.X)
        lbl(title_bar, "GameSDK-Kit", fg=C_ACCENT, bg=C_HDR,
            font=_F13B).pack(side=tk.LEFT)
        lbl(title_bar, "  Live Struct Viewer", fg=C_DIM,
            bg=C_HDR).pack(side=tk.LEFT)
        self._count_lbl = lbl(title_bar, f"{len(self.data):,} classes",
                               fg=C_DIM, bg=C_HDR)
        self._count_lbl.pack(side=tk.RIGHT)

        attach = tk.Frame(r, bg=C_PANEL, pady=5, padx=10)
        attach.pack(fill=tk.X)
        lbl(attach, "Process:", fg=C_DIM, bg=C_PANEL).pack(side=tk.LEFT)
        self.proc_var = tk.StringVar()
        entry(attach, self.proc_var, w=28).pack(side=tk.LEFT, padx=6)
        self._attach_btn = btn(attach, "Attach", self._attach,
                               fg=C_FG, bg="#2a3a6a")
        self._attach_btn.pack(side=tk.LEFT)
        self._status = lbl(attach, "● not attached", fg=C_RED, bg=C_PANEL)
        self._status.pack(side=tk.LEFT, padx=10)
        btn(attach, "◀", self._back,  fg=C_DIM, bg=C_PANEL,
            padx=5).pack(side=tk.LEFT, padx=(20, 2))
        btn(attach, "▶", self._fwd,   fg=C_DIM, bg=C_PANEL,
            padx=5).pack(side=tk.LEFT, padx=2)

        addr_row = tk.Frame(r, bg=C_BG, pady=4, padx=10)
        addr_row.pack(fill=tk.X)
        lbl(addr_row, "Address:", fg=C_DIM, bg=C_BG).pack(side=tk.LEFT)
        self._addr_var = tk.StringVar()
        addr_e = entry(addr_row, self._addr_var, w=20, fg=C_GREEN)
        addr_e.pack(side=tk.LEFT, padx=6)
        addr_e.bind("<Return>", lambda e: self._live_view())
        btn(addr_row, "▶ Live View", self._live_view,
            fg=C_GREEN, bg="#1a3020").pack(side=tk.LEFT)
        btn(addr_row, "✕ Clear", self._clear_addr,
            fg=C_DIM, bg=C_BG, padx=4).pack(side=tk.LEFT, padx=6)
        btn(addr_row, "📌 Pin Field", self._pin,
            fg=C_FG, bg=C_ROW).pack(side=tk.LEFT, padx=6)
        self._addr_hint = lbl(addr_row,
            "Optional — browse fields without an address",
            fg=C_DIM, bg=C_BG)
        self._addr_hint.pack(side=tk.LEFT, padx=8)

        tk.Frame(r, bg=C_SEP, height=1).pack(fill=tk.X)

        body = tk.PanedWindow(r, orient=tk.HORIZONTAL,
                              bg=C_BG, sashwidth=5,
                              sashrelief=tk.FLAT, bd=0)
        body.pack(fill=tk.BOTH, expand=True)

        left = tk.Frame(body, bg=C_PANEL)
        body.add(left, minsize=160, width=260)

        lbl(left, "Classes / Structs", fg=C_ACCENT, bg=C_HDR,
            font=_F9B,
            pady=5, padx=8).pack(fill=tk.X)

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write",
            lambda *_: self._fill_list(self._search_var.get()))
        entry(left, self._search_var, w=24).pack(
            fill=tk.X, padx=6, pady=4)

        lf = tk.Frame(left, bg=C_PANEL)
        lf.pack(fill=tk.BOTH, expand=True)
        self._cls_lb = tk.Listbox(
            lf, bg=C_PANEL, fg=C_FG,
            selectbackground="#3b4068", selectforeground=C_FG,
            font=_F9, relief=tk.FLAT,
            borderwidth=0, activestyle="none", highlightthickness=0)
        ls = tk.Scrollbar(lf, orient=tk.VERTICAL,
                          command=self._cls_lb.yview,
                          bg=C_ROW, troughcolor=C_PANEL)
        self._cls_lb.configure(yscrollcommand=ls.set)
        self._cls_lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ls.pack(side=tk.RIGHT, fill=tk.Y)
        self._cls_lb.bind("<<ListboxSelect>>", self._on_select)

        right = tk.Frame(body, bg=C_BG)
        body.add(right, minsize=400)

        info_bar = tk.Frame(right, bg=C_HDR, pady=6, padx=10)
        info_bar.pack(fill=tk.X, side=tk.TOP)

        self._cls_name_lbl = lbl(info_bar, "← select a class",
                                  fg=C_ACCENT, bg=C_HDR,
                                  font=_F10B)
        self._cls_name_lbl.pack(side=tk.LEFT)

        self._cls_meta_lbl = lbl(info_bar, "", fg=C_DIM, bg=C_HDR)
        self._cls_meta_lbl.pack(side=tk.RIGHT)

        tk.Frame(right, bg=C_ACCENT, height=1).pack(fill=tk.X, side=tk.TOP)

        tbl = tk.Frame(right, bg=C_BG)
        tbl.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        cols = ("field", "type", "offset", "size", "value")
        self._tree = ttk.Treeview(tbl, columns=cols,
                                  show="headings", selectmode="browse")
        for col, w, lbl_text, anchor, stretch in [
            ("field",  200, "Field Name",  "w",      False),
            ("type",   185, "Type",        "w",      False),
            ("offset",  72, "Offset",      "center", False),
            ("size",    50, "Size",        "center", False),
            ("value",    0, "Live Value",  "w",      True),
        ]:
            self._tree.heading(col, text=lbl_text)
            self._tree.column(col, width=w, minwidth=40,
                              anchor=anchor, stretch=stretch)

        ts = tk.Scrollbar(tbl, orient=tk.VERTICAL,
                          command=self._tree.yview,
                          bg=C_ROW, troughcolor=C_PANEL)
        self._tree.configure(yscrollcommand=ts.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ts.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.bind("<Double-1>", self._follow_ptr)
        self._tree.tag_configure("ptr",    foreground=C_ACCENT)
        self._tree.tag_configure("live",   foreground=C_GREEN)
        self._tree.tag_configure("dim",    foreground=C_DIM)

        self._pin_outer = tk.Frame(right, bg=C_HDR)

        pin_hdr = tk.Frame(self._pin_outer, bg=C_HDR, pady=3, padx=8)
        pin_hdr.pack(fill=tk.X)
        lbl(pin_hdr, "📌 Pinned", fg=C_ACCENT, bg=C_HDR,
            font=_F8B).pack(side=tk.LEFT)
        btn(pin_hdr, "✕ Unpin", self._unpin,
            fg=C_DIM, bg=C_HDR, padx=4, pady=1).pack(side=tk.RIGHT)

        pin_tbl = tk.Frame(self._pin_outer, bg=C_BG, height=100)
        pin_tbl.pack(fill=tk.X)
        pin_tbl.pack_propagate(False)

        pcols = ("class", "field", "value")
        self._pin_tree = ttk.Treeview(pin_tbl, columns=pcols,
                                      show="headings", height=4)
        for col, w, stretch in [("class", 130, False),
                                 ("field", 170, False),
                                 ("value",   0, True)]:
            self._pin_tree.heading(col, text=col.title())
            self._pin_tree.column(col, width=w, minwidth=40, stretch=stretch)
        ps = tk.Scrollbar(pin_tbl, orient=tk.VERTICAL,
                          command=self._pin_tree.yview,
                          bg=C_ROW, troughcolor=C_PANEL)
        self._pin_tree.configure(yscrollcommand=ps.set)
        self._pin_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ps.pack(side=tk.RIGHT, fill=tk.Y)

    def _fill_list(self, filt: str):
        ft = filt.lower().strip()
        names = [n for n in self._names if ft in n.lower()] if ft else self._names
        self._cls_lb.delete(0, tk.END)
        for n in names:
            self._cls_lb.insert(tk.END, n)
        self._count_lbl.configure(
            text=f"{len(names):,} / {len(self.data):,} classes")

    def _on_select(self, _=None):
        sel = self._cls_lb.curselection()
        if not sel:
            return
        self.cur_class = self._cls_lb.get(sel[0])
        self._show_fields()

    def _show_fields(self):
        self._tree.delete(*self._tree.get_children())
        if self.cur_class not in self.data:
            return
        d       = self.data[self.cur_class]
        members = d.get("members", [])
        inherit = d.get("inherit", [])
        size    = d.get("size", 0)

        self._cls_name_lbl.configure(text=self.cur_class)
        field_word = "field" if len(members) == 1 else "fields"
        meta = f"size: 0x{size:X}   {len(members)} {field_word}"
        if inherit:
            chain = " → ".join(inherit[:5])
            if len(inherit) > 5:
                chain += " ..."
            meta += f"   inherits: {chain}"
        self._cls_meta_lbl.configure(text=meta)

        if not members:
            if inherit:
                self._tree.insert("", tk.END, tags=("dim",), values=(
                    "— no own fields —", "", "", "", ""))
                self._tree.insert("", tk.END, tags=("dim",), values=(
                    "Inherited from:", "", "", "", "double-click to navigate"))
                for parent in inherit:
                    parent_count = len(self.data.get(parent, {}).get("members", []))
                    self._tree.insert("", tk.END, tags=("ptr",), values=(
                        f"  ↳ {parent}",
                        f"({parent_count} fields)",
                        "", "", "double-click →"))
            else:
                self._tree.insert("", tk.END, tags=("dim",), values=(
                    "— no fields in dump —", "", "", "", ""))
            return

        for m in members:
            is_ptr = any(k in m["type"] for k in ("*", "Ptr", "Pointer", "Object"))
            tag    = "ptr" if is_ptr else "live" if self.cur_addr else "dim"
            self._tree.insert("", tk.END, tags=(tag,), values=(
                m["name"],
                m["type"],
                f"0x{m['offset']:X}",
                m["size"],
                "⮞ ptr" if is_ptr else "",
            ))

    def _live_view(self):
        raw = self._addr_var.get().strip()
        if not raw:
            return
        try:
            addr = int(raw, 16)
        except ValueError:
            messagebox.showwarning("Live Struct Viewer", "Invalid address — hex only, e.g. 0x1A2B3C4D")
            return
        if self.cur_class and self.cur_addr:
            self.history = self.history[:self.hist_pos + 1]
            self.history.append((self.cur_class, self.cur_addr))
            self.hist_pos = len(self.history) - 1
        self.cur_addr = addr
        self._show_fields()
        self._addr_hint.configure(
            text=f"Updating every {self.POLL_MS}ms", fg=C_GREEN)

    def _clear_addr(self):
        self.cur_addr = 0
        self._addr_var.set("")
        self._addr_hint.configure(
            text="Optional — browse fields without an address", fg=C_DIM)
        self._show_fields()

    def _attach(self):
        proc = self.proc_var.get().strip()
        if not proc:
            messagebox.showwarning("Attach", "Enter a process name.")
            return
        if self.reader.ok:
            self.reader.detach()
            self._status.configure(text="● not attached", fg=C_RED)
            self._attach_btn.configure(text="Attach")
            return
        if self.reader.attach(proc):
            self._status.configure(
                text=f"● PID {self.reader.pid}", fg=C_GREEN)
            self._attach_btn.configure(text="Detach")
        else:
            self._status.configure(text=f"● failed: {proc}", fg=C_RED)

    def _poll(self):
        if self.reader.ok and self.cur_addr and self.cur_class:
            for iid in self._tree.get_children():
                v = self._tree.item(iid, "values")
                try:
                    off  = int(v[2], 16)
                    size = int(v[3])
                except (ValueError, IndexError):
                    continue
                val  = self.reader.fmt(self.cur_addr + off, size)
                is_ptr = any(k in v[1] for k in ("*", "Ptr", "Pointer", "Object"))
                tag  = "ptr" if is_ptr else "live"
                self._tree.item(iid, tags=(tag,),
                                values=(v[0], v[1], v[2], v[3], val))

            for i, iid in enumerate(self._pin_tree.get_children()):
                if i < len(self.pinned):
                    cls, fld, paddr, psize = self.pinned[i]
                    val = self.reader.fmt(paddr, psize)
                    self._pin_tree.item(iid,
                                       values=(cls, fld, val))

        self._poll_id = self.root.after(self.POLL_MS, self._poll)

    def _back(self):
        if self.hist_pos > 0:
            self.hist_pos -= 1
            cls, addr = self.history[self.hist_pos]
            self.cur_class = cls; self.cur_addr = addr
            self._addr_var.set(f"0x{addr:X}")
            self._show_fields()

    def _fwd(self):
        if self.hist_pos < len(self.history) - 1:
            self.hist_pos += 1
            cls, addr = self.history[self.hist_pos]
            self.cur_class = cls; self.cur_addr = addr
            self._addr_var.set(f"0x{addr:X}")
            self._show_fields()

    def _follow_ptr(self, _=None):
        sel = self._tree.selection()
        if not sel:
            return
        v = self._tree.item(sel[0], "values")
        fname = v[0].strip()

        if fname.startswith("↳ "):
            parent = fname[2:].strip()
            if parent in self.data:
                self._nav_to_class(parent)
            return

        if not any(k in v[1] for k in ("*", "Ptr", "Pointer", "Object")):
            return
        if not self.reader.ok or not self.cur_addr:
            messagebox.showinfo("Live Struct Viewer",
                "Attach to the process and set an address to follow pointers.")
            return
        try:
            off = int(v[2], 16)
        except ValueError:
            return
        pv = self.reader.ptr(self.cur_addr + off)
        if pv and pv > 0x10000:
            self._addr_var.set(f"0x{pv:X}")
            inner = v[1].replace("*","").replace("ObjectProperty","").strip()
            if inner in self.data:
                self._nav_to_class(inner)
            self._live_view()

    def _nav_to_class(self, class_name: str):
        if class_name not in self.data:
            return
        self.cur_class = class_name
        if class_name in self._names:
            idx = self._names.index(class_name)
            self._cls_lb.selection_clear(0, tk.END)
            self._cls_lb.selection_set(idx)
            self._cls_lb.see(idx)
        self._show_fields()

    def _pin(self):
        sel = self._tree.selection()
        if not sel or not self.cur_addr:
            messagebox.showinfo("Pin",
                "Set a live address and select a field to pin.")
            return
        v = self._tree.item(sel[0], "values")
        try:
            off  = int(v[2], 16)
            size = int(v[3])
        except (ValueError, IndexError):
            return
        self.pinned.append((self.cur_class, v[0],
                            self.cur_addr + off, size))
        self._pin_tree.insert("", tk.END,
                              values=(self.cur_class, v[0], ""))
        if not self._pin_outer.winfo_ismapped():
            self._pin_outer.pack(fill=tk.X, side=tk.BOTTOM,
                                 before=self._tree.master)

    def _unpin(self):
        sel = self._pin_tree.selection()
        if not sel:
            return
        idx = self._pin_tree.index(sel[0])
        if 0 <= idx < len(self.pinned):
            self.pinned.pop(idx)
        self._pin_tree.delete(sel[0])
        if not self.pinned:
            self._pin_outer.pack_forget()

    def destroy(self):
        if self._poll_id:
            self.root.after_cancel(self._poll_id)
        self.reader.detach()

def main():
    p = argparse.ArgumentParser(description="Live Struct Viewer")
    p.add_argument("--dump",    "-d", required=True)
    p.add_argument("--process", "-p", default="")
    a = p.parse_args()
    if not os.path.isdir(a.dump):
        print(f"[!!] Not found: {a.dump}"); return 1
    data = load_dump_data(a.dump)
    if not data:
        print("[!!] No class data found."); return 1
    print(f"[OK] {len(data):,} classes loaded")
    root = tk.Tk()
    app  = LiveViewerApp(root, data, process_name=a.process)
    root.protocol("WM_DELETE_WINDOW",
                  lambda: (app.destroy(), root.destroy()))
    root.mainloop()
    return 0

if __name__ == "__main__":
    sys.exit(main())
