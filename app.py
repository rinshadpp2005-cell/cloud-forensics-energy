#!/usr/bin/env python3
"""
app.py
------
Tkinter GUI front-end for the Cloud Forensics File Evidence Collector.
Project PRJN26-141 — Energy Sector Breach Investigation

Run:
    python app.py

All scanning logic delegates to the existing modules:
scanner.py, comparator.py, report_generator.py, logger_config.py
The GUI adds NO business logic — it is a pure presentation layer.

Terminal commands still work exactly as before:
    python forensic_tool.py baseline --path sample_energy_data/
    python forensic_tool.py scan     --path sample_energy_data/
    python forensic_tool.py compare  --path sample_energy_data/ --report
"""

import logging
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ── Import local forensic modules ─────────────────────────────────────────────
try:
    from comparator import compare_with_baseline, load_baseline, save_baseline
    from logger_config import setup_logger
    from report_generator import generate_csv_report, generate_html_report
    from scanner import scan_directory
except ImportError as _exc:
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "Import Error",
        f"Cannot load forensic modules:\n{_exc}\n\n"
        "Make sure app.py lives in the same folder as\n"
        "scanner.py, comparator.py, report_generator.py, logger_config.py",
    )
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Colour palette  (matches the HTML dashboard)
# ─────────────────────────────────────────────────────────────────────────────
C = {
    "bg":        "#0d1117",
    "surface":   "#161b22",
    "surface2":  "#1c2128",
    "border":    "#30363d",
    "text":      "#c9d1d9",
    "muted":     "#8b949e",
    "blue":      "#58a6ff",
    "green":     "#3fb950",
    "yellow":    "#e3b341",
    "red":       "#f85149",
    "purple":    "#bc8cff",
    "btn":       "#21262d",
    "btn_hover": "#30363d",
    "sel":       "#1f6feb",
}


# ─────────────────────────────────────────────────────────────────────────────
# Logging handler that routes records → thread-safe queue
# ─────────────────────────────────────────────────────────────────────────────
class _QueueLogHandler(logging.Handler):
    def __init__(self, q: queue.Queue) -> None:
        super().__init__()
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        self._q.put(("log", record.levelno, self.format(record)))


# ─────────────────────────────────────────────────────────────────────────────
# Main GUI Application
# ─────────────────────────────────────────────────────────────────────────────
class ForensicApp:
    TITLE    = "Cloud Forensics Evidence Collector — PRJN26-141"
    MIN_W    = 1080
    MIN_H    = 740

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(self.TITLE)
        self.root.minsize(self.MIN_W, self.MIN_H)
        self.root.configure(bg=C["bg"])

        # ── State variables ───────────────────────────────────────────────────
        self.target_var  = tk.StringVar(value=str(Path("sample_energy_data").resolve()))
        self.output_var  = tk.StringVar(value=str(Path(".").resolve()))
        self.report_var  = tk.BooleanVar(value=True)
        self._busy       = False
        self._last_csv   : str | None = None
        self._last_html  : str | None = None
        self._q          : queue.Queue = queue.Queue()
        self._sort_asc   : dict[str, bool] = {}

        # ── Build ─────────────────────────────────────────────────────────────
        self._apply_style()
        self._build_ui()
        self._wire_logger()
        self._poll()          # start 40 ms queue consumer

    # ─────────────────────────────────────────────────────────────────────────
    # ttk Style / theming
    # ─────────────────────────────────────────────────────────────────────────
    def _apply_style(self) -> None:
        s = ttk.Style(self.root)
        s.theme_use("clam")

        s.configure(".",
            background=C["bg"], foreground=C["text"],
            fieldbackground=C["surface"], troughcolor=C["surface2"],
            bordercolor=C["border"], darkcolor=C["border"],
            lightcolor=C["border"], relief="flat",
            font=("Segoe UI", 10),
        )
        # ── Notebook ──────────────────────────────────────────────────────────
        s.configure("TNotebook",
            background=C["bg"], borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab",
            background=C["surface2"], foreground=C["muted"],
            padding=[18, 7], borderwidth=0, font=("Segoe UI", 9, "bold"))
        s.map("TNotebook.Tab",
            background=[("selected", C["surface"]), ("active", C["btn_hover"])],
            foreground=[("selected", C["blue"]),    ("active", C["text"])],
        )
        # ── Treeview ──────────────────────────────────────────────────────────
        s.configure("Treeview",
            background=C["surface"], foreground=C["text"],
            fieldbackground=C["surface"], rowheight=26, borderwidth=0,
            font=("Consolas", 9),
        )
        s.configure("Treeview.Heading",
            background=C["surface2"], foreground=C["muted"],
            relief="flat", font=("Segoe UI", 9, "bold"),
        )
        s.map("Treeview",
            background=[("selected", C["sel"])],
            foreground=[("selected", "#ffffff")],
        )
        s.map("Treeview.Heading",
            background=[("active", C["btn_hover"])],
            foreground=[("active", C["text"])],
        )
        # ── Scrollbar ─────────────────────────────────────────────────────────
        s.configure("TScrollbar",
            background=C["surface2"], troughcolor=C["bg"],
            arrowcolor=C["muted"], borderwidth=0, width=10)
        # ── Progressbar ───────────────────────────────────────────────────────
        s.configure("green.Horizontal.TProgressbar",
            background=C["green"], troughcolor=C["surface2"],
            borderwidth=0, thickness=5)
        s.configure("blue.Horizontal.TProgressbar",
            background=C["blue"], troughcolor=C["surface2"],
            borderwidth=0, thickness=5)
        # ── Entry ─────────────────────────────────────────────────────────────
        s.configure("TEntry",
            fieldbackground=C["surface2"], foreground=C["text"],
            insertcolor=C["text"], borderwidth=1)
        s.map("TEntry", fieldbackground=[("focus", C["surface"])])
        # ── Checkbutton ───────────────────────────────────────────────────────
        s.configure("TCheckbutton",
            background=C["bg"], foreground=C["muted"],
            indicatorcolor=C["surface2"], font=("Segoe UI", 9))
        s.map("TCheckbutton", foreground=[("active", C["text"])])
        # ── Frames / Labels ───────────────────────────────────────────────────
        s.configure("TFrame",    background=C["bg"])
        s.configure("TLabel",    background=C["bg"],       foreground=C["text"])
        s.configure("TSeparator", background=C["border"])

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        r = self.root
        r.columnconfigure(0, weight=1)
        r.rowconfigure(5, weight=1)   # notebook row expands

        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(r, bg=C["bg"])
        hdr.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 6))

        tk.Label(hdr, text="Cloud Forensics Evidence Collector",
                 bg=C["bg"], fg=C["blue"],
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        tk.Label(hdr, text="   PRJN26-141 — Energy Sector Breach Investigation",
                 bg=C["bg"], fg=C["muted"],
                 font=("Segoe UI", 9)).pack(side="left", pady=(6, 0))

        ts = tk.Label(hdr, text="", bg=C["bg"], fg=C["muted"],
                      font=("Consolas", 8))
        ts.pack(side="right", pady=(6, 0))
        self._update_clock(ts)

        ttk.Separator(r, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=22, pady=(0, 10))

        # ── Path pickers ──────────────────────────────────────────────────────
        pf = tk.Frame(r, bg=C["bg"])
        pf.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 8))
        pf.columnconfigure(1, weight=1)

        for row_i, (label_text, var) in enumerate([
            ("Target Directory", self.target_var),
            ("Output Directory", self.output_var),
        ]):
            tk.Label(pf, text=f"{label_text}:",
                     bg=C["bg"], fg=C["muted"],
                     font=("Segoe UI", 9), width=15,
                     anchor="w").grid(row=row_i, column=0, sticky="w",
                                      padx=(0, 10), pady=3)
            entry = ttk.Entry(pf, textvariable=var, font=("Consolas", 9))
            entry.grid(row=row_i, column=1, sticky="ew", padx=(0, 8), pady=3)
            _v = var  # capture for lambda
            self._flat_btn(pf, "Browse",
                           lambda v=_v: self._browse(v),
                           fg=C["muted"]).grid(row=row_i, column=2, pady=3)

        # ── Action buttons ────────────────────────────────────────────────────
        af = tk.Frame(r, bg=C["bg"])
        af.grid(row=3, column=0, sticky="ew", padx=22, pady=8)

        self._flat_btn(af, "  ○  Create Baseline  ",
                       self._run_baseline, fg=C["blue"],
                       font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
        self._flat_btn(af, "  ●  Scan Directory   ",
                       self._run_scan, fg=C["green"],
                       font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
        self._flat_btn(af, "  ◑  Compare Changes  ",
                       self._run_compare, fg=C["yellow"],
                       font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 20))

        ttk.Checkbutton(af, text="Generate Reports on Compare",
                        variable=self.report_var).pack(side="left")

        # divider
        ttk.Separator(af, orient="vertical").pack(side="left", fill="y",
                                                   padx=16, pady=4)
        self._flat_btn(af, "  Clear Log  ",
                       self._clear_log, fg=C["muted"]).pack(side="left")

        # ── Stats bar ─────────────────────────────────────────────────────────
        self._build_stats_row(r, row=4)

        # ── Notebook ──────────────────────────────────────────────────────────
        nb = ttk.Notebook(r)
        nb.grid(row=5, column=0, sticky="nsew", padx=22, pady=(2, 6))
        self._nb = nb

        tab_files = tk.Frame(nb, bg=C["surface"])
        nb.add(tab_files, text="  Evidence Files  ")
        self._build_file_tree(tab_files)

        tab_log = tk.Frame(nb, bg=C["bg"])
        nb.add(tab_log, text="  Live Log  ")
        self._build_log_panel(tab_log)

        # ── Bottom bar ────────────────────────────────────────────────────────
        bf = tk.Frame(r, bg=C["bg"])
        bf.grid(row=6, column=0, sticky="ew", padx=22, pady=(0, 14))
        bf.columnconfigure(1, weight=1)

        self._prog_var = tk.DoubleVar(value=0)
        self._prog = ttk.Progressbar(
            bf, variable=self._prog_var, maximum=100, length=200,
            style="blue.Horizontal.TProgressbar")
        self._prog.grid(row=0, column=0, padx=(0, 14))

        self._status_lbl = tk.Label(bf, text="Ready",
                                    bg=C["bg"], fg=C["muted"],
                                    font=("Segoe UI", 9), anchor="w")
        self._status_lbl.grid(row=0, column=1, sticky="ew")

        btn_row = tk.Frame(bf, bg=C["bg"])
        btn_row.grid(row=0, column=2, sticky="e")

        self._html_btn = self._flat_btn(btn_row, "  Open HTML Dashboard  ",
                                        self._open_html, fg=C["purple"])
        self._html_btn.pack(side="left", padx=(0, 8))
        self._html_btn["state"] = "disabled"

        self._csv_btn = self._flat_btn(btn_row, "  Open CSV Report  ",
                                       self._open_csv, fg=C["muted"])
        self._csv_btn.pack(side="left")
        self._csv_btn["state"] = "disabled"

    # ─────────────────────────────────────────────────────────────────────────
    # Stats cards
    # ─────────────────────────────────────────────────────────────────────────
    def _build_stats_row(self, parent: tk.Widget, row: int) -> None:
        sf = tk.Frame(parent, bg=C["bg"])
        sf.grid(row=row, column=0, sticky="ew", padx=22, pady=(0, 6))

        specs = [
            ("Total Files", "0",  C["blue"]),
            ("New",         "0",  C["green"]),
            ("Modified",    "0",  C["yellow"]),
            ("Deleted",     "0",  C["red"]),
            ("Clean",       "0",  C["muted"]),
        ]
        self._stat_val: dict[str, tk.Label] = {}
        for i, (name, val, color) in enumerate(specs):
            sf.columnconfigure(i, weight=1)
            card = tk.Frame(sf, bg=C["surface"],
                            highlightbackground=C["border"],
                            highlightthickness=1)
            card.grid(row=0, column=i, padx=(0, 8), sticky="nsew")

            v_lbl = tk.Label(card, text=val,
                             bg=C["surface"], fg=color,
                             font=("Segoe UI", 24, "bold"))
            v_lbl.pack(pady=(10, 0), padx=24)

            tk.Label(card, text=name.upper(),
                     bg=C["surface"], fg=C["muted"],
                     font=("Segoe UI", 7, "bold")).pack(pady=(0, 8))

            self._stat_val[name] = v_lbl

    # ─────────────────────────────────────────────────────────────────────────
    # Evidence Files treeview
    # ─────────────────────────────────────────────────────────────────────────
    def _build_file_tree(self, parent: tk.Widget) -> None:
        cols = ("status", "filename", "ext", "size", "created",
                "modified", "accessed", "md5")
        tv = ttk.Treeview(parent, columns=cols, show="headings",
                          selectmode="browse")
        self._tree = tv

        col_specs = [
            ("status",   "Status",       96,  "center"),
            ("filename", "Filename",     230, "w"),
            ("ext",      "Type",         58,  "center"),
            ("size",     "Size (B)",     88,  "e"),
            ("created",  "Created",      138, "w"),
            ("modified", "Last Modified",138, "w"),
            ("accessed", "Last Accessed",138, "w"),
            ("md5",      "MD5 (partial)",130, "w"),
        ]
        for col, heading, width, anchor in col_specs:
            tv.heading(col, text=heading,
                       command=lambda c=col: self._sort_tree(c))
            tv.column(col, width=width, minwidth=40, anchor=anchor)

        # Row colour tags
        tv.tag_configure("new",
            background="#0b2218", foreground=C["green"])
        tv.tag_configure("modified",
            background="#1c1500", foreground=C["yellow"])
        tv.tag_configure("deleted",
            background="#1a0a09", foreground=C["red"])
        tv.tag_configure("clean",
            background=C["surface"], foreground=C["text"])
        tv.tag_configure("clean_alt",
            background="#13191f", foreground=C["text"])

        sb_y = ttk.Scrollbar(parent, orient="vertical",   command=tv.yview)
        sb_x = ttk.Scrollbar(parent, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)

        tv.grid(row=0, column=0, sticky="nsew")
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")

        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    # ─────────────────────────────────────────────────────────────────────────
    # Live log text panel
    # ─────────────────────────────────────────────────────────────────────────
    def _build_log_panel(self, parent: tk.Widget) -> None:
        # Toolbar
        tb = tk.Frame(parent, bg=C["surface2"])
        tb.pack(fill="x", side="top")

        tk.Label(tb, text="  forensic_log.txt  ",
                 bg=C["surface2"], fg=C["muted"],
                 font=("Consolas", 8)).pack(side="left", pady=4)

        self._flat_btn(tb, "Clear", self._clear_log,
                       fg=C["muted"]).pack(side="right", padx=6, pady=3)

        # Text area
        frame = tk.Frame(parent, bg=C["bg"])
        frame.pack(fill="both", expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._log_text = tk.Text(
            frame,
            bg=C["bg"], fg=C["text"],
            font=("Consolas", 9),
            insertbackground=C["text"],
            selectbackground=C["sel"],
            relief="flat", bd=0,
            wrap="none", state="disabled",
            padx=10, pady=6,
        )
        sb_y = ttk.Scrollbar(frame, orient="vertical",
                             command=self._log_text.yview)
        sb_x = ttk.Scrollbar(frame, orient="horizontal",
                             command=self._log_text.xview)
        self._log_text.configure(yscrollcommand=sb_y.set,
                                 xscrollcommand=sb_x.set)

        self._log_text.grid(row=0, column=0, sticky="nsew")
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")

        # Colour tags per log level
        self._log_text.tag_configure("DEBUG",    foreground=C["muted"])
        self._log_text.tag_configure("INFO",     foreground=C["text"])
        self._log_text.tag_configure("WARNING",  foreground=C["yellow"])
        self._log_text.tag_configure("ERROR",    foreground=C["red"])
        self._log_text.tag_configure("CRITICAL", foreground=C["red"],
                                     font=("Consolas", 9, "bold"))
        self._log_text.tag_configure("UI",       foreground=C["blue"])

    # ─────────────────────────────────────────────────────────────────────────
    # Logging wiring
    # ─────────────────────────────────────────────────────────────────────────
    def _wire_logger(self) -> None:
        self._logger = setup_logger()
        h = _QueueLogHandler(self._q)
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        self._logger.addHandler(h)
        # Startup message
        self._logger.info("GUI started — PRJN26-141 Cloud Forensics Tool")

    # ─────────────────────────────────────────────────────────────────────────
    # Queue consumer  (main thread, every 40 ms)
    # ─────────────────────────────────────────────────────────────────────────
    def _poll(self) -> None:
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._append_log(msg[1], msg[2])
                elif kind == "status":
                    self._set_status(msg[1], msg[2])
                elif kind == "results":
                    self._display_results(*msg[1:])
                elif kind == "done":
                    self._on_done(msg[1])
                elif kind == "error":
                    self._on_error(msg[1])
                elif kind == "clear_busy":
                    self._clear_busy()
        except queue.Empty:
            pass
        finally:
            self.root.after(40, self._poll)

    def _append_log(self, level: int, text: str) -> None:
        tag = {
            logging.DEBUG:    "DEBUG",
            logging.INFO:     "INFO",
            logging.WARNING:  "WARNING",
            logging.ERROR:    "ERROR",
            logging.CRITICAL: "CRITICAL",
        }.get(level, "INFO")
        w = self._log_text
        w.configure(state="normal")
        w.insert("end", text + "\n", tag)
        w.see("end")
        w.configure(state="disabled")

    def _append_ui_log(self, text: str) -> None:
        """Write a UI-sourced message to the log panel without going through logger."""
        w = self._log_text
        w.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        w.insert("end", f"{ts} [UI      ] {text}\n", "UI")
        w.see("end")
        w.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────────────────
    # Results display
    # ─────────────────────────────────────────────────────────────────────────
    def _display_results(self, records, new_files, modified, deleted,
                         csv_path, html_path) -> None:
        # Clear treeview
        for item in self._tree.get_children():
            self._tree.delete(item)

        # Update stat cards
        flagged = len(new_files) + len(modified) + len(deleted)
        clean   = max(0, len(records) - len(new_files) - len(modified))

        self._stat_val["Total Files"].config(text=str(len(records) + len(deleted)))
        self._stat_val["New"].config(text=str(len(new_files)))
        self._stat_val["Modified"].config(text=str(len(modified)))
        self._stat_val["Deleted"].config(text=str(len(deleted)))
        self._stat_val["Clean"].config(text=str(clean))

        # Populate treeview
        all_rows = list(records) + list(deleted)
        for i, rec in enumerate(all_rows):
            status = rec.get("status", "UNCHANGED")
            tag = {
                "NEW":       "new",
                "MODIFIED":  "modified",
                "DELETED":   "deleted",
            }.get(status, "clean" if i % 2 == 0 else "clean_alt")

            md5_s = (rec.get("md5") or "")
            md5_s = md5_s[:16] + "…" if len(md5_s) >= 16 else md5_s

            self._tree.insert("", "end", tags=(tag,), values=(
                status,
                rec.get("filename", ""),
                rec.get("extension", ""),
                f"{rec.get('size_bytes', 0):,}",
                rec.get("created",  ""),
                rec.get("modified", ""),
                rec.get("accessed", ""),
                md5_s,
            ))

        # Store report paths + enable buttons
        self._last_csv  = csv_path
        self._last_html = html_path

        self._csv_btn["state"]  = "normal" if csv_path  else "disabled"
        self._html_btn["state"] = "normal" if html_path else "disabled"

        # Alert popup if flagged files found
        if flagged > 0:
            self._set_status(
                f"ALERT — {flagged} suspicious file(s) detected!", C["red"])

        # Switch to Files tab
        self._nb.select(0)

    # ─────────────────────────────────────────────────────────────────────────
    # Status / progress helpers
    # ─────────────────────────────────────────────────────────────────────────
    def _set_status(self, text: str, color: str = None) -> None:
        self._status_lbl.config(text=text,
                                fg=color or C["muted"])

    def _set_busy(self, msg: str) -> None:
        self._busy = True
        self._set_status(msg, C["muted"])
        self._prog.configure(mode="indeterminate",
                             style="blue.Horizontal.TProgressbar")
        self._prog.start(12)
        self._html_btn["state"] = "disabled"
        self._csv_btn["state"]  = "disabled"

    def _clear_busy(self) -> None:
        self._busy = False
        self._prog.stop()
        self._prog.configure(mode="determinate")
        self._prog_var.set(100)
        self.root.after(1800, lambda: self._prog_var.set(0))

    def _on_done(self, msg: str) -> None:
        self._clear_busy()
        self._set_status(msg, C["green"])
        self._prog.configure(style="green.Horizontal.TProgressbar")

    def _on_error(self, msg: str) -> None:
        self._clear_busy()
        self._set_status(f"Error: {msg}", C["red"])
        messagebox.showerror("Forensic Tool Error", msg, parent=self.root)

    # ─────────────────────────────────────────────────────────────────────────
    # Treeview sorting
    # ─────────────────────────────────────────────────────────────────────────
    def _sort_tree(self, col: str) -> None:
        rows = [(self._tree.set(k, col), k)
                for k in self._tree.get_children("")]
        asc  = not self._sort_asc.get(col, False)
        self._sort_asc[col] = asc

        try:
            rows.sort(key=lambda t: float(t[0].replace(",", "")),
                      reverse=not asc)
        except ValueError:
            rows.sort(key=lambda t: t[0].lower(), reverse=not asc)

        for idx, (_, k) in enumerate(rows):
            self._tree.move(k, "", idx)

    # ─────────────────────────────────────────────────────────────────────────
    # Action button handlers
    # ─────────────────────────────────────────────────────────────────────────
    def _validate_path(self) -> str | None:
        p = self.target_var.get().strip()
        if not p:
            messagebox.showwarning("No Path", "Please enter a target directory.",
                                   parent=self.root)
            return None
        if not Path(p).is_dir():
            messagebox.showerror("Path Not Found",
                                 f"Directory does not exist:\n{p}",
                                 parent=self.root)
            return None
        return p

    def _run_baseline(self) -> None:
        if self._busy:
            return
        path = self._validate_path()
        if not path:
            return
        self._append_ui_log(f"Creating baseline for: {path}")
        self._set_busy("Creating baseline…")
        threading.Thread(target=self._work_baseline,
                         args=(path,), daemon=True).start()

    def _run_scan(self) -> None:
        if self._busy:
            return
        path = self._validate_path()
        if not path:
            return
        output = self.output_var.get().strip() or "."
        self._append_ui_log(f"Scanning: {path}")
        self._set_busy("Scanning directory…")
        threading.Thread(target=self._work_scan,
                         args=(path, output), daemon=True).start()

    def _run_compare(self) -> None:
        if self._busy:
            return
        path = self._validate_path()
        if not path:
            return
        output = self.output_var.get().strip() or "."
        gen    = self.report_var.get()
        self._append_ui_log(f"Comparing: {path}")
        self._set_busy("Comparing against baseline…")
        threading.Thread(target=self._work_compare,
                         args=(path, output, gen), daemon=True).start()

    def _clear_log(self) -> None:
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")

    # ─────────────────────────────────────────────────────────────────────────
    # Worker threads  (NO tkinter calls — only queue puts)
    # ─────────────────────────────────────────────────────────────────────────
    def _work_baseline(self, path: str) -> None:
        try:
            self._q.put(("status", "Scanning files…", C["muted"]))
            records   = scan_directory(path, self._logger)
            self._q.put(("status", "Writing baseline JSON…", C["muted"]))
            bl_path   = save_baseline(records, path, self._logger)

            for r in records:
                r["status"] = "UNCHANGED"
            self._q.put(("results", records, [], [], [], None, None))
            self._q.put(("done",
                f"Baseline created — {len(records)} files indexed  |  {bl_path}"))
        except Exception as exc:
            self._q.put(("error", str(exc)))
        finally:
            self._q.put(("clear_busy",))

    def _work_scan(self, path: str, output: str) -> None:
        try:
            self._q.put(("status", "Scanning files…", C["muted"]))
            records  = scan_directory(path, self._logger)
            baseline = load_baseline(path, self._logger)

            if baseline:
                self._q.put(("status", "Comparing hashes against baseline…",
                              C["muted"]))
                new_files, modified, deleted = compare_with_baseline(
                    records, baseline, self._logger)
            else:
                self._q.put(("status",
                    "No baseline found — all files marked NEW", C["yellow"]))
                new_files, modified, deleted = [], [], []
                for r in records:
                    r["status"] = "NEW"
                new_files = list(records)

            self._q.put(("status", "Generating reports…", C["muted"]))
            os.makedirs(output, exist_ok=True)
            csv_path  = generate_csv_report(
                records, new_files, modified, deleted, output)
            html_path = generate_html_report(
                records, new_files, modified, deleted, path, output)

            flagged = len(new_files) + len(modified) + len(deleted)
            self._q.put(("results", records, new_files, modified,
                         deleted, csv_path, html_path))
            self._q.put(("done",
                f"Scan complete — {len(records)} files | "
                f"{flagged} flagged | Reports saved"))
        except Exception as exc:
            self._q.put(("error", str(exc)))
        finally:
            self._q.put(("clear_busy",))

    def _work_compare(self, path: str, output: str,
                      gen_reports: bool) -> None:
        try:
            baseline = load_baseline(path, self._logger)
            if not baseline:
                self._q.put(("error",
                    f"No baseline found for:\n{path}\n\n"
                    "Click 'Create Baseline' first."))
                return

            self._q.put(("status", "Scanning files…", C["muted"]))
            records = scan_directory(path, self._logger)
            self._q.put(("status", "Comparing hashes…", C["muted"]))
            new_files, modified, deleted = compare_with_baseline(
                records, baseline, self._logger)

            csv_path = html_path = None
            if gen_reports:
                self._q.put(("status", "Generating reports…", C["muted"]))
                os.makedirs(output, exist_ok=True)
                csv_path  = generate_csv_report(
                    records, new_files, modified, deleted, output)
                html_path = generate_html_report(
                    records, new_files, modified, deleted, path, output)

            flagged = len(new_files) + len(modified) + len(deleted)
            self._q.put(("results", records, new_files, modified,
                         deleted, csv_path, html_path))
            self._q.put(("done",
                f"Compare done — {len(records)} files | {flagged} flagged"))
        except Exception as exc:
            self._q.put(("error", str(exc)))
        finally:
            self._q.put(("clear_busy",))

    # ─────────────────────────────────────────────────────────────────────────
    # Report launchers
    # ─────────────────────────────────────────────────────────────────────────
    def _open_html(self) -> None:
        if self._last_html and Path(self._last_html).exists():
            webbrowser.open(Path(self._last_html).resolve().as_uri())
        else:
            messagebox.showinfo("Not Available",
                                "No HTML report has been generated yet.",
                                parent=self.root)

    def _open_csv(self) -> None:
        if self._last_csv and Path(self._last_csv).exists():
            p = str(Path(self._last_csv).resolve())
            if sys.platform == "win32":
                os.startfile(p)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", p])
            else:
                subprocess.Popen(["xdg-open", p])
        else:
            messagebox.showinfo("Not Available",
                                "No CSV report has been generated yet.",
                                parent=self.root)

    # ─────────────────────────────────────────────────────────────────────────
    # Utility widgets
    # ─────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _flat_btn(parent, text: str, cmd,
                  fg: str = C["text"],
                  font=("Segoe UI", 9)) -> tk.Button:
        """Create a flat, hover-aware dark button."""
        btn = tk.Button(
            parent,
            text=text, command=cmd,
            bg=C["btn"], fg=fg,
            activebackground=C["btn_hover"], activeforeground=fg,
            relief="flat", bd=0, cursor="hand2",
            font=font,
            padx=10, pady=5,
        )
        btn.bind("<Enter>", lambda _: btn.config(bg=C["btn_hover"]))
        btn.bind("<Leave>", lambda _: btn.config(bg=C["btn"]))
        return btn

    def _browse(self, var: tk.StringVar) -> None:
        d = filedialog.askdirectory(
            initialdir=var.get() or ".",
            parent=self.root,
            title="Select Directory",
        )
        if d:
            var.set(str(Path(d).resolve()))

    def _update_clock(self, lbl: tk.Label) -> None:
        lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, lambda: self._update_clock(lbl))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    root = tk.Tk()
    try:
        # Suppress the default tkinter icon on Windows
        root.iconbitmap(default="")
    except Exception:
        pass
    root.geometry("1100x760")
    ForensicApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
