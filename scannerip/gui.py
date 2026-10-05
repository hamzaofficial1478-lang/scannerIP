"""Desktop app: camera preview, risk report, live IP shield and ID layers.

Tkinter isn't thread-safe, so the camera, the shield and the link inspector
all run on background threads and talk to the window through a queue. None
of those threads ever holds a reference to the window itself: if the last
reference to a Tk object is dropped on the wrong thread, Tk crashes.
"""

from __future__ import annotations

import gc
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageTk

from .analyzer import Report, make_visible
from .decoder import CameraWorker, Decoded, decode_file
from .identity import IdentityVault
from .rotator import RotationError, RotationEvent, Rotator, Shield, SimulatedRotator
from .scanlog import ScanLog

PREVIEW_W, PREVIEW_H = 640, 360
LEVEL_STYLE = {  # background, text
    "CLEAN": ("#2e7d32", "white"),
    "LOW": ("#00838f", "white"),
    "MEDIUM": ("#f9a825", "black"),
    "HIGH": ("#e65100", "white"),
    "DANGEROUS": ("#b71c1c", "white"),
}
SEVERITY_TAG = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


class LatestFrame:
    """Passes the newest camera frame from the camera thread to the window."""

    def __init__(self):
        self._lock = threading.Lock()
        self._image: Image.Image | None = None

    def put(self, frame, codes) -> None:  # runs on the camera thread
        import cv2
        import numpy as np

        for code in codes:
            cv2.polylines(frame, [np.array(code.corners, dtype=np.int32)], True, (118, 230, 0), 3)
        image = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        with self._lock:
            self._image = image

    def take(self) -> Image.Image | None:
        with self._lock:
            image, self._image = self._image, None
        return image


class App:
    def __init__(self, root: tk.Tk, rotator: Rotator, interval: float | None = None,
                 camera_index: int = 0, vault: IdentityVault | None = None,
                 log: ScanLog | None = None):
        self.root = root
        self.events: queue.Queue = queue.Queue()
        events = self.events  # background callbacks get the queue, never `self`
        self.vault = vault or IdentityVault.load()
        self.log = log or ScanLog()
        self.shield = Shield(rotator, self.vault, interval,
                             on_rotate=lambda ev: events.put(("rotate", ev)),
                             on_error=lambda exc: events.put(("shield_error", exc)))
        self.camera_index = camera_index
        self.camera: CameraWorker | None = None
        self.frames = LatestFrame()
        self._photo = None
        self.report: Report | None = None
        self.closed = False

        self._build()
        self.shield.start()
        self._timers = {"poll": self.root.after(40, self._poll),
                        "tick": self.root.after(250, self._tick)}
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    # ---------- layout ----------
    def _build(self) -> None:
        root = self.root
        root.title("ScannerIP - safe QR scanner")
        root.geometry("1220x760")
        root.minsize(1000, 680)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Big.TLabel", font=("TkDefaultFont", 16, "bold"))
        style.configure("IP.TLabel", font=("TkFixedFont", 15, "bold"))
        style.configure("Mono.TLabel", font=("TkFixedFont", 10))
        style.configure("Small.TLabel", foreground="#666666")

        top = ttk.Frame(root, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="ScannerIP", style="Big.TLabel").pack(side="left")
        ttk.Label(top, text="  scan first, trust later", style="Small.TLabel").pack(side="left")
        rot = self.shield.rotator
        mode_text = f"Shield: {rot.name}"
        self.mode_label = tk.Label(top, text=mode_text, padx=8, pady=2,
                                   bg="#2e7d32" if rot.anonymous else "#f9a825",
                                   fg="white" if rot.anonymous else "black")
        self.mode_label.pack(side="right")

        self.status = ttk.Label(root, text=f"Scan log: {self.log.path}", style="Small.TLabel",
                                padding=(10, 0, 10, 6))
        self.status.pack(side="bottom", fill="x")

        body = ttk.Frame(root, padding=(10, 0, 10, 6))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1, minsize=PREVIEW_W)
        body.columnconfigure(1, weight=1, minsize=530)
        body.rowconfigure(0, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = ttk.Frame(body)
        right.grid(row=0, column=1, sticky="nsew")

        # camera / image preview
        holder = tk.Frame(left, width=PREVIEW_W, height=PREVIEW_H, bg="#1e1e1e")
        holder.pack(fill="x")
        holder.pack_propagate(False)
        self.preview = tk.Label(holder, bg="#1e1e1e", fg="#bbbbbb",
                                text="Camera is off.\nStart the camera or open an image.")
        self.preview.pack(fill="both", expand=True)

        buttons = ttk.Frame(left, padding=(0, 6))
        buttons.pack(fill="x")
        self.start_btn = ttk.Button(buttons, text="Start camera", command=self.start_camera)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(buttons, text="Stop camera", command=self.stop_camera,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(buttons, text="Open image...", command=self.open_image).pack(side="left")

        # last scan
        result = ttk.LabelFrame(left, text="Last scan", padding=8)
        result.pack(fill="both", expand=True)
        head = ttk.Frame(result)
        head.pack(fill="x")
        self.badge = tk.Label(head, text="  nothing yet  ", bg="#9e9e9e", fg="white",
                              font=("TkDefaultFont", 11, "bold"), padx=8, pady=3)
        self.badge.pack(side="left")
        self.kind_label = ttk.Label(head, text="")
        self.kind_label.pack(side="left", padx=10)

        self.content = tk.Text(result, height=3, wrap="char", font="TkFixedFont",
                               relief="flat", background="#f4f4f4")
        self.content.pack(fill="x", pady=(6, 4))
        self.findings = tk.Text(result, height=6, wrap="word", relief="flat", background="#fbfbfb",
                                font="TkDefaultFont")
        self.findings.pack(fill="both", expand=True)
        for tag, colour in (("info", "#555555"), ("low", "#00838f"), ("medium", "#a66b00"),
                            ("high", "#e65100"), ("critical", "#b71c1c"), ("advice", "#000000")):
            self.findings.tag_configure(tag, foreground=colour)
        self.findings.tag_configure("advice", font=("TkDefaultFont", 10, "bold"))
        for widget in (self.content, self.findings):
            widget.configure(state="disabled")

        actions = ttk.Frame(result, padding=(0, 6, 0, 0))
        actions.pack(fill="x")
        self.inspect_btn = ttk.Button(actions, text="Inspect link through shield",
                                      command=self.inspect_link, state="disabled")
        self.inspect_btn.pack(side="left")
        ttk.Button(actions, text="Copy text", command=self.copy_content).pack(side="left", padx=6)
        ttk.Label(actions, text="Links are never opened automatically.",
                  style="Small.TLabel").pack(side="right")

        # network shield
        shield = ttk.LabelFrame(right, text="Network shield (IP shifting)", padding=8)
        shield.pack(fill="x")
        self.ip_label = ttk.Label(shield, text="connecting...", style="IP.TLabel")
        self.ip_label.pack(anchor="w")
        self.via_label = ttk.Label(shield, text="", style="Small.TLabel")
        self.via_label.pack(anchor="w")
        row = ttk.Frame(shield)
        row.pack(fill="x", pady=(4, 0))
        self.count_label = ttk.Label(row, text="Shift #0")
        self.count_label.pack(side="left")
        self.next_label = ttk.Label(row, text="")
        self.next_label.pack(side="left", padx=12)
        ttk.Button(row, text="Shift now", command=self.shift_now).pack(side="right")
        if not rot.anonymous:
            ttk.Label(shield, text="Demo mode: these addresses are made up and your real IP is "
                                   "NOT hidden. Use Tor or proxy mode for real protection.",
                      foreground="#a66b00", wraplength=420).pack(anchor="w", pady=(4, 0))

        # identity layers
        ident = ttk.LabelFrame(right, text="Device ID layers", padding=8)
        ident.pack(fill="x", pady=8)
        self.layer_values = []
        for i, (name, value, why) in enumerate(self.vault.layers()):
            ttk.Label(ident, text=name).grid(row=i * 2, column=0, sticky="w")
            val = ttk.Label(ident, text=value, style="Mono.TLabel")
            val.grid(row=i * 2, column=1, sticky="w", padx=(8, 0))
            ttk.Label(ident, text=why, style="Small.TLabel").grid(row=i * 2 + 1, column=0,
                                                                  columnspan=2, sticky="w",
                                                                  pady=(0, 4))
            self.layer_values.append(val)

        # shift history and scan history share the space as tabs
        tabs = ttk.Notebook(right)
        tabs.pack(fill="both", expand=True)
        self.shift_tree = self._table(tabs, "Shift history (IP + ID change together)", (
            ("n", "#", 40), ("time", "Time", 72), ("ip", "Exit IP", 140), ("rid", "Rotating ID", 190)))
        self.scan_tree = self._table(tabs, "Scan history", (
            ("time", "Time", 72), ("risk", "Risk", 100), ("rid", "Logged as", 196),
            ("text", "Content", 145)))
        self.tabs = tabs

    @staticmethod
    def _table(tabs: ttk.Notebook, title: str, columns) -> ttk.Treeview:
        frame = ttk.Frame(tabs, padding=4)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=8)
        for col, label, width in columns:
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=40, anchor="w", stretch=col in ("rid", "text"))
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        tabs.add(frame, text=title)
        return tree

    # ---------- background -> UI ----------
    def _poll(self) -> None:
        if self.closed:
            return
        try:
            while True:
                kind, data = self.events.get_nowait()
                handler = getattr(self, f"_on_{kind}")
                handler(data)
        except queue.Empty:
            pass
        frame = self.frames.take()
        if frame is not None:
            self._show_image(frame)
        self._timers["poll"] = self.root.after(40, self._poll)

    def _tick(self) -> None:
        if self.closed:
            return
        left = self.shield.seconds_left()
        self.next_label.configure(text=f"next shift in {left:0.0f}s" if left is not None else "")
        self._timers["tick"] = self.root.after(250, self._tick)

    def _on_rotate(self, ev: RotationEvent) -> None:
        self.ip_label.configure(text=ev.exit.ip)
        tor = {True: " - Tor confirmed", False: " - not a Tor exit"}.get(ev.exit.is_tor, "")
        self.via_label.configure(text=f"via {ev.exit.via}{tor}")
        self.count_label.configure(text=f"Shift #{ev.identity.rotation}")
        for label, (_, value, _) in zip(self.layer_values, self.vault.layers()):
            label.configure(text=value)
        self.shift_tree.insert("", 0, values=(ev.identity.rotation, time.strftime("%H:%M:%S"),
                                              ev.exit.ip, ev.identity.rotating_id))
        for extra in self.shift_tree.get_children()[50:]:
            self.shift_tree.delete(extra)

    def _on_shield_error(self, exc: Exception) -> None:
        self.ip_label.configure(text="shift failed")
        self.set_status(f"Shield problem: {exc}")

    def _on_code(self, code: Decoded) -> None:
        self.handle_scan(code)

    def _on_camera_error(self, exc: Exception) -> None:
        self.set_status(str(exc))
        self._camera_stopped()

    def _on_inspected(self, payload) -> None:
        url, result = payload
        self.inspect_btn.configure(state="normal")
        self._show_inspection(url, result)

    # ---------- scanning ----------
    def handle_scan(self, code: Decoded) -> Report:
        report = code.report()
        snapshot = self.vault.current
        self.log.record(code.format, report, snapshot)
        self.report = report
        self._show_report(report, code.format)
        rid = snapshot.rotating_id if snapshot else "-"
        self.scan_tree.insert("", 0, values=(time.strftime("%H:%M:%S"),
                                             f"{report.level} {report.score}", rid,
                                             make_visible(report.payload.summary())[:120]))
        return report

    def _show_report(self, report: Report, fmt: str) -> None:
        bg, fg = LEVEL_STYLE[report.level]
        self.badge.configure(text=f"  {report.level}  {report.score}/100  ", bg=bg, fg=fg)
        self.kind_label.configure(text=f"{report.payload.label}   [{fmt}]")
        raw = report.payload.raw if report.payload.kind != "binary" else report.payload.summary()
        self._set_text(self.content, make_visible(raw))
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")
        if not report.findings:
            self.findings.insert("end", "No warning signs found.\n", "info")
        for f in report.findings:
            self.findings.insert("end", f"[{f.severity.upper()}] {f.message}\n", SEVERITY_TAG[f.severity])
        self.findings.insert("end", "\n" + report.advice, "advice")
        self.findings.configure(state="disabled")
        can_inspect = (report.payload.kind == "url"
                       and report.payload.fields.get("scheme") in ("http", "https")
                       and self.shield.rotator.anonymous)
        self.inspect_btn.configure(state="normal" if can_inspect else "disabled")

    def open_image(self) -> None:
        path = filedialog.askopenfilename(title="Choose an image with a code in it", filetypes=[
            ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.webp *.tif *.tiff"), ("All files", "*")])
        if path:
            self.scan_file(path)

    def scan_file(self, path: str) -> list[Decoded]:
        try:
            codes = decode_file(path)
            img = Image.open(path).convert("RGB")
        except OSError as exc:
            self.set_status(f"Couldn't open {path}: {exc}")
            return []
        draw = ImageDraw.Draw(img)
        for code in codes:
            draw.polygon(code.corners, outline="#00e676", width=max(3, img.width // 150))
        self._show_image(img)
        if not codes:
            self.set_status("No code found in that image.")
        for code in codes:
            self.handle_scan(code)
        return codes

    def _show_image(self, img: Image.Image) -> None:
        img = img.copy()
        img.thumbnail((PREVIEW_W, PREVIEW_H))
        self._photo = ImageTk.PhotoImage(img)
        self.preview.configure(image=self._photo, text="")

    # ---------- camera ----------
    def start_camera(self) -> None:
        if self.camera and self.camera.is_alive():
            return
        events = self.events
        self.camera = CameraWorker(self.camera_index, on_frame=self.frames.put,
                                   on_new=lambda code: events.put(("code", code)),
                                   on_error=lambda exc: events.put(("camera_error", exc)))
        self.camera.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.set_status("Camera on. Hold a code up to it.")

    def stop_camera(self) -> None:
        if self.camera:
            self.camera.stop()
        self._camera_stopped()

    def _camera_stopped(self) -> None:
        self.camera = None
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    # ---------- actions ----------
    def shift_now(self) -> None:
        shield, events = self.shield, self.events

        def work():
            try:
                shield.rotate_now()
            except Exception as exc:
                events.put(("shield_error", exc))
        threading.Thread(target=work, daemon=True).start()

    def inspect_link(self) -> None:
        if not self.report or self.report.payload.kind != "url":
            return
        url = self.report.payload.fields["url"]
        self.inspect_btn.configure(state="disabled")
        self.set_status(f"Inspecting {url[:60]} through the shield...")

        shield, events = self.shield, self.events

        def work():
            from .inspector import inspect_url
            try:
                result = inspect_url(url, shield.proxies())
            except Exception as exc:
                result = exc
            events.put(("inspected", (url, result)))
        threading.Thread(target=work, daemon=True).start()

    def _show_inspection(self, url: str, result) -> None:
        win = tk.Toplevel(self.root)
        win.title("Where does this link go?")
        win.geometry("760x420")
        text = tk.Text(win, wrap="word", font="TkFixedFont")
        text.pack(fill="both", expand=True)
        if isinstance(result, Exception):
            text.insert("end", f"Inspection failed: {result}\n")
        else:
            ip = self.shield.current.exit.ip if self.shield.current else "?"
            text.insert("end", f"Checked through {ip} - the site never saw your real IP.\n\n")
            for i, hop in enumerate(result.hops):
                text.insert("end", f"{i}. [{hop.status}] {hop.url}\n")
            if result.error:
                text.insert("end", f"\nStopped early: {result.error}\n")
            text.insert("end", "\n")
            for f in result.extra:
                text.insert("end", f"[{f.severity.upper()}] {f.message}\n")
            if result.report:
                r = result.report
                text.insert("end", f"\nFinal destination: {r.level} ({r.score}/100)\n")
                for f in r.findings:
                    text.insert("end", f"[{f.severity.upper()}] {f.message}\n")
                text.insert("end", f"\n{r.advice}\n")
        text.configure(state="disabled")
        self.set_status("Inspection finished.")

    def copy_content(self) -> None:
        if self.report:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.report.payload.raw)
            self.set_status("Copied. Paste it somewhere harmless, not straight into a browser.")

    def set_status(self, text: str) -> None:
        self.status.configure(text=text)

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for timer in self._timers.values():
            self.root.after_cancel(timer)
        if self.camera:
            self.camera.stop()
            self.camera = None
        self.shield.stop(timeout=1.0)
        threading.Thread(target=self.shield.rotator.close, daemon=True).start()
        self._photo = None
        self.root.destroy()


def run(args) -> int:
    from .cli import build_rotator

    root = tk.Tk()
    try:
        rotator = build_rotator(args)
    except RotationError as exc:
        root.withdraw()
        if not messagebox.askyesno("Shield not available",
                                   f"{exc}\n\nCarry on in demo mode? (IPs will be simulated "
                                   "and your real IP will NOT be hidden.)"):
            root.destroy()
            return 2
        rotator = SimulatedRotator()
        root.deiconify()
    app = App(root, rotator, interval=args.interval, camera_index=args.camera)
    root.mainloop()
    app.close()
    # Free every Tk object here, on the main thread, before the program exits
    # while the shield thread may still be finishing a request.
    del app, root
    gc.collect()
    return 0
