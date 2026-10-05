"""Command line entry point: python -m scannerip <command>."""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time

from .analyzer import Report
from .identity import IdentityVault
from .rotator import (ProxyPoolRotator, RotationError, RotationEvent, Rotator, Shield,
                      SimulatedRotator, TorRotator)

LEVEL_COLOURS = {"CLEAN": "32", "LOW": "36", "MEDIUM": "33", "HIGH": "31", "DANGEROUS": "1;41;97"}
SEVERITY_ICONS = {"info": "i", "low": "-", "medium": "!", "high": "!!", "critical": "XX"}


def _colour(text: str, code: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


def print_report(report: Report, fmt: str = "", rotating_id: str | None = None) -> None:
    p = report.payload
    badge = _colour(f" {report.level} {report.score}/100 ", LEVEL_COLOURS[report.level])
    print(f"{badge}  {p.label}{f'  [{fmt}]' if fmt else ''}")
    print(f"  Content : {p.summary()!r}" if p.kind != "binary" else f"  Content : {p.summary()}")
    for f in report.findings:
        print(f"  {SEVERITY_ICONS[f.severity]:>2} {f.message}")
    print(f"  Advice  : {report.advice}")
    if rotating_id:
        print(f"  Logged as {rotating_id}")
    print()


def build_rotator(args) -> Rotator:
    if args.mode == "tor":
        return TorRotator(socks_port=args.socks_port, control_port=args.control_port,
                          password=os.environ.get("TOR_CONTROL_PASSWORD"))
    if args.mode == "proxy":
        if not args.proxies:
            raise RotationError("--mode proxy needs --proxies FILE (one proxy URL per line).")
        return ProxyPoolRotator.from_file(args.proxies)
    return SimulatedRotator()


def _add_shield_args(p: argparse.ArgumentParser, default_mode: str = "simulate") -> None:
    p.add_argument("--mode", choices=("tor", "proxy", "simulate"), default=default_mode,
                   help="how to shift the IP (default: %(default)s)")
    p.add_argument("--interval", type=float, default=None,
                   help="seconds between IP shifts (default: 5 simulate, 10 proxy, 30 Tor; "
                        "Tor won't go below 10)")
    p.add_argument("--proxies", help="file with one proxy URL per line, for --mode proxy")
    p.add_argument("--socks-port", type=int, help="Tor SOCKS port (auto: 9050, then 9150)")
    p.add_argument("--control-port", type=int, help="Tor control port (auto: 9051, then 9151)")


def cmd_scan(args) -> int:
    from .decoder import decode_file
    from .scanlog import ScanLog

    vault = IdentityVault.load()
    snapshot = vault.rotate("offline")
    log = None if args.no_log else ScanLog()
    found_any = False
    paths = []
    for pattern in args.images:  # Windows shells don't expand *.png for us
        paths.extend(sorted(glob.glob(pattern)) if glob.has_magic(pattern) else [pattern])
    for path in paths:
        try:
            codes = decode_file(path)
        except OSError as exc:
            print(f"{path}: can't open ({exc})", file=sys.stderr)
            continue
        print(f"== {path}: {len(codes)} code(s) found")
        for code in codes:
            found_any = True
            report = code.report()
            print_report(report, code.format, snapshot.rotating_id if log else None)
            if log:
                log.record(code.format, report, snapshot)
    return 0 if found_any else 1


def cmd_camera(args) -> int:
    from .decoder import CameraWorker
    from .scanlog import ScanLog

    vault = IdentityVault.load()
    log = ScanLog()
    errors: list[Exception] = []

    def on_new(code):
        snap = vault.rotate("offline")
        report = code.report()
        print_report(report, code.format, snap.rotating_id)
        log.record(code.format, report, snap)

    worker = CameraWorker(args.index, on_new=on_new, on_error=errors.append)
    worker.start()
    print("Point a code at the camera. Ctrl+C to stop.\n")
    try:
        while worker.is_alive():
            worker.join(0.5)
    except KeyboardInterrupt:
        worker.stop()
    if errors:
        print(f"Camera error: {errors[0]}", file=sys.stderr)
        return 1
    return 0


def cmd_identity(args) -> int:
    vault = IdentityVault.load()
    vault.rotate("not connected")
    for name, value, why in vault.layers():
        print(f"{name:<32}{value}")
        print(f"{'':<32}{why}")
    return 0


def cmd_shield(args) -> int:
    vault = IdentityVault.load()
    rotator = build_rotator(args)
    if not rotator.anonymous:
        print(_colour("SIMULATED MODE: these are made-up documentation addresses. "
                      "Your real IP is NOT hidden.", "33"))

    def on_rotate(ev: RotationEvent):
        tor = {True: "  (Tor confirmed)", False: "  (NOT Tor)"}.get(ev.exit.is_tor, "")
        print(f"#{ev.identity.rotation:<4} {time.strftime('%H:%M:%S')}  IP {ev.exit.ip:<40} "
              f"{ev.identity.rotating_id}  via {ev.exit.via}{tor}")

    shield = Shield(rotator, vault, args.interval, on_rotate=on_rotate,
                    on_error=lambda e: print(f"rotation failed: {e}", file=sys.stderr))
    print(f"Shifting IP every {shield.interval:g}s using {rotator.name}. Ctrl+C to stop.\n")
    shield.start()
    try:
        while shield.running and (not args.count or vault.rotation < args.count):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    shield.close()
    return 0


def cmd_inspect(args) -> int:
    from .inspector import inspect_url

    rotator = build_rotator(args)
    if not rotator.anonymous:
        print("Link inspection needs --mode tor or --mode proxy, so the site never sees "
              "your real IP.", file=sys.stderr)
        return 2
    shield = Shield(rotator, IdentityVault.load())
    event = shield.rotate_now()
    print(f"Inspecting via {event.exit.ip} ({event.exit.via})...\n")
    result = inspect_url(args.url, shield.proxies())
    for i, hop in enumerate(result.hops):
        print(f"  {i}. [{hop.status}] {hop.url}")
    if result.error:
        print(f"  stopped: {result.error}")
    for f in result.extra:
        print(f"  {SEVERITY_ICONS[f.severity]:>2} {f.message}")
    print()
    if result.report:
        print("Where it ends up:")
        print_report(result.report)
    shield.close()
    return 0


def cmd_samples(args) -> int:
    from .samples import write_samples

    for path in write_samples(args.folder):
        print(path)
    return 0


def cmd_gui(args) -> int:
    from .gui import run

    return run(args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scannerip", description=(
        "Scan any QR code or barcode safely, with IP shifting and layered device IDs."))
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("gui", help="open the desktop app (default)")
    _add_shield_args(p)
    p.add_argument("--camera", type=int, default=0, help="camera index (default 0)")
    p.set_defaults(func=cmd_gui)

    p = sub.add_parser("scan", help="scan codes in image files")
    p.add_argument("images", nargs="+")
    p.add_argument("--no-log", action="store_true", help="don't write to the scan log")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("camera", help="scan from the webcam in the terminal")
    p.add_argument("--index", type=int, default=0)
    p.set_defaults(func=cmd_camera)

    p = sub.add_parser("shield", help="run IP shifting and show each new IP and ID")
    _add_shield_args(p)
    p.add_argument("--count", type=int, default=0, help="stop after this many shifts")
    p.set_defaults(func=cmd_shield)

    p = sub.add_parser("identity", help="show the device ID layers")
    p.set_defaults(func=cmd_identity)

    p = sub.add_parser("inspect", help="follow a link's redirects through the shield")
    p.add_argument("url")
    _add_shield_args(p, default_mode="tor")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("samples", help="write demo QR codes (safe and dodgy) to a folder")
    p.add_argument("folder", nargs="?", default="samples")
    p.set_defaults(func=cmd_samples)

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv.insert(0, "gui")  # plain "python -m scannerip --mode tor" opens the app
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RotationError as exc:
        print(f"Shield error: {exc}", file=sys.stderr)
        return 2
