"""IP shifting.

Your public IP address is what a website sees when you connect. If a QR code
leads to an attacker's server, that address gives away roughly where you are
and which network you're on, and lets them tie your visits together. The
rotators here push traffic through someone else's address and swap it every
few seconds.

Three ways to do it:

* TorRotator         real, free. Needs Tor running (Tor Browser is enough).
* ProxyPoolRotator   real. Cycles through a list of proxies you supply.
* SimulatedRotator   fake, for classroom demos where Tor is blocked. Uses the
                     RFC 5737 documentation ranges so it can never be mistaken
                     for a real address, and it refuses to carry any traffic.
"""

from __future__ import annotations

import ipaddress
import os
import random
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

import requests

from .identity import IdentitySnapshot, IdentityVault

IP_CHECK_URLS = (
    "https://check.torproject.org/api/ip",   # {"IsTor": true, "IP": "..."}
    "https://api.ipify.org?format=json",     # {"ip": "..."}
)

# RFC 5737: reserved for documentation, never routed on the internet.
DOC_NETWORKS = tuple(ipaddress.ip_network(n) for n in
                     ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


class RotationError(Exception):
    pass


@dataclass(frozen=True)
class ExitInfo:
    ip: str
    via: str
    is_tor: bool | None = None


def lookup_exit_ip(proxies: dict | None, timeout: float = 20.0) -> tuple[str, bool | None]:
    """Ask a public "what's my IP" service what address it sees us coming from."""
    last_error: Exception | None = None
    for url in IP_CHECK_URLS:
        try:
            with requests.Session() as s:
                s.trust_env = False  # ignore NO_PROXY and friends, so nothing slips out directly
                data = s.get(url, proxies=proxies, timeout=timeout).json()
            ip = str(ipaddress.ip_address(data.get("IP") or data.get("ip")))
            return ip, data.get("IsTor")
        except Exception as exc:  # try the next service
            last_error = exc
    raise RotationError(f"Couldn't find out the exit IP: {last_error}")


class Rotator:
    name = "base"
    anonymous = False       # True only if traffic really leaves from another address
    min_interval = 1.0      # seconds
    default_interval = 15.0

    def rotate(self) -> ExitInfo:
        raise NotImplementedError

    def proxies(self) -> dict:
        """requests-style proxies for the current exit. Raises if there isn't one."""
        raise RotationError(f"{self.name} doesn't carry real traffic")

    def close(self) -> None:
        pass


class SimulatedRotator(Rotator):
    name = "Simulated (demo only - not a real IP)"
    anonymous = False
    min_interval = 2.0
    default_interval = 5.0

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._last = ""

    def rotate(self) -> ExitInfo:
        while True:
            net = self._rng.choice(DOC_NETWORKS)
            ip = str(net[self._rng.randrange(1, 255)])
            if ip != self._last:
                self._last = ip
                return ExitInfo(ip, "simulated")


class TorRotator(Rotator):
    """Gets a new Tor circuit (and so, nearly always, a new exit IP) on each rotation.

    Two tricks, used together:
    1. A different SOCKS username per rotation. Tor's IsolateSOCKSAuth (on by
       default) puts streams with different credentials on different circuits,
       so this works even with plain Tor Browser and no control port.
    2. If a control port is reachable, also send NEWNYM ("new identity"). Tor
       only honours that about once every 10 seconds, hence min_interval.

    Every rotation builds a fresh circuit, and the Tor Project asks people not
    to do that needlessly because it loads the volunteer-run network. So the
    default is a gentler 30 seconds.
    """

    name = "Tor"
    anonymous = True
    min_interval = 10.0
    default_interval = 30.0

    def __init__(self, host: str = "127.0.0.1", socks_port: int | None = None,
                 control_port: int | None = None, password: str | None = None,
                 lookup: Callable[[dict | None], tuple[str, bool | None]] = lookup_exit_ip,
                 max_attempts: int = 2):
        self.host = host
        self.socks_port = self._find_port((socks_port,) if socks_port else (9050, 9150), "SOCKS")
        self._lookup = lookup
        self._max_attempts = max_attempts
        self._tag = os.urandom(4).hex()
        self._circuit = 0
        self._last_ip = ""
        self._controller = self._connect_controller(control_port, password)

    def _find_port(self, ports: tuple[int, ...], what: str) -> int:
        for port in ports:
            try:
                with socket.create_connection((self.host, port), timeout=1.5):
                    return port
            except OSError:
                continue
        raise RotationError(f"Tor doesn't seem to be running (no {what} port on "
                            f"{', '.join(map(str, ports))}). Start Tor or Tor Browser first.")

    def _connect_controller(self, port: int | None, password: str | None):
        try:
            from stem.control import Controller  # optional dependency
        except ImportError:
            return None
        for candidate in ([port] if port else [9051, 9151]):
            try:
                ctl = Controller.from_port(address=self.host, port=candidate)
                ctl.authenticate(password=password)
                return ctl
            except Exception:
                continue
        return None  # fine, SOCKS isolation still gives us new circuits

    @property
    def has_control_port(self) -> bool:
        return self._controller is not None

    def proxies(self) -> dict:
        # socks5h (not socks5) so DNS lookups go through Tor too, no DNS leak.
        url = f"socks5h://sip-{self._tag}-{self._circuit}:x@{self.host}:{self.socks_port}"
        return {"http": url, "https": url}

    def rotate(self) -> ExitInfo:
        ip, is_tor = "", None
        for _ in range(self._max_attempts):
            self._circuit += 1
            if self._controller is not None:
                try:
                    from stem import Signal
                    self._controller.signal(Signal.NEWNYM)
                except Exception:
                    pass
            ip, is_tor = self._lookup(self.proxies())
            if ip != self._last_ip:
                break
        self._last_ip = ip
        return ExitInfo(ip, f"Tor circuit #{self._circuit}", is_tor)

    def close(self) -> None:
        if self._controller is not None:
            self._controller.close()


class ProxyPoolRotator(Rotator):
    """Round-robin through proxies you provide (http://, https://, socks5h://)."""

    name = "Proxy pool"
    anonymous = True
    min_interval = 3.0
    default_interval = 10.0

    def __init__(self, proxy_urls: list[str],
                 lookup: Callable[[dict | None], tuple[str, bool | None]] = lookup_exit_ip):
        self._pool = [self.normalise(u) for u in proxy_urls if u.strip()]
        if not self._pool:
            raise RotationError("The proxy list is empty.")
        self._lookup = lookup
        self._index = -1
        self._current: str | None = None

    @staticmethod
    def normalise(url: str) -> str:
        url = url.strip()
        return url if "://" in url else "http://" + url

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "ProxyPoolRotator":
        with open(path, encoding="utf-8") as fh:
            lines = [ln.split("#", 1)[0].strip() for ln in fh]
        return cls([ln for ln in lines if ln], **kwargs)

    def proxies(self) -> dict:
        if self._current is None:
            raise RotationError("No working proxy yet.")
        return {"http": self._current, "https": self._current}

    def rotate(self) -> ExitInfo:
        for _ in range(len(self._pool)):
            self._index = (self._index + 1) % len(self._pool)
            candidate = self._pool[self._index]
            try:
                ip, is_tor = self._lookup({"http": candidate, "https": candidate})
            except Exception:
                continue  # dead proxy, skip it
            self._current = candidate
            return ExitInfo(ip, f"proxy {self._index + 1}/{len(self._pool)}", is_tor)
        self._current = None
        raise RotationError("None of the proxies answered.")


@dataclass(frozen=True)
class RotationEvent:
    exit: ExitInfo
    identity: IdentitySnapshot


class Shield:
    """Runs the rotator on a timer and rolls the identity along with it."""

    def __init__(self, rotator: Rotator, vault: IdentityVault, interval: float | None = None,
                 on_rotate: Callable[[RotationEvent], None] | None = None,
                 on_error: Callable[[Exception], None] | None = None, history: int = 50):
        self.rotator = rotator
        self.vault = vault
        self.interval = max(float(interval or rotator.default_interval), rotator.min_interval)
        self.on_rotate = on_rotate
        self.on_error = on_error
        self.history: deque[RotationEvent] = deque(maxlen=history)
        self.current: RotationEvent | None = None
        self.next_at: float | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def rotate_now(self) -> RotationEvent:
        with self._lock:
            exit_info = self.rotator.rotate()
            event = RotationEvent(exit_info, self.vault.rotate(exit_info.ip))
            self.current = event
            self.history.append(event)
        if self.on_rotate:
            self.on_rotate(event)
        return event

    def proxies(self) -> dict:
        """Proxies for the *current* exit. Waits if a rotation is mid-way."""
        with self._lock:
            return self.rotator.proxies()

    def seconds_left(self) -> float | None:
        if self.next_at is None:
            return None
        return max(0.0, self.next_at - time.monotonic())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ip-shield", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.rotate_now()
            except Exception as exc:
                if self.on_error:
                    self.on_error(exc)
            self.next_at = time.monotonic() + self.interval
            if self._stop.wait(self.interval):
                break
        self.next_at = None

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self._thread = None

    def close(self) -> None:
        self.stop()
        self.rotator.close()
