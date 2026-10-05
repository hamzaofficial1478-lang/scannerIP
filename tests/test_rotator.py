import ipaddress
import os
import socket
import threading
import time

import pytest

from scannerip import rotator as rot
from scannerip.identity import IdentityVault
from scannerip.rotator import (DOC_NETWORKS, ProxyPoolRotator, RotationError, Shield,
                               SimulatedRotator, TorRotator)

FP = b"test-device"


def vault():
    return IdentityVault(os.urandom(32), FP)


def test_simulated_ips_are_documentation_addresses():
    r = SimulatedRotator(seed=1)
    ips = [r.rotate().ip for _ in range(30)]
    assert all(any(ipaddress.ip_address(ip) in net for net in DOC_NETWORKS) for ip in ips)
    assert all(a != b for a, b in zip(ips, ips[1:]))
    assert r.anonymous is False
    with pytest.raises(RotationError):
        r.proxies()  # never pretends to carry real traffic


def test_proxy_pool_skips_dead_proxies(tmp_path):
    answers = {"http://p1:8080": "198.51.100.1", "socks5h://p3:1080": "198.51.100.3"}

    def lookup(proxies):
        url = proxies["https"]
        if url not in answers:
            raise OSError("dead")
        return answers[url], False

    listing = tmp_path / "proxies.txt"
    listing.write_text("p1:8080\n# comment\nhttp://p2:8080\n\nsocks5h://p3:1080  # tor-ish\n")
    r = ProxyPoolRotator.from_file(str(listing), lookup=lookup)
    with pytest.raises(RotationError):
        r.proxies()
    assert r.rotate().ip == "198.51.100.1"
    assert r.proxies()["https"] == "http://p1:8080"
    assert r.rotate().ip == "198.51.100.3"  # p2 is dead, skipped
    assert r.rotate().ip == "198.51.100.1"  # wraps round


def test_proxy_pool_all_dead():
    def lookup(_):
        raise OSError("nope")
    r = ProxyPoolRotator(["http://a:1"], lookup=lookup)
    with pytest.raises(RotationError):
        r.rotate()
    with pytest.raises(RotationError):
        r.proxies()


@pytest.fixture
def fake_tor_port():
    """A listening socket so TorRotator thinks Tor is up."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    yield server.getsockname()[1]
    server.close()


def test_tor_uses_new_socks_identity_each_rotation(fake_tor_port):
    seen = []
    ips = iter(["185.220.101.1", "185.220.101.1", "185.220.101.2", "185.220.101.3"])

    def lookup(proxies):
        seen.append(proxies["https"])
        return next(ips), True

    r = TorRotator(socks_port=fake_tor_port, control_port=1, lookup=lookup)
    assert not r.has_control_port
    first = r.rotate()
    second = r.rotate()  # first try returns the same IP, so it retries
    assert (first.ip, second.ip) == ("185.220.101.1", "185.220.101.2")
    assert first.is_tor is True
    assert len(set(seen)) == len(seen) == 3
    assert all(u.startswith("socks5h://") for u in seen)  # DNS goes through Tor too


def test_tor_not_running():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]  # nothing listening here once closed
    with pytest.raises(RotationError, match="Tor"):
        TorRotator(socks_port=free_port, lookup=lambda p: ("192.0.2.1", True))


def test_shield_rotates_ip_and_identity_together():
    events = []
    shield = Shield(SimulatedRotator(seed=3), vault(), interval=0.05, on_rotate=events.append)
    assert shield.interval == SimulatedRotator.min_interval  # clamped
    shield.interval = 0.05  # speed things up for the test
    shield.start()
    deadline = time.monotonic() + 3
    while len(events) < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    shield.stop()
    assert len(events) >= 3
    assert len({e.exit.ip for e in events}) == len(events)
    assert len({e.identity.rotating_id for e in events}) == len(events)
    assert all(e.identity.exit_ip == e.exit.ip for e in events)
    assert not shield.running and shield.seconds_left() is None


def test_shield_reports_errors_and_keeps_going():
    class Flaky(SimulatedRotator):
        calls = 0

        def rotate(self):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise RotationError("blip")
            return super().rotate()

    errors, events = [], []
    shield = Shield(Flaky(), vault(), on_rotate=events.append, on_error=errors.append)
    shield.interval = 0.02
    shield.start()
    deadline = time.monotonic() + 3
    while not events and time.monotonic() < deadline:
        time.sleep(0.01)
    shield.stop()
    assert errors and events


def test_lookup_exit_ip_tries_next_service(monkeypatch):
    calls = []

    class FakeResp:
        def __init__(self, data):
            self._data = data

        def json(self):
            return self._data

    class FakeSession:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, proxies=None, timeout=None):
            calls.append((url, proxies, self.trust_env))
            if "torproject" in url:
                raise OSError("blocked")
            return FakeResp({"ip": "198.51.100.77"})

    monkeypatch.setattr(rot.requests, "Session", FakeSession)
    ip, is_tor = rot.lookup_exit_ip({"https": "socks5h://x"})
    assert (ip, is_tor) == ("198.51.100.77", None)
    assert len(calls) == 2 and all(c[2] is False for c in calls)


def test_rotate_now_is_thread_safe():
    shield = Shield(SimulatedRotator(), vault())
    threads = [threading.Thread(target=shield.rotate_now) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert shield.vault.rotation == 10
    assert len(shield.history) == 10
