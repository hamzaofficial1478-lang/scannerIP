"""Layered device identity that changes every time the IP changes.

The idea is that your real device ID never leaves this program. Everything
anyone else could ever see is derived from it in a one-way fashion, and the
outermost layer is re-derived on every IP rotation so two scans can't be
linked together just by looking at the IDs.

    Layer 0  Hardware fingerprint   machine ID + MAC + host name. In memory only.
    Layer 1  Sealed copy            Layer 0 encrypted with AES-256-GCM. Fresh
                                    random nonce each rotation, so the
                                    ciphertext looks different every time.
                                    Only the key on this machine opens it.
    Layer 2  Anonymous root ID      HMAC-SHA256(secret, Layer 0). One-way:
                                    there's no maths to get Layer 0 back.
    Layer 3  Session ID             HMAC(root, random nonce). New every launch.
    Layer 4  Rotating ID            HMAC(session, rotation number + exit IP).
                                    New on every IP change.

HMAC is RFC 2104, HKDF is RFC 5869 and AES-GCM is NIST SP 800-38D.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import platform
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SEAL_AAD = b"scannerip/layer1/v1"


def app_home() -> Path:
    """Where the secret key and scan log live (override with SCANNERIP_HOME)."""
    return Path(os.environ.get("SCANNERIP_HOME") or Path.home() / ".scannerip")


def load_or_create_secret(home: Path | None = None) -> bytes:
    """32 random bytes kept on this machine only. Created on first run."""
    home = home or app_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "secret.key"
    if path.exists():
        data = path.read_bytes()
        if len(data) == 32:
            return data
        path.unlink()  # truncated or corrupt, start again
    data = os.urandom(32)
    try:
        # O_EXCL: if another copy of the app beat us to it, use theirs instead.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes()
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return data


def read_machine_id() -> str:
    system = platform.system()
    try:
        if system == "Linux":
            for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                try:
                    value = Path(candidate).read_text().strip()
                except OSError:
                    continue
                if value:
                    return value
        elif system == "Windows":
            import winreg

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography",
                                 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            return str(winreg.QueryValueEx(key, "MachineGuid")[0])
        elif system == "Darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split("=")[-1].strip().strip('"')
    except Exception:
        pass
    return ""


def hardware_fingerprint() -> bytes:
    parts = [read_machine_id(), platform.node(), platform.machine()]
    node = uuid.getnode()
    # If the multicast bit is set, Python couldn't find a real MAC and made one
    # up at random, which would change every run. Leave it out in that case.
    if not (node >> 40) & 1:
        parts.append(f"{node:012x}")
    return "|".join(parts).encode("utf-8")


def _hkdf(secret: bytes, label: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(secret)


def _mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def format_id(prefix: str, digest: bytes, groups: int = 4) -> str:
    hexed = digest[: groups * 2].hex().upper()
    return prefix + "-" + "-".join(hexed[i:i + 4] for i in range(0, len(hexed), 4))


@dataclass(frozen=True)
class IdentitySnapshot:
    rotation: int
    exit_ip: str
    rotating_id: str
    sealed: str
    session_id: str
    root_id: str
    at: float


class IdentityVault:
    """Holds Layer 0 and hands out the derived layers."""

    def __init__(self, secret: bytes, fingerprint: bytes | None = None):
        if len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        self.__fingerprint = fingerprint if fingerprint is not None else hardware_fingerprint()
        self.__seal_key = _hkdf(secret, b"scannerip/seal-key/v1")
        root = _mac(_hkdf(secret, b"scannerip/root-key/v1"), self.__fingerprint)
        self.root_id = format_id("ROOT", root)
        self.__session_key = _mac(root, os.urandom(16))
        self.session_id = format_id("SID", self.__session_key)
        self.rotation = 0
        self.current: IdentitySnapshot | None = None

    @classmethod
    def load(cls, home: Path | None = None) -> "IdentityVault":
        return cls(load_or_create_secret(home))

    def __repr__(self) -> str:  # keep Layer 0 out of logs and tracebacks
        return f"<IdentityVault {self.root_id} rotation={self.rotation}>"

    @property
    def fingerprint_size(self) -> int:
        return len(self.__fingerprint)

    def seal(self) -> str:
        """Layer 1: encrypt Layer 0. A new nonce every call means new ciphertext."""
        nonce = os.urandom(12)
        blob = AESGCM(self.__seal_key).encrypt(nonce, self.__fingerprint, SEAL_AAD)
        return base64.urlsafe_b64encode(nonce + blob).decode("ascii")

    def unseal(self, token: str) -> bytes:
        """Open a Layer 1 token. Raises cryptography's InvalidTag with the wrong key."""
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        return AESGCM(self.__seal_key).decrypt(raw[:12], raw[12:], SEAL_AAD)

    def rotate(self, exit_ip: str) -> IdentitySnapshot:
        """Layer 4: derive a brand new ID for this rotation and exit IP."""
        self.rotation += 1
        msg = f"{self.rotation}|{exit_ip}|{time.time_ns()}".encode()
        snapshot = IdentitySnapshot(
            rotation=self.rotation,
            exit_ip=exit_ip,
            rotating_id=format_id("RID", _mac(self.__session_key, msg)),
            sealed=self.seal(),
            session_id=self.session_id,
            root_id=self.root_id,
            at=time.time(),
        )
        self.current = snapshot
        return snapshot

    def layers(self) -> list[tuple[str, str, str]]:
        """(name, value, explanation) rows for the UI. Layer 0 is never included."""
        cur = self.current
        sealed = cur.sealed if cur else self.seal()
        return [
            ("Layer 0  Hardware ID", "●" * 12 + f"  ({self.fingerprint_size} bytes)",
             "Never shown, saved or sent anywhere."),
            ("Layer 1  Sealed (AES-256-GCM)", sealed[:28] + "...",
             "Encrypted copy. Only the key on this machine can open it."),
            ("Layer 2  Anonymous root", self.root_id,
             "One-way HMAC of Layer 0. Can't be reversed."),
            ("Layer 3  Session", self.session_id,
             "New every time the app starts."),
            ("Layer 4  Rotating ID", cur.rotating_id if cur else "(waiting for first rotation)",
             "Changes with every IP shift."),
        ]
