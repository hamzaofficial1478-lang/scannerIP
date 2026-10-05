"""Decode every kind of 2D/1D code from images and camera frames.

Uses ZXing-C++, which reads QR Code (Model 1 and 2), Micro QR, rMQR, Aztec,
Data Matrix, PDF417, MaxiCode and the usual 1D barcodes (EAN, UPC, Code 128,
Code 39, ITF, Codabar, DataBar ...). It also copes with rotated, inverted
(light-on-dark) and small codes.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import zxingcpp
from PIL import Image

from .analyzer import Report, analyse
from .payloads import Payload, classify


@dataclass(frozen=True)
class Decoded:
    format: str
    text: str
    raw: bytes
    is_binary: bool
    corners: tuple[tuple[int, int], ...]

    def payload(self) -> Payload:
        return classify(self.text, self.raw, self.is_binary)

    def report(self) -> Report:
        return analyse(self.payload())


def decode(image) -> list[Decoded]:
    """Decode a PIL image or a numpy array (greyscale or BGR, as OpenCV gives)."""
    found = []
    for r in zxingcpp.read_barcodes(image):
        p = r.position
        corners = tuple((pt.x, pt.y) for pt in (p.top_left, p.top_right,
                                                  p.bottom_right, p.bottom_left))
        found.append(Decoded(
            format=str(r.format),
            text=r.text,
            raw=bytes(r.bytes),
            is_binary=r.content_type == zxingcpp.ContentType.Binary,
            corners=corners,
        ))
    return found


def decode_file(path: str | Path) -> list[Decoded]:
    with Image.open(path) as img:
        img.load()
        if img.mode not in ("L", "RGB"):
            img = img.convert("RGB")
        return decode(img)


class CameraWorker(threading.Thread):
    """Reads frames from a webcam on a background thread and decodes them.

    `on_frame(frame_bgr, decoded)` gets every frame (for a preview);
    `on_new(decoded)` only fires for codes not seen in the last `cooldown`
    seconds, so holding a code up to the camera doesn't spam results.
    """

    def __init__(self, index: int = 0, on_frame: Callable | None = None,
                 on_new: Callable[[Decoded], None] | None = None,
                 on_error: Callable[[Exception], None] | None = None, cooldown: float = 4.0):
        super().__init__(name="camera", daemon=True)
        self.index = index
        self.on_frame = on_frame
        self.on_new = on_new
        self.on_error = on_error
        self.cooldown = cooldown
        self._stop = threading.Event()
        self._seen: dict[str, float] = {}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            import cv2
        except ImportError as exc:
            self._fail(RuntimeError(f"OpenCV isn't installed ({exc})."))
            return
        cap = cv2.VideoCapture(self.index)
        if not cap.isOpened():
            self._fail(RuntimeError(f"Couldn't open camera {self.index}."))
            return
        try:
            while not self._stop.is_set():
                ok, frame = cap.read()
                if not ok:
                    self._fail(RuntimeError("Camera stopped sending frames."))
                    return
                codes = decode(frame)
                if self.on_frame:
                    self.on_frame(frame, codes)
                now = time.monotonic()
                for code in codes:
                    if now - self._seen.get(code.text, -1e9) > self.cooldown and self.on_new:
                        self.on_new(code)
                    self._seen[code.text] = now
        finally:
            cap.release()

    def _fail(self, exc: Exception) -> None:
        if self.on_error:
            self.on_error(exc)
