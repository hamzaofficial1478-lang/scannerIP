import numpy as np
import pytest
import zxingcpp
from PIL import Image

from scannerip.decoder import decode, decode_file
from scannerip.samples import SAMPLES, render, write_samples

F = zxingcpp.BarcodeFormat


@pytest.mark.parametrize("text, fmt, expected", [
    ("https://example.com/qr", F.QRCode, "QR Code"),
    ("MICRO1", F.MicroQRCode, "Micro QR Code"),
    ("https://example.com/rmqr", F.RMQRCode, "rMQR Code"),
    ("aztec text", F.Aztec, "Aztec"),
    ("datamatrix text", F.DataMatrix, "Data Matrix"),
    ("pdf417 text", F.PDF417, "PDF417"),
    ("CODE128-TEST", F.Code128, "Code 128"),
])
def test_reads_every_kind_of_code(text, fmt, expected):
    codes = decode(render(text, fmt))
    assert len(codes) == 1
    assert codes[0].text == text
    assert codes[0].format == expected


def test_rotated_inverted_and_on_a_busy_background():
    code = render("https://example.com/hard", F.QRCode, scale=6).convert("L")
    rotated = code.rotate(90, expand=True)
    inverted = Image.fromarray(255 - np.array(code))
    rng = np.random.default_rng(0)
    noisy = Image.fromarray(rng.integers(0, 256, (600, 600), dtype=np.uint8))
    noisy.paste(code, (150, 150))
    for img in (rotated, inverted, noisy):
        assert [c.text for c in decode(img)] == ["https://example.com/hard"]


def test_several_codes_in_one_image():
    canvas = Image.new("L", (900, 400), 255)
    canvas.paste(render("first", F.QRCode).convert("L"), (20, 20))
    canvas.paste(render("second", F.DataMatrix).convert("L"), (500, 20))
    assert sorted(c.text for c in decode(canvas)) == ["first", "second"]


def test_opencv_style_bgr_frame():
    rgb = np.array(render("from a webcam", F.QRCode).convert("RGB"))
    bgr = np.ascontiguousarray(rgb[:, :, ::-1])
    assert decode(bgr)[0].text == "from a webcam"


def test_binary_payload_is_flagged():
    barcode = zxingcpp.create_barcode(b"\x00\x01\xffdata", F.QRCode)
    img = Image.fromarray(np.array(zxingcpp.write_barcode_to_image(barcode, scale=4)))
    code = decode(img)[0]
    assert code.is_binary and code.raw == b"\x00\x01\xffdata"
    assert code.payload().kind == "binary"


def test_corners_are_reported():
    code = decode(render("corners", F.QRCode, scale=4))[0]
    assert len(code.corners) == 4
    xs = [x for x, _ in code.corners]
    assert max(xs) > min(xs)


def test_all_samples_decode_back(tmp_path):
    paths = write_samples(tmp_path)
    assert len(paths) == len(SAMPLES)
    for path, (_, text, _) in zip(paths, SAMPLES):
        found = decode_file(path)
        assert [c.text for c in found] == [text], path.name


def test_empty_image_finds_nothing(tmp_path):
    blank = tmp_path / "blank.png"
    Image.new("RGB", (200, 200), "white").save(blank)
    assert decode_file(blank) == []
