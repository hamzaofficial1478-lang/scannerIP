"""Generate a set of test codes for demos and for the test suite.

Every "malicious" sample uses reserved names (RFC 2606 .example) or
documentation IP ranges (RFC 5737), so none of them lead anywhere real.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import zxingcpp
from PIL import Image

from .payloads import emv_crc16

F = zxingcpp.BarcodeFormat


def _emv(merchant: str, amount: str, tamper: bool = False) -> str:
    def tlv(tag: str, value: str) -> str:
        return f"{tag}{len(value):02d}{value}"
    body = (tlv("00", "01") + tlv("01", "12") + tlv("26", tlv("00", "com.example.pay") + tlv("01", "1234567890"))
            + tlv("52", "5812") + tlv("53", "586") + tlv("54", amount) + tlv("58", "PK")
            + tlv("59", merchant) + tlv("60", "Lahore") + "6304")
    crc = emv_crc16(body)
    if tamper:
        crc = f"{(int(crc, 16) ^ 0x0F0F):04X}"
    return body + crc


SAMPLES: list[tuple[str, str, object]] = [
    ("01_safe_website", "https://www.bbc.co.uk/news", F.QRCode),
    ("02_wifi_home_wpa2", "WIFI:T:WPA;S:HomeNet;P:correct horse battery staple;;", F.QRCode),
    ("03_wifi_open_trap", "WIFI:T:nopass;S:Free Airport WiFi;;", F.QRCode),
    ("04_contact_vcard", "BEGIN:VCARD\nVERSION:3.0\nFN:Ayesha Khan\nTEL:+44 20 7946 0000\n"
                         "EMAIL:ayesha@example.com\nURL:https://example.com\nEND:VCARD", F.QRCode),
    ("05_phish_at_sign", "https://paypal.com@login-verify.example/secure/update", F.QRCode),
    ("06_bare_ip_login", "http://203.0.113.7/bank/login.php", F.QRCode),
    ("07_fake_app_download", "https://free-updates.example/whatsapp-gold.apk", F.QRCode),
    ("08_shortened_link", "https://bit.ly/3xExample", F.QRCode),
    ("09_ussd_code", "tel:*%2306%23", F.QRCode),
    ("10_javascript_link", "javascript:alert('gotcha')", F.QRCode),
    ("11_punycode_lookalike", "https://xn--pple-43d.example/id", F.QRCode),
    ("12_brand_impersonation", "https://secure-paypal-account.example/verify", F.QRCode),
    ("13_premium_sms", "SMSTO:84433:WIN PRIZE", F.QRCode),
    ("14_payment_genuine", _emv("Chai Corner", "250.00"), F.QRCode),
    ("15_payment_tampered", _emv("Chai Corner", "250.00", tamper=True), F.QRCode),
    ("16_crypto_request", "bitcoin:bc1qexampleaddressxxxxxxxxxxxxxxxxxxxxxx?amount=0.05", F.QRCode),
    ("17_hidden_rtl_trick", "Invoice for: ‮gpj.exe", F.QRCode),
    ("18_otp_setup", "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
     F.QRCode),
    ("19_micro_qr", "HELLO 2026", F.MicroQRCode),
    ("20_rmqr", "https://www.gov.uk", F.RMQRCode),
    ("21_aztec", "https://www.nhs.uk", F.Aztec),
    ("22_datamatrix", "Lab sample #42", F.DataMatrix),
    ("23_pdf417", "BOARDING PASS LHR-LHE SEAT 23A", F.PDF417),
    ("24_barcode_ean13", "5012345678900", F.EAN13),
]


def render(text: str, fmt, scale: int = 8) -> Image.Image:
    barcode = zxingcpp.create_barcode(text, fmt)
    return Image.fromarray(np.array(zxingcpp.write_barcode_to_image(barcode, scale=scale)))


def write_samples(folder: str | Path) -> list[Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text, fmt in SAMPLES:
        path = folder / f"{name}.png"
        render(text, fmt).save(path)
        written.append(path)
    return written
