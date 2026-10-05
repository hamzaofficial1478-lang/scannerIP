"""Work out what kind of data a scanned code is carrying.

A QR code is only ever text (or raw bytes). It can't run anything by itself.
The danger comes from what a phone *does* with that text: opening a link,
joining a Wi-Fi network, dialling a number, paying someone. So the first job
is to label the payload properly, before anything is allowed to act on it.

Formats follow the de facto conventions documented on the ZXing wiki
("Barcode Contents"), EMVCo for merchant payment codes, and the usual URI
schemes (RFC 3986, RFC 6068 mailto, RFC 3966 tel, RFC 5870 geo).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

KIND_LABELS = {
    "url": "Web link / app link",
    "wifi": "Wi-Fi network",
    "contact": "Contact card",
    "email": "Email",
    "sms": "Text message",
    "phone": "Phone number",
    "geo": "Map location",
    "calendar": "Calendar event",
    "otp": "2FA / authenticator setup",
    "crypto": "Crypto payment",
    "payment": "Merchant payment",
    "text": "Plain text",
    "binary": "Binary data",
}

# Schemes that don't use "//" but are still links a phone will happily act on.
OPAQUE_SCHEMES = {
    "javascript", "vbscript", "data", "file", "intent", "market",
    "itms-apps", "itms-services", "about", "blob", "content",
}

CRYPTO_SCHEMES = {
    "bitcoin", "bitcoincash", "litecoin", "ethereum", "dogecoin",
    "monero", "solana", "tron", "ripple", "cardano",
}

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,30}):(.*)$", re.S)
EMBEDDED_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)


@dataclass
class Payload:
    kind: str
    raw: str
    fields: dict[str, str] = field(default_factory=dict)
    is_binary: bool = False

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)

    def summary(self) -> str:
        """One line a human can read without the payload doing anything."""
        f = self.fields
        if self.kind == "url":
            return f.get("url", self.raw)
        if self.kind == "wifi":
            security = f.get("T") or "none"
            return f"Network '{f.get('S', '?')}' (security: {security})"
        if self.kind == "contact":
            return f.get("name") or f.get("FN") or "Unnamed contact"
        if self.kind == "email":
            return f"To {f.get('to', '?')} - subject: {f.get('subject', '')}"
        if self.kind == "sms":
            return f"To {f.get('number', '?')}: {f.get('body', '')}"
        if self.kind == "phone":
            return f.get("number", self.raw)
        if self.kind == "geo":
            return f"{f.get('lat')}, {f.get('lon')}"
        if self.kind == "calendar":
            return f.get("SUMMARY", "Untitled event")
        if self.kind == "otp":
            return f"{f.get('issuer', '?')} - {f.get('account', '?')} (secret hidden)"
        if self.kind == "crypto":
            return f"{f.get('coin')} to {f.get('address')} {f.get('amount', '')}".strip()
        if self.kind == "payment":
            return f"Pay {f.get('merchant', '?')} {f.get('amount', '')}".strip()
        if self.kind == "binary":
            return f"{len(self.raw) // 2} bytes of binary data"
        text = self.raw.replace("\n", " ")
        return text if len(text) <= 80 else text[:77] + "..."


def classify(text: str, raw_bytes: bytes | None = None, is_binary: bool = False) -> Payload:
    """Turn decoded text into a labelled Payload."""
    if is_binary:
        data = raw_bytes if raw_bytes is not None else text.encode("latin-1", "replace")
        return Payload("binary", data.hex(), {"length": str(len(data))}, is_binary=True)

    stripped = text.strip()
    upper = stripped.upper()

    if upper.startswith("WIFI:"):
        return Payload("wifi", text, _split_fields(stripped[5:]))
    if upper.startswith("MECARD:"):
        f = _split_fields(stripped[7:])
        name = f.get("N", "")
        if "," in name:  # MECARD writes "Surname,Firstname"
            last, first = name.split(",", 1)
            name = f"{first} {last}".strip()
        f["name"] = name
        return Payload("contact", text, f)
    if upper.startswith("BEGIN:VCARD"):
        f = _parse_ical_like(stripped)
        f["name"] = f.get("FN") or f.get("N", "").replace(";", " ").strip()
        return Payload("contact", text, f)
    if upper.startswith("BEGIN:VEVENT") or upper.startswith("BEGIN:VCALENDAR"):
        return Payload("calendar", text, _parse_ical_like(stripped))
    if upper.startswith("MATMSG:"):
        f = _split_fields(stripped[7:])
        return Payload("email", text, {"to": f.get("TO", ""), "subject": f.get("SUB", ""),
                                       "body": f.get("BODY", "")})
    if upper.startswith("SMSTO:") or upper.startswith("SMS:"):
        return Payload("sms", text, _parse_sms(stripped))
    if upper.startswith("MAILTO:"):
        return Payload("email", text, _parse_mailto(stripped))
    if upper.startswith("TEL:"):
        return Payload("phone", text, {"number": unquote(stripped[4:]).strip()})
    if upper.startswith("GEO:"):
        return Payload("geo", text, _parse_geo(stripped))
    if upper.startswith("OTPAUTH://"):
        return Payload("otp", text, _parse_otpauth(stripped))
    if upper.startswith("UPI://"):
        q = {k: v[0] for k, v in parse_qs(urlsplit(stripped).query).items()}
        return Payload("payment", text, {"scheme": "UPI", "merchant": q.get("pn", q.get("pa", "")),
                                         "account": q.get("pa", ""), "amount": q.get("am", "")})
    if stripped.startswith("000201"):
        emv = _parse_emvco(stripped)
        if emv is not None:
            return Payload("payment", text, emv)

    m = _SCHEME_RE.match(stripped)
    if m and " " not in m.group(1):
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme in CRYPTO_SCHEMES:
            return Payload("crypto", text, _parse_crypto(scheme, rest))
        if rest.startswith("//") or scheme in OPAQUE_SCHEMES:
            return Payload("url", text, {"url": stripped, "scheme": scheme})

    if re.match(r"^www\.[^\s]+\.[a-z]{2,}", stripped, re.I) and " " not in stripped:
        # Most phones open "www.something.com" as a link, so treat it as one.
        return Payload("url", text, {"url": "http://" + stripped, "scheme": "http",
                                     "note": "no scheme - a phone would assume http"})

    return Payload("text", text, {"embedded_urls": " ".join(EMBEDDED_URL_RE.findall(text))})


def _split_fields(body: str) -> dict[str, str]:
    """Parse ZXing/MECARD style 'K:value;K2:value;;' with backslash escapes."""
    fields: dict[str, str] = {}
    key, buf, in_value, escaped = "", [], False, False
    for ch in body:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":" and not in_value:
            key, buf, in_value = "".join(buf).strip().upper(), [], True
        elif ch == ";":
            if in_value and key:
                value = "".join(buf)
                fields[key] = f"{fields[key]}, {value}" if key in fields else value
            key, buf, in_value = "", [], False
        else:
            buf.append(ch)
    if in_value and key:
        value = "".join(buf)
        fields[key] = f"{fields[key]}, {value}" if key in fields else value
    return fields


def _parse_ical_like(text: str) -> dict[str, str]:
    """Rough reader for vCard / iCalendar: KEY;params:value lines."""
    unfolded = re.sub(r"\r?\n[ \t]", "", text)  # RFC 6350 line folding
    fields: dict[str, str] = {}
    for line in unfolded.splitlines():
        if ":" not in line:
            continue
        head, value = line.split(":", 1)
        key = head.split(";", 1)[0].strip().upper()
        if key in ("BEGIN", "END", "VERSION"):
            continue
        fields[key] = f"{fields[key]}, {value.strip()}" if key in fields else value.strip()
    return fields


def _parse_sms(text: str) -> dict[str, str]:
    upper = text.upper()
    if upper.startswith("SMSTO:"):
        number, _, body = text[6:].partition(":")
        return {"number": number.strip(), "body": body}
    rest = text[4:]
    number, query = rest, ""
    sep = re.search(r"[?;&]", rest)
    if sep:
        number, query = rest[:sep.start()], rest[sep.end():]
    body = parse_qs(query).get("body", [""])[0]
    return {"number": unquote(number).strip(), "body": body}


def _parse_mailto(text: str) -> dict[str, str]:
    parts = urlsplit(text)
    q = {k.lower(): v[0] for k, v in parse_qs(parts.query).items()}
    return {"to": unquote(parts.path), "subject": q.get("subject", ""), "body": q.get("body", "")}


def _parse_geo(text: str) -> dict[str, str]:
    coords, _, query = text[4:].partition("?")
    bits = coords.split(",")
    out = {"lat": bits[0].strip() if bits else "", "lon": bits[1].strip() if len(bits) > 1 else ""}
    if query:
        out["query"] = unquote(query)
    return out


def _parse_otpauth(text: str) -> dict[str, str]:
    parts = urlsplit(text)
    q = {k.lower(): v[0] for k, v in parse_qs(parts.query).items()}
    label = unquote(parts.path.lstrip("/"))
    issuer, _, account = label.partition(":") if ":" in label else ("", "", label)
    secret = q.get("secret", "")
    return {
        "type": parts.netloc.lower(),
        "issuer": q.get("issuer", issuer),
        "account": account,
        # Never show the full secret: anyone holding it can generate your codes.
        "secret": (secret[:2] + "*" * max(len(secret) - 2, 0)) if secret else "",
    }


def _parse_crypto(scheme: str, rest: str) -> dict[str, str]:
    address, _, query = rest.lstrip("/").partition("?")
    q = {k.lower(): v[0] for k, v in parse_qs(query).items()}
    out = {"coin": scheme, "address": address}
    if "amount" in q:
        out["amount"] = q["amount"]
    if "label" in q:
        out["label"] = q["label"]
    return out


def emv_crc16(data: str) -> str:
    """CRC-16/CCITT-FALSE as used by EMVCo merchant QR codes (tag 63)."""
    crc = 0xFFFF
    for byte in data.encode("utf-8"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return f"{crc:04X}"


def _parse_emvco(text: str) -> dict[str, str] | None:
    """Read the top-level TLV fields of an EMVCo merchant-presented QR."""
    tags: dict[str, str] = {}
    i = 0
    while i + 4 <= len(text):
        tag, length = text[i:i + 2], text[i + 2:i + 4]
        if not (tag.isdigit() and length.isdigit()):
            return None
        value = text[i + 4:i + 4 + int(length)]
        tags[tag] = value
        i += 4 + int(length)
    if i != len(text) or "63" not in tags:
        return None
    expected = emv_crc16(text[:-4])
    return {
        "scheme": "EMVCo",
        "merchant": tags.get("59", ""),
        "city": tags.get("60", ""),
        "amount": tags.get("54", ""),
        "currency": tags.get("53", ""),
        "country": tags.get("58", ""),
        "crc_ok": "yes" if tags["63"].upper() == expected else "no",
    }
