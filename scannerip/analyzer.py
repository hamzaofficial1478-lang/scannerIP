"""Look for red flags in a scanned payload before anything acts on it.

These are heuristics, not a guarantee. A clean result means "nothing obvious
jumped out", never "this is definitely safe". The rules are based on common
QR phishing ("quishing") tricks: links hidden behind shorteners, look-alike
domains, bare IP addresses, swapped payment stickers and so on.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

from .payloads import EMBEDDED_URL_RE, Payload, classify

SEVERITY_POINTS = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 80}

LEVELS = (  # (minimum score, level, advice)
    (80, "DANGEROUS", "Do not open this. Delete the photo and move on."),
    (45, "HIGH", "Very likely a trap. Don't open it unless you can check it some other way."),
    (25, "MEDIUM", "Be careful. Check where it really goes before you trust it."),
    (10, "LOW", "Minor warning signs. Probably fine, but have a look first."),
    (0, "CLEAN", "No red flags found. That's not a promise it's safe, just nothing obvious."),
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "qrco.de", "s.id", "v.gd", "shorte.st", "adf.ly", "bl.ink", "lnkd.in",
}

# TLDs that turn up a lot in abuse reports (cheap or free to register) plus the
# newer ones that look like file names.
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "rest", "cam", "icu", "monster", "buzz", "cyou", "sbs",
}

DANGEROUS_EXTENSIONS = {
    "apk", "exe", "msi", "bat", "cmd", "scr", "ps1", "vbs", "js", "jar", "dmg",
    "pkg", "deb", "sh", "hta", "lnk", "iso", "img", "docm", "xlsm", "pptm", "reg",
    "mobileconfig", "ipa", "xapk", "apks",
}

BRANDS = {
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google",
    "gmail", "amazon", "facebook", "instagram", "whatsapp", "netflix", "binance",
    "coinbase", "metamask", "dhl", "fedex", "ups", "royalmail", "hmrc", "nhs",
    "easypaisa", "jazzcash", "hbl", "meezan", "steam", "roblox", "tiktok",
    "snapchat", "linkedin", "dropbox", "docusign",
}

# Real domains a brand owns that don't simply start with "<brand>.".
OFFICIAL_DOMAINS = {
    "microsoft": {"microsoftonline.com", "microsoft365.com", "office.com", "live.com", "azure.com"},
    "google": {"googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com"},
    "amazon": {"amazonaws.com", "amazon-adsystem.com"},
    "paypal": {"paypalobjects.com", "paypal-community.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "apple": {"apple.news", "applecard.apple"},
    "facebook": {"facebookmail.com"},
    "dropbox": {"dropboxusercontent.com"},
}

PHISHY_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "banking", "password", "wallet", "confirm", "suspend",
    "unlock", "reward", "prize", "free-gift", "claim",
)

# Two-part public suffixes, enough for a rough "registrable domain" guess.
SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "nhs.uk", "me.uk",
    "com.pk", "org.pk", "edu.pk", "gov.pk", "net.pk", "com.au", "net.au",
    "org.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.tr",
    "com.sa", "com.my", "com.sg", "co.ke", "com.ng", "com.eg",
}

# Home/office networks, loopback and link-local: where routers and printers live.
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
))

SCRIPT_RE = re.compile(
    r"<script|javascript:|powershell|cmd\.exe|/bin/(ba)?sh|curl\s+\S+\s*\|\s*(ba)?sh"
    r"|wget\s+http|rm\s+-rf|eval\(|invoke-expression|certutil\s+-urlcache",
    re.I,
)
BIDI_CHARS = set("‪‫‬‭‮⁦⁧⁨⁩")
ZERO_WIDTH = set("​‌‍⁠﻿")


@dataclass
class Finding:
    severity: str
    message: str


@dataclass
class Report:
    payload: Payload
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(SEVERITY_POINTS[f.severity] for f in self.findings))

    @property
    def level(self) -> str:
        return next(level for floor, level, _ in LEVELS if self.score >= floor)

    @property
    def advice(self) -> str:
        return next(advice for floor, _, advice in LEVELS if self.score >= floor)


def analyse(payload: Payload) -> Report:
    found: list[Finding] = []
    if not payload.is_binary:
        _check_hidden_characters(payload.raw, found)
    checker = _CHECKERS.get(payload.kind)
    if checker:
        checker(payload, found)
    report = Report(payload)
    seen = set()
    for f in found:  # the same link can show up in several fields
        if (f.severity, f.message) not in seen:
            seen.add((f.severity, f.message))
            report.findings.append(f)
    return report


def analyse_text(text: str) -> Report:
    return analyse(classify(text))


def make_visible(text: str) -> str:
    """Swap invisible/direction-changing characters for a visible tag like <U+202E>."""
    out = []
    for ch in text:
        if ch in BIDI_CHARS or ch in ZERO_WIDTH or (ord(ch) < 32 and ch not in "\r\n\t"):
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def registrable_domain(host: str) -> str:
    """Best-effort 'example.co.uk' from 'login.example.co.uk' (no full PSL)."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_url(url: str, out: list[Finding], nested: bool = False) -> None:
    """Run all the link checks, appending findings to `out`."""
    prefix = "Embedded link: " if nested else ""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()

    if scheme in ("javascript", "vbscript"):
        out.append(Finding("critical", prefix + "Runs script code the moment it's opened."))
        return
    if scheme == "data":
        out.append(Finding("high", prefix + "A 'data:' link carries a whole page or file inside "
                                            "the code. Classic way to fake a login page."))
        return
    if scheme == "file":
        out.append(Finding("high", prefix + "Points at a file on your own device."))
        return
    if scheme == "intent":
        out.append(Finding("high", prefix + "Android intent link: can launch apps directly."))
        return
    if scheme in ("itms-services",):
        out.append(Finding("critical", prefix + "Tries to install an iOS app from outside the App Store."))
        return
    if scheme not in ("http", "https", "ftp"):
        out.append(Finding("medium", prefix + f"Opens another app ('{scheme}:') rather than a web page."))
        return
    if scheme == "http":
        out.append(Finding("medium", prefix + "Not encrypted (http). Anyone on the same network "
                                              "can read or change what comes back."))
    elif scheme == "ftp":
        out.append(Finding("low", prefix + "Old-fashioned FTP link, unencrypted."))

    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        out.append(Finding("high", prefix + "The link is malformed (bad host or port)."))
        return
    if not host:
        out.append(Finding("high", prefix + "Link has no proper host name."))
        return

    if "@" in parts.netloc:
        out.append(Finding("high", prefix + f"Contains '@'. Everything before it is ignored, "
                                            f"so the real site is '{host}'."))

    ip = _as_ip(host)
    if ip is not None:
        out.append(Finding("high", prefix + "Uses a bare IP address instead of a name. Real "
                                            "companies almost never do this."))
        if any(ip in net for net in LOCAL_NETWORKS if net.version == ip.version):
            out.append(Finding("medium", prefix + "Points into a local/private network "
                                                  "(router pages, internal devices)."))
    else:
        _check_hostname(host, out, prefix)

    if port is not None and port not in (80, 443):
        out.append(Finding("low", prefix + f"Uses an unusual port ({port})."))

    path = unquote(parts.path).lower()
    ext = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    if ext in DANGEROUS_EXTENSIONS:
        out.append(Finding("critical", prefix + f"Downloads a '.{ext}' file. That's an app or "
                                                "script that could install malware."))

    rest = (path + "?" + unquote(parts.query)).lower()
    if ip is None:
        domain = registrable_domain(host)
        brand = impersonated_brand(path, domain)
        if brand and not impersonated_brand(host, domain):
            out.append(Finding("low", prefix + f"Talks about '{brand}' in the link, "
                                               f"but the site is '{domain}'."))
    words = sorted({w for w in PHISHY_WORDS if w in rest})
    if words:
        out.append(Finding("low", prefix + "Uses words phishing pages love: " + ", ".join(words[:4])))

    for key, values in parse_qs(parts.query).items():
        if any(v.lower().startswith(("http://", "https://", "//")) for v in values):
            out.append(Finding("medium", prefix + f"Passes another link in '{key}=' - "
                                                  "a common way to bounce you somewhere else."))
            break

    if len(url) > 200:
        out.append(Finding("low", prefix + f"Very long link ({len(url)} characters), "
                                           "often used to hide the real part."))
    if url.count("%") > 10:
        out.append(Finding("low", prefix + "Heavily percent-encoded, which can hide what it says."))


def _check_hostname(host: str, out: list[Finding], prefix: str) -> None:
    if not host.isascii():
        out.append(Finding("high", prefix + "Domain uses non-English letters that can imitate "
                                            "a real site (homograph attack)."))
    if "xn--" in host:
        try:
            shown = host.encode("ascii").decode("idna")
        except UnicodeError:
            shown = host
        out.append(Finding("high", prefix + f"Punycode domain - it really displays as '{shown}', "
                                            "which may imitate a real site."))

    domain = registrable_domain(host)
    if domain in SHORTENERS or host in SHORTENERS:
        out.append(Finding("medium", prefix + f"Link shortener ({domain}) hides the real destination."))

    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        out.append(Finding("low", prefix + f"Ends in '.{tld}', a domain ending abused a lot by scammers."))

    if host.count(".") >= 4:
        out.append(Finding("low", prefix + "Lots of subdomains stacked up, often used to look official."))

    brand = impersonated_brand(host, domain)
    if brand:
        out.append(Finding("high", prefix + f"Mentions '{brand}' but the real domain is "
                                            f"'{domain}'. Looks like impersonation."))


def impersonated_brand(text: str, domain: str) -> str | None:
    """Return a brand named in `text` that `domain` doesn't actually belong to."""
    labels = domain.split(".")
    for brand in sorted(BRANDS):
        # "paypal.co.uk" or "trust.nhs.uk" really do belong to the brand.
        if brand in labels or domain in OFFICIAL_DOMAINS.get(brand, ()):
            continue
        # Short names need a boundary both sides, or "ups" would match "upset".
        tail = r"(?![a-z0-9])" if len(brand) <= 4 else ""
        if re.search(rf"(?<![a-z0-9]){brand}{tail}", text):
            return brand
    return None


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    # Browsers also accept a plain decimal or hex number as an IPv4 address.
    if re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", host):
        try:
            return ipaddress.ip_address(int(host, 0))
        except ValueError:
            return None
    return None


def _check_hidden_characters(text: str, out: list[Finding]) -> None:
    chars = set(text)
    if chars & BIDI_CHARS:
        out.append(Finding("high", "Hidden text-direction characters that make the content "
                                   "display differently from what it really says."))
    if chars & ZERO_WIDTH:
        out.append(Finding("medium", "Contains invisible zero-width characters."))
    if any(ord(c) < 32 and c not in "\r\n\t" for c in chars):
        out.append(Finding("medium", "Contains invisible control characters."))


def _check_url_payload(p: Payload, out: list[Finding]) -> None:
    if p.fields.get("note"):
        out.append(Finding("low", "No http/https given, so a phone would open it as plain http."))
    check_url(p.fields["url"], out)


def _check_wifi(p: Payload, out: list[Finding]) -> None:
    security = p.fields.get("T", "").upper()
    if security in ("", "NOPASS", "NONE"):
        out.append(Finding("medium", "Open network with no password. Whoever runs it can watch "
                                     "your unencrypted traffic."))
    elif security == "WEP":
        out.append(Finding("medium", "Uses WEP, which has been broken for years."))
    if p.fields.get("H", "").lower() == "true":
        out.append(Finding("low", "Hidden network. Unusual for a public Wi-Fi code."))
    out.append(Finding("info", "Joining a network hands its owner a view of your traffic. "
                               "Only join if you trust who put the code there."))


def _check_sms(p: Payload, out: list[Finding]) -> None:
    digits = re.sub(r"\D", "", p.fields.get("number", ""))
    if 0 < len(digits) <= 6:
        out.append(Finding("high", f"Sends to a short code ({digits}). Premium-rate SMS scams "
                                   "use these to charge your bill."))
    if p.fields.get("body"):
        out.append(Finding("info", "Message is pre-written. Read it before you hit send."))
    _check_text_links(p.fields.get("body", ""), out)


def _check_phone(p: Payload, out: list[Finding]) -> None:
    number = p.fields.get("number", "")
    if "*" in number or "#" in number:
        out.append(Finding("critical", "This is a USSD/MMI code, not a phone number. These can "
                                       "change phone settings, divert calls or show your IMEI."))
        return
    digits = re.sub(r"\D", "", number)
    if 0 < len(digits) <= 6:
        out.append(Finding("medium", "Very short number - could be a premium-rate service."))
    if digits.startswith(("449", "09")) and len(digits) > 6:
        out.append(Finding("medium", "Looks like a premium-rate number (09...)."))


def _check_email(p: Payload, out: list[Finding]) -> None:
    _check_text_links(p.fields.get("body", ""), out)


def _check_fields_for_links(p: Payload, out: list[Finding]) -> None:
    for value in p.fields.values():
        _check_text_links(value, out)


def _check_otp(p: Payload, out: list[Finding]) -> None:
    out.append(Finding("low", "Adds an account to your authenticator app. Only scan this if you're "
                              "setting up 2FA on that site right now, and never share a photo of it."))


def _check_crypto(p: Payload, out: list[Finding]) -> None:
    out.append(Finding("medium", "Crypto payment request. Scammers swap these codes so money goes to "
                                 "them - check the address character by character. Crypto can't be refunded."))


def _check_payment(p: Payload, out: list[Finding]) -> None:
    out.append(Finding("medium", "Payment code. Fake stickers over real ones (parking meters, "
                                 "shop counters) are a known scam - check the merchant name before paying."))
    if p.fields.get("crc_ok") == "no":
        out.append(Finding("high", "The payment code's checksum doesn't match. It's been edited "
                                   "or damaged."))


def _check_text(p: Payload, out: list[Finding]) -> None:
    if SCRIPT_RE.search(p.raw):
        out.append(Finding("high", "Contains what looks like commands or script code. "
                                   "Never paste this into a terminal or browser."))
    _check_text_links(p.raw, out)


def _check_binary(p: Payload, out: list[Finding]) -> None:
    out.append(Finding("medium", "Raw binary data rather than text. Normal QR codes rarely need this, "
                                 "so don't feed it to other apps."))


def _check_text_links(text: str, out: list[Finding]) -> None:
    for link in EMBEDDED_URL_RE.findall(text or "")[:5]:
        check_url(link if "://" in link else "http://" + link, out, nested=True)


_CHECKERS = {
    "url": _check_url_payload,
    "wifi": _check_wifi,
    "sms": _check_sms,
    "phone": _check_phone,
    "email": _check_email,
    "contact": _check_fields_for_links,
    "calendar": _check_fields_for_links,
    "otp": _check_otp,
    "crypto": _check_crypto,
    "payment": _check_payment,
    "text": _check_text,
    "binary": _check_binary,
}
