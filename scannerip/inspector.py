"""Check where a link really goes, without opening it in a browser.

Shorteners and redirect chains are how most malicious QR links hide. This
follows the chain hop by hop through the shield (Tor or a proxy), so the
server only ever sees the rotated IP. It sends HEAD requests, never runs any
JavaScript, keeps no cookies between hops and never downloads the page body.

What it can't see: redirects done with JavaScript or <meta refresh> inside
the page, because it deliberately never reads the page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

from .analyzer import DANGEROUS_EXTENSIONS, Finding, Report, analyse_text

# A plain, very common browser string. Same for everyone, so it reveals nothing
# about this device, and cloaking sites behave as they would for a real victim.
GENERIC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.5",
    "DNT": "1",
}

DANGEROUS_TYPES = {
    "application/vnd.android.package-archive",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-ms-installer",
    "application/x-msi",
    "application/java-archive",
    "application/x-sh",
    "application/x-apple-diskimage",
    "application/x-apple-aspen-config",
    "application/hta",
}


@dataclass
class Hop:
    url: str
    status: int
    content_type: str = ""
    location: str = ""
    disposition: str = ""


@dataclass
class Inspection:
    start_url: str
    hops: list[Hop] = field(default_factory=list)
    report: Report | None = None
    extra: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def final_url(self) -> str:
        return self.hops[-1].url if self.hops else self.start_url


def inspect_url(url: str, proxies: dict, max_hops: int = 8, timeout: float = 20.0,
                session_factory=requests.Session) -> Inspection:
    """Follow redirects through `proxies` and analyse where we end up."""
    if not proxies:
        raise ValueError("Refusing to inspect a link without the shield - "
                         "that would show the site your real IP address.")
    if urlsplit(url).scheme.lower() not in ("http", "https"):
        raise ValueError("Only http/https links can be inspected.")

    result = Inspection(url)
    current = url
    with session_factory() as session:
        session.trust_env = False
        session.headers.update(GENERIC_HEADERS)
        for _ in range(max_hops):
            session.cookies.clear()
            try:
                resp = session.head(current, proxies=proxies, allow_redirects=False, timeout=timeout)
                if resp.status_code in (403, 405, 501):  # some servers refuse HEAD
                    resp.close()
                    resp = session.get(current, proxies=proxies, allow_redirects=False,
                                       timeout=timeout, stream=True)
                resp.close()  # we never read the body
            except requests.RequestException as exc:
                result.error = f"{type(exc).__name__}: {exc}"
                break

            location = resp.headers.get("Location", "")
            hop = Hop(current, resp.status_code, resp.headers.get("Content-Type", ""),
                      location, resp.headers.get("Content-Disposition", ""))
            result.hops.append(hop)
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                nxt = urljoin(current, location)
                if urlsplit(nxt).scheme.lower() not in ("http", "https"):
                    result.extra.append(Finding("high", f"Redirects to a non-web link: {nxt[:80]}"))
                    break
                current = nxt
                continue
            break
        else:
            result.extra.append(Finding("medium", f"More than {max_hops} redirects. "
                                                  "Legit sites rarely bounce you around this much."))

    if len(result.hops) > 1:
        hosts = {urlsplit(h.url).hostname for h in result.hops}
        result.extra.append(Finding("info", f"Went through {len(result.hops) - 1} redirect(s) "
                                            f"across {len(hosts)} different site(s)."))
        start_host = urlsplit(url).hostname
        if urlsplit(result.final_url).hostname != start_host:
            result.extra.append(Finding("low", "Ends up on a different site from the one in the code."))

    if result.hops:
        _check_download(result.hops[-1], result.extra)
    result.report = analyse_text(result.final_url)
    return result


def _check_download(hop: Hop, out: list[Finding]) -> None:
    ctype = hop.content_type.split(";", 1)[0].strip().lower()
    if ctype in DANGEROUS_TYPES:
        out.append(Finding("critical", f"Final page is an app/installer download ({ctype})."))
    disposition = hop.disposition.lower()
    if "attachment" in disposition:
        name = disposition.split("filename=", 1)[-1].strip('"; ') if "filename=" in disposition else ""
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            out.append(Finding("critical", f"Final page forces a download of '{name}'."))
        else:
            out.append(Finding("medium", "Final page forces a file download."))
