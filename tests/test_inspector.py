import pytest
import requests

from scannerip.inspector import inspect_url

PROXIES = {"http": "socks5h://u:p@127.0.0.1:9050", "https": "socks5h://u:p@127.0.0.1:9050"}


class FakeResponse:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}

    def close(self):
        pass


def fake_session(routes, log):
    """routes: {(method, url): FakeResponse}"""

    class Session:
        def __init__(self):
            self.headers = {}
            self.cookies = requests.cookies.RequestsCookieJar()
            self.trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def _go(self, method, url, **kw):
            log.append((method, url, kw.get("proxies"), kw.get("allow_redirects"), self.trust_env,
                        dict(self.headers)))
            resp = routes.get((method, url))
            if resp is None:
                raise requests.ConnectionError("no route")
            return resp

        def head(self, url, **kw):
            return self._go("HEAD", url, **kw)

        def get(self, url, **kw):
            return self._go("GET", url, **kw)

    return Session


def test_refuses_without_shield():
    with pytest.raises(ValueError, match="real IP"):
        inspect_url("https://bit.ly/x", None)
    with pytest.raises(ValueError):
        inspect_url("javascript:alert(1)", PROXIES)


def test_follows_shortener_to_an_apk():
    routes = {
        ("HEAD", "https://bit.ly/x"): FakeResponse(301, {"Location": "https://step.example/go"}),
        ("HEAD", "https://step.example/go"): FakeResponse(302, {"Location": "/files/app.apk"}),
        ("HEAD", "https://step.example/files/app.apk"): FakeResponse(
            200, {"Content-Type": "application/vnd.android.package-archive"}),
    }
    log = []
    result = inspect_url("https://bit.ly/x", PROXIES, session_factory=fake_session(routes, log))
    assert [h.url for h in result.hops] == ["https://bit.ly/x", "https://step.example/go",
                                            "https://step.example/files/app.apk"]
    assert result.final_url.endswith("app.apk")
    assert result.report.level == "DANGEROUS"
    assert any(f.severity == "critical" for f in result.extra)
    # every request went through the shield, never followed redirects blindly,
    # ignored environment proxy settings and sent a generic user agent
    assert all(entry[2] == PROXIES and entry[3] is False and entry[4] is False for entry in log)
    assert all("Firefox" in entry[5]["User-Agent"] for entry in log)


def test_falls_back_to_get_when_head_refused():
    routes = {
        ("HEAD", "https://shop.example/"): FakeResponse(405),
        ("GET", "https://shop.example/"): FakeResponse(200, {"Content-Type": "text/html"}),
    }
    log = []
    result = inspect_url("https://shop.example/", PROXIES, session_factory=fake_session(routes, log))
    assert [e[0] for e in log] == ["HEAD", "GET"]
    assert result.hops[-1].status == 200


def test_redirect_loop_is_capped():
    routes = {("HEAD", "https://loop.example/"): FakeResponse(302, {"Location": "https://loop.example/"})}
    result = inspect_url("https://loop.example/", PROXIES, max_hops=4,
                         session_factory=fake_session(routes, []))
    assert len(result.hops) == 4
    assert any("More than 4 redirects" in f.message for f in result.extra)


def test_redirect_to_non_web_scheme_stops():
    routes = {("HEAD", "https://a.example/"): FakeResponse(302, {"Location": "intent://scan#Intent;end"})}
    result = inspect_url("https://a.example/", PROXIES, session_factory=fake_session(routes, []))
    assert any("non-web" in f.message for f in result.extra)


def test_network_error_is_reported_not_raised():
    result = inspect_url("https://down.example/", PROXIES, session_factory=fake_session({}, []))
    assert "ConnectionError" in result.error
    assert result.hops == []
