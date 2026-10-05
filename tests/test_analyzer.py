import pytest

from scannerip.analyzer import analyse_text, make_visible, registrable_domain


def level(text):
    return analyse_text(text).level


def messages(text):
    return " | ".join(f.message for f in analyse_text(text).findings)


@pytest.mark.parametrize("url", [
    "https://www.bbc.co.uk/news",
    "https://www.gov.uk/browse/education",
    "https://www.nhs.uk/conditions/",
    "https://en.wikipedia.org/wiki/QR_code",
    "https://login.microsoftonline.com/",
    "https://www.paypal.com/uk/home",
])
def test_normal_sites_are_clean_or_low(url):
    assert level(url) in ("CLEAN", "LOW"), messages(url)


@pytest.mark.parametrize("url, expected", [
    ("javascript:alert(1)", "DANGEROUS"),
    ("https://example.com/files/free-robux.apk", "DANGEROUS"),
    ("itms-services://?action=download-manifest&url=https://x.example/m.plist", "DANGEROUS"),
    ("https://paypal.com@login-verify.example/secure", "HIGH"),
    ("https://secure-paypal-account.example/", "HIGH"),
    ("https://xn--pple-43d.com/", "HIGH"),
    ("https://аpple.com/", "HIGH"),
    ("data:text/html;base64,PHNjcmlwdD4=", "HIGH"),
])
def test_dodgy_links(url, expected):
    assert level(url) == expected, messages(url)


def test_bare_ip_and_local_network():
    msg = messages("http://192.168.1.1/admin")
    assert "bare IP" in msg and "local/private" in msg
    assert "local/private" not in messages("http://203.0.113.9/")


def test_decimal_ip_trick():
    assert "bare IP" in messages("http://3232235777/")


def test_shortener_and_open_redirect():
    assert "shortener" in messages("https://bit.ly/abc")
    assert "Passes another link" in messages("https://example.com/r?url=https://evil.example")


def test_short_brands_need_word_boundaries():
    assert "ups" not in messages("https://upset-stomach.example/")
    assert "Mentions 'ups'" in messages("https://ups-parcel.example/")


def test_wifi_rules():
    assert level("WIFI:T:nopass;S:Free;;") == "MEDIUM"
    assert "WEP" in messages("WIFI:T:WEP;S:Old;P:12345;;")
    assert level("WIFI:T:WPA;S:Home;P:longpassword;;") == "CLEAN"


def test_phone_and_sms_rules():
    assert level("tel:*%2306%23") == "DANGEROUS"
    assert level("tel:+442079460000") == "CLEAN"
    assert level("SMSTO:84433:WIN") == "HIGH"


def test_payment_rules():
    from scannerip.payloads import emv_crc16
    body = "000201010211520458125303586540510.005802PK5905Shop16006Lahore6304"
    assert level(body + emv_crc16(body)) == "MEDIUM"
    assert level(body + "0000") == "HIGH"


def test_text_rules():
    assert level("Just a note") == "CLEAN"
    assert level("powershell -enc ZQBjAGgAbwA=") == "HIGH"
    assert level("Invoice ‮gpj.exe") == "HIGH"
    assert "Embedded link" in messages("Menu at http://203.0.113.4/menu")


def test_findings_are_not_duplicated():
    report = analyse_text("BEGIN:VCARD\nURL:http://203.0.113.4/\nNOTE:http://203.0.113.4/\nEND:VCARD")
    texts = [f.message for f in report.findings]
    assert len(texts) == len(set(texts))


def test_make_visible():
    assert make_visible("a‮b​c") == "a<U+202E>b<U+200B>c"
    assert make_visible("line1\nline2") == "line1\nline2"


def test_registrable_domain():
    assert registrable_domain("login.example.co.uk") == "example.co.uk"
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("shop.com.pk") == "shop.com.pk"
