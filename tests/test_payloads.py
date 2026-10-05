from scannerip.payloads import classify, emv_crc16


def test_wifi_with_escaped_characters():
    p = classify(r'WIFI:T:WPA;S:My\;Cafe\:2;P:pa\\ss\,word;H:false;;')
    assert p.kind == "wifi"
    assert p.fields["S"] == "My;Cafe:2"
    assert p.fields["P"] == "pa\\ss,word"
    assert p.fields["T"] == "WPA"


def test_mecard_name_is_flipped():
    p = classify("MECARD:N:Khan,Ayesha;TEL:0123;TEL:0456;EMAIL:a@example.com;;")
    assert p.kind == "contact"
    assert p.fields["name"] == "Ayesha Khan"
    assert p.fields["TEL"] == "0123, 0456"


def test_vcard_with_folded_line():
    p = classify("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Sam\r\n Smith\r\nURL:https://example.com\r\nEND:VCARD")
    assert p.kind == "contact"
    assert p.fields["FN"] == "SamSmith"
    assert p.fields["URL"] == "https://example.com"


def test_sms_variants():
    assert classify("SMSTO:+447700900000:hello there").fields == {
        "number": "+447700900000", "body": "hello there"}
    assert classify("sms:+447700900000?body=hi%20you").fields["body"] == "hi you"
    assert classify("sms:12345").fields["number"] == "12345"


def test_email_formats():
    assert classify("mailto:bob@example.com?subject=Hi&body=See%20you").fields == {
        "to": "bob@example.com", "subject": "Hi", "body": "See you"}
    assert classify("MATMSG:TO:bob@example.com;SUB:Hi;BODY:Yo;;").fields["to"] == "bob@example.com"


def test_phone_geo_calendar():
    assert classify("tel:*%2306%23").fields["number"] == "*#06#"
    geo = classify("geo:51.5074,-0.1278?q=London")
    assert (geo.kind, geo.fields["lat"], geo.fields["lon"]) == ("geo", "51.5074", "-0.1278")
    cal = classify("BEGIN:VEVENT\nSUMMARY:Exam\nDTSTART:20261101T090000Z\nEND:VEVENT")
    assert cal.kind == "calendar" and cal.fields["SUMMARY"] == "Exam"


def test_otp_secret_is_masked():
    p = classify("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
    assert p.kind == "otp"
    assert p.fields["account"] == "alice@example.com"
    assert p.fields["issuer"] == "Example"
    assert "JBSWY3DPEHPK3PXP" not in p.fields["secret"]
    assert "JBSWY3DPEHPK3PXP" not in p.summary()


def test_crypto_and_upi():
    btc = classify("bitcoin:bc1qxyz?amount=0.1&label=Shop")
    assert btc.kind == "crypto" and btc.fields["address"] == "bc1qxyz" and btc.fields["amount"] == "0.1"
    upi = classify("upi://pay?pa=shop@bank&pn=Corner%20Shop&am=99")
    assert upi.kind == "payment" and upi.fields["merchant"] == "Corner Shop"


def test_emvco_checksum():
    body = "000201010211520458125303586540510.005802PK5905Shop16006Lahore6304"
    good = classify(body + emv_crc16(body))
    assert good.kind == "payment" and good.fields["crc_ok"] == "yes"
    assert good.fields["merchant"] == "Shop1"
    bad = classify(body + "0000")
    assert bad.fields["crc_ok"] == "no"


def test_crc_known_vector():
    # CRC-16/CCITT-FALSE check value for "123456789" is 0x29B1.
    assert emv_crc16("123456789") == "29B1"


def test_urls_and_text():
    assert classify("https://example.com/x").kind == "url"
    assert classify("javascript:alert(1)").fields["scheme"] == "javascript"
    www = classify("www.example.com/page")
    assert www.kind == "url" and www.fields["url"] == "http://www.example.com/page"
    note = classify("Note: meet at 5")
    assert note.kind == "text"
    t = classify("Menu here https://example.com/menu thanks")
    assert t.kind == "text" and t.fields["embedded_urls"] == "https://example.com/menu"


def test_binary():
    p = classify("", raw_bytes=b"\x00\x01\xff", is_binary=True)
    assert p.kind == "binary" and p.raw == "0001ff" and p.summary() == "3 bytes of binary data"


def test_uppercase_qr_alphanumeric_urls():
    # QR's compact alphanumeric mode only has capitals, so codes often carry
    # links like this. They must still be treated (and checked) as links.
    from scannerip.analyzer import analyse_text
    p = classify("HTTP://EXAMPLE.COM/FILES/UPDATE.APK")
    assert p.kind == "url" and p.fields["scheme"] == "http"
    assert analyse_text("HTTP://EXAMPLE.COM/FILES/UPDATE.APK").level == "DANGEROUS"
