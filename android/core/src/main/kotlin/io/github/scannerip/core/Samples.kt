package io.github.scannerip.core

/*
 * Demo codes, the same set as the desktop version's samples folder.
 *
 * Every "malicious" sample uses reserved names (RFC 2606 .example) or
 * documentation IP ranges (RFC 5737), so none of them lead anywhere real.
 */

data class Sample(val name: String, val text: String)

private fun emv(merchant: String, amount: String, tamper: Boolean = false): String {
    fun tlv(tag: String, value: String) = tag + "%02d".format(value.length) + value
    val body = tlv("00", "01") + tlv("01", "12") +
        tlv("26", tlv("00", "com.example.pay") + tlv("01", "1234567890")) +
        tlv("52", "5812") + tlv("53", "586") + tlv("54", amount) + tlv("58", "PK") +
        tlv("59", merchant) + tlv("60", "Lahore") + "6304"
    var crc = emvCrc16(body)
    if (tamper) crc = "%04X".format(crc.toInt(16) xor 0x0F0F)
    return body + crc
}

val SAMPLES = listOf(
    Sample("Safe website", "https://www.bbc.co.uk/news"),
    Sample("Home Wi-Fi (WPA2)", "WIFI:T:WPA;S:HomeNet;P:correct horse battery staple;;"),
    Sample("Open Wi-Fi trap", "WIFI:T:nopass;S:Free Airport WiFi;;"),
    Sample("Contact card", "BEGIN:VCARD\nVERSION:3.0\nFN:Ayesha Khan\nTEL:+44 20 7946 0000\n" +
        "EMAIL:ayesha@example.com\nURL:https://example.com\nEND:VCARD"),
    Sample("Phishing '@' trick", "https://paypal.com@login-verify.example/secure/update"),
    Sample("Bare IP login page", "http://203.0.113.7/bank/login.php"),
    Sample("Fake app download", "https://free-updates.example/whatsapp-gold.apk"),
    Sample("Shortened link", "https://bit.ly/3xExample"),
    Sample("USSD code", "tel:*%2306%23"),
    Sample("JavaScript link", "javascript:alert('gotcha')"),
    Sample("Punycode look-alike", "https://xn--pple-43d.example/id"),
    Sample("Brand impersonation", "https://secure-paypal-account.example/verify"),
    Sample("Premium SMS", "SMSTO:84433:WIN PRIZE"),
    Sample("Genuine payment", emv("Chai Corner", "250.00")),
    Sample("Tampered payment", emv("Chai Corner", "250.00", tamper = true)),
    Sample("Crypto request", "bitcoin:bc1qexampleaddressxxxxxxxxxxxxxxxxxxxxxx?amount=0.05"),
    Sample("Hidden right-to-left trick", "Invoice for: ‮gpj.exe"),
    Sample("2FA setup", "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
    Sample("Plain text", "Lab sample #42"),
    Sample("Boarding pass", "BOARDING PASS LHR-LHE SEAT 23A"),
)
