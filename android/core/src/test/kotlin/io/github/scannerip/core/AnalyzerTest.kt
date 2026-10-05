package io.github.scannerip.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AnalyzerTest {
    private fun level(text: String) = analyseText(text).level
    private fun messages(text: String) = analyseText(text).findings.joinToString(" | ") { it.message }

    @Test
    fun normalSitesAreCleanOrLow() {
        for (url in listOf(
            "https://www.bbc.co.uk/news",
            "https://www.gov.uk/browse/education",
            "https://www.nhs.uk/conditions/",
            "https://en.wikipedia.org/wiki/QR_code",
            "https://login.microsoftonline.com/",
            "https://www.paypal.com/uk/home",
        )) {
            assertTrue(level(url) in setOf(Level.CLEAN, Level.LOW), "$url -> ${messages(url)}")
        }
    }

    @Test
    fun dodgyLinks() {
        val cases = mapOf(
            "javascript:alert(1)" to Level.DANGEROUS,
            "https://example.com/files/free-robux.apk" to Level.DANGEROUS,
            "itms-services://?action=download-manifest&url=https://x.example/m.plist" to Level.DANGEROUS,
            "https://paypal.com@login-verify.example/secure" to Level.HIGH,
            "https://secure-paypal-account.example/" to Level.HIGH,
            "https://xn--pple-43d.com/" to Level.HIGH,
            "https://аpple.com/" to Level.HIGH,
            "data:text/html;base64,PHNjcmlwdD4=" to Level.HIGH,
        )
        for ((url, expected) in cases) assertEquals(expected, level(url), "$url -> ${messages(url)}")
    }

    @Test
    fun bareIpAndLocalNetwork() {
        val msg = messages("http://192.168.1.1/admin")
        assertTrue("bare IP" in msg && "local/private" in msg)
        assertFalse("local/private" in messages("http://203.0.113.9/"))
        assertTrue("local/private" in messages("http://[fe80::1]/"))
    }

    @Test
    fun decimalIpTrick() = assertTrue("bare IP" in messages("http://3232235777/"))

    @Test
    fun shortenerAndOpenRedirect() {
        assertTrue("shortener" in messages("https://bit.ly/abc"))
        assertTrue("Passes another link" in messages("https://example.com/r?url=https://evil.example"))
    }

    @Test
    fun shortBrandsNeedWordBoundaries() {
        assertFalse("ups" in messages("https://upset-stomach.example/"))
        assertTrue("Mentions 'ups'" in messages("https://ups-parcel.example/"))
    }

    @Test
    fun badPortIsMalformed() = assertTrue("malformed" in messages("https://example.com:99999/"))

    @Test
    fun wifiRules() {
        assertEquals(Level.MEDIUM, level("WIFI:T:nopass;S:Free;;"))
        assertTrue("WEP" in messages("WIFI:T:WEP;S:Old;P:12345;;"))
        assertEquals(Level.CLEAN, level("WIFI:T:WPA;S:Home;P:longpassword;;"))
    }

    @Test
    fun phoneAndSmsRules() {
        assertEquals(Level.DANGEROUS, level("tel:*%2306%23"))
        assertEquals(Level.CLEAN, level("tel:+442079460000"))
        assertEquals(Level.HIGH, level("SMSTO:84433:WIN"))
    }

    @Test
    fun paymentRules() {
        val body = "000201010211520458125303586540510.005802PK5905Shop16006Lahore6304"
        assertEquals(Level.MEDIUM, level(body + emvCrc16(body)))
        assertEquals(Level.HIGH, level(body + "0000"))
    }

    @Test
    fun textRules() {
        assertEquals(Level.CLEAN, level("Just a note"))
        assertEquals(Level.HIGH, level("powershell -enc ZQBjAGgAbwA="))
        assertEquals(Level.HIGH, level("Invoice ‮gpj.exe"))
        assertTrue("Embedded link" in messages("Menu at http://203.0.113.4/menu"))
    }

    @Test
    fun findingsAreNotDuplicated() {
        val report = analyseText("BEGIN:VCARD\nURL:http://203.0.113.4/\nNOTE:http://203.0.113.4/\nEND:VCARD")
        val texts = report.findings.map { it.message }
        assertEquals(texts.size, texts.toSet().size)
    }

    @Test
    fun makeVisibleShowsHiddenCharacters() {
        assertEquals("a<U+202E>b<U+200B>c", makeVisible("a‮b​c"))
        assertEquals("line1\nline2", makeVisible("line1\nline2"))
    }

    @Test
    fun registrableDomains() {
        assertEquals("example.co.uk", registrableDomain("login.example.co.uk"))
        assertEquals("example.com", registrableDomain("a.b.example.com"))
        assertEquals("shop.com.pk", registrableDomain("shop.com.pk"))
    }

    /** Same samples as the desktop app, with exactly the scores the Python version gives. */
    @Test
    fun samplesMatchTheDesktopVersion() {
        val expected = mapOf(
            "Safe website" to 0,
            "Home Wi-Fi (WPA2)" to 0,
            "Open Wi-Fi trap" to 25,
            "Contact card" to 0,
            "Phishing '@' trick" to 55,
            "Bare IP login page" to 80,
            "Fake app download" to 90,
            "Shortened link" to 25,
            "USSD code" to 80,
            "JavaScript link" to 80,
            "Punycode look-alike" to 45,
            "Brand impersonation" to 55,
            "Premium SMS" to 45,
            "Genuine payment" to 25,
            "Tampered payment" to 70,
            "Crypto request" to 25,
            "Hidden right-to-left trick" to 45,
            "2FA setup" to 10,
            "Plain text" to 0,
            "Boarding pass" to 0,
        )
        assertEquals(expected.keys, SAMPLES.map { it.name }.toSet())
        for (sample in SAMPLES) {
            assertEquals(expected[sample.name], analyseText(sample.text).score, "${sample.name}: ${messages(sample.text)}")
        }
        // Byte-for-byte the same payment code the Python sample generator makes.
        assertEquals("00020101021226330015com.example.pay011012345678905204581253035865406250.005802PK" +
            "5911Chai Corner6006Lahore6304A186", SAMPLES.first { it.name == "Genuine payment" }.text)
    }
}
