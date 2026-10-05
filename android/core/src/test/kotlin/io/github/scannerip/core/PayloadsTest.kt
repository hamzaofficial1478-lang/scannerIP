package io.github.scannerip.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PayloadsTest {
    @Test
    fun wifiWithEscapedCharacters() {
        val p = classify("""WIFI:T:WPA;S:My\;Cafe\:2;P:pa\\ss\,word;H:false;;""")
        assertEquals(Kind.WIFI, p.kind)
        assertEquals("My;Cafe:2", p.fields["S"])
        assertEquals("pa\\ss,word", p.fields["P"])
        assertEquals("WPA", p.fields["T"])
    }

    @Test
    fun mecardNameIsFlipped() {
        val p = classify("MECARD:N:Khan,Ayesha;TEL:0123;TEL:0456;EMAIL:a@example.com;;")
        assertEquals(Kind.CONTACT, p.kind)
        assertEquals("Ayesha Khan", p.fields["name"])
        assertEquals("0123, 0456", p.fields["TEL"])
    }

    @Test
    fun vcardWithFoldedLine() {
        val p = classify("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Sam\r\n Smith\r\nURL:https://example.com\r\nEND:VCARD")
        assertEquals(Kind.CONTACT, p.kind)
        assertEquals("SamSmith", p.fields["FN"])
        assertEquals("https://example.com", p.fields["URL"])
    }

    @Test
    fun smsVariants() {
        assertEquals(mapOf("number" to "+447700900000", "body" to "hello there"),
            classify("SMSTO:+447700900000:hello there").fields)
        assertEquals("hi you", classify("sms:+447700900000?body=hi%20you").fields["body"])
        assertEquals("12345", classify("sms:12345").fields["number"])
    }

    @Test
    fun emailFormats() {
        assertEquals(mapOf("to" to "bob@example.com", "subject" to "Hi", "body" to "See you"),
            classify("mailto:bob@example.com?subject=Hi&body=See%20you").fields)
        assertEquals("bob@example.com", classify("MATMSG:TO:bob@example.com;SUB:Hi;BODY:Yo;;").fields["to"])
    }

    @Test
    fun phoneGeoCalendar() {
        assertEquals("*#06#", classify("tel:*%2306%23").fields["number"])
        val geo = classify("geo:51.5074,-0.1278?q=London")
        assertEquals(Kind.GEO, geo.kind)
        assertEquals("51.5074", geo.fields["lat"])
        assertEquals("-0.1278", geo.fields["lon"])
        val cal = classify("BEGIN:VEVENT\nSUMMARY:Exam\nDTSTART:20261101T090000Z\nEND:VEVENT")
        assertEquals(Kind.CALENDAR, cal.kind)
        assertEquals("Exam", cal.fields["SUMMARY"])
    }

    @Test
    fun otpSecretIsMasked() {
        val p = classify("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        assertEquals(Kind.OTP, p.kind)
        assertEquals("alice@example.com", p.fields["account"])
        assertEquals("Example", p.fields["issuer"])
        assertFalse("JBSWY3DPEHPK3PXP" in p.fields["secret"]!!)
        assertFalse("JBSWY3DPEHPK3PXP" in p.summary())
    }

    @Test
    fun cryptoAndUpi() {
        val btc = classify("bitcoin:bc1qxyz?amount=0.1&label=Shop")
        assertEquals(Kind.CRYPTO, btc.kind)
        assertEquals("bc1qxyz", btc.fields["address"])
        assertEquals("0.1", btc.fields["amount"])
        val upi = classify("upi://pay?pa=shop@bank&pn=Corner%20Shop&am=99")
        assertEquals(Kind.PAYMENT, upi.kind)
        assertEquals("Corner Shop", upi.fields["merchant"])
    }

    @Test
    fun emvcoChecksum() {
        val body = "000201010211520458125303586540510.005802PK5905Shop16006Lahore6304"
        val good = classify(body + emvCrc16(body))
        assertEquals(Kind.PAYMENT, good.kind)
        assertEquals("yes", good.fields["crc_ok"])
        assertEquals("Shop1", good.fields["merchant"])
        assertEquals("no", classify(body + "0000").fields["crc_ok"])
    }

    @Test
    fun crcKnownVector() {
        // CRC-16/CCITT-FALSE check value for "123456789" is 0x29B1.
        assertEquals("29B1", emvCrc16("123456789"))
    }

    @Test
    fun urlsAndText() {
        assertEquals(Kind.URL, classify("https://example.com/x").kind)
        assertEquals("javascript", classify("javascript:alert(1)").fields["scheme"])
        val www = classify("www.example.com/page")
        assertEquals(Kind.URL, www.kind)
        assertEquals("http://www.example.com/page", www.fields["url"])
        assertEquals(Kind.TEXT, classify("Note: meet at 5").kind)
        val t = classify("Menu here https://example.com/menu thanks")
        assertEquals(Kind.TEXT, t.kind)
        assertEquals("https://example.com/menu", t.fields["embedded_urls"])
    }

    @Test
    fun binary() {
        val p = classify("", rawBytes = byteArrayOf(0, 1, 0xff.toByte()), isBinary = true)
        assertEquals(Kind.BINARY, p.kind)
        assertEquals("0001ff", p.raw)
        assertEquals("3 bytes of binary data", p.summary())
    }

    @Test
    fun uppercaseQrAlphanumericUrls() {
        // QR's compact alphanumeric mode only has capitals, so codes often carry
        // links like this. They must still be treated (and checked) as links.
        val p = classify("HTTP://EXAMPLE.COM/FILES/UPDATE.APK")
        assertEquals(Kind.URL, p.kind)
        assertEquals("http", p.fields["scheme"])
        assertEquals(Level.DANGEROUS, analyseText("HTTP://EXAMPLE.COM/FILES/UPDATE.APK").level)
    }

    @Test
    fun everySampleClassifies() {
        assertTrue(SAMPLES.size >= 20)
        for (sample in SAMPLES) analyseText(sample.text) // must not throw
        assertEquals(Kind.PAYMENT, classify(SAMPLES.first { it.name == "Genuine payment" }.text).kind)
    }
}
