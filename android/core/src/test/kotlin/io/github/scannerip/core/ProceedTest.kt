package io.github.scannerip.core

import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProceedTest {
    private fun proceed(text: String) = proceedFor(classify(text))

    @Test
    fun webLinksOpenBehindTheShield() {
        val p = assertIs<Proceed.Browse>(proceed("https://accounts.google.com/devicephoneverification/start?x=1"))
        assertEquals("https://accounts.google.com/devicephoneverification/start?x=1", p.url)
        assertTrue(p.shielded)
        assertEquals("http://www.example.com/menu", assertIs<Proceed.Browse>(proceed("www.example.com/menu")).url)
    }

    @Test
    fun linksThatCanRunCodeAreNeverOpened() {
        for (bad in listOf("javascript:alert(1)", "intent://scan/#Intent;scheme=zxing;end", "data:text/html,hi",
            "file:///sdcard/x", "content://contacts/people", "itms-services://?action=download-manifest")) {
            assertIs<Proceed.CopyOnly>(proceed(bad), bad)
        }
    }

    @Test
    fun otherAppLinksGoToThatApp() {
        val p = assertIs<Proceed.OpenApp>(proceed("whatsapp://send?text=hi"))
        assertEquals("whatsapp", p.scheme)
        assertFalse(p.shielded)
        assertIs<Proceed.OpenApp>(proceed("market://details?id=org.torproject.android"))
    }

    @Test
    fun wifiCodes() {
        val home = assertIs<Proceed.JoinWifi>(proceed("WIFI:T:WPA;S:HomeNet;P:correct horse battery staple;;"))
        assertEquals(Proceed.JoinWifi("HomeNet", "correct horse battery staple", WifiSecurity.WPA, false), home)
        assertEquals(WifiSecurity.OPEN, assertIs<Proceed.JoinWifi>(proceed("WIFI:T:nopass;S:Free Airport WiFi;;")).security)
        assertEquals(WifiSecurity.OPEN, assertIs<Proceed.JoinWifi>(proceed("WIFI:S:NoTypeGiven;;")).security)
        assertEquals(WifiSecurity.WPA3, assertIs<Proceed.JoinWifi>(proceed("WIFI:T:SAE;S:New;P:12345678;;")).security)
        assertTrue(assertIs<Proceed.JoinWifi>(proceed("WIFI:T:WEP;S:Old;P:abcde;H:true;;")).hidden)
        assertIs<Proceed.CopyOnly>(proceed("WIFI:T:WPA2-EAP;S:eduroam;E:PEAP;I:me;P:pw;;"))
        assertIs<Proceed.CopyOnly>(proceed("WIFI:T:WPA;P:nameless;;"))
    }

    @Test
    fun contactCards() {
        val v = assertIs<Proceed.AddContact>(proceed(SAMPLES.first { it.name == "Contact card" }.text)).card
        assertEquals("Ayesha Khan", v.name)
        assertEquals(listOf("+44 20 7946 0000"), v.phones)
        assertEquals(listOf("ayesha@example.com"), v.emails)
        assertEquals("https://example.com", v.website)

        val m = assertIs<Proceed.AddContact>(proceed("MECARD:N:Khan,Ayesha;TEL:0123;TEL:0456;ADR:1 High St,Lahore;;")).card
        assertEquals(listOf("0123", "0456"), m.phones)
        assertEquals("1 High St, Lahore", m.address)

        val adr = assertIs<Proceed.AddContact>(proceed("BEGIN:VCARD\nFN:X\nADR;TYPE=work:;;1 Mall Rd;Lahore;;54000;Pakistan\nEND:VCARD")).card
        assertEquals("1 Mall Rd, Lahore, 54000, Pakistan", adr.address)
    }

    @Test
    fun callsTextsAndEmails() {
        assertEquals(Proceed.Call("*#06#"), proceed("tel:*%2306%23"))
        assertEquals(Proceed.Text("84433", "WIN PRIZE"), proceed("SMSTO:84433:WIN PRIZE"))
        assertEquals(Proceed.Email("a@example.com", "Hi", "Body text"),
            proceed("mailto:a@example.com?subject=Hi&body=Body%20text"))
        assertEquals(Proceed.Email("b@example.com", "Sub", "Msg"), proceed("MATMSG:TO:b@example.com;SUB:Sub;BODY:Msg;;"))
        assertIs<Proceed.CopyOnly>(proceed("tel:"))
    }

    @Test
    fun mapsAuthenticatorsAndPayments() {
        assertEquals(Proceed.ShowOnMap("geo:31.5204,74.3587?q=Badshahi"), proceed(" geo:31.5204,74.3587?q=Badshahi "))
        // The authenticator needs the real secret, not the hidden version shown on screen.
        val otp = assertIs<Proceed.AddAuthenticator>(proceed(SAMPLES.first { it.name == "2FA setup" }.text))
        assertTrue("secret=JBSWY3DPEHPK3PXP" in otp.uri)
        assertEquals("bitcoin", assertIs<Proceed.Pay>(proceed(SAMPLES.first { it.name == "Crypto request" }.text)).what)
        assertEquals("UPI", assertIs<Proceed.Pay>(proceed("upi://pay?pa=shop@bank&pn=Shop&am=10")).what)
        // EMVCo codes have no link in them: you scan them from your bank's own app.
        assertIs<Proceed.CopyOnly>(proceed(SAMPLES.first { it.name == "Genuine payment" }.text))
    }

    @Test
    fun calendarEvents() {
        val e = assertIs<Proceed.AddEvent>(proceed(
            "BEGIN:VEVENT\nSUMMARY:Science fair\nDTSTART:20261020T090000Z\nDTEND:20261020T120000Z\nLOCATION:Hall\nEND:VEVENT"))
        assertEquals("Science fair", e.title)
        assertEquals(1_792_486_800_000L, e.startMillis)
        assertEquals(e.startMillis!! + 3 * 3600_000L, e.endMillis)
        assertFalse(e.allDay)
        assertEquals("Hall", e.location)

        val day = assertIs<Proceed.AddEvent>(proceed("BEGIN:VEVENT\nSUMMARY:Holiday\nDTSTART;VALUE=DATE:20261225\nEND:VEVENT"))
        assertTrue(day.allDay)
        assertNull(day.endMillis)
    }

    @Test
    fun icalTimes() {
        assertEquals(0L to false, parseIcalTime("19700101T000000Z"))
        assertEquals(3600_000L to false, parseIcalTime("19700101T020000", ZoneOffset.ofHours(1)))
        assertEquals(86_400_000L to true, parseIcalTime("19700102"))
        assertNull(parseIcalTime("next tuesday"))
    }

    @Test
    fun textAndRawData() {
        assertIs<Proceed.CopyOnly>(proceed("Lab sample #42"))
        assertEquals("https://example.com/menu", assertIs<Proceed.Browse>(proceed("Menu: https://example.com/menu")).url)
        assertIs<Proceed.CopyOnly>(proceedFor(classify("", byteArrayOf(1, 2, 3), isBinary = true)))
    }

    @Test
    fun everyDemoCodeHasAnAnswer() {
        // No sample should crash, and the dangerous link types must stay copy-only.
        val answers = SAMPLES.associate { it.name to proceed(it.text) }
        assertIs<Proceed.CopyOnly>(answers["JavaScript link"])
        assertIs<Proceed.Browse>(answers["Fake app download"])
        assertIs<Proceed.JoinWifi>(answers["Open Wi-Fi trap"])
    }
}
