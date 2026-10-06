package io.github.scannerip.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebTest {
    @Test
    fun userAgentLosesThePhoneModel() {
        val webView = "Mozilla/5.0 (Linux; Android 14; SM-A145F Build/UP1A.231005.007; wv) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Version/4.0 Chrome/140.0.7339.207 Mobile Safari/537.36"
        val plain = genericUserAgent(webView)
        assertEquals("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) " +
            "Chrome/140.0.7339.207 Mobile Safari/537.36", plain)
        assertFalse("SM-A145F" in plain)
        assertFalse("wv" in plain)
    }

    @Test
    fun webRtcScriptCoversEveryWayIn() {
        for (name in listOf("RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel", "mediaDevices",
            "contentWindow", "contentDocument")) {
            assertTrue(name in NO_WEBRTC_SCRIPT, name)
        }
        // Balanced brackets is a cheap guard against a typo breaking the whole script.
        assertEquals(NO_WEBRTC_SCRIPT.count { it == '(' }, NO_WEBRTC_SCRIPT.count { it == ')' })
        assertEquals(NO_WEBRTC_SCRIPT.count { it == '{' }, NO_WEBRTC_SCRIPT.count { it == '}' })
    }
}
