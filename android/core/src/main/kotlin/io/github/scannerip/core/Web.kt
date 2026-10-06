package io.github.scannerip.core

/*
 * Small pieces of the shielded browser that don't need a phone to test.
 */

/**
 * The browser's user agent with the phone model and the "this is an app's
 * WebView" markers taken out. What's left matches what Chrome on Android
 * itself sends these days ("Android 10; K"), so the site learns nothing about
 * which phone this is.
 */
fun genericUserAgent(default: String): String =
    default.replace(Regex("\\(Linux; Android [^)]*\\)"), "(Linux; Android 10; K)")
        .replace(" Version/4.0", "")
        .replace(Regex("\\s+"), " ")
        .trim()

/**
 * Runs at the start of every page and frame, before the page's own scripts.
 *
 * WebRTC (the browser's video-call machinery) can open its own network
 * connections that don't go through a proxy. A page can use that to learn
 * your real IP even when everything else goes through Tor, so it's removed.
 * Frames made on the fly get the same treatment as soon as the page touches
 * them.
 */
val NO_WEBRTC_SCRIPT = """
(function () {
  var names = ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection', 'RTCDataChannel',
    'RTCIceCandidate', 'RTCSessionDescription', 'RTCRtpSender', 'RTCRtpReceiver', 'RTCRtpTransceiver',
    'RTCDtlsTransport', 'RTCIceTransport', 'RTCSctpTransport', 'RTCCertificate'];
  function scrub(w) {
    if (!w) return w;
    names.forEach(function (n) {
      try { Object.defineProperty(w, n, { value: undefined, writable: false, configurable: false }); }
      catch (e) { try { delete w[n]; } catch (e2) {} }
    });
    try { if (w.navigator) Object.defineProperty(w.navigator, 'mediaDevices', { value: undefined, configurable: false }); } catch (e) {}
    return w;
  }
  scrub(window);
  function guard(proto, prop, toWindow) {
    try {
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.get) return;
      Object.defineProperty(proto, prop, {
        get: function () { var v = d.get.call(this); scrub(toWindow(v)); return v; },
        configurable: false
      });
    } catch (e) {}
  }
  guard(HTMLIFrameElement.prototype, 'contentWindow', function (v) { return v; });
  guard(HTMLIFrameElement.prototype, 'contentDocument', function (v) { return v && v.defaultView; });
  guard(HTMLObjectElement.prototype, 'contentWindow', function (v) { return v; });
})();
""".trimIndent()
