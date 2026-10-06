package io.github.scannerip.app

import android.annotation.SuppressLint
import android.net.Uri
import android.webkit.CookieManager
import android.webkit.GeolocationPermissions
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.UserAgentMetadata
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import io.github.scannerip.core.NO_WEBRTC_SCRIPT
import io.github.scannerip.core.genericUserAgent
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import kotlin.coroutines.resume

/**
 * ScannerIP's own browser, for opening links from codes behind the shield.
 *
 * It's Android's WebView, which is Chrome underneath, so pages work as
 * normal. What's different:
 *  - Every request goes through the shield, via a proxy override pointed at
 *    SocksRelay. If that can't be set up, nothing loads at all.
 *  - WebRTC is taken out of every page, because it can reach the internet
 *    without going through a proxy and so give away your real IP.
 *  - Cookies, storage and cache are wiped for every new code and every new
 *    IP, so one visit can't be tied to the next.
 *  - The user agent doesn't name your phone model.
 *  - Downloads, links into other apps, location, camera and microphone are
 *    all refused.
 */
object ShieldedWeb {
    private val now = Executor { it.run() }

    /** Point every WebView in the app at the relay. Returns once it's in force, or false if this WebView can't. */
    suspend fun pointAtShield(port: Int): Boolean {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) return false
        return suspendCancellableCoroutine { cont ->
            try {
                // socks5 (not "socks", which means SOCKS4) so site names go to Tor unresolved.
                val config = ProxyConfig.Builder().addProxyRule("socks5://127.0.0.1:$port").build()
                ProxyController.getInstance().setProxyOverride(config, now) { if (cont.isActive) cont.resume(true) }
            } catch (_: IllegalArgumentException) {
                if (cont.isActive) cont.resume(false)
            }
        }
    }

    /** Forget everything earlier pages stored, then call [then]. */
    fun wipe(webView: WebView?, then: () -> Unit = {}) {
        webView?.clearCache(true)
        webView?.clearHistory()
        WebStorage.getInstance().deleteAllData()
        CookieManager.getInstance().removeAllCookies { then() }
    }

    /**
     * Set up a fresh WebView for shielded browsing. Returns false if
     * JavaScript had to stay off because WebRTC couldn't be removed.
     */
    @SuppressLint("SetJavaScriptEnabled") // only once WebRTC can be stripped out first
    fun configure(
        webView: WebView,
        onUrl: (String) -> Unit,
        onProgress: (Int) -> Unit,
        onBlocked: (String) -> Unit,
        onCrashed: () -> Unit,
    ): Boolean {
        val canScrub = WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)
        val settings = webView.settings
        settings.javaScriptEnabled = canScrub
        settings.domStorageEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.setGeolocationEnabled(false)
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.setSupportMultipleWindows(false)
        settings.javaScriptCanOpenWindowsAutomatically = false
        settings.mediaPlaybackRequiresUserGesture = true
        settings.userAgentString = genericUserAgent(WebSettings.getDefaultUserAgent(webView.context))
        if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
            WebViewCompat.addDocumentStartJavaScript(webView, NO_WEBRTC_SCRIPT, setOf("*"))
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.USER_AGENT_METADATA)) {
            val metadata = WebSettingsCompat.getUserAgentMetadata(settings)
            WebSettingsCompat.setUserAgentMetadata(settings,
                UserAgentMetadata.Builder(metadata).setModel("").setPlatformVersion("10.0.0").build())
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.SAFE_BROWSING_ENABLE)) {
            WebSettingsCompat.setSafeBrowsingEnabled(settings, true) // Google's phishing warnings stay on
        }
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, false)

        webView.webViewClient = ShieldedClient(onUrl, onBlocked, onCrashed)
        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView, newProgress: Int) = onProgress(newProgress)

            override fun onPermissionRequest(request: PermissionRequest) = request.deny()

            override fun onGeolocationPermissionsShowPrompt(origin: String?, callback: GeolocationPermissions.Callback?) {
                callback?.invoke(origin, false, false)
            }

            override fun onShowFileChooser(
                view: WebView?,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?,
            ): Boolean {
                filePathCallback?.onReceiveValue(null)
                onBlocked("This page wanted a file from your phone. Not in the shielded browser.")
                return true
            }
        }
        webView.setDownloadListener { _, _, _, mimeType, _ ->
            onBlocked("Blocked a download ($mimeType). Files from QR codes are a common way to sneak malware onto phones.")
        }
        return canScrub
    }

    // onRenderProcessGone is right below. The lint check mistakes Kotlin's
    // ": WebViewClient()" super call for a bare WebViewClient without one.
    @SuppressLint("MissingOnRenderProcessGone")
    private class ShieldedClient(
        private val onUrl: (String) -> Unit,
        private val onBlocked: (String) -> Unit,
        private val onCrashed: () -> Unit,
    ) : WebViewClient() {
        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
            val scheme = request.url.scheme?.lowercase()
            if (scheme == "http" || scheme == "https") return false
            onBlocked("Blocked a jump to another app ($scheme:), because that app wouldn't go through the shield.")
            return true
        }

        override fun doUpdateVisitedHistory(view: WebView, url: String?, isReload: Boolean) {
            url?.let(onUrl)
        }

        // A page that crashes the browser engine (or runs it out of memory)
        // closes the browser instead of taking the whole app down.
        override fun onRenderProcessGone(view: WebView, detail: RenderProcessGoneDetail): Boolean {
            onCrashed()
            return true
        }
    }
}
