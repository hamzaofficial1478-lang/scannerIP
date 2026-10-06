package io.github.scannerip.app.ui

import android.webkit.WebView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import io.github.scannerip.app.BrowserUi
import io.github.scannerip.app.ShieldedWeb

/**
 * The shielded browser, laid out: a bar that always says which address the
 * site sees and which ID is live, and the page underneath. The page itself is
 * a slot, so the tests can draw the bar without a real WebView.
 */
@Composable
fun BrowserScreen(
    state: BrowserUi,
    pageUrl: String?,
    progress: Int,
    snackbar: SnackbarHostState,
    onClose: () -> Unit,
    onNewIp: () -> Unit,
    page: @Composable (Modifier) -> Unit,
) {
    Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            Surface(tonalElevation = 3.dp) {
                Column(Modifier.fillMaxWidth().padding(start = 4.dp, end = 8.dp, top = 4.dp, bottom = 8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = onClose) { Icon(Icons.Filled.Close, contentDescription = "Close the browser") }
                        Column(Modifier.weight(1f)) {
                            Text("Shielded browser", fontWeight = FontWeight.Bold)
                            Text(pageUrl ?: state.url, fontFamily = FontFamily.Monospace, fontSize = 12.sp,
                                maxLines = 1, overflow = TextOverflow.Ellipsis,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = onNewIp, enabled = state.ready) {
                            Icon(Icons.Filled.Refresh, contentDescription = null)
                            Spacer(Modifier.width(4.dp))
                            Text("New IP")
                        }
                    }
                    Row(Modifier.padding(start = 12.dp, top = 2.dp), verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatusDot(if (state.ready) ShieldGreen else ShieldGrey)
                        if (state.ready) {
                            Text("Site sees ${state.exitIp}", fontFamily = FontFamily.Monospace, fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold)
                            Text(state.rotatingId.orEmpty(), fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                                maxLines = 1, overflow = TextOverflow.Ellipsis,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        } else {
                            Text("Getting a fresh IP and ID for this page...", fontSize = 13.sp)
                        }
                    }
                }
            }
            if (state.ready && progress in 1..99) {
                LinearProgressIndicator(progress = { progress / 100f }, modifier = Modifier.fillMaxWidth())
            } else {
                HorizontalDivider()
            }
            if (state.ready) {
                page(Modifier.weight(1f).fillMaxWidth())
            } else {
                Waiting(Modifier.weight(1f).fillMaxWidth(), "Shifting to a new address so this site can't tie the visit to you.")
            }
        }
    }
}

@Composable
private fun Waiting(modifier: Modifier, text: String, spinner: Boolean = true) {
    Box(modifier.padding(32.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            if (spinner) CircularProgressIndicator()
            Text(text, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 16.dp))
        }
    }
}

/** The real thing: [BrowserScreen] with a WebView that only ever talks through the shield. */
@Composable
fun ShieldedBrowser(
    state: BrowserUi,
    snackbar: SnackbarHostState,
    onClose: () -> Unit,
    onNewIp: (String?) -> Unit,
    onMessage: (String) -> Unit,
) {
    var pageUrl by remember(state.session) { mutableStateOf<String?>(null) }
    var progress by remember(state.session) { mutableIntStateOf(0) }
    var webView by remember { mutableStateOf<WebView?>(null) }
    // null while the proxy is being set, then whether it worked.
    var proxied by remember(state.proxyPort) { mutableStateOf<Boolean?>(null) }
    LaunchedEffect(state.proxyPort) {
        if (state.ready) proxied = ShieldedWeb.pointAtShield(state.proxyPort)
    }
    BackHandler {
        val w = webView
        if (w != null && w.canGoBack()) w.goBack() else onClose()
    }
    BrowserScreen(state, pageUrl, progress, snackbar, onClose, onNewIp = { onNewIp(pageUrl) }) { modifier ->
        when (proxied) {
            null -> Waiting(modifier, "Sending the browser through the shield...")
            false -> Waiting(modifier, spinner = false, text = "This phone's built-in browser engine can't be sent " +
                "through a proxy, so ScannerIP won't open the page here. Use Check where it goes or Copy instead.")
            true -> key(state.session) {
                AndroidView(
                    factory = { context ->
                        WebView(context).also { w ->
                            val js = ShieldedWeb.configure(w, onUrl = { pageUrl = it }, onProgress = { progress = it },
                                onBlocked = onMessage, onCrashed = {
                                    onMessage("That page crashed the browser, so it's been closed.")
                                    onClose()
                                })
                            if (!js) onMessage("JavaScript is off, because this phone's browser engine can't block WebRTC " +
                                "(which could give away your real IP). Some pages may not work.")
                            webView = w
                            // Nothing from an earlier page may follow this one.
                            ShieldedWeb.wipe(w) { w.loadUrl(state.url) }
                        }
                    },
                    onRelease = { w ->
                        if (webView === w) webView = null
                        w.stopLoading()
                        w.destroy()
                        ShieldedWeb.wipe(null)
                    },
                    modifier = modifier,
                )
            }
        }
    }
}
