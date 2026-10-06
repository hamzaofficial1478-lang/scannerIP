package io.github.scannerip.app.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.scannerip.app.AppViewModel
import io.github.scannerip.app.InspectUi
import io.github.scannerip.app.Launcher
import io.github.scannerip.app.ShieldState
import io.github.scannerip.app.ShieldUi
import io.github.scannerip.core.Proceed
import kotlinx.coroutines.launch

enum class Tab(val label: String, val icon: ImageVector) {
    SCAN("Scan", Icons.Filled.Search),
    CHECK("Check", Icons.Filled.Edit),
    SHIELD("Shield", Icons.Filled.Lock),
    IDS("IDs", Icons.Filled.Person),
    HISTORY("History", Icons.AutoMirrored.Filled.List),
}

@Composable
fun ScannerIpApp(vm: AppViewModel) {
    val context = LocalContext.current
    val haptics = LocalHapticFeedback.current
    val shield by vm.shield.collectAsStateWithLifecycle()
    val lastScan by vm.lastScan.collectAsStateWithLifecycle()
    val layers by vm.layers.collectAsStateWithLifecycle()
    val history by vm.history.collectAsStateWithLifecycle()
    val inspection by vm.inspection.collectAsStateWithLifecycle()
    val codesInView by vm.codesInView.collectAsStateWithLifecycle()
    val updates by vm.updates.collectAsStateWithLifecycle()
    val backgroundUpdates by vm.backgroundUpdates.collectAsStateWithLifecycle()
    val browser by vm.browser.collectAsStateWithLifecycle()

    var tab by rememberSaveable { mutableStateOf(Tab.SCAN) }
    var torchOn by rememberSaveable { mutableStateOf(false) }
    var hasCamera by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val snackbar = remember { SnackbarHostState() }

    val askCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted -> hasCamera = granted }
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri: Uri? ->
        uri?.let(vm::decodeImage)
    }

    val askNotifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    LaunchedEffect(Unit) {
        if (vm.shouldAskForNotifications()) {
            vm.notificationsAsked()
            askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    LaunchedEffect(Unit) { vm.messages.collect { snackbar.showSnackbar(it) } }
    LaunchedEffect(lastScan?.id) { if (lastScan != null) haptics.performHapticFeedback(HapticFeedbackType.LongPress) }

    val scope = rememberCoroutineScope()
    val copy: (String) -> Unit = { text ->
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Scanned code", text))
        // Android 13+ shows its own "copied" confirmation.
        if (Build.VERSION.SDK_INT < 33) scope.launch { snackbar.showSnackbar("Copied. Paste it somewhere harmless, not straight into a browser.") }
    }
    val inspecting = inspection is InspectUi.Running
    val say: (String) -> Unit = { message -> scope.launch { snackbar.showSnackbar(message) } }
    // Going ahead with a code: web pages open in the shielded browser, everything
    // else goes to the phone app for it. Either way the shield moves on to a new IP and ID.
    val proceed: (Proceed) -> Unit = { action ->
        if (action is Proceed.Browse) {
            vm.openShielded(action.url)
        } else {
            Launcher.launch(context, action)?.let(say)
            vm.proceededElsewhere()
        }
    }
    val openOutside: (String) -> Unit = { url ->
        Launcher.openInBrowser(context, url)?.let(say)
        vm.proceededElsewhere()
    }

    val open = browser
    if (open != null) {
        ShieldedBrowser(open, snackbar, onClose = vm::closeBrowser, onNewIp = vm::newBrowserIdentity, onMessage = say)
        return
    }

    Scaffold(
        topBar = {
            Column {
                TopBar(shield)
                UpdateBanner(updates, onUpdate = vm::installUpdate)
            }
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = null) },
                        label = { Text(t.label) },
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                Tab.SCAN -> ScanScreen(
                    hasCameraPermission = hasCamera,
                    codesInView = codesInView,
                    torchOn = torchOn,
                    lastScan = lastScan,
                    canInspect = shield.canInspect,
                    inspecting = inspecting,
                    onAskPermission = { askCamera.launch(Manifest.permission.CAMERA) },
                    onPickImage = { pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                    onToggleTorch = { torchOn = !torchOn },
                    onInspect = vm::inspect,
                    onCopy = copy,
                    camera = { modifier -> CameraPreview(vm::onCameraCodes, torchOn, modifier) },
                    onProceed = proceed,
                    onOpenInBrowser = openOutside,
                )
                Tab.CHECK -> CheckScreen(
                    lastScan = lastScan,
                    canInspect = shield.canInspect,
                    inspecting = inspecting,
                    onCheck = { vm.checkText(it) },
                    onSample = { vm.checkText(it.text, "Demo code") },
                    onInspect = vm::inspect,
                    onCopy = copy,
                    onProceed = proceed,
                    onOpenInBrowser = openOutside,
                )
                Tab.SHIELD -> ShieldScreen(
                    state = shield,
                    onMode = vm::setMode,
                    onInterval = vm::setInterval,
                    onShiftNow = vm::shiftNow,
                    onRetry = vm::retryShield,
                    onProxyText = vm::setProxyText,
                    onStartOrbot = vm::startOrbot,
                    onGetOrbot = { openStore(context) },
                    onBridges = vm::setBridges,
                    onShowOwnIp = vm::showOwnIp,
                    onSeeItOnAWebsite = { vm.openShielded("https://check.torproject.org/") },
                    footer = {
                        UpdatesCard(vm.appVersion, updates, backgroundUpdates,
                            onCheck = vm::checkForUpdates, onBackgroundChecks = vm::setBackgroundUpdates)
                    },
                )
                Tab.IDS -> IdsScreen(layers, vm.keyDescription,
                    onResetAdId = { Launcher.openAdSettings(context)?.let(say) }, onVerifySeal = vm::verifySeal)
                Tab.HISTORY -> HistoryScreen(
                    entries = history,
                    onShare = {
                        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, vm.historyAsText())
                        context.startActivity(Intent.createChooser(send, "Share scan history"))
                    },
                    onClear = vm::clearHistory,
                )
            }
        }
    }

    InspectionDialog(inspection, onDismiss = vm::dismissInspection)
}

@Composable
private fun TopBar(shield: ShieldUi) {
    Row(
        Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text("ScannerIP", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text("scan first, trust later", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        ShieldChip(shield)
    }
}

@Composable
fun ShieldChip(shield: ShieldUi) {
    val (colour, text) = when (shield.state) {
        ShieldState.ACTIVE -> ShieldGreen to (shield.current?.exit?.ip ?: "Shield on")
        ShieldState.DEMO -> ShieldAmber to "Demo ${shield.current?.exit?.ip ?: ""}".trim()
        ShieldState.STARTING -> ShieldGrey to (shield.torProgress?.let { "Tor $it%" } ?: "Connecting")
        ShieldState.ERROR -> ShieldRed to "Shield off"
    }
    Row(
        Modifier
            .clip(RoundedCornerShape(50))
            .background(colour.copy(alpha = 0.15f))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusDot(colour)
        Spacer(Modifier.width(6.dp))
        Text(text, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun InspectionDialog(state: InspectUi, onDismiss: () -> Unit) {
    val (title, body) = when (state) {
        InspectUi.Idle, is InspectUi.Running -> return
        is InspectUi.Failed -> "Couldn't check that link" to state.message
        is InspectUi.Done -> "Where this link really goes" to buildString {
            val r = state.result
            appendLine("Checked through ${state.viaIp ?: "the shield"}. The site never saw your real IP.")
            appendLine()
            r.hops.forEachIndexed { i, hop -> appendLine("$i. [${hop.status}] ${hop.url}") }
            if (r.error.isNotEmpty()) appendLine("\nStopped early: ${r.error}")
            if (r.extra.isNotEmpty()) appendLine()
            r.extra.forEach { appendLine("${it.severity.name}: ${it.message}") }
            r.report?.let { report ->
                appendLine("\nFinal destination: ${report.level.name} (${report.score}/100)")
                report.findings.forEach { appendLine("${it.severity.name}: ${it.message}") }
                appendLine("\n${report.advice}")
            }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Text(body, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.verticalScroll(rememberScrollState()))
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
    )
}

private fun openStore(context: Context) {
    val market = Intent(Intent.ACTION_VIEW, "market://details?id=org.torproject.android".toUri())
    val web = Intent(Intent.ACTION_VIEW, "https://play.google.com/store/apps/details?id=org.torproject.android".toUri())
    try {
        context.startActivity(market)
    } catch (_: Exception) {
        context.startActivity(web)
    }
}
