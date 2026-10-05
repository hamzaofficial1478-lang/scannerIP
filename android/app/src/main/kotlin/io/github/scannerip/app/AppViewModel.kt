package io.github.scannerip.app

import android.app.Application
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.SystemClock
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.scannerip.core.Decoded
import io.github.scannerip.core.IdentityVault
import io.github.scannerip.core.Inspection
import io.github.scannerip.core.Kind
import io.github.scannerip.core.Layer
import io.github.scannerip.core.ProxyPoolRotator
import io.github.scannerip.core.Report
import io.github.scannerip.core.RotationError
import io.github.scannerip.core.RotationEvent
import io.github.scannerip.core.Rotator
import io.github.scannerip.core.ScanEntry
import io.github.scannerip.core.ScanLog
import io.github.scannerip.core.Shield
import io.github.scannerip.core.SimulatedRotator
import io.github.scannerip.core.TorRotator
import io.github.scannerip.core.inspectUrl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.math.roundToInt

enum class ShieldMode(
    val title: String,
    val blurb: String,
    val minInterval: Int,
    val defaultInterval: Int,
    val anonymous: Boolean,
) {
    BUILT_IN_TOR("Tor (built in)", "Real IP shifting through Tor, running inside this app. The first start takes up to a minute.", 10, 30, true),
    ORBOT("Tor via Orbot", "Uses the Orbot app's Tor instead. Handy on networks that block Tor, because Orbot can use bridges.", 10, 30, true),
    PROXY_LIST("Proxy list", "Cycles through proxies you type in, one per line.", 3, 10, true),
    DEMO("Demo mode", "Made-up addresses for presentations. Your real IP is NOT hidden.", 2, 5, false),
}

enum class ShieldState { STARTING, ACTIVE, ERROR, DEMO }

data class ShieldUi(
    val mode: ShieldMode = ShieldMode.BUILT_IN_TOR,
    val state: ShieldState = ShieldState.STARTING,
    val status: String = "Starting...",
    val torProgress: Int? = null,
    val current: RotationEvent? = null,
    val history: List<RotationEvent> = emptyList(),
    val secondsLeft: Int? = null,
    val intervalSeconds: Int = mode.defaultInterval,
    val proxyText: String = "",
    val orbotInstalled: Boolean = false,
) {
    /** Link checks only make sense when traffic really goes through another address. */
    val canInspect: Boolean get() = mode.anonymous && state == ShieldState.ACTIVE
}

data class ScanResult(
    val id: Long,
    val format: String,
    val report: Report,
    val image: Bitmap?,
    val loggedAs: String?,
) {
    val inspectableUrl: String?
        get() = report.payload.takeIf { it.kind == Kind.URL && it.fields["scheme"] in setOf("http", "https") }
            ?.fields?.get("url")
}

sealed interface InspectUi {
    data object Idle : InspectUi
    data class Running(val url: String) : InspectUi
    data class Done(val url: String, val result: Inspection, val viaIp: String?) : InspectUi
    data class Failed(val url: String, val message: String) : InspectUi
}

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val tor = (app as ScannerIpApplication).tor
    private val scanLog = ScanLog(File(app.filesDir, "scan_log.jsonl"))
    // One at a time, in order: the first load must finish before any new scan is added.
    @OptIn(ExperimentalCoroutinesApi::class)
    private val logQueue = Dispatchers.IO.limitedParallelism(1)

    private val _shield = MutableStateFlow(loadShieldPrefs())
    val shield: StateFlow<ShieldUi> = _shield

    private val _layers = MutableStateFlow<List<Layer>>(emptyList())
    val layers: StateFlow<List<Layer>> = _layers

    private val _lastScan = MutableStateFlow<ScanResult?>(null)
    val lastScan: StateFlow<ScanResult?> = _lastScan

    private val _history = MutableStateFlow<List<ScanEntry>>(emptyList())
    val history: StateFlow<List<ScanEntry>> = _history

    private val _inspection = MutableStateFlow<InspectUi>(InspectUi.Idle)
    val inspection: StateFlow<InspectUi> = _inspection

    private val _codesInView = MutableStateFlow(false)
    val codesInView: StateFlow<Boolean> = _codesInView

    private val _messages = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val messages: SharedFlow<String> = _messages

    @Volatile private var vault: IdentityVault? = null
    @Volatile private var shieldRunner: Shield? = null
    @Volatile private var generation = 0
    private var torWatcher: Job? = null
    private val seen = HashMap<String, Long>()

    init {
        viewModelScope.launch {
            // Keystore key generation can take a moment, so keep it off the main thread.
            val v = withContext(Dispatchers.Default) {
                IdentityVault(deviceKeys(getApplication()), deviceFingerprint(getApplication()))
            }
            vault = v
            _layers.value = v.layers()
            startShield()
        }
        viewModelScope.launch(logQueue) {
            _history.value = scanLog.readAll().asReversed()
        }
        viewModelScope.launch {
            while (true) {
                delay(500)
                val left = shieldRunner?.secondsLeft()?.roundToInt()
                if (left != _shield.value.secondsLeft) _shield.update { it.copy(secondsLeft = left) }
            }
        }
    }

    // ---------- shield ----------

    private fun loadShieldPrefs(): ShieldUi {
        val mode = prefs.getString("mode", null)?.let { name -> ShieldMode.entries.find { it.name == name } }
            ?: ShieldMode.BUILT_IN_TOR
        return ShieldUi(mode = mode, intervalSeconds = intervalFor(mode), proxyText = prefs.getString("proxies", "").orEmpty())
    }

    private fun intervalFor(mode: ShieldMode) =
        prefs.getInt("interval_${mode.name}", mode.defaultInterval).coerceIn(mode.minInterval, MAX_INTERVAL)

    fun setMode(mode: ShieldMode) {
        if (mode == _shield.value.mode) return
        prefs.edit { putString("mode", mode.name) }
        _shield.update { it.copy(mode = mode, intervalSeconds = intervalFor(mode)) }
        viewModelScope.launch { startShield() }
    }

    fun setInterval(seconds: Int) {
        val mode = _shield.value.mode
        val value = seconds.coerceIn(mode.minInterval, MAX_INTERVAL)
        prefs.edit { putInt("interval_${mode.name}", value) }
        shieldRunner?.intervalMillis = value * 1000L
        _shield.update { it.copy(intervalSeconds = value) }
    }

    fun setProxyText(text: String) {
        prefs.edit { putString("proxies", text) }
        _shield.update { it.copy(proxyText = text) }
    }

    fun retryShield() {
        viewModelScope.launch { startShield() }
    }

    fun shiftNow() {
        val runner = shieldRunner ?: return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                runner.rotateNow()
            } catch (e: Exception) {
                _messages.emit("Shift failed: ${e.message}")
            }
        }
    }

    private fun setStatus(state: ShieldState, status: String, progress: Int? = null) =
        _shield.update { it.copy(state = state, status = status, torProgress = progress) }

    private suspend fun startShield() {
        val v = vault ?: return
        stopShield()
        val gen = ++generation
        torWatcher?.cancel()
        val mode = _shield.value.mode
        _shield.update { it.copy(current = null, history = emptyList(), torProgress = null, secondsLeft = null, orbotInstalled = isOrbotInstalled()) }
        when (mode) {
            ShieldMode.DEMO -> launchShield(gen, SimulatedRotator(), v)
            ShieldMode.PROXY_LIST -> try {
                launchShield(gen, ProxyPoolRotator(_shield.value.proxyText.lines()), v)
            } catch (e: RotationError) {
                setStatus(ShieldState.ERROR, e.message ?: "Proxy list problem")
            }
            ShieldMode.ORBOT -> {
                setStatus(ShieldState.STARTING, "Looking for Orbot...")
                val up = withContext(Dispatchers.IO) { TorRotator.isListening("127.0.0.1", ORBOT_SOCKS_PORT) }
                if (gen != generation) return
                if (up) {
                    launchShield(gen, TorRotator(socksPort = ORBOT_SOCKS_PORT, name = "Tor via Orbot"), v)
                } else {
                    setStatus(ShieldState.ERROR, "Orbot isn't running. Open Orbot and tap Start, then Try again.")
                }
            }
            ShieldMode.BUILT_IN_TOR -> {
                tor.start()
                torWatcher = viewModelScope.launch {
                    tor.state.collect { state ->
                        if (gen != generation) return@collect
                        when (state) {
                            TorState.Off -> setStatus(ShieldState.STARTING, "Starting Tor...", 0)
                            is TorState.Starting -> setStatus(ShieldState.STARTING,
                                "Starting Tor ${state.progress}% - ${state.summary}", state.progress)
                            is TorState.Ready -> if (shieldRunner == null) {
                                launchShield(gen, TorRotator(socksPort = state.socksPort, name = "Tor (built in)",
                                    newIdentity = tor::newIdentity), v)
                            }
                            is TorState.Failed -> setStatus(ShieldState.ERROR, state.message)
                        }
                    }
                }
            }
        }
    }

    private fun launchShield(gen: Int, rotator: Rotator, v: IdentityVault) {
        val runner = Shield(
            rotator, v, _shield.value.intervalSeconds,
            onRotate = { event -> if (gen == generation) onRotated(event, rotator) },
            onError = { e -> if (gen == generation) setStatus(ShieldState.ERROR, "Shift failed: ${e.message}. Trying again shortly.") },
        )
        shieldRunner = runner
        if (rotator.anonymous) setStatus(ShieldState.STARTING, "Getting the first exit IP...")
        else setStatus(ShieldState.DEMO, "Demo mode - made-up IPs")
        runner.start()
    }

    private fun onRotated(event: RotationEvent, rotator: Rotator) {
        val torNote = when (event.exit.isTor) { true -> " - Tor confirmed"; false -> " - not a Tor exit"; null -> "" }
        _shield.update {
            it.copy(
                state = if (rotator.anonymous) ShieldState.ACTIVE else ShieldState.DEMO,
                status = if (rotator.anonymous) "Protected via ${event.exit.via}$torNote" else "Demo mode - made-up IPs",
                torProgress = null,
                current = event,
                history = (listOf(event) + it.history).take(50),
            )
        }
        vault?.let { _layers.value = it.layers() }
    }

    private fun stopShield() {
        shieldRunner?.let { old ->
            old.onRotate = null
            old.onError = null
            old.close(waitMillis = 0) // don't hold up the screen if a shift is mid-way
        }
        shieldRunner = null
    }

    private fun isOrbotInstalled(): Boolean = try {
        getApplication<Application>().packageManager.getPackageInfo(ORBOT_PACKAGE, 0)
        true
    } catch (_: Exception) {
        false
    }

    /** Ask Orbot to start (the same broadcast Orbot's own helper library sends), then try again. */
    fun startOrbot() {
        val app = getApplication<Application>()
        app.sendBroadcast(Intent("org.torproject.android.intent.action.START")
            .setPackage(ORBOT_PACKAGE)
            .putExtra("org.torproject.android.intent.extra.PACKAGE_NAME", app.packageName))
        viewModelScope.launch {
            _messages.emit("Asked Orbot to start. Trying again in a few seconds...")
            delay(6000)
            startShield()
        }
    }

    // ---------- scanning ----------

    /** Called from the camera's analysis thread for every frame. */
    fun onCameraCodes(codes: List<Decoded>) {
        _codesInView.value = codes.isNotEmpty()
        val now = SystemClock.elapsedRealtime()
        // Holding a code in front of the camera shouldn't report it 30 times a second.
        val fresh = synchronized(seen) {
            if (seen.size > 200) seen.entries.removeAll { now - it.value > COOLDOWN_MS }
            codes.filter { code ->
                val last = seen.put(code.key, now)
                last == null || now - last > COOLDOWN_MS
            }
        }
        fresh.forEach { report(it, null) }
    }

    fun decodeImage(uri: Uri) {
        viewModelScope.launch(Dispatchers.Default) {
            try {
                val bitmap = CodeReader.loadBitmap(getApplication(), uri)
                val codes = CodeReader.decodeBitmap(bitmap)
                if (codes.isEmpty()) {
                    _messages.emit("No code found in that picture.")
                    return@launch
                }
                val annotated = CodeReader.annotate(bitmap, codes)
                codes.forEach { report(it, annotated) }
                if (codes.size > 1) _messages.emit("Found ${codes.size} codes. Showing the last one; all of them are in History.")
            } catch (e: Exception) {
                _messages.emit("Couldn't read that picture: ${e.message}")
            }
        }
    }

    fun checkText(text: String, source: String = "Typed in") {
        if (text.isBlank()) return
        report(Decoded(source, text, text.toByteArray(), isBinary = false), null)
    }

    private fun report(code: Decoded, image: Bitmap?) {
        val report = code.report()
        val snapshot = vault?.current
        _lastScan.value = ScanResult(System.nanoTime(), code.format, report, image, snapshot?.rotatingId)
        _inspection.value = InspectUi.Idle
        viewModelScope.launch(logQueue) {
            val entry = scanLog.record(code.format, report, snapshot)
            _history.update { listOf(entry) + it }
        }
    }

    fun inspect(url: String) {
        val runner = shieldRunner
        if (runner == null || !_shield.value.canInspect) {
            _messages.tryEmit("Link checks need Tor, Orbot or a proxy switched on (Shield tab), so the site never sees your real IP.")
            return
        }
        _inspection.value = InspectUi.Running(url)
        viewModelScope.launch(Dispatchers.IO) {
            _inspection.value = try {
                InspectUi.Done(url, inspectUrl(url, runner.route()), runner.current?.exit?.ip)
            } catch (e: Exception) {
                InspectUi.Failed(url, e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun dismissInspection() {
        _inspection.value = InspectUi.Idle
    }

    // ---------- IDs and history ----------

    fun verifySeal() {
        viewModelScope.launch(Dispatchers.Default) {
            val v = vault ?: return@launch
            val token = v.current?.sealed ?: v.seal()
            _messages.emit(
                if (v.verifySeal(token)) "Layer 1 opened with this phone's own key and matches Layer 0. No other phone's key can do that."
                else "The seal didn't open. That shouldn't happen - try restarting the app.",
            )
        }
    }

    val keyDescription: String get() = vault?.keyDescription ?: ""

    fun clearHistory() {
        viewModelScope.launch(logQueue) {
            scanLog.clear()
            _history.value = emptyList()
        }
    }

    fun historyAsText(): String = buildString {
        appendLine("ScannerIP scan history (newest first). Each scan is logged under a rotating ID, not the phone's ID.")
        for (e in _history.value.take(200)) {
            appendLine()
            appendLine("${e.time}  ${e.level} ${e.score}/100  ${e.format}  logged as ${e.rotatingId ?: "-"}")
            appendLine(e.content)
            e.findings.forEach { appendLine("  - $it") }
        }
    }

    override fun onCleared() {
        generation++
        stopShield()
    }

    companion object {
        const val MAX_INTERVAL = 300
        const val COOLDOWN_MS = 4000L
        const val ORBOT_PACKAGE = "org.torproject.android"
        const val ORBOT_SOCKS_PORT = 9050
    }
}
