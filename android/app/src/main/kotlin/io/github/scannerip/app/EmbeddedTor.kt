@file:Suppress("DEPRECATION") // LocalBroadcastManager: TorService still reports errors through it

package io.github.scannerip.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import androidx.core.content.edit
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import io.github.scannerip.core.BridgeType
import io.github.scannerip.core.Bridges
import io.github.scannerip.core.StallWatch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.torproject.jni.TorService

sealed interface TorState {
    data object Off : TorState
    data class Starting(val progress: Int, val summary: String, val via: BridgeType = BridgeType.NONE) : TorState
    data class Ready(val socksPort: Int, val via: BridgeType = BridgeType.NONE) : TorState
    data class Failed(val message: String) : TorState
}

/** How the built-in Tor gets in: worked out by the app, or one fixed way. */
enum class BridgeChoice(val title: String, val type: BridgeType?, val blurb: String) {
    AUTO("Automatic", null, "Tries Tor directly, then each kind of bridge until one gets through. Remembers what worked."),
    NONE(BridgeType.NONE.title, BridgeType.NONE, BridgeType.NONE.blurb),
    OBFS4(BridgeType.OBFS4.title, BridgeType.OBFS4, BridgeType.OBFS4.blurb),
    SNOWFLAKE(BridgeType.SNOWFLAKE.title, BridgeType.SNOWFLAKE, BridgeType.SNOWFLAKE.blurb),
    MEEK(BridgeType.MEEK.title, BridgeType.MEEK, BridgeType.MEEK.blurb),
}

/**
 * Tor running inside the app, via the Guardian Project's tor-android library
 * (the same Tor that powers Orbot). Started once and left running for the
 * life of the app, because Tor can't be restarted cleanly inside one process.
 *
 * If the network blocks Tor, start-up stalls (usually at 10%). In automatic
 * mode the app then switches the running Tor over to a bridge, trying each
 * kind in turn, and remembers which one worked for next time.
 */
class EmbeddedTor(private val app: Application) {
    private val _state = MutableStateFlow<TorState>(TorState.Off)
    val state: StateFlow<TorState> = _state

    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val _choice = MutableStateFlow(
        prefs.getString(KEY_CHOICE, null)?.let { name -> BridgeChoice.entries.find { it.name == name } } ?: BridgeChoice.AUTO)
    val choice: StateFlow<BridgeChoice> = _choice

    // Only one thing at a time talks to Tor's control port.
    @OptIn(ExperimentalCoroutinesApi::class)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))
    @Volatile private var service: TorService? = null
    private var started = false
    private var poller: Job? = null
    private var transports: Transports? = null // loaded only once a bridge is needed

    private var plan: List<BridgeType> = emptyList()
    private var stage = 0
    private var current = BridgeType.NONE
    private var watch = StallWatch(Bridges.patienceMillis(BridgeType.NONE))

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            service = (binder as TorService.LocalBinder).service
            poll()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
            _state.value = TorState.Failed("Tor stopped unexpectedly. Close and reopen the app to restart it.")
        }
    }

    private val errors = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra(Intent.EXTRA_TEXT) ?: "unknown error"
            _state.value = TorState.Failed("Tor couldn't start: $message")
        }
    }

    @Synchronized
    fun start() {
        if (started) return
        started = true
        _state.value = TorState.Starting(0, "Starting Tor")
        LocalBroadcastManager.getInstance(app).registerReceiver(errors, IntentFilter(TorService.ACTION_ERROR))
        if (!app.bindService(Intent(app, TorService::class.java), connection, Context.BIND_AUTO_CREATE)) {
            _state.value = TorState.Failed("Couldn't start the built-in Tor service.")
        }
    }

    /** Ask Tor for a brand new identity (fresh circuits). */
    fun newIdentity() {
        service?.torControlConnection?.signal("NEWNYM")
    }

    /** Pick how Tor gets in. Takes effect straight away if Tor is already running. */
    fun setChoice(choice: BridgeChoice) {
        prefs.edit { putString(KEY_CHOICE, choice.name) }
        _choice.value = choice
        if (service != null) poll()
    }

    /** Work out a way in from the top again (the Try again button). */
    fun retry() {
        if (service != null && _state.value !is TorState.Ready) poll()
    }

    /** Watch Tor's start-up until the first circuit is up, moving to a bridge if it stalls. */
    private fun poll() {
        poller?.cancel()
        poller = scope.launch {
            var planned = false
            while (isActive) {
                val svc = service
                if (svc?.torControlConnection != null) {
                    if (!planned) {
                        planned = true
                        startPlan()
                    }
                    val phase = svc.getInfo("status/bootstrap-phase").orEmpty()
                    val progress = Regex("PROGRESS=(\\d+)").find(phase)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                    val summary = Regex("SUMMARY=\"([^\"]*)\"").find(phase)?.groupValues?.get(1) ?: "Starting Tor"
                    val port = svc.socksPort
                    if (svc.getInfo("status/circuit-established") == "1" && port > 0) {
                        if (_choice.value == BridgeChoice.AUTO) prefs.edit { putString(KEY_WORKED, current.name) }
                        _state.value = TorState.Ready(port, current)
                        return@launch
                    }
                    if (watch.stalled(progress)) moveOn()
                    if (_state.value !is TorState.Failed) _state.value = TorState.Starting(progress, describe(summary), current)
                }
                delay(1000)
            }
        }
    }

    private fun startPlan() {
        val worked = prefs.getString(KEY_WORKED, null)?.let { name -> BridgeType.entries.find { it.name == name } }
        plan = _choice.value.type?.let { listOf(it) } ?: Bridges.autoOrder(worked)
        stage = 0
        if (_state.value is TorState.Failed) _state.value = TorState.Starting(0, "Starting Tor")
        // A fresh Tor has no bridges set, so a direct start needs no changes.
        if (plan[0] == BridgeType.NONE && current == BridgeType.NONE) begin(BridgeType.NONE) else use(plan[0])
    }

    private fun moveOn() {
        if (stage + 1 < plan.size) {
            stage += 1
            use(plan[stage])
        } else if (_state.value !is TorState.Failed) {
            _state.value = TorState.Failed(
                if (plan.size == 1) "Tor isn't getting through with \"${current.title}\" on this network. " +
                    "Pick Automatic or another bridge below."
                else "Tor can't get through on this network, even with bridges. Try Orbot, a proxy list or another network.")
        }
    }

    private fun begin(type: BridgeType) {
        current = type
        watch = StallWatch(Bridges.patienceMillis(type))
    }

    /** Switch the running Tor over to [type]. */
    private fun use(type: BridgeType) {
        begin(type)
        try {
            val conn = service?.torControlConnection ?: return
            val port = if (type == BridgeType.NONE) 0 else (transports ?: Transports(app).also { transports = it }).start(type)
            conn.setConf("DisableNetwork", "1")
            conn.setConf(Bridges.torConfig(type, port))
            conn.setConf("DisableNetwork", "0")
            transports?.stopAllExcept(type)
        } catch (e: Exception) {
            // A bridge that won't even start is as good as stuck, so move on next time round.
            _state.value = TorState.Starting(0, "The ${type.title} bridge wouldn't start (${e.message})", type)
            watch = StallWatch(0)
        }
    }

    private fun describe(summary: String) =
        if (current == BridgeType.NONE) summary else "${current.title} bridge: $summary"

    private companion object {
        const val KEY_CHOICE = "tor_bridges"
        const val KEY_WORKED = "tor_bridges_worked"
    }
}
