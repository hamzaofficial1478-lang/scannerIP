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
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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
    data class Starting(val progress: Int, val summary: String) : TorState
    data class Ready(val socksPort: Int) : TorState
    data class Failed(val message: String) : TorState
}

/**
 * Tor running inside the app, via the Guardian Project's tor-android library
 * (the same Tor that powers Orbot). Started once and left running for the
 * life of the app, because Tor can't be restarted cleanly inside one process.
 */
class EmbeddedTor(private val app: Application) {
    private val _state = MutableStateFlow<TorState>(TorState.Off)
    val state: StateFlow<TorState> = _state

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var service: TorService? = null
    private var started = false
    private var poller: Job? = null

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

    /** Watch Tor's bootstrap progress until the first circuit is up. */
    private fun poll() {
        poller?.cancel()
        poller = scope.launch {
            while (isActive) {
                val svc = service
                if (svc?.torControlConnection != null) {
                    val phase = svc.getInfo("status/bootstrap-phase").orEmpty()
                    val progress = Regex("PROGRESS=(\\d+)").find(phase)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                    val summary = Regex("SUMMARY=\"([^\"]*)\"").find(phase)?.groupValues?.get(1) ?: "Starting Tor"
                    val circuit = svc.getInfo("status/circuit-established") == "1"
                    val port = svc.socksPort
                    if (circuit && port > 0) {
                        _state.value = TorState.Ready(port)
                        return@launch
                    }
                    if (_state.value !is TorState.Failed) _state.value = TorState.Starting(progress, summary)
                }
                delay(1000)
            }
        }
    }
}
