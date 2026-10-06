package io.github.scannerip.app

import android.app.Application
import androidx.annotation.VisibleForTesting
import io.github.scannerip.core.ExitLookup
import io.github.scannerip.core.Route

/** Holds the one built-in Tor instance and the updater for the whole app. */
class ScannerIpApplication : Application() {
    val tor: EmbeddedTor by lazy { EmbeddedTor(this) }

    private var updaterOverride: AppUpdater? = null
    private val defaultUpdater by lazy { AppUpdater(this) }
    val updater: AppUpdater get() = updaterOverride ?: defaultUpdater

    /** Normally null. Tests set it to answer "what's my IP?" themselves, so a proxy-list shield works offline. */
    var exitLookup: ((Route) -> ExitLookup)? = null

    /** Lets tests point the updater at a fake GitHub. */
    @VisibleForTesting
    fun useUpdater(updater: AppUpdater) {
        updaterOverride = updater
    }
}
