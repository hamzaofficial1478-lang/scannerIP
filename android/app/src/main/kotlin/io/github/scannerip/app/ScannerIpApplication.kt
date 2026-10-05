package io.github.scannerip.app

import android.app.Application

/** Holds the one built-in Tor instance for the whole app. */
class ScannerIpApplication : Application() {
    val tor: EmbeddedTor by lazy { EmbeddedTor(this) }
}
