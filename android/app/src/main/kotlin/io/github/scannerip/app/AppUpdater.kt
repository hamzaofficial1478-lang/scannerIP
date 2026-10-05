package io.github.scannerip.app

import android.Manifest
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.IntentCompat
import androidx.core.content.edit
import androidx.core.content.pm.PackageInfoCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.scannerip.core.Net
import io.github.scannerip.core.Route
import io.github.scannerip.core.UpdateError
import io.github.scannerip.core.UpdateInfo
import io.github.scannerip.core.Updates
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data object UpToDate : UpdateState
    data class Available(val info: UpdateInfo) : UpdateState
    data class Downloading(val info: UpdateInfo, val progress: Float) : UpdateState
    data class Installing(val info: UpdateInfo) : UpdateState
    data class Failed(val message: String, val info: UpdateInfo?) : UpdateState
}

/**
 * Keeps ScannerIP up to date from this project's GitHub releases.
 *
 * Checks happen through the shield like everything else. The download is
 * only handed to Android if its SHA-256 matches the published fingerprint,
 * it's this app's package, it's newer than what's installed and it's signed
 * with the same key. Android then asks you to confirm the update (from
 * Android 12 it can skip that once ScannerIP has installed itself before).
 */
class AppUpdater(
    private val app: Application,
    val baseUrl: String = BuildConfig.UPDATE_URL,
    val installedVersionCode: Int = BuildConfig.VERSION_CODE,
    val installedVersionName: String = BuildConfig.VERSION_NAME,
) {
    private val prefs = app.getSharedPreferences("updates", Context.MODE_PRIVATE)
    private val _state = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = _state

    init {
        // An update the background check already found shows up straight away.
        pendingUpdate()?.let { _state.value = UpdateState.Available(it) }
    }

    val backgroundChecks: Boolean get() = prefs.getBoolean(KEY_BACKGROUND, true)

    fun setBackgroundChecks(on: Boolean) {
        prefs.edit { putBoolean(KEY_BACKGROUND, on) }
        schedule()
    }

    /** Daily-ish background check while the app is closed (direct to GitHub, Tor isn't running then). */
    fun schedule() {
        val work = WorkManager.getInstance(app)
        if (!backgroundChecks) {
            work.cancelUniqueWork(WORK_NAME)
            return
        }
        val request = PeriodicWorkRequestBuilder<UpdateWorker>(12, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        work.enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
    }

    /** Ask GitHub what the newest build is. [route] null means straight out, not through the shield. */
    suspend fun check(route: Route?): UpdateInfo? = withContext(Dispatchers.IO) {
        _state.value = UpdateState.Checking
        try {
            val info = Updates.fetchInfo(Net.client(route, followRedirects = true), baseUrl + "version.json")
            remember(info)
            _state.value = if (Updates.isNewer(info, installedVersionCode)) UpdateState.Available(info) else UpdateState.UpToDate
            info
        } catch (e: Exception) {
            _state.value = UpdateState.Failed("Couldn't check for updates: ${e.message}", null)
            null
        }
    }

    /** Download the update through [route], verify it and hand it to Android's installer. */
    suspend fun downloadAndInstall(route: Route?) = withContext(Dispatchers.IO) {
        val info = when (val s = _state.value) {
            is UpdateState.Available -> s.info
            is UpdateState.Failed -> s.info
            else -> null
        } ?: return@withContext
        _state.value = UpdateState.Downloading(info, 0f)
        try {
            val dir = File(app.cacheDir, "updates").apply { deleteRecursively(); mkdirs() }
            val file = Updates.download(
                Net.client(route, timeoutSeconds = 60, followRedirects = true, callTimeoutSeconds = 0),
                baseUrl + "ScannerIP.apk", File(dir, "ScannerIP-${info.versionCode}.apk"), info.sha256,
            ) { done, total ->
                if (total > 0) _state.value = UpdateState.Downloading(info, done.toFloat() / total)
            }
            verifyApk(file, info)
            _state.value = UpdateState.Installing(info)
            install(file)
        } catch (e: Exception) {
            _state.value = UpdateState.Failed(e.message ?: e.javaClass.simpleName, info)
        }
    }

    /** Refuse anything that isn't a newer build of this very app, signed with the same key. */
    internal fun verifyApk(file: File, info: UpdateInfo) {
        val pm = app.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
        else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val archive = pm.getPackageArchiveInfo(file.path, flags)
            ?: throw UpdateError("The download isn't a valid Android app.")
        if (archive.packageName != app.packageName) {
            throw UpdateError("The download is a different app (${archive.packageName}), so it was rejected.")
        }
        val version = PackageInfoCompat.getLongVersionCode(archive)
        if (version != info.versionCode.toLong() || version <= installedVersionCode) {
            throw UpdateError("The download's version ($version) isn't the newer one GitHub promised.")
        }
        // Android refuses a differently-signed update anyway; checking first gives a clear message.
        val theirs = signers(archive)
        val ours = signers(pm.getPackageInfo(app.packageName, flags))
        if (theirs.isNotEmpty() && ours.isNotEmpty() && theirs != ours) {
            throw UpdateError("The download is signed by someone else, so it was rejected.")
        }
    }

    private fun signers(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners
        else @Suppress("DEPRECATION") info.signatures
        return signatures.orEmpty().map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }

    private fun install(file: File) {
        val installer = app.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(app.packageName)
            // Android 12+: once ScannerIP installed itself, later updates can skip the prompt.
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        installer.openSession(sessionId).use { session ->
            file.inputStream().use { input ->
                session.openWrite("ScannerIP.apk", 0, file.length()).use { output ->
                    input.copyTo(output)
                    session.fsync(output)
                }
            }
            val callback = Intent(app, InstallResultReceiver::class.java).setPackage(app.packageName)
            // Mutable so the installer can attach its result; the intent itself is explicit.
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
            session.commit(PendingIntent.getBroadcast(app, sessionId, callback, flags).intentSender)
        }
    }

    internal fun onInstallFailed(message: String) {
        val info = (_state.value as? UpdateState.Installing)?.info
        _state.value = UpdateState.Failed("Android didn't install the update: $message", info)
    }

    /** Save what GitHub said, so a later launch can show the update without asking again. */
    internal fun remember(info: UpdateInfo) {
        prefs.edit { putString(KEY_PENDING, Updates.encode(info)) }
    }

    internal fun pendingUpdate(): UpdateInfo? = prefs.getString(KEY_PENDING, null)
        ?.let { runCatching { Updates.parse(it) }.getOrNull() }
        ?.takeIf { Updates.isNewer(it, installedVersionCode) }

    /** Only one notification per new build. */
    internal fun shouldNotify(info: UpdateInfo): Boolean {
        if (!Updates.isNewer(info, installedVersionCode) || prefs.getInt(KEY_NOTIFIED, 0) >= info.versionCode) return false
        prefs.edit { putInt(KEY_NOTIFIED, info.versionCode) }
        return true
    }

    fun notify(info: UpdateInfo) {
        val open = Intent(app, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        post("ScannerIP ${info.versionName} is ready", info.notes.ifBlank { "Tap to open ScannerIP and update." }, open)
    }

    /** The update is verified but ScannerIP was in the background, so Android's prompt waits behind a tap. */
    internal fun notifyConfirm(confirm: Intent) {
        val info = (_state.value as? UpdateState.Installing)?.info
        post("Tap to finish updating ScannerIP", "Version ${info?.versionName ?: "update"} is downloaded and checked.", confirm)
    }

    private fun post(title: String, text: String, target: Intent) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ActivityCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        val manager = app.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "App updates", NotificationManager.IMPORTANCE_DEFAULT))
        val tap = PendingIntent.getActivity(app, 0, target, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = NotificationCompat.Builder(app, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_update)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        NotificationManagerCompat.from(app).notify(NOTIFICATION_ID, notification)
    }

    companion object {
        const val WORK_NAME = "update-check"
        const val CHANNEL = "updates"
        const val NOTIFICATION_ID = 1
        private const val KEY_BACKGROUND = "background_checks"
        private const val KEY_PENDING = "pending_update"
        private const val KEY_NOTIFIED = "notified_version"
    }
}

/** The background check: runs about twice a day while the app is closed. */
class UpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val updater = (applicationContext as ScannerIpApplication).updater
        if (!updater.backgroundChecks) return Result.success()
        val info = try {
            withContext(Dispatchers.IO) {
                Updates.fetchInfo(Net.client(null, followRedirects = true), updater.baseUrl + "version.json")
            }
        } catch (_: Exception) {
            return Result.retry()
        }
        updater.remember(info)
        if (updater.shouldNotify(info)) updater.notify(info)
        return Result.success()
    }
}

/** Android's installer reports back here: ask the user to confirm, or say what went wrong. */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val updater = (context.applicationContext as ScannerIpApplication).updater
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // The system's own "Do you want to update this app?" screen. Android won't let an
                // app in the background open it, so then it waits behind a notification instead.
                val confirm = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)
                    ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) ?: return
                val onScreen = ProcessLifecycleOwner.get().lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
                if (onScreen) context.startActivity(confirm) else updater.notifyConfirm(confirm)
            }
            PackageInstaller.STATUS_SUCCESS -> {} // the new version is already running
            else -> updater.onInstallFailed(intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "error $status")
        }
    }
}
