package io.github.scannerip.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/*
 * Append-only scan history, tagged with the rotating ID rather than the device.
 *
 * If this file ever leaks, the scans in it can't be traced back to the phone
 * or even linked to each other across IP shifts.
 */

@Serializable
data class ScanEntry(
    val time: String,
    val rotatingId: String?,
    val format: String,
    val kind: String,
    val level: String,
    val score: Int,
    val content: String,
    val findings: List<String>,
)

class ScanLog(val file: File) {
    private val json = Json { ignoreUnknownKeys = true }

    @Synchronized
    fun record(format: String, report: Report, snapshot: IdentitySnapshot?): ScanEntry {
        val entry = ScanEntry(
            time = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.UK).format(Date()),
            rotatingId = snapshot?.rotatingId,
            format = format,
            kind = report.payload.kind.name.lowercase(),
            level = report.level.name,
            score = report.score,
            content = report.payload.raw.take(500),
            findings = report.findings.map { "${it.severity.name.lowercase()}: ${it.message}" },
        )
        file.parentFile?.mkdirs()
        file.appendText(json.encodeToString(entry) + "\n")
        return entry
    }

    /** Every entry, oldest first. Lines that don't parse are skipped. */
    @Synchronized
    fun readAll(): List<ScanEntry> {
        if (!file.exists()) return emptyList()
        return file.readLines().mapNotNull { line ->
            if (line.isBlank()) null else runCatching { json.decodeFromString<ScanEntry>(line) }.getOrNull()
        }
    }

    @Synchronized
    fun clear() {
        file.delete()
    }
}
