package io.github.scannerip.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.scannerip.app.ScanResult
import io.github.scannerip.core.Finding
import io.github.scannerip.core.Level
import io.github.scannerip.core.Proceed
import io.github.scannerip.core.makeVisible

@Composable
fun RiskBadge(level: Level, score: Int, modifier: Modifier = Modifier, small: Boolean = false) {
    val (bg, fg) = levelColours(level)
    Text(
        text = if (small) "${level.name} $score" else "${level.name}  $score/100",
        color = fg,
        fontWeight = FontWeight.Bold,
        fontSize = if (small) 11.sp else 14.sp,
        modifier = modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .padding(horizontal = if (small) 6.dp else 10.dp, vertical = if (small) 2.dp else 4.dp),
    )
}

@Composable
fun SectionCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(Modifier.padding(14.dp)) { content() }
    }
}

@Composable
fun StatusDot(colour: Color, modifier: Modifier = Modifier) {
    Spacer(modifier.size(10.dp).clip(CircleShape).background(colour))
}

@Composable
fun FindingLine(finding: Finding) {
    val dark = isSystemInDarkTheme()
    Row(Modifier.padding(vertical = 3.dp)) {
        Text(
            finding.severity.name,
            color = severityColour(finding.severity, dark),
            fontWeight = FontWeight.Bold,
            fontSize = 11.sp,
            modifier = Modifier.width(70.dp).padding(top = 2.dp),
        )
        Text(finding.message, style = MaterialTheme.typography.bodyMedium)
    }
}

/** The risk report for one scan, with the buttons to go ahead. Nothing happens on its own. */
@Composable
fun ResultCard(
    result: ScanResult,
    canInspect: Boolean,
    inspecting: Boolean,
    onInspect: (String) -> Unit,
    onCopy: (String) -> Unit,
    onProceed: (Proceed) -> Unit = {},
    onOpenInBrowser: (String) -> Unit = {},
) {
    val report = result.report
    SectionCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RiskBadge(report.level, report.score)
            Spacer(Modifier.width(10.dp))
            Column {
                Text(report.payload.label, fontWeight = FontWeight.SemiBold)
                Text(result.format, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        result.image?.let { bitmap ->
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "The picture you scanned, with the code outlined",
                contentScale = ContentScale.Fit,
                modifier = Modifier.padding(top = 10.dp).fillMaxWidth().heightIn(max = 220.dp).clip(RoundedCornerShape(10.dp)),
            )
        }
        val shown = if (report.payload.isBinary) report.payload.summary() else makeVisible(report.payload.raw)
        SelectionContainer {
            Text(
                shown,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
                modifier = Modifier
                    .padding(top = 10.dp)
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(10.dp),
            )
        }
        Spacer(Modifier.padding(top = 6.dp))
        if (report.findings.isEmpty()) {
            Text("No warning signs found.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        report.findings.forEach { FindingLine(it) }
        Text(report.advice, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
        result.loggedAs?.let {
            Text("Logged as $it", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
        }
        ProceedButtons(result, canInspect, onProceed, onOpenInBrowser)
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            result.inspectableUrl?.let { url ->
                OutlinedButton(onClick = { onInspect(url) }, enabled = canInspect && !inspecting) {
                    if (inspecting) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Check where it goes")
                }
            }
            OutlinedButton(onClick = { onCopy(report.payload.raw) }) { Text("Copy") }
        }
        Text("Nothing happens until you tap a button.", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
    }
}

private sealed interface Confirm {
    data class GoAhead(val action: Proceed) : Confirm
    data class Outside(val url: String) : Confirm
}

/**
 * The "go ahead" button for this kind of code, plus the plain-English line
 * about where it goes. Risky codes and anything that leaves the shield ask
 * first.
 */
@Composable
private fun ProceedButtons(
    result: ScanResult,
    canBrowse: Boolean,
    onProceed: (Proceed) -> Unit,
    onOpenInBrowser: (String) -> Unit,
) {
    val report = result.report
    val proceed = result.proceed
    val risky = report.level == Level.HIGH || report.level == Level.DANGEROUS
    var confirm by remember(result.id) { mutableStateOf<Confirm?>(null) }

    if (proceed !is Proceed.CopyOnly) {
        Button(
            onClick = { if (risky) confirm = Confirm.GoAhead(proceed) else onProceed(proceed) },
            enabled = canBrowse || !proceed.shielded,
            modifier = Modifier.padding(top = 10.dp).fillMaxWidth(),
        ) { Text(proceed.button) }
    }
    val note = when {
        proceed is Proceed.CopyOnly -> proceed.reason
        proceed.shielded && canBrowse ->
            "Opens inside ScannerIP through the shield, on a fresh IP and ID. Downloads and jumps into other apps are blocked."
        proceed.shielded -> "Open safely needs the shield switched on (the chip at the top turns green)."
        else -> "Hands over to your phone's own app, which doesn't go through the shield. ScannerIP still moves to a fresh IP and ID."
    }
    Text(note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp))
    if (proceed is Proceed.Browse) {
        TextButton(onClick = { confirm = Confirm.Outside(proceed.url) }, contentPadding = PaddingValues(0.dp)) {
            Text("Open in my browser instead")
        }
    }

    confirm?.let { c ->
        val warning = "ScannerIP rated this ${report.level.name} (${report.score}/100). ${report.advice}"
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text(if (c is Confirm.Outside) "Open without the shield?" else "This code looks dangerous") },
            text = {
                Text(when (c) {
                    is Confirm.Outside -> "Your normal browser will open it with your real IP address, so the site can " +
                        "see roughly where you are. That's fine for sites you trust, like a sign-in or verification " +
                        "page from Google or your bank." + if (risky) "\n\n$warning" else ""
                    is Confirm.GoAhead -> "$warning\n\n" + if (c.action.shielded) "If you go ahead, it opens in the " +
                        "shielded browser, which blocks downloads and jumps into other apps."
                    else "If you go ahead, it's handed to your phone's own app."
                })
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    when (c) {
                        is Confirm.Outside -> onOpenInBrowser(c.url)
                        is Confirm.GoAhead -> onProceed(c.action)
                    }
                }) { Text(if (c is Confirm.Outside) "Open in browser" else "Go ahead anyway") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
        )
    }
}
