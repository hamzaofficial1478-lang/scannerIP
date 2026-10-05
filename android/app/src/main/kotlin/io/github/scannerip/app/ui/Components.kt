package io.github.scannerip.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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

/** The risk report for one scan. Nothing in here ever opens the link. */
@Composable
fun ResultCard(
    result: ScanResult,
    canInspect: Boolean,
    inspecting: Boolean,
    onInspect: (String) -> Unit,
    onCopy: (String) -> Unit,
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
        Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            result.inspectableUrl?.let { url ->
                Button(onClick = { onInspect(url) }, enabled = canInspect && !inspecting) {
                    if (inspecting) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text("Check where it goes")
                }
            }
            OutlinedButton(onClick = { onCopy(report.payload.raw) }) { Text("Copy") }
        }
        if (result.inspectableUrl != null && !canInspect) {
            Text("Checking where a link goes needs Tor, Orbot or a proxy switched on in the Shield tab.",
                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp))
        }
        Text("Links are never opened automatically.", style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
    }
}
