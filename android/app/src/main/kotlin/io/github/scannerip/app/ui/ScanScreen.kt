package io.github.scannerip.app.ui

import android.util.Size
import android.view.ViewGroup
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.github.scannerip.app.CodeAnalyzer
import io.github.scannerip.app.ScanResult
import io.github.scannerip.core.Decoded
import io.github.scannerip.core.Proceed
import java.util.concurrent.Executors

@Composable
fun ScanScreen(
    hasCameraPermission: Boolean,
    codesInView: Boolean,
    torchOn: Boolean,
    lastScan: ScanResult?,
    canInspect: Boolean,
    inspecting: Boolean,
    onAskPermission: () -> Unit,
    onPickImage: () -> Unit,
    onToggleTorch: () -> Unit,
    onInspect: (String) -> Unit,
    onCopy: (String) -> Unit,
    camera: @Composable (Modifier) -> Unit,
    onProceed: (Proceed) -> Unit = {},
    onOpenInBrowser: (String) -> Unit = {},
) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        val frame = if (codesInView) Color(0xFF00E676) else MaterialTheme.colorScheme.outline
        Box(
            Modifier
                .fillMaxWidth()
                .height(300.dp)
                .clip(RoundedCornerShape(20.dp))
                .background(Color(0xFF111614))
                .border(if (codesInView) 4.dp else 1.dp, frame, RoundedCornerShape(20.dp)),
            contentAlignment = Alignment.Center,
        ) {
            if (hasCameraPermission) {
                camera(Modifier.fillMaxSize())
                Text(
                    if (codesInView) "Code found" else "Point at any QR code or barcode",
                    color = Color.White,
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(10.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(Color(0x99000000))
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                )
            } else {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
                    Text("ScannerIP needs the camera to read codes. Nothing is recorded or sent anywhere.",
                        color = Color.White, textAlign = TextAlign.Center)
                    Button(onClick = onAskPermission, modifier = Modifier.padding(top = 12.dp)) { Text("Allow camera") }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onPickImage) { Text("Scan a picture") }
            OutlinedButton(onClick = onToggleTorch, enabled = hasCameraPermission) {
                Text(if (torchOn) "Torch off" else "Torch on")
            }
        }
        if (lastScan != null) {
            ResultCard(lastScan, canInspect, inspecting, onInspect, onCopy, onProceed, onOpenInBrowser)
        } else {
            SectionCard {
                Text("Nothing scanned yet", style = MaterialTheme.typography.titleMedium)
                Text("Point the camera at a code or pick a screenshot. ScannerIP reads it, checks it for " +
                    "scam tricks and shows you what's inside. Nothing is opened until you say so.",
                    modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}

/** Live CameraX preview with ZXing-C++ reading every frame. */
@Composable
fun CameraPreview(onCodes: (List<Decoded>) -> Unit, torchOn: Boolean, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val latestOnCodes by rememberUpdatedState(onCodes)
    val previewView = remember {
        PreviewView(context).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            scaleType = PreviewView.ScaleType.FILL_CENTER
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
        }
    }
    var camera by remember { mutableStateOf<Camera?>(null) }

    DisposableEffect(lifecycleOwner) {
        val executor = Executors.newSingleThreadExecutor()
        val providerFuture = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        providerFuture.addListener({
            val cameraProvider = providerFuture.get()
            provider = cameraProvider
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .setResolutionSelector(ResolutionSelector.Builder()
                    .setResolutionStrategy(ResolutionStrategy(Size(1280, 720),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER))
                    .build())
                .build()
            analysis.setAnalyzer(executor, CodeAnalyzer { codes -> latestOnCodes(codes) })
            try {
                cameraProvider.unbindAll()
                camera = cameraProvider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (_: Exception) {
                camera = null // no usable back camera; picking a picture still works
            }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            provider?.unbindAll()
            executor.shutdown()
            latestOnCodes(emptyList()) // so the "code found" frame doesn't stay lit
        }
    }
    LaunchedEffect(camera, torchOn) {
        camera?.let { if (it.cameraInfo.hasFlashUnit()) it.cameraControl.enableTorch(torchOn) }
    }
    AndroidView(factory = { previewView }, modifier = modifier)
}
