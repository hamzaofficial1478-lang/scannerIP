package io.github.scannerip.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import io.github.scannerip.app.ui.ScannerIpApp
import io.github.scannerip.app.ui.ScannerIpTheme

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ScannerIpTheme {
                ScannerIpApp(vm)
            }
        }
    }
}
