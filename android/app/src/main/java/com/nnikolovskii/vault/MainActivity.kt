package com.nnikolovskii.vault

import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.nnikolovskii.vault.ui.IncognitoKeyboard
import com.nnikolovskii.vault.ui.VaultRoot
import com.nnikolovskii.vault.ui.VaultTheme
import com.nnikolovskii.vault.ui.VaultViewModel
import com.nnikolovskii.vault.ui.VaultVmFactory

class MainActivity : ComponentActivity() {
    private val model: VaultViewModel by viewModels { VaultVmFactory(application as VaultApp) }

    override fun onCreate(savedInstanceState: Bundle?) {
        // No screenshots, screen recording, or recents thumbnail. Ever.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) setRecentsScreenshotEnabled(false)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        // System autofill never sees vault fields (no "save password?" for the passphrase).
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        setContent {
            VaultTheme {
                IncognitoKeyboard {
                    VaultRoot(model)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        // Before the first frame: a vault left in the background too long locks here.
        (application as VaultApp).autoLock.onAppStart()
        // Then, if locked, the biometric prompt may show by itself.
        model.onForeground()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        (application as VaultApp).autoLock.onUserInteraction()
    }
}
