package com.bastionsecurity.sidecheck

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.tv.material3.LocalContentColor
import com.bastionsecurity.sidecheck.data.DeviceMode
import com.bastionsecurity.sidecheck.data.DeviceModeStore
import com.bastionsecurity.sidecheck.ui.apk.ApkCheckScreen
import com.bastionsecurity.sidecheck.ui.apk.ApkCheckState
import com.bastionsecurity.sidecheck.ui.apk.ApkCheckViewModel
import com.bastionsecurity.sidecheck.ui.theme.SC
import com.bastionsecurity.sidecheck.ui.theme.SideCheckTheme

/**
 * "Check before install".
 *  - A file manager or Downloader sends ACTION_VIEW for an APK ("Open with SideCheck").
 *  - Opening it with no file shows how to use "Open with" (Home's "Check an app" lists installed
 *    apps instead; most TV boxes have no document picker).
 */
class ApkCheckActivity : ComponentActivity() {

    private val vm: ApkCheckViewModel by viewModels {
        viewModelFactory { initializer { ApkCheckViewModel((application as SideCheckApp).container) } }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DeviceModeStore.applyOrientation(this)
        vm.start(intent.viewUri())

        setContent {
            val mode = DeviceModeStore.current(this)
            SideCheckTheme(mode) {
                CompositionLocalProvider(LocalContentColor provides SC.Text) {
                    Box(Modifier.fillMaxSize().background(SC.Bg).then(if (mode == DeviceMode.MOBILE) Modifier.safeDrawingPadding() else Modifier)) {
                        val state by vm.state.collectAsStateWithLifecycle()
                        val launch by vm.launch.collectAsStateWithLifecycle()
                        LaunchedEffect(launch) {
                            launch?.let {
                                vm.launched()
                                try {
                                    startActivity(it)
                                } catch (e: ActivityNotFoundException) {
                                    Log.w("SideCheck", "No activity for $it", e)
                                    // Settings page missing on this TV: fall back to main Settings.
                                    runCatching { startActivity(Intent(android.provider.Settings.ACTION_SETTINGS)) }
                                }
                            }
                        }
                        LifecycleResumeEffect(Unit) {
                            vm.onResume()
                            onPauseOrDispose { }
                        }
                        ApkCheckScreen(
                            state = state,
                            onInstall = vm::installAnyway,
                            onDontInstall = { vm.discard(); finish() },
                            onAllowInstalls = vm::openInstallPermissionSettings,
                            onOpenApp = { pkg ->
                                startActivity(
                                    Intent(this@ApkCheckActivity, MainActivity::class.java)
                                        .putExtra(MainActivity.EXTRA_PACKAGE, pkg)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                                )
                                finish()
                            },
                            onDone = { if (state !is ApkCheckState.Ready) vm.discard(); finish() },
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.viewUri()?.let(vm::onNewFile)
    }

    private fun Intent.viewUri(): Uri? = if (action == Intent.ACTION_VIEW) data else null

}
