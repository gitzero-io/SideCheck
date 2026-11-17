package com.bastionsecurity.sidecheck

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.tv.material3.LocalContentColor
import androidx.tv.material3.Text
import com.bastionsecurity.sidecheck.ui.detail.DetailScreen
import com.bastionsecurity.sidecheck.ui.detail.DetailViewModel
import com.bastionsecurity.sidecheck.ui.home.HomeScreen
import com.bastionsecurity.sidecheck.ui.home.HomeViewModel
import com.bastionsecurity.sidecheck.ui.pick.PickAppScreen
import com.bastionsecurity.sidecheck.ui.pick.PickAppViewModel
import com.bastionsecurity.sidecheck.ui.results.ResultsFilter
import com.bastionsecurity.sidecheck.ui.results.ResultsScreen
import com.bastionsecurity.sidecheck.ui.results.ResultsViewModel
import com.bastionsecurity.sidecheck.ui.theme.SC
import com.bastionsecurity.sidecheck.ui.theme.SideCheckTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val c = (application as SideCheckApp).container
        // On launch: catch up on apps installed/updated since last time. No notifications here;
        // they show on the Home screen instead.
        lifecycleScope.launch { runCatching { c.backgroundChecker.check(notify = false) } }
        askForNotificationsOnce()
        setContent {
            SideCheckTheme {
                // Default text color for anything not inside a card.
                CompositionLocalProvider(LocalContentColor provides SC.Text) {
                    AppNav(c, startPackage = intent.getStringExtra(EXTRA_PACKAGE))
                }
            }
        }
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* either answer is fine */ }

    /** Android 13+ needs permission to post notifications. Ask once; never nag. */
    private fun askForNotificationsOnce() {
        if (Build.VERSION.SDK_INT < 33) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        val prefs = getSharedPreferences("ui", MODE_PRIVATE)
        if (prefs.getBoolean("asked_notifications", false)) return
        prefs.edit { putBoolean("asked_notifications", true) }
        notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    companion object {
        /** Open straight to one app's report (used by notifications in Phase 4). */
        const val EXTRA_PACKAGE = "com.bastionsecurity.sidecheck.PACKAGE"
    }
}

@Composable
private fun AppNav(c: AppContainer, startPackage: String?) {
    val nav = rememberNavController()
    NavHost(nav, startDestination = "home", modifier = Modifier.fillMaxSize().background(SC.Bg)) {
        composable("home") {
            val vm = viewModel { HomeViewModel(c.app, c.repository, c.watch, c.trust) }
            HomeScreen(
                vm,
                onOpenApp = { nav.navigate("app/$it") },
                onOpenResults = { nav.navigate("results/${ResultsFilter.ATTENTION.name}") { launchSingleTop = true } },
                onOpenTrusted = { nav.navigate("results/${ResultsFilter.TRUSTED.name}") },
                onCheckApp = { nav.navigate("pick") },
            )
        }
        composable("results/{filter}", arguments = listOf(navArgument("filter") { type = NavType.StringType })) { back ->
            val filter = runCatching { ResultsFilter.valueOf(back.arguments?.getString("filter")!!) }.getOrDefault(ResultsFilter.ALL)
            val vm = viewModel { ResultsViewModel(c.repository) }
            ResultsScreen(vm, filter, onOpenApp = { nav.navigate("app/$it") }, onBackHome = { nav.popBackStack("home", false) })
        }
        composable("pick") {
            val vm = viewModel { PickAppViewModel(c.app, { c.collector }, c.repository) }
            PickAppScreen(vm, onPick = { nav.navigate("app/$it") })
        }
        composable("app/{pkg}", arguments = listOf(navArgument("pkg") { type = NavType.StringType })) { back ->
            val pkg = back.arguments?.getString("pkg").orEmpty()
            val vm = viewModel(key = pkg) { DetailViewModel(c.app, pkg, c.repository, c.trust, c.watch, c.grants, c.shizuku) }
            DetailScreen(vm, onGone = { nav.popBackStack() })
        }
    }
    LaunchedEffect(startPackage) { if (startPackage != null) nav.navigate("app/$startPackage") }
}
