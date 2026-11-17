package com.bastionsecurity.sidecheck

import android.app.Application
import com.bastionsecurity.sidecheck.collect.PackageCollector
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.data.TrustStore
import com.bastionsecurity.sidecheck.data.WatchState
import com.bastionsecurity.sidecheck.engine.Analyzer
import com.bastionsecurity.sidecheck.engine.providers.BundledRuleSetProvider
import com.bastionsecurity.sidecheck.engine.providers.FreeTier
import com.bastionsecurity.sidecheck.engine.providers.NoOpReputationProvider
import com.bastionsecurity.sidecheck.engine.providers.PremiumFeatures
import com.bastionsecurity.sidecheck.grants.GrantInspector
import com.bastionsecurity.sidecheck.grants.ShizukuBridge
import com.bastionsecurity.sidecheck.work.BackgroundChecker
import com.bastionsecurity.sidecheck.work.ChangedPackagesWorker
import com.bastionsecurity.sidecheck.work.Notifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

class SideCheckApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        container.shizuku.start()
        container.notifier.ensureChannel()
        ChangedPackagesWorker.schedule(this)
    }
}

/** Manual dependency wiring. Small enough that a DI framework isn't worth it. */
class AppContainer(val app: Application) {
    /** Lives as long as the process, so a scan keeps going when you move between screens. */
    val appScope = CoroutineScope(SupervisorJob())

    val premium: PremiumFeatures = FreeTier

    val analyzer: Analyzer by lazy {
        // v1: bundled rules, no reputation lookups (no INTERNET permission).
        Analyzer(BundledRuleSetProvider().loadBlocking(), NoOpReputationProvider)
    }

    val collector: PackageCollector by lazy {
        PackageCollector(app.packageManager, app.packageName, analyzer.apkInspector)
    }

    val trust = TrustStore(app)
    val watch = WatchState(app)
    val repository = ScanRepository(app, { collector }, { analyzer }, trust, watch, appScope)
    val notifier = Notifier(app)
    val backgroundChecker = BackgroundChecker(app, { collector }, repository, trust, watch, notifier)
    val shizuku = ShizukuBridge(app)
    val grants = GrantInspector(app, shizuku)
}
