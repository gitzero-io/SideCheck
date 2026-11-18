package com.bastionsecurity.sidecheck

import android.app.Application
import com.bastionsecurity.sidecheck.collect.FirmwareCheck
import com.bastionsecurity.sidecheck.collect.PackageCollector
import com.bastionsecurity.sidecheck.data.DeviceModeStore
import com.bastionsecurity.sidecheck.data.ScanRepository
import com.bastionsecurity.sidecheck.data.TrustStore
import com.bastionsecurity.sidecheck.data.WatchState
import com.bastionsecurity.sidecheck.engine.Analyzer
import com.bastionsecurity.sidecheck.engine.providers.BundledRuleSetProvider
import com.bastionsecurity.sidecheck.engine.providers.FreeTier
import com.bastionsecurity.sidecheck.engine.malware.LocalMalwareReputationProvider
import com.bastionsecurity.sidecheck.engine.model.Platform
import com.bastionsecurity.sidecheck.engine.providers.RuleBundle
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

    val bundle: RuleBundle by lazy { BundledRuleSetProvider().loadBlocking() }

    /** Offline known-malware list (bundled). A cloud lookup can be layered on later (premium). */
    val malware: LocalMalwareReputationProvider by lazy { LocalMalwareReputationProvider(bundle.malware) }

    val analyzer: Analyzer by lazy { Analyzer(bundle, malware) }

    val firmwareCheck: FirmwareCheck by lazy { FirmwareCheck(app, malware.matcher) { collector } }

    val collector: PackageCollector by lazy {
        PackageCollector(app.packageManager, app.packageName, analyzer.apkInspector)
    }

    val trust = TrustStore(app)
    val watch = WatchState(app)
    /** TV or phone/tablet rules, from the user's first-launch answer. Read per analysis so a switch applies at once. */
    fun platform(): Platform = DeviceModeStore.platform(app)

    val repository = ScanRepository(app, { collector }, { analyzer }, ::platform, { firmwareCheck }, trust, watch, appScope)
    val notifier = Notifier(app)
    val backgroundChecker = BackgroundChecker(app, { collector }, repository, trust, watch, notifier)
    val shizuku = ShizukuBridge(app)
    val grants = GrantInspector(app, shizuku)
}
