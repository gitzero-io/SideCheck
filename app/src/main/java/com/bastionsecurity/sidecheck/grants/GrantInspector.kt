package com.bastionsecurity.sidecheck.grants

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.net.Uri
import android.os.Build
import android.provider.Settings

/** One thing an app is (or isn't) allowed to do, and how the user can change it. */
data class Grant(
    val key: String,
    val title: String,
    val kind: Kind,
    /** null = we couldn't read it (Android doesn't let normal apps check this one). */
    val allowed: Boolean?,
    /** For runtime permissions: the manifest name. For app-ops: the op name. */
    val technicalName: String,
    /** Can Shizuku flip it directly? */
    val shizukuToggle: ShizukuToggle?,
    /** Settings screen to change it by hand, already checked to exist on this device. */
    val settingsIntent: Intent?,
    val note: String? = null,
) {
    enum class Kind { RUNTIME, SPECIAL }
}

sealed interface ShizukuToggle {
    data class Runtime(val permission: String) : ShizukuToggle
    data class AppOp(val op: String) : ShizukuToggle
}

/**
 * Reads what each app is currently allowed to do: runtime permissions (from the package's grant
 * flags) and special access (overlay, install apps, usage access, accessibility, notifications,
 * device admin). Blocking — call on a background thread.
 */
class GrantInspector(private val context: Context, private val shizuku: ShizukuBridge) {

    private val pm = context.packageManager

    suspend fun grantsFor(pkg: String): List<Grant> {
        val pi = try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(
                    (PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS).toLong(),
                ))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            return emptyList()
        }
        return runtimeGrants(pi) + specialGrants(pi)
    }

    private fun runtimeGrants(pi: PackageInfo): List<Grant> {
        val perms = pi.requestedPermissions ?: return emptyList()
        val flags = pi.requestedPermissionsFlags ?: IntArray(perms.size)
        val legacy = (pi.applicationInfo?.targetSdkVersion ?: 0) < 23
        val appDetails = SystemScreens.appDetails(context, pi.packageName)
        return perms.indices.mapNotNull { i ->
            val name = perms[i]
            val info = runCatching { pm.getPermissionInfo(name, 0) }.getOrNull() ?: return@mapNotNull null
            if (!isDangerous(info)) return@mapNotNull null
            val granted = flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
            Grant(
                key = "rt:$name",
                title = info.loadLabel(pm).toString().replaceFirstChar { it.uppercase() },
                kind = Grant.Kind.RUNTIME,
                allowed = granted,
                technicalName = name,
                // Old-style apps (built for Android 5 or older) can't have permissions revoked with pm.
                shizukuToggle = if (legacy) null else ShizukuToggle.Runtime(name),
                settingsIntent = appDetails,
                note = if (legacy) "This app is built for old Android, so Android gave it this at install time." else null,
            )
        }
    }

    private suspend fun specialGrants(pi: PackageInfo): List<Grant> {
        val pkg = pi.packageName
        val requested = pi.requestedPermissions.orEmpty().toSet()
        val uid = pi.applicationInfo?.uid ?: return emptyList()
        val out = mutableListOf<Grant>()

        suspend fun appOp(permission: String, op: String, opStr: String, title: String, intent: Intent?) {
            if (permission !in requested) return
            out += Grant(
                key = "op:$op",
                title = title,
                kind = Grant.Kind.SPECIAL,
                allowed = readOp(opStr, op, uid, pkg),
                technicalName = op,
                shizukuToggle = ShizukuToggle.AppOp(op),
                settingsIntent = intent ?: SystemScreens.appDetails(context, pkg),
            )
        }

        appOp(
            "android.permission.SYSTEM_ALERT_WINDOW", "SYSTEM_ALERT_WINDOW", AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
            "Show on top of other apps", SystemScreens.forPackage(context, Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkg),
        )
        appOp(
            "android.permission.REQUEST_INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "android:request_install_packages",
            "Install apps (often used for its own updates)", SystemScreens.forPackage(context, Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkg),
        )
        appOp(
            "android.permission.PACKAGE_USAGE_STATS", "GET_USAGE_STATS", AppOpsManager.OPSTR_GET_USAGE_STATS,
            "See which apps you use", SystemScreens.plain(context, Settings.ACTION_USAGE_ACCESS_SETTINGS),
        )
        appOp(
            "android.permission.WRITE_SETTINGS", "WRITE_SETTINGS", AppOpsManager.OPSTR_WRITE_SETTINGS,
            "Change system settings", SystemScreens.forPackage(context, Settings.ACTION_MANAGE_WRITE_SETTINGS, pkg),
        )

        val services = pi.services.orEmpty()
        val a11y = services.filter { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" }
        if (a11y.isNotEmpty()) {
            val enabled = secureList(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            out += Grant(
                key = "special:a11y",
                title = "Read and control the screen (accessibility)",
                kind = Grant.Kind.SPECIAL,
                allowed = enabled?.let { list -> list.any { it.substringBefore('/') == pkg } },
                technicalName = "BIND_ACCESSIBILITY_SERVICE",
                shizukuToggle = null,
                settingsIntent = SystemScreens.plain(context, Settings.ACTION_ACCESSIBILITY_SETTINGS),
            )
        }
        val listeners = services.filter { it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" }
        if (listeners.isNotEmpty()) {
            val enabled = secureList("enabled_notification_listeners")
            out += Grant(
                key = "special:notif",
                title = "Read your notifications",
                kind = Grant.Kind.SPECIAL,
                allowed = enabled?.let { list -> list.any { it.substringBefore('/') == pkg } },
                technicalName = "BIND_NOTIFICATION_LISTENER_SERVICE",
                shizukuToggle = null,
                settingsIntent = SystemScreens.plain(context, Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS),
            )
        }
        val admins = pi.receivers.orEmpty().filter { it.permission == "android.permission.BIND_DEVICE_ADMIN" }
        if (admins.isNotEmpty()) {
            val dpm = context.getSystemService(DevicePolicyManager::class.java)
            val active = runCatching { dpm.activeAdmins.orEmpty().any { it.packageName == pkg } }.getOrNull()
            out += Grant(
                key = "special:admin",
                title = "Device admin",
                kind = Grant.Kind.SPECIAL,
                allowed = active,
                technicalName = "BIND_DEVICE_ADMIN",
                shizukuToggle = null,
                settingsIntent = SystemScreens.plain(context, "android.settings.DEVICE_ADMIN_SETTINGS")
                    ?: SystemScreens.plain(context, Settings.ACTION_SECURITY_SETTINGS),
                note = if (active == true) "You may need to turn this off before Android lets you remove the app." else null,
            )
        }
        return out
    }

    /**
     * App-op state for another app. Android usually blocks normal apps from reading this, so we
     * try the public API, then Shizuku, and otherwise report "unknown".
     */
    private suspend fun readOp(opStr: String, op: String, uid: Int, pkg: String): Boolean? {
        val aom = context.getSystemService(AppOpsManager::class.java)
        val mode = try {
            if (Build.VERSION.SDK_INT >= 29) aom.unsafeCheckOpNoThrow(opStr, uid, pkg)
            else @Suppress("DEPRECATION") aom.checkOpNoThrow(opStr, uid, pkg)
        } catch (_: SecurityException) {
            null
        }
        when (mode) {
            AppOpsManager.MODE_ALLOWED -> return true
            AppOpsManager.MODE_IGNORED, AppOpsManager.MODE_ERRORED -> return false
        }
        if (shizuku.status.value == ShizukuBridge.Status.READY) {
            when (shizuku.getAppOp(pkg, op)) {
                "allow" -> return true
                "ignore", "deny", "default" -> return false
            }
        }
        // MODE_DEFAULT from the public API: for these special-access ops it means "not turned on".
        return if (mode == AppOpsManager.MODE_DEFAULT) false else null
    }

    private fun secureList(key: String): List<String>? = try {
        Settings.Secure.getString(context.contentResolver, key)?.split(':')?.filter { it.isNotBlank() } ?: emptyList()
    } catch (_: SecurityException) {
        null
    }

    private fun isDangerous(info: PermissionInfo): Boolean =
        if (Build.VERSION.SDK_INT >= 28) {
            info.protection == PermissionInfo.PROTECTION_DANGEROUS
        } else {
            @Suppress("DEPRECATION")
            info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE == PermissionInfo.PROTECTION_DANGEROUS
        }
}

/** Settings screens, only returned if this device actually has them (many TV builds don't). */
object SystemScreens {
    fun appDetails(context: Context, pkg: String): Intent? =
        forPackage(context, Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg)

    fun forPackage(context: Context, action: String, pkg: String): Intent? =
        Intent(action, Uri.fromParts("package", pkg, null)).takeIf { exists(context, it) }

    fun plain(context: Context, action: String): Intent? = Intent(action).takeIf { exists(context, it) }

    private fun exists(context: Context, intent: Intent): Boolean {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= 33) {
            pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(0)) != null
        } else {
            @Suppress("DEPRECATION") pm.resolveActivity(intent, 0) != null
        }
    }
}
