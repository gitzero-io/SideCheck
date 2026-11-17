package com.bastionsecurity.sidecheck.install

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

/**
 * Hands a checked APK to Android's own installer. SideCheck never installs silently: the system
 * installer always shows its own confirmation screen.
 */
class InstallHandoff(private val context: Context) {

    /** Has the user allowed SideCheck to "install unknown apps"? Required before handing off. */
    fun canInstall(): Boolean = context.packageManager.canRequestPackageInstalls()

    /** The Settings page where the user can allow that. Google TV may show a list of all apps. */
    fun allowInstallsIntent(): Intent =
        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.fromParts("package", context.packageName, null))

    /**
     * Builds an explicit intent to the system package installer. Explicit, because SideCheck
     * itself also handles APK files and must not end up in a loop with itself.
     */
    fun installIntent(apk: File): Intent? {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.files", apk)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, MIME_APK)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val pm = context.packageManager
        val candidates = if (Build.VERSION.SDK_INT >= 33) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }.map { it.activityInfo }.filter { it.packageName != context.packageName }
        val installer = candidates.firstOrNull { it.packageName.contains("packageinstaller") } ?: candidates.firstOrNull()
            ?: return null
        return intent.setComponent(ComponentName(installer.packageName, installer.name))
    }

    companion object {
        const val MIME_APK = "application/vnd.android.package-archive"
    }
}
