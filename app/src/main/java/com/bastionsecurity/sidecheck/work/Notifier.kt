package com.bastionsecurity.sidecheck.work

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.bastionsecurity.sidecheck.MainActivity
import com.bastionsecurity.sidecheck.R
import com.bastionsecurity.sidecheck.engine.model.AppReport

/**
 * "New app installed: X — Grade D. Tap to review."
 *
 * Note for Google TV: there's no heads-up popup like on phones. Notifications land in
 * Settings → Notifications, so the Home screen also lists recent changes.
 */
class Notifier(private val context: Context) {

    enum class Reason { NEW_INSTALL, NEW_SIGNER, WORSE_GRADE, UPDATED_NEEDS_ATTENTION }

    fun ensureChannel() {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "New and updated apps", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "When an app is installed or changes in a way worth a look"
            },
        )
    }

    fun canPost(): Boolean =
        (Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) &&
            NotificationManagerCompat.from(context).areNotificationsEnabled()

    /** Returns true if posted. */
    fun post(report: AppReport, reason: Reason): Boolean {
        if (!canPost()) return false
        ensureChannel()
        val f = report.facts
        val title = when (reason) {
            Reason.NEW_INSTALL -> "New app installed: ${f.label}"
            Reason.NEW_SIGNER -> "${f.label} was replaced by a version from someone else"
            Reason.WORSE_GRADE -> "${f.label} was updated and now does more"
            Reason.UPDATED_NEEDS_ATTENTION -> "${f.label} was updated"
        }
        val text = "Grade ${report.grade.label}. ${if (report.needsAttention) "Tap to review." else "Tap to see what it can do."}"

        val open = Intent(context, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_PACKAGE, f.packageName)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        val pi = PendingIntent.getActivity(
            context,
            f.packageName.hashCode(),
            open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val n = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$text\n${report.verdict}"))
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .build()
        return try {
            NotificationManagerCompat.from(context).notify(f.packageName.hashCode(), n)
            true
        } catch (_: SecurityException) {
            false
        }
    }

    companion object { const val CHANNEL = "new_apps" }
}
