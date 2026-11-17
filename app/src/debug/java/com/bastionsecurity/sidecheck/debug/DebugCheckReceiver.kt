package com.bastionsecurity.sidecheck.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.bastionsecurity.sidecheck.work.ChangedPackagesWorker

/**
 * DEBUG BUILDS ONLY. Runs the background check right now instead of waiting for the hourly job:
 *   adb shell am broadcast -a com.bastionsecurity.sidecheck.debug.CHECK_NOW -p com.bastionsecurity.sidecheck
 */
class DebugCheckReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        WorkManager.getInstance(context).enqueue(OneTimeWorkRequestBuilder<ChangedPackagesWorker>().build())
    }
}
