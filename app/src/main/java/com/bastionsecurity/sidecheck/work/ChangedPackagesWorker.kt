package com.bastionsecurity.sidecheck.work

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.bastionsecurity.sidecheck.SideCheckApp
import java.util.concurrent.TimeUnit

/** Hourly: check apps that were installed or updated since last time. Only changed apps are read. */
class ChangedPackagesWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result = try {
        val c = (applicationContext as SideCheckApp).container
        val outcome = c.backgroundChecker.check(notify = true)
        Log.i(TAG, "Background check done: ${outcome.checked.size} checked, ${outcome.notified} notified")
        Result.success()
    } catch (e: Exception) {
        Log.e(TAG, "Background check failed", e)
        Result.retry()
    }

    companion object {
        private const val TAG = "SideCheck"
        const val UNIQUE_NAME = "changed-packages"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ChangedPackagesWorker>(1, TimeUnit.HOURS, 15, TimeUnit.MINUTES).build()
            // KEEP: don't reset the timer every time the app starts.
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(UNIQUE_NAME, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}
