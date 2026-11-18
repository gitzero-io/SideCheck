package com.bastionsecurity.sidecheck.data

import android.app.Activity
import android.app.UiModeManager
import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import androidx.core.content.edit
import com.bastionsecurity.sidecheck.engine.model.Platform

/** What the user said they're running SideCheck on. Asked once, on first launch. */
enum class DeviceMode { TV, MOBILE }

object DeviceModeStore {
    private const val PREFS = "ui"
    private const val KEY = "device_mode"

    /** The saved answer, or null if the user hasn't been asked yet. */
    fun get(context: Context): DeviceMode? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null)
            ?.let { runCatching { DeviceMode.valueOf(it) }.getOrNull() }

    fun set(context: Context, mode: DeviceMode) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { putString(KEY, mode.name) }

    /** Best guess from the hardware, used to pre-select an answer and before the user has chosen. */
    fun detect(context: Context): DeviceMode {
        val uiMode = context.getSystemService(UiModeManager::class.java)?.currentModeType
        val tv = uiMode == Configuration.UI_MODE_TYPE_TELEVISION ||
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
        return if (tv) DeviceMode.TV else DeviceMode.MOBILE
    }

    fun current(context: Context): DeviceMode = get(context) ?: detect(context)

    /** Which version of the grading rules to use for this device. */
    fun platform(context: Context): Platform =
        if (current(context) == DeviceMode.TV) Platform.TV else Platform.PHONE

    /** "TV" or "device", for messages built outside Compose. */
    fun noun(context: Context): String = if (current(context) == DeviceMode.TV) "TV" else "device"

    /** TV stays landscape; phones and tablets follow the user's rotation setting. */
    fun applyOrientation(activity: Activity, mode: DeviceMode = current(activity)) {
        activity.requestedOrientation = when (mode) {
            DeviceMode.TV -> ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE
            DeviceMode.MOBILE -> ActivityInfo.SCREEN_ORIENTATION_FULL_USER
        }
    }
}
