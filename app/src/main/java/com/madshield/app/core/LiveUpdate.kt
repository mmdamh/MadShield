package com.madshield.app.core

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings

/**
 * Android 16+ "Live updates": an ongoing notification that Android may show on the lock screen and as a chip in the
 * status bar. The app only asks (two extras on the notification); Android decides, and the person can switch it
 * off per app. The framework names are read by reflection so the app still builds with the current compile SDK
 * and simply does nothing on older phones. No timers: the chip text changes only when the speed line does.
 */
object LiveUpdate {
    const val MIN_SDK = 36
    private const val DEFAULT_REQUEST_KEY = "android.requestPromotedOngoing"
    private const val DEFAULT_CHIP_KEY = "android.shortCriticalText"

    fun supported(): Boolean = Build.VERSION.SDK_INT >= MIN_SDK

    private fun key(field: String, fallback: String): String =
        try { Notification::class.java.getField(field).get(null) as? String ?: fallback } catch (_: Throwable) { fallback }

    /** The extras that ask for the promotion; [chip] is the short text beside the status-bar icon. Null below Android 16. */
    fun extras(chip: String?): Bundle? {
        if (!supported()) return null
        return Bundle().apply {
            putBoolean(key("EXTRA_REQUEST_PROMOTED_ONGOING", DEFAULT_REQUEST_KEY), true)
            if (!chip.isNullOrEmpty()) putString(key("EXTRA_SHORT_CRITICAL_TEXT", DEFAULT_CHIP_KEY), chip)
        }
    }

    /** False when the person switched "Live updates" off for this app in Android's settings. */
    fun allowed(ctx: Context): Boolean {
        if (!supported()) return false
        return try {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            NotificationManager::class.java.getMethod("canPostPromotedNotifications").invoke(nm) as? Boolean ?: true
        } catch (_: Throwable) { true }
    }

    /** Android's page where Live updates can be switched on for this app. */
    fun settingsIntent(ctx: Context): Intent {
        val found: String? = try {
            Settings::class.java.getField("ACTION_MANAGE_APP_PROMOTED_NOTIFICATIONS").get(null) as? String
        } catch (_: Throwable) { null }
        val action = found ?: "android.settings.MANAGE_APP_PROMOTED_NOTIFICATIONS"
        return Intent(action).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}
