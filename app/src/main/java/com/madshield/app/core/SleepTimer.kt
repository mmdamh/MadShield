package com.madshield.app.core

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import com.madshield.app.vpn.AetherVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Sleep timer (update41): after the chosen time the connection is stopped, exactly as if the user had pressed
 * Disconnect (the VPN and its engine end, the Kill Switch lets go).
 *
 * Battery: ONE alarm held by Android, nothing else. No timer, wake lock or polling of ours; the screen reads the end
 * time only while it is visible. The alarm is an inexact "allow while idle" one, so it needs no special permission
 * and may fire a little late in deep sleep, never early. When it fires it starts the service's own disconnect action
 * through a PendingIntent, the same path as the notification's Disconnect button.
 *
 * The end time is also written to a tiny preferences file so the screen can show the countdown again after the app's
 * process was killed. It is trusted only while the alarm still exists (a reboot drops alarms, and the VPN with them).
 */
object SleepTimer {
    private const val PREFS = "sleep_timer"
    private const val KEY_END = "end_at"
    private const val REQUEST = 4101

    private val _endAt = MutableStateFlow<Long?>(null)
    /** Wall-clock end of the running timer, or null. */
    val endAt = _endAt.asStateFlow()

    /** Reads the saved timer once (call when the Home screen appears). Drops it if its alarm is gone or the time passed. */
    fun restore(context: Context) {
        val ctx = context.applicationContext
        val saved = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(KEY_END, 0L)
        val now = System.currentTimeMillis()
        _endAt.value = if (saved != 0L && SleepTimerPlan.stillAhead(saved, now) && alarmExists(ctx)) saved else null
        if (_endAt.value == null && saved != 0L) save(ctx, null)
    }

    fun start(context: Context, minutes: Int, proxyOnly: Boolean) {
        val ctx = context.applicationContext
        schedule(ctx, SleepTimerPlan.endAt(System.currentTimeMillis(), minutes), proxyOnly)
    }

    /** Adds [SleepTimerPlan.EXTEND_MINUTES] to a running timer. */
    fun extend(context: Context, proxyOnly: Boolean) {
        val ctx = context.applicationContext
        val now = System.currentTimeMillis()
        val current = _endAt.value ?: return
        schedule(ctx, SleepTimerPlan.extend(current, now), proxyOnly)
    }

    /** Stops the timer. Safe to call when none runs; the services call it when they end, so it never outlives a connection. */
    fun cancel(context: Context) {
        val ctx = context.applicationContext
        val am = ctx.getSystemService(AlarmManager::class.java)
        for (proxy in listOf(false, true)) {
            pending(ctx, proxy, PendingIntent.FLAG_NO_CREATE)?.let { runCatching { am?.cancel(it) }; it.cancel() }
        }
        if (_endAt.value != null) _endAt.value = null
        save(ctx, null)
    }

    private fun schedule(ctx: Context, endAtMs: Long, proxyOnly: Boolean) {
        val am = ctx.getSystemService(AlarmManager::class.java) ?: return
        val pi = pending(ctx, proxyOnly, PendingIntent.FLAG_UPDATE_CURRENT) ?: return
        val inMs = (endAtMs - System.currentTimeMillis()).coerceAtLeast(1_000L)
        am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + inMs, pi)
        save(ctx, endAtMs)
        _endAt.value = endAtMs
    }

    private fun alarmExists(ctx: Context): Boolean =
        listOf(false, true).any { pending(ctx, it, PendingIntent.FLAG_NO_CREATE) != null }

    private fun pending(ctx: Context, proxyOnly: Boolean, flag: Int): PendingIntent? {
        val intent = if (proxyOnly) Intent(ctx, ProxyOnlyService::class.java).setAction(ProxyOnlyService.ACTION_STOP)
        else Intent(ctx, AetherVpnService::class.java).setAction(AetherVpnService.ACTION_DISCONNECT)
        return PendingIntent.getService(ctx, REQUEST, intent, flag or PendingIntent.FLAG_IMMUTABLE)
    }

    private fun save(ctx: Context, endAtMs: Long?) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().apply {
            if (endAtMs == null) remove(KEY_END) else putLong(KEY_END, endAtMs)
        }.apply()
    }
}
