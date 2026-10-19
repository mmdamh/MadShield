package com.aethershield.app.core

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.aethershield.app.MainActivity
import com.aethershield.app.R

/**
 * The ongoing status notification, in the style of sing-box: a quiet line of text (the speed, when the
 * user wants it) and a Disconnect button. Shared by the VPN and the proxy-only service.
 */
object StatusNotification {
    fun build(
        ctx: Context,
        channelId: String,
        text: String,
        subText: String?,
        stopIntent: Intent
    ): Notification {
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            ctx, 1, stopIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(ctx, channelId)
            .setContentTitle(ctx.getString(R.string.app_name))
            .setContentText(text)
            .apply { if (subText != null) setSubText(subText) }
            .setSmallIcon(R.drawable.ic_stat_madshield)
            .setContentIntent(open)
            .addAction(0, ctx.getString(R.string.notif_disconnect), stop)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }
}
