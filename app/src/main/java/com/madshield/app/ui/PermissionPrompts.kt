package com.madshield.app.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.core.app.NotificationManagerCompat
import com.madshield.app.R

/** The two things the app asks the phone for: showing its notification, and not being put to sleep. */
enum class PermKind { NOTIFICATIONS, BATTERY }

/** Plain checks and intents, no state. Nothing here runs by itself or on a timer. */
object Perms {
    /** False when the permission was refused (Android 13+) or the app's notifications are switched off in Settings. */
    fun notificationsAllowed(ctx: Context): Boolean = try {
        NotificationManagerCompat.from(ctx).areNotificationsEnabled()
    } catch (_: Exception) { true }

    fun batteryExempt(ctx: Context): Boolean = try {
        (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager).isIgnoringBatteryOptimizations(ctx.packageName)
    } catch (_: Exception) { true }

    fun notificationSettingsIntent(ctx: Context): Intent =
        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)

    /** The one-tap system dialog "let this app run in the background". */
    fun batteryRequestIntent(ctx: Context): Intent =
        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${ctx.packageName}"))

    /** Fallback: the system's list of apps, where the person can pick this one. */
    fun batteryListIntent(): Intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
}

/** Our own short explanation before the system asks, so the system dialog is not a surprise. */
@Composable
fun PermissionDialog(kind: PermKind, onAllow: () -> Unit, onLater: () -> Unit) {
    AlertDialog(
        onDismissRequest = onLater,
        title = {
            Text(stringResource(if (kind == PermKind.NOTIFICATIONS) R.string.perm_notif_title else R.string.perm_battery_title))
        },
        text = {
            Text(stringResource(if (kind == PermKind.NOTIFICATIONS) R.string.perm_notif_body else R.string.perm_battery_body))
        },
        confirmButton = { TextButton(onClick = onAllow) { Text(stringResource(R.string.perm_allow)) } },
        dismissButton = { TextButton(onClick = onLater) { Text(stringResource(R.string.perm_later)) } }
    )
}
