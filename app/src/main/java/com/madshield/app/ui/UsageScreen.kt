package com.madshield.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.DayUsage
import com.madshield.app.core.InsightHub
import com.madshield.app.core.UsageFile
import com.madshield.app.core.UsageLedger
import com.madshield.app.ui.components.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.LocalDate

/**
 * Daily data use. The page reads the small usage file once when it opens (after asking a running service to write
 * its latest numbers) and never polls. Only byte totals per day exist: no domains, no DNS, no per-app figures.
 */
@Composable
fun UsageScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var ledger by remember { mutableStateOf<UsageLedger?>(null) }
    var range by remember { mutableStateOf(7) }
    var confirmReset by remember { mutableStateOf(false) }
    var reload by remember { mutableIntStateOf(0) }

    LaunchedEffect(reload) {
        ledger = withContext(Dispatchers.IO) {
            InsightHub.flushUsage?.invoke()
            UsageFile.read(ctx.filesDir)
        }
    }

    Scaffold(topBar = { BackTopBar(stringResource(R.string.usage_title), onBack) }) { padding ->
        val l = ledger
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            if (l == null) return@Column
            val today = LocalDate.now()
            val days = (range - 1 downTo 0).map { today.minusDays(it.toLong()).toString() }
            val data = days.map { l.get(it) }
            val t = l.get(today.toString())

            SectionCard(stringResource(R.string.usage_today)) {
                Text(formatBytes(t.total), style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Legend(MaterialTheme.colorScheme.primary, "↓ " + formatBytes(t.down))
                    Legend(MaterialTheme.colorScheme.tertiary, "↑ " + formatBytes(t.up))
                }
                Spacer(Modifier.height(12.dp))
                SplitBar(t.wifi, t.mobile, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.secondary)
                Spacer(Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Legend(MaterialTheme.colorScheme.primary, stringResource(R.string.usage_wifi) + "  " + formatBytes(t.wifi))
                    Legend(MaterialTheme.colorScheme.secondary, stringResource(R.string.usage_mobile) + "  " + formatBytes(t.mobile))
                }
            }

            SectionCard(stringResource(R.string.usage_history)) {
                ChoiceChips(
                    listOf(stringResource(R.string.usage_7d) to 7, stringResource(R.string.usage_30d) to 30), range
                ) { range = it }
                Spacer(Modifier.height(12.dp))
                BarChart(data, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.tertiary)
                Spacer(Modifier.height(8.dp))
                val sum = data.fold(0L) { a, d -> a + d.total }
                Text(
                    stringResource(R.string.usage_total_range, formatBytes(sum)),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            SectionCard(stringResource(R.string.usage_routes)) {
                val vpn = t.vpn; val direct = t.direct
                if (vpn + direct + t.blocked == 0L) {
                    HelperText(stringResource(R.string.usage_routes_none))
                } else {
                    SplitBar(vpn, direct, routeColor(com.madshield.app.core.RouteAction.PROXY), routeColor(com.madshield.app.core.RouteAction.DIRECT))
                    Spacer(Modifier.height(8.dp))
                    Legend(routeColor(com.madshield.app.core.RouteAction.PROXY), stringResource(R.string.route_vpn) + "  " + formatBytes(vpn))
                    Spacer(Modifier.height(4.dp))
                    Legend(routeColor(com.madshield.app.core.RouteAction.DIRECT), stringResource(R.string.route_direct) + "  " + formatBytes(direct))
                    Spacer(Modifier.height(4.dp))
                    Legend(routeColor(com.madshield.app.core.RouteAction.BLOCK), stringResource(R.string.usage_blocked_requests, t.blocked))
                }
            }

            HelperText(stringResource(R.string.usage_privacy))
            OutlinedButton(onClick = { confirmReset = true }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.usage_reset))
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text(stringResource(R.string.usage_reset)) },
            text = { Text(stringResource(R.string.usage_reset_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmReset = false
                    UsageFile.delete(ctx.filesDir)
                    ledger = UsageLedger()
                }) { Text(stringResource(R.string.usage_reset_do)) }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text(stringResource(R.string.action_cancel)) } }
        )
    }
}

@Composable
private fun Legend(color: Color, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
    }
}

/** A single horizontal bar split in two parts (e.g. Wi-Fi / mobile). Empty when both are zero. */
@Composable
private fun SplitBar(a: Long, b: Long, ca: Color, cb: Color) {
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    Canvas(Modifier.fillMaxWidth().height(10.dp)) {
        val r = CornerRadius(size.height / 2)
        drawRoundRect(track, size = size, cornerRadius = r)
        val total = (a + b).toFloat()
        if (total > 0f) {
            val wa = size.width * (a / total)
            if (a > 0) drawRoundRect(ca, size = Size(wa.coerceAtLeast(size.height), size.height), cornerRadius = r)
            if (b > 0) {
                val wb = (size.width - wa).coerceAtLeast(size.height)
                drawRoundRect(cb, topLeft = Offset(size.width - wb, 0f), size = Size(wb, size.height), cornerRadius = r)
            }
        }
    }
}

/** Per-day stacked bars: download below, upload on top. Drawn once; no animation. */
@Composable
private fun BarChart(days: List<DayUsage>, down: Color, up: Color) {
    val max = (days.maxOfOrNull { it.total } ?: 0L).coerceAtLeast(1L).toFloat()
    val baseline = MaterialTheme.colorScheme.outlineVariant
    Canvas(Modifier.fillMaxWidth().height(120.dp)) {
        val n = days.size
        val gap = if (n > 14) 2.dp.toPx() else 6.dp.toPx()
        val w = (size.width - gap * (n - 1)) / n
        drawLine(baseline, Offset(0f, size.height), Offset(size.width, size.height), strokeWidth = 1.dp.toPx())
        days.forEachIndexed { i, d ->
            val x = i * (w + gap)
            val hd = size.height * (d.down / max)
            val hu = size.height * (d.up / max)
            if (hd > 0f) drawRect(down, Offset(x, size.height - hd), Size(w, hd))
            if (hu > 0f) drawRect(up, Offset(x, size.height - hd - hu), Size(w, hu))
        }
    }
}
