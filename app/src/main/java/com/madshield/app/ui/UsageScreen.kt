package com.madshield.app.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.gestures.detectTapGestures
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
import androidx.compose.ui.input.pointer.pointerInput
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
    var picked by remember { mutableStateOf<String?>(null) } // the day whose bar was tapped
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
                ) { range = it; picked = null }
                Spacer(Modifier.height(12.dp))
                val sel = data.indexOfFirst { it.day == picked }.takeIf { it >= 0 }
                val vpnColor = routeColor(com.madshield.app.core.RouteAction.PROXY)
                val directColor = routeColor(com.madshield.app.core.RouteAction.DIRECT)
                BarChart(data, sel, vpnColor, directColor, MaterialTheme.colorScheme.outlineVariant) { i ->
                    picked = if (data[i].day == picked) null else data[i].day
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                    Legend(vpnColor, stringResource(R.string.route_vpn))
                    Legend(directColor, stringResource(R.string.route_direct))
                }
                Spacer(Modifier.height(8.dp))
                val d = sel?.let { data[it] }
                if (d == null) {
                    Text(
                        stringResource(R.string.usage_tap_hint),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    Text(d.day + "   " + formatBytes(d.total), style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                        Legend(MaterialTheme.colorScheme.primary, "↓ " + formatBytes(d.down))
                        Legend(MaterialTheme.colorScheme.tertiary, "↑ " + formatBytes(d.up))
                    }
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                        Legend(MaterialTheme.colorScheme.primary, stringResource(R.string.usage_wifi) + "  " + formatBytes(d.wifi))
                        Legend(MaterialTheme.colorScheme.secondary, stringResource(R.string.usage_mobile) + "  " + formatBytes(d.mobile))
                    }
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
                        Legend(vpnColor, stringResource(R.string.route_vpn) + "  " + formatBytes(d.vpn))
                        Legend(directColor, stringResource(R.string.route_direct) + "  " + formatBytes(d.direct))
                    }
                    Spacer(Modifier.height(4.dp))
                    Legend(routeColor(com.madshield.app.core.RouteAction.BLOCK), stringResource(R.string.usage_blocked_requests, d.blocked))
                }
                Spacer(Modifier.height(8.dp))
                val sum = data.fold(0L) { a, d -> a + d.total }
                Text(
                    stringResource(R.string.usage_total_range, formatBytes(sum)),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    stringResource(R.string.usage_blocked_range, data.fold(0L) { a, d -> a + d.blocked }),
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
                // The monthly figure: the last 30 days, whatever range the chart above shows.
                val month = (29 downTo 0).fold(0L) { a, i -> a + l.get(today.minusDays(i.toLong()).toString()).blocked }
                Spacer(Modifier.height(8.dp))
                Legend(routeColor(com.madshield.app.core.RouteAction.BLOCK), stringResource(R.string.usage_blocked_month, month))
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

/**
 * Per-day stacked bars: what went through the VPN below, what went direct on top, and (only when the day has more
 * traffic than the routing front counted, e.g. an older day) the remainder in a neutral colour. A tap on a bar (or
 * the space above it) selects that day.
 */
@Composable
private fun BarChart(days: List<DayUsage>, selected: Int?, vpn: Color, direct: Color, rest: Color, onTap: (Int) -> Unit) {
    val max = (days.maxOfOrNull { maxOf(it.total, it.vpn + it.direct) } ?: 0L).coerceAtLeast(1L).toFloat()
    val baseline = MaterialTheme.colorScheme.outlineVariant
    val n = days.size
    val tap by rememberUpdatedState(onTap) // the gesture block below is not restarted, so it must not keep an old lambda
    Canvas(
        Modifier.fillMaxWidth().height(120.dp).pointerInput(n) {
            detectTapGestures { pos ->
                if (n > 0) tap((pos.x / size.width * n).toInt().coerceIn(0, n - 1))
            }
        }
    ) {
        val gap = if (n > 14) 2.dp.toPx() else 6.dp.toPx()
        val w = (size.width - gap * (n - 1)) / n
        drawLine(baseline, Offset(0f, size.height), Offset(size.width, size.height), strokeWidth = 1.dp.toPx())
        days.forEachIndexed { i, d ->
            val x = i * (w + gap)
            val dim = if (selected == null || selected == i) 1f else 0.35f
            val hv = size.height * (d.vpn / max)
            val hd = size.height * (d.direct / max)
            val hr = size.height * (maxOf(d.total - d.vpn - d.direct, 0L) / max)
            var y = size.height
            if (hv > 0f) { y -= hv; drawRect(vpn.copy(alpha = dim), Offset(x, y), Size(w, hv)) }
            if (hd > 0f) { y -= hd; drawRect(direct.copy(alpha = dim), Offset(x, y), Size(w, hd)) }
            if (hr > 0f) { y -= hr; drawRect(rest.copy(alpha = dim), Offset(x, y), Size(w, hr)) }
            // A day with no data still gets a thin tick, so it can be tapped and read as "0".
            if (hv <= 0f && hd <= 0f && hr <= 0f) drawRect(baseline, Offset(x, size.height - 2.dp.toPx()), Size(w, 2.dp.toPx()))
        }
    }
}
