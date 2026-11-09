package com.madshield.app.ui

import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Bedtime
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.madshield.app.R
import com.madshield.app.core.ExitCheck
import com.madshield.app.core.ExitIpHub
import com.madshield.app.core.SleepTimer
import com.madshield.app.core.SleepTimerPlan
import com.madshield.app.ui.components.ChoiceChips
import com.madshield.app.ui.components.CookieBadge
import com.madshield.app.ui.components.HelperText
import com.madshield.app.ui.components.rememberIsForeground
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

/*
 * update41: the two additions on Home. (1) The exit address under the Connect button: the IP the world sees through the
 * tunnel and its country, small; a tap opens the details (IPv4, IPv6, country, data center) with "check again".
 * (2) The sleep timer: a button in the header that opens a sheet; while a timer runs it shows the time left.
 * Neither starts anything by itself beyond ONE short request per connection and ONE alarm.
 */

// ------------------------------------------------------------------------------------------------------- exit IP

/** The small line inside the hero card: flag, address, country. Tapping it opens [ExitIpSheet]. */
@Composable
internal fun ExitIpChip(onClick: () -> Unit) {
    val v4 by ExitIpHub.v4.collectAsState()
    val ink = MaterialTheme.colorScheme.onPrimaryContainer
    Surface(onClick = onClick, shape = CircleShape, color = ink.copy(alpha = 0.12f), modifier = Modifier.widthIn(max = 320.dp)) {
        Row(
            Modifier.padding(start = 14.dp, end = 8.dp, top = 7.dp, bottom = 7.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            when (val r = v4) {
                is ExitCheck.Ok -> {
                    val code = r.info.country
                    if (code != null) {
                        Text(flagOf(code), style = MaterialTheme.typography.bodyMedium)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(
                        ltr(r.info.ip), style = MaterialTheme.typography.labelLarge, color = ink,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false)
                    )
                    if (code != null) {
                        Text(" · ", style = MaterialTheme.typography.labelMedium, color = ink.copy(alpha = 0.7f))
                        Text(
                            countryName(code), style = MaterialTheme.typography.labelMedium, color = ink.copy(alpha = 0.85f),
                            maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                is ExitCheck.Unreachable -> Text(stringResource(R.string.exit_chip_unreachable), style = MaterialTheme.typography.labelLarge, color = ink)
                else -> {
                    CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = ink)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.exit_chip_checking), style = MaterialTheme.typography.labelLarge, color = ink)
                }
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, null, tint = ink.copy(alpha = 0.7f), modifier = Modifier.size(18.dp))
        }
    }
}

/** The details: address, IPv6 through the tunnel, country, data center. IPv6 is asked when the sheet opens. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ExitIpSheet(socksPort: Int, vpnMode: Boolean, onDismiss: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val v4 by ExitIpHub.v4.collectAsState()
    val v6 by ExitIpHub.v6.collectAsState()
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val ctx = LocalContext.current
    val copied = stringResource(R.string.copied)

    LaunchedEffect(Unit) { if (ExitIpHub.v6.value is ExitCheck.Idle) ExitIpHub.check(socksPort, ipv6 = true) }

    val info = (v4 as? ExitCheck.Ok)?.info
    val code = info?.country
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CookieBadge(60.dp) {
                    if (code != null) Text(flagOf(code), style = MaterialTheme.typography.headlineSmall)
                    else Icon(Icons.Rounded.Public, null, tint = cs.onPrimaryContainer)
                }
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.exit_sheet_title), style = MaterialTheme.typography.labelLarge, color = cs.primary)
                    SelectionContainer {
                        Text(
                            ltr(info?.ip ?: "—"), style = MaterialTheme.typography.titleLarge,
                            maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        code?.let { countryName(it) } ?: stringResource(R.string.exit_unknown),
                        style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant
                    )
                }
            }

            Surface(shape = RoundedCornerShape(28.dp), color = cs.surfaceContainer, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(horizontal = 18.dp, vertical = 6.dp)) {
                    DetailRow(stringResource(R.string.exit_row_address)) {
                        when (val r = v4) {
                            is ExitCheck.Ok -> ValueText(ltr(r.info.ip))
                            is ExitCheck.Unreachable -> ValueText(stringResource(R.string.exit_unreachable))
                            else -> Checking()
                        }
                    }
                    HorizontalDivider(color = cs.outlineVariant.copy(alpha = 0.5f))
                    DetailRow(stringResource(R.string.exit_row_ipv6)) {
                        when (val r = v6) {
                            is ExitCheck.Ok -> ValueText(ltr(r.info.ip))
                            is ExitCheck.Unreachable -> ValueText(stringResource(R.string.exit_v6_none))
                            else -> Checking()
                        }
                    }
                    HorizontalDivider(color = cs.outlineVariant.copy(alpha = 0.5f))
                    DetailRow(stringResource(R.string.exit_row_country)) {
                        ValueText(code?.let { "${flagOf(it)}  ${countryName(it)}" } ?: stringResource(R.string.exit_unknown))
                    }
                    info?.colo?.let { colo ->
                        HorizontalDivider(color = cs.outlineVariant.copy(alpha = 0.5f))
                        DetailRow(stringResource(R.string.exit_row_dc)) { ValueText(ltr(colo)) }
                    }
                }
            }

            if (v6 is ExitCheck.Unreachable) {
                HelperText(stringResource(if (vpnMode) R.string.exit_v6_none_note_vpn else R.string.exit_v6_none_note))
            }
            HelperText(stringResource(R.string.exit_foot))

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                FilledTonalButton(
                    onClick = {
                        info?.let {
                            clipboard.setText(AnnotatedString(it.ip))
                            Toast.makeText(ctx, copied, Toast.LENGTH_SHORT).show()
                        }
                    },
                    enabled = info != null, shape = RoundedCornerShape(24.dp), modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.exit_copy_ip)) }
                Button(
                    onClick = {
                        scope.launch { ExitIpHub.check(socksPort, ipv6 = false) }
                        scope.launch { ExitIpHub.check(socksPort, ipv6 = true) }
                    },
                    enabled = v4 !is ExitCheck.Loading && v6 !is ExitCheck.Loading,
                    shape = RoundedCornerShape(24.dp), modifier = Modifier.weight(1f)
                ) { Text(stringResource(R.string.exit_recheck)) }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(0.42f))
        Box(Modifier.weight(0.58f), contentAlignment = Alignment.CenterEnd) { value() }
    }
}

@Composable
private fun ValueText(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface, textAlign = TextAlign.End)
}

@Composable
private fun Checking() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.exit_checking), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ----------------------------------------------------------------------------------------------------- sleep timer

/** The current time, refreshed about every 20 s while the screen is visible and [active]; no timer runs otherwise. */
@Composable
internal fun rememberMinuteNow(active: Boolean): State<Long> {
    val now = remember { mutableStateOf(System.currentTimeMillis()) }
    val foreground by rememberIsForeground()
    LaunchedEffect(active, foreground) {
        now.value = System.currentTimeMillis()
        if (!active || !foreground) return@LaunchedEffect
        while (true) {
            delay(20_000)
            now.value = System.currentTimeMillis()
        }
    }
    return now
}

/** Header button: a moon, or the moon with the time left (h:mm) while a timer runs. */
@Composable
internal fun SleepButton(onClick: () -> Unit) {
    val end by SleepTimer.endAt.collectAsState()
    val now by rememberMinuteNow(end != null)
    val e = end
    if (e == null) {
        FilledTonalIconButton(onClick = onClick) {
            Icon(Icons.Rounded.Bedtime, contentDescription = stringResource(R.string.sleep_title))
        }
    } else {
        val left = ltr(SleepTimerPlan.format(SleepTimerPlan.remainingMs(e, now)))
        Surface(onClick = onClick, shape = CircleShape, color = MaterialTheme.colorScheme.tertiaryContainer) {
            Row(Modifier.padding(horizontal = 14.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Bedtime, null, tint = MaterialTheme.colorScheme.onTertiaryContainer, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(left, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onTertiaryContainer)
            }
        }
    }
}

/** Choose the time and start; or, while it runs, see the time left, add 15 minutes or cancel. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SleepTimerSheet(proxyOnly: Boolean, onDismiss: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val ctx = LocalContext.current
    val end by SleepTimer.endAt.collectAsState()
    val now by rememberMinuteNow(true)
    var minutes by remember { mutableIntStateOf(SleepTimerPlan.DEFAULT_MINUTES) }
    val timeFormat = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }

    val e = end
    val big = if (e != null) SleepTimerPlan.format(SleepTimerPlan.remainingMs(e, now)) else SleepTimerPlan.format(minutes * 60_000L)
    val stopsAt = timeFormat.format(Date(e ?: SleepTimerPlan.endAt(now, minutes)))

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column {
                Text(stringResource(R.string.sleep_title), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.sleep_sub), style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
            }

            Surface(shape = RoundedCornerShape(28.dp), color = cs.primaryContainer, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.fillMaxWidth().padding(vertical = 18.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(ltr(big), style = MaterialTheme.typography.displaySmall, color = cs.onPrimaryContainer)
                    Text(
                        stringResource(R.string.sleep_stops_at, ltr(stopsAt)), style = MaterialTheme.typography.bodyMedium,
                        color = cs.onPrimaryContainer.copy(alpha = 0.78f)
                    )
                }
            }

            if (e == null) {
                ChoiceChips(
                    options = SleepTimerPlan.PRESET_MINUTES.map { m ->
                        (if (m < 60) stringResource(R.string.sleep_min, m) else stringResource(R.string.sleep_hour, m / 60)) to m
                    },
                    selected = minutes,
                    onSelect = { minutes = it }
                )
                Button(
                    onClick = { SleepTimer.start(ctx, minutes, proxyOnly); onDismiss() },
                    shape = RoundedCornerShape(24.dp), modifier = Modifier.fillMaxWidth().height(52.dp)
                ) { Text(stringResource(R.string.sleep_start)) }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                    FilledTonalButton(
                        onClick = { SleepTimer.extend(ctx, proxyOnly) },
                        shape = RoundedCornerShape(24.dp), modifier = Modifier.weight(1f)
                    ) { Text(stringResource(R.string.sleep_extend)) }
                    OutlinedButton(
                        onClick = { SleepTimer.cancel(ctx); onDismiss() },
                        shape = RoundedCornerShape(24.dp), modifier = Modifier.weight(1f)
                    ) { Text(stringResource(R.string.sleep_cancel)) }
                }
            }
            HelperText(stringResource(R.string.sleep_note))
        }
    }
}
