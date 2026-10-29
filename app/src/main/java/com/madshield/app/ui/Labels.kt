package com.madshield.app.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.madshield.app.R
import com.madshield.app.core.Protocol

/** Wraps text that must stay left-to-right (addresses, numbers) so it is not reordered inside RTL text. */
fun ltr(text: String): String = "⁦$text⁩"

@Composable
fun protocolShort(p: Protocol): String = stringResource(
    when (p) {
        Protocol.SMART -> R.string.proto_smart_short
        Protocol.MASQUE_H3 -> R.string.proto_h3_short
        Protocol.MASQUE_H2 -> R.string.proto_h2_short
        Protocol.WIREGUARD -> R.string.proto_wg_short
        Protocol.GOOL -> R.string.proto_gool_short
        Protocol.GOOL_CLASSIC -> R.string.proto_gool_classic_short
    }
)

@Composable
fun protocolLong(p: Protocol): String = stringResource(
    when (p) {
        Protocol.SMART -> R.string.proto_smart_long
        Protocol.MASQUE_H3 -> R.string.proto_h3_long
        Protocol.MASQUE_H2 -> R.string.proto_h2_long
        Protocol.WIREGUARD -> R.string.proto_wg_long
        Protocol.GOOL -> R.string.proto_gool_long
        Protocol.GOOL_CLASSIC -> R.string.proto_gool_classic_long
    }
)

@Composable
fun scanLabel(mode: String): String = stringResource(
    when (mode) {
        "turbo" -> R.string.scan_turbo
        "balanced" -> R.string.scan_balanced
        "thorough" -> R.string.scan_thorough
        "verified" -> R.string.scan_verified
        else -> R.string.scan_ironclad
    }
)

@Composable
fun noizeLabel(profile: String): String = stringResource(
    when (profile) {
        "off" -> R.string.noize_off
        "light" -> R.string.noize_light
        "firewall" -> R.string.noize_firewall
        "balanced" -> R.string.noize_balanced
        "gfw" -> R.string.noize_gfw
        else -> R.string.noize_aggressive
    }
)

@Composable
fun ipLabel(mode: String): String = stringResource(
    when (mode) {
        "v4" -> R.string.ip_v4
        "v6" -> R.string.ip_v6
        else -> R.string.ip_both
    }
)
