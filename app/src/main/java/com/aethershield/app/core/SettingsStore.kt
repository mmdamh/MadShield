package com.aethershield.app.core

import android.content.Context
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.aethershield.app.ui.theme.DarkMode
import com.aethershield.app.ui.theme.UiPrefs
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "aethershield_settings")

/**
 * Everything here is local-only. There is no backend, no sync, no telemetry --
 * this class only ever talks to on-device storage.
 *
 * Non-secret settings (mode, DNS list, rule lists, toggles) live in plain
 * DataStore, because they are not sensitive and readability during debugging
 * matters more than encrypting a list of domain names.
 *
 * The one thing that IS sensitive -- an optional Zero Trust service-token
 * secret -- goes through EncryptedSharedPreferences instead, which wraps a
 * non-exportable AES-256-GCM key held in the Android Keystore. It is never
 * written to the plain DataStore file and never leaves the device.
 */
class SettingsStore(private val context: Context) {

    private object Keys {
        val MODE = stringPreferencesKey("mode")
        val PROTOCOL = stringPreferencesKey("protocol")
        val DNS = stringSetPreferencesKey("dns_resolvers")
        val DIRECT_RULES = stringSetPreferencesKey("direct_rules")
        val BLOCK_RULES = stringSetPreferencesKey("block_rules")
        val APP_SELECTION_MODE = stringPreferencesKey("app_selection_mode")
        val SELECTED_PACKAGES = stringSetPreferencesKey("selected_packages")
        val KILL_SWITCH = booleanPreferencesKey("kill_switch")
        val ZT_TEAM = stringPreferencesKey("zt_team")
        val EXIT_LOC = stringPreferencesKey("exit_loc")
        val SCAN = stringPreferencesKey("scan_mode")
        val IP_MODE = stringPreferencesKey("ip_mode")
        val NOIZE = stringPreferencesKey("noize_profile")
        val FRAGMENT = booleanPreferencesKey("fragment")
        val ECH = booleanPreferencesKey("ech")
        val ECH_DNS = stringPreferencesKey("ech_dns")
        val MASQUE_H2 = booleanPreferencesKey("masque_http2_v2") // v2: older builds stored an unset "false" here, which would hide the new HTTP/2 default
        val MTU = intPreferencesKey("mtu")
        val QUICK_RECONNECT = booleanPreferencesKey("quick_reconnect")
        val CHAIN = stringPreferencesKey("privacy_chain")
        val PSIPHON_REGION = stringPreferencesKey("psiphon_region")
        val PERF = stringPreferencesKey("perf_profile")
        val NOTIF_SPEED = booleanPreferencesKey("notif_speed")

        // Local DoH (update11). The resolver list is ONE newline-separated string, not a set: order is the
        // order they are tried in, and a string set would lose it.
        val DOH_ON = booleanPreferencesKey("doh_on")
        val DOH_RESOLVERS = stringPreferencesKey("doh_resolvers")
        val DOH_VIA_TOR = booleanPreferencesKey("doh_via_tor")
        val DOH_SERVE_STALE = booleanPreferencesKey("doh_serve_stale")
        val DOH_FOR_DIRECT = booleanPreferencesKey("doh_for_direct")

        // Appearance (never affects the tunnel)
        val THEME_ID = stringPreferencesKey("ui_theme_id")
        val DARK_MODE = stringPreferencesKey("ui_dark_mode")
        val AMOLED = booleanPreferencesKey("ui_amoled")
    }

    private val encryptedPrefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "aethershield_secrets",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    val configFlow: Flow<EngineConfig> = context.dataStore.data.map { p ->
        EngineConfig(
            mode = p[Keys.MODE]?.let { runCatching { ConnectionMode.valueOf(it) }.getOrNull() }
                ?: ConnectionMode.PROXY_ONLY,
            protocol = Protocol.fromStored(p[Keys.PROTOCOL]),
            dnsResolvers = (p[Keys.DNS] ?: emptySet()).toList(),
            directRules = (p[Keys.DIRECT_RULES] ?: emptySet()).toList(),
            blockRules = (p[Keys.BLOCK_RULES] ?: emptySet()).toList(),
            appSelectionMode = p[Keys.APP_SELECTION_MODE]
                ?.let { runCatching { AppSelectionMode.valueOf(it) }.getOrNull() }
                ?: AppSelectionMode.NONE,
            selectedPackages = p[Keys.SELECTED_PACKAGES] ?: emptySet(),
            killSwitchEnabled = p[Keys.KILL_SWITCH] ?: true,
            zeroTrustTeam = p[Keys.ZT_TEAM],
            exitLoc = p[Keys.EXIT_LOC]?.takeIf { it.isNotBlank() },
            scanMode = CoreChoices.scanOrDefault(p[Keys.SCAN]),
            ipMode = CoreChoices.ipOrDefault(p[Keys.IP_MODE]),
            noizeProfile = CoreChoices.noizeOrDefault(p[Keys.NOIZE]),
            fragment = p[Keys.FRAGMENT] ?: false,
            ech = p[Keys.ECH] ?: false,
            echDns = p[Keys.ECH_DNS]?.takeIf { it.isNotBlank() },
            masqueHttp2 = p[Keys.MASQUE_H2] ?: true,
            mtu = (p[Keys.MTU] ?: CoreChoices.DEFAULT_MTU).coerceIn(CoreChoices.MIN_MTU, CoreChoices.MAX_MTU),
            quickReconnect = p[Keys.QUICK_RECONNECT] ?: true,
            privacyChain = PrivacyChain.fromStored(p[Keys.CHAIN]),
            psiphonRegion = Chain.normalizeRegion(p[Keys.PSIPHON_REGION]),
            perfProfile = CoreChoices.perfOrDefault(p[Keys.PERF]),
            notifSpeed = p[Keys.NOTIF_SPEED] ?: true,
            dohOn = p[Keys.DOH_ON] ?: false,
            dohResolvers = (p[Keys.DOH_RESOLVERS] ?: "").split('\n').map { it.trim() }.filter { it.isNotEmpty() },
            dohViaTor = p[Keys.DOH_VIA_TOR] ?: true,
            dohServeStale = p[Keys.DOH_SERVE_STALE] ?: false,
            dohForDirect = p[Keys.DOH_FOR_DIRECT] ?: false
        )
    }

    val uiPrefsFlow: Flow<UiPrefs> = context.dataStore.data.map { p ->
        UiPrefs(
            themeId = p[Keys.THEME_ID] ?: UiPrefs().themeId,
            darkMode = p[Keys.DARK_MODE]?.let { runCatching { DarkMode.valueOf(it) }.getOrNull() } ?: DarkMode.SYSTEM,
            amoled = p[Keys.AMOLED] ?: false
        )
    }

    suspend fun updateUi(transform: (UiPrefs) -> UiPrefs) {
        val current = transform(uiPrefsFlow.first())
        context.dataStore.edit { p ->
            p[Keys.THEME_ID] = current.themeId
            p[Keys.DARK_MODE] = current.darkMode.name
            p[Keys.AMOLED] = current.amoled
        }
    }

    suspend fun update(transform: (EngineConfig) -> EngineConfig) {
        // Read the current value once, apply transform, write back. Simplest
        // correct approach for a settings screen this size.
        val current = transform(configFlow.first())
        context.dataStore.edit { p ->
            p[Keys.MODE] = current.mode.name
            p[Keys.PROTOCOL] = current.protocol.name
            p[Keys.DNS] = current.dnsResolvers.toSet()
            p[Keys.DIRECT_RULES] = current.directRules.toSet()
            p[Keys.BLOCK_RULES] = current.blockRules.toSet()
            p[Keys.APP_SELECTION_MODE] = current.appSelectionMode.name
            p[Keys.SELECTED_PACKAGES] = current.selectedPackages
            p[Keys.KILL_SWITCH] = current.killSwitchEnabled
            if (current.zeroTrustTeam.isNullOrBlank()) p.remove(Keys.ZT_TEAM) else p[Keys.ZT_TEAM] = current.zeroTrustTeam
            if (current.exitLoc.isNullOrBlank()) p.remove(Keys.EXIT_LOC) else p[Keys.EXIT_LOC] = current.exitLoc
            p[Keys.SCAN] = current.scanMode
            p[Keys.IP_MODE] = current.ipMode
            p[Keys.NOIZE] = current.noizeProfile
            p[Keys.FRAGMENT] = current.fragment
            p[Keys.ECH] = current.ech
            if (current.echDns.isNullOrBlank()) p.remove(Keys.ECH_DNS) else p[Keys.ECH_DNS] = current.echDns
            p[Keys.MASQUE_H2] = current.masqueHttp2
            p[Keys.MTU] = current.mtu.coerceIn(CoreChoices.MIN_MTU, CoreChoices.MAX_MTU)
            p[Keys.QUICK_RECONNECT] = current.quickReconnect
            p[Keys.CHAIN] = current.privacyChain.name
            p[Keys.PERF] = CoreChoices.perfOrDefault(current.perfProfile)
            p[Keys.NOTIF_SPEED] = current.notifSpeed
            p[Keys.DOH_ON] = current.dohOn
            if (current.dohResolvers.isEmpty()) p.remove(Keys.DOH_RESOLVERS) else p[Keys.DOH_RESOLVERS] = current.dohResolvers.joinToString("\n")
            p[Keys.DOH_VIA_TOR] = current.dohViaTor
            p[Keys.DOH_SERVE_STALE] = current.dohServeStale
            p[Keys.DOH_FOR_DIRECT] = current.dohForDirect
            val region = Chain.normalizeRegion(current.psiphonRegion)
            if (region == null) p.remove(Keys.PSIPHON_REGION) else p[Keys.PSIPHON_REGION] = region
        }
    }

    /** Zero Trust service-token secret, Keystore-encrypted, separate from the rest. */
    fun getServiceTokenSecret(): String? = encryptedPrefs.getString("zt_service_secret", null)
    fun setServiceTokenSecret(value: String?) {
        encryptedPrefs.edit().apply {
            if (value == null) remove("zt_service_secret") else putString("zt_service_secret", value)
        }.apply()
    }
}
