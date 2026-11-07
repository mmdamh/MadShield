package com.madshield.app.core

/**
 * What a running connection was started with, as far as a change needs a new connection to take effect.
 *
 * Settings the running service applies at once (UDP Support, Foxy's Block/Direct for other ports, the saved custom link,
 * notification options) are NOT in here: changing them never asks for a reconnect. Everything the engine reads only
 * while it starts is: when the user changes one of those while connected, the app asks "Reconnect now / Later".
 * Pure, so it is checked off-device.
 */
data class RestartKey(
    val mode: ConnectionMode,
    val engineKind: EngineKind,
    val protocol: Protocol,
    val socksPort: Int,
    val scanMode: String,
    val ipMode: String,
    val noizeProfile: String,
    val fragment: Boolean,
    val ech: Boolean,
    val echDns: String?,
    val masqueHttp2: Boolean,
    val mtu: Int,
    val quickReconnect: Boolean,
    val exitLoc: String?,
    val dnsResolvers: List<String>,
    val directRules: List<String>,
    val blockRules: List<String>,
    val appSelectionMode: AppSelectionMode,
    val selectedPackages: Set<String>,
    val killSwitchEnabled: Boolean,
    val zeroTrustTeam: String?,
    val chain: PrivacyChain,
    /** Only meaningful with Psiphon; null otherwise, so a stored country never asks for a reconnect by itself. */
    val psiphonRegion: String?,
    val perfProfile: String,
    val powerSaver: Boolean,
    val doh: List<String>?,
    val dohViaTor: Boolean,
    val dohServeStale: Boolean,
    val dohForDirect: Boolean,
    val masqueSni: String,
    val tlsPreset: TlsPreset,
    val tunEngine: TunEngineId
)

fun EngineConfig.restartKey(): RestartKey {
    val foxy = engineKind == EngineKind.FIREFOX
    return RestartKey(
        mode = mode, engineKind = engineKind,
        // The WARP-only settings are not read by the Foxy engine: changing them must not ask for a reconnect there.
        protocol = if (foxy) Protocol.SMART else protocol,
        socksPort = socksPort,
        scanMode = if (foxy) "" else scanMode, ipMode = ipMode,
        noizeProfile = if (foxy) "" else noizeProfile,
        fragment = !foxy && fragment, ech = !foxy && ech, echDns = if (foxy) null else echDns,
        masqueHttp2 = !foxy && masqueHttp2, mtu = mtu, quickReconnect = !foxy && quickReconnect,
        exitLoc = if (foxy) null else exitLoc,
        dnsResolvers = if (foxy) emptyList() else dnsResolvers,
        directRules = directRules, blockRules = blockRules,
        appSelectionMode = appSelectionMode, selectedPackages = selectedPackages,
        killSwitchEnabled = killSwitchEnabled,
        zeroTrustTeam = if (foxy) null else zeroTrustTeam,
        chain = effectiveChain,
        psiphonRegion = if (effectiveChain == PrivacyChain.PSIPHON) Chain.normalizeRegion(psiphonRegion) else null,
        perfProfile = if (foxy) "" else perfProfile,
        powerSaver = powerSaver,
        doh = if (dohActive) dohResolvers else null,
        dohViaTor = dohEnabled && dohViaTor, dohServeStale = dohEnabled && dohServeStale, dohForDirect = dohEnabled && dohForDirect,
        masqueSni = if (foxy) "" else masqueSni, tlsPreset = if (foxy) TlsPreset.DEFAULT else tlsPreset,
        tunEngine = tunEngine
    )
}
