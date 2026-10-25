package com.aethershield.app.core

/**
 * Builds the complete, explicit AETHER_* environment for the core. Pure
 * function (no Android types) so it is easy to reason about and to test.
 *
 * The core is configured ENTIRELY through environment variables, with no
 * command-line arguments -- the same contract the field-tested AetherGUI uses.
 * Nothing sensitive ever appears in argv (visible to other processes), and the
 * names stay stable across core versions even when flag spellings change.
 *
 * TWO v2.3.0 TRAPS this exists to avoid:
 *  1. If AETHER_MASQUE_HTTP2 is left unset for a MASQUE-based protocol, the
 *     core falls into an INTERACTIVE "which carrier?" prompt. A background
 *     service has no stdin, so it would hang forever looking like "stuck
 *     connecting". It is always set explicitly (and stdin is closed too).
 *  2. The core must not inherit stray AETHER_* variables from the parent
 *     environment (see [isInherited]).
 */
object EngineEnvironment {

    /** Variables stripped from the inherited environment before ours are applied. */
    fun isInherited(name: String): Boolean = name.startsWith("AETHER_") || name == "RUST_LOG"

    fun build(
        config: EngineConfig,
        configFilePath: String,
        tmpDirPath: String,
        routesFilePath: String?,
        secretEnv: Map<String, String>,
        chainBinPath: String? = null,
        chainDirPath: String? = null,
        plan: FrontPlan
    ): Map<String, String> {
        val env = linkedMapOf<String, String>()

        env["AETHER_PROTOCOL"] = when (config.protocol) {
            Protocol.SMART -> "smart"
            Protocol.MASQUE_H3, Protocol.MASQUE_H2 -> "masque"
            Protocol.WIREGUARD -> "wg"
            Protocol.GOOL, Protocol.GOOL_CLASSIC -> "gool"
        }
        env["AETHER_SCAN"] = CoreChoices.scanOrDefault(config.scanMode)
        env["AETHER_IP"] = CoreChoices.ipOrDefault(config.ipMode)
        env["AETHER_NOIZE"] = CoreChoices.noizeOrDefault(config.noizeProfile)
        env["AETHER_LOG_LEVEL"] = "info"
        CoreChoices.perfOrDefault(config.perfProfile).takeIf { it != "auto" }?.let { env["AETHER_PERF_PROFILE"] = it }
        val chain = config.effectiveChain
        // [plan] decides every port. When RouteFront owns the public port (local DoH, or routing rules with a
        // chain) the chain moves to CHAIN_PORT; with a chain on, the core's own WARP proxy is always on an
        // internal port and Psiphon/Tor (the chain's final exit) take the next one up. See FrontPlan.
        val chainBind = "${TunnelConfig.SOCKS_HOST}:${plan.chainPort ?: config.socksPort}"
        env["AETHER_SOCKS"] = "${TunnelConfig.SOCKS_HOST}:${plan.corePort}"
        when (chain) {
            PrivacyChain.NONE -> Unit
            // The core runs plain on plan.corePort; sing-box is a separate process started by EngineProcessManager,
            // and it dials the core's SOCKS port itself. Nothing for the core to know.
            PrivacyChain.SINGBOX -> Unit
            PrivacyChain.PSIPHON -> {
                env["AETHER_PSIPHON"] = "chain"
                env["AETHER_PSIPHON_BIND"] = chainBind
                env["AETHER_PSIPHON_MODE"] = "auto"
                Chain.normalizeRegion(config.psiphonRegion)?.let { env["AETHER_PSIPHON_REGION"] = it }
                chainDirPath?.let { env["AETHER_PSIPHON_DIR"] = it }
                chainBinPath?.let { env["AETHER_PSIPHON_BIN"] = it }
                // libpsiphon is a Go program and inherits the core's environment. Cap its worker
                // threads so a burst can't spread over every big core, and give the Go runtime a
                // generous soft memory ceiling as a safety net. The ceiling is far above Psiphon's
                // normal heap on purpose: a limit set too low is what causes a GC death spiral.
                env["GOMAXPROCS"] = Chain.GO_MAX_PROCS
                env["GOMEMLIMIT"] = Chain.GO_MEMORY_LIMIT
            }
            PrivacyChain.TOR -> {
                env["AETHER_TOR"] = "chain"
                env["AETHER_TOR_BIND"] = chainBind
                // Same as AetherGUI/Android chain mode: no bridges, the underlay carries tor directly.
                env["AETHER_TOR_BRIDGES"] = "off"
                chainDirPath?.let { env["AETHER_TOR_DIR"] = it }
            }
        }
        env["AETHER_CONFIG"] = configFilePath
        env["AETHER_QUICK_RECONNECT"] = if (config.quickReconnect) "1" else "0"
        env["TMPDIR"] = tmpDirPath

        // MASQUE-based protocols need the carrier chosen explicitly (trap 1).
        val carrierMatters = config.protocol == Protocol.MASQUE_H3 ||
            config.protocol == Protocol.MASQUE_H2 || config.protocol == Protocol.GOOL
        val http2 = config.protocol == Protocol.MASQUE_H2 ||
            (config.protocol == Protocol.GOOL && config.masqueHttp2)
        if (carrierMatters) {
            env["AETHER_MASQUE_HTTP2"] = if (http2) "1" else "0"
            // The MASQUE outer tunnel budget follows the TUN MTU, as AetherGUI does.
            env["AETHER_MASQUE_MTU"] = config.effectiveMtu.toString()
        }
        if (config.protocol == Protocol.GOOL_CLASSIC) {
            env["AETHER_GOOL_MODE"] = "classic"
        }

        if (config.fragment && http2) {
            env["AETHER_MASQUE_H2_FRAGMENT"] = "1"
            env["AETHER_MASQUE_H2_FRAGMENT_SIZE"] = "16-32"
            env["AETHER_MASQUE_H2_FRAGMENT_DELAY"] = "2-10"
        }
        if (config.ech) {
            env["AETHER_ECH"] = "auto"
            config.echDns?.trim()?.takeIf { it.isNotEmpty() && DnsConfig.isValidEchResolver(it) }
                ?.let { env["AETHER_ECH_DNS"] = it }
        }

        // update19: ONLY when the user chose something. A name that fails validation is dropped, never passed on,
        // because the core refuses to start on a value it does not accept.
        if (MasqueSni.appliesTo(config.protocol)) {
            MasqueSni.envValue(config.masqueSni)?.let { env["AETHER_MASQUE_SNI"] = it }
        }
        // The fingerprint also covers the calls to the WARP API, so it is not limited to the MASQUE protocols.
        env.putAll(config.tlsPreset.env())

        config.exitLoc?.takeIf { it.isNotBlank() }?.let {
            env["AETHER_EXIT_LOC"] = it
            env["AETHER_EXIT_LOC_SECS"] = "180"
        }
        if (config.dnsResolvers.isNotEmpty()) env["AETHER_DNS"] = config.dnsResolvers.joinToString(",")
        routesFilePath?.let { env["AETHER_ROUTES_FILE"] = it }
        config.zeroTrustTeam?.takeIf { it.isNotBlank() }?.let { env["AETHER_TEAM"] = it }

        if (config.powerSaver) env.putAll(BatterySaver.env())

        env.putAll(secretEnv)
        return env
    }
}
