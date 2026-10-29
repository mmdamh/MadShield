package com.madshield.app.core

/**
 * What the UDP section of Diagnostics and the Settings hint say. Pure, so every combination is tested.
 *
 *  OFF              UDP Support is off and in effect: every UDP ASSOCIATE is refused, nothing UDP is sent.
 *  RELAY            on and carried by [UdpRelay]: rules apply to every datagram.
 *  UPSTREAM_DIRECT  on, but no front runs (no rules / DoH to enforce): hev talks UDP to the upstream itself.
 *  CHAIN_REFUSES    on, but Psiphon/Tor carry TCP only: the chain refuses UDP.
 *  PENDING_ON/OFF   the setting was changed and cannot be applied without a front: it takes effect at the next connect.
 */
enum class UdpState { OFF, RELAY, UPSTREAM_DIRECT, CHAIN_REFUSES, PENDING_ON, PENDING_OFF }

object UdpStatus {
    fun chainCanCarryUdp(chain: PrivacyChain): Boolean = chain == PrivacyChain.NONE || chain == PrivacyChain.SINGBOX

    /**
     * @param settingOn the saved "UDP Support" value
     * @param chain the chain that really runs
     * @param frontRunning a RouteFront runs ([DiagnosticsHub.UdpView.carried] != null)
     * @param frontCarries that front carries UDP right now (ignored without a front)
     * @param startedOn the value the running tunnel was started with (what a no-front tunnel is doing)
     */
    fun of(settingOn: Boolean, chain: PrivacyChain, frontRunning: Boolean, frontCarries: Boolean, startedOn: Boolean): UdpState {
        val can = chainCanCarryUdp(chain)
        if (frontRunning) {
            return when {
                !settingOn -> UdpState.OFF
                !can -> UdpState.CHAIN_REFUSES
                frontCarries -> UdpState.RELAY
                else -> UdpState.PENDING_ON // cannot happen while the live collector runs; kept honest
            }
        }
        // No front: the tunnel runs with UDP on (UDP off always starts a front).
        return when {
            !settingOn -> UdpState.PENDING_OFF
            !startedOn -> UdpState.PENDING_ON
            !can -> UdpState.CHAIN_REFUSES
            else -> UdpState.UPSTREAM_DIRECT
        }
    }
}
