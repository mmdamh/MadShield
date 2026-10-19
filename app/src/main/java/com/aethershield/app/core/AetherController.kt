package com.aethershield.app.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed class ConnectionState {
    data object Idle : ConnectionState()
    data object Connecting : ConnectionState()
    data class Connected(
        val socksAddress: String,
        val sinceMs: Long = System.currentTimeMillis()
    ) : ConnectionState()
    data object Disconnecting : ConnectionState()
    data class Error(val message: String) : ConnectionState()
}

/**
 * The single source of truth for "are we actually connected". The UI
 * (HomeScreen) reads this instead of tracking its own tap state, so tapping
 * Connect shows "Connecting" immediately and only flips to "Connected" once
 * AetherVpnService has confirmed the tunnel is really up (SOCKS5 reachable
 * and, once wired, the self-test in superviseEngine passes) -- not the
 * instant the button was pressed.
 */
object AetherController {
    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    val state = _state.asStateFlow()

    fun setState(newState: ConnectionState) {
        synchronized(tracker) {
            val old = _state.value.kind()
            _state.value = newState
            _stats.value = tracker.onTransition(old, newState.kind(), System.currentTimeMillis())
        }
        if (newState !is ConnectionState.Connected && newState !is ConnectionState.Connecting) _active.value = null
    }

    /** Retries, errors and the time of the last state change, for the Diagnostics page (cheap: a few counters). */
    private val tracker = ConnStatsTracker()
    private val _stats = MutableStateFlow(ConnStats())
    val stats = _stats.asStateFlow()

    private fun ConnectionState.kind(): StateKind = when (this) {
        ConnectionState.Idle -> StateKind.IDLE
        ConnectionState.Connecting -> StateKind.CONNECTING
        is ConnectionState.Connected -> StateKind.CONNECTED
        ConnectionState.Disconnecting -> StateKind.DISCONNECTING
        is ConnectionState.Error -> StateKind.ERROR
    }

    /** The protocol/carrier that is REALLY running, which differs from the setting after a fallback. */
    private val _active = MutableStateFlow<EngineConfig?>(null)
    val active = _active.asStateFlow()
    fun setActive(config: EngineConfig?) { _active.value = config }
}
