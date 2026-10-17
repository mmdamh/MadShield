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
        _state.value = newState
    }
}
