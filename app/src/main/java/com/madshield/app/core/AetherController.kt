package com.madshield.app.core

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
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

/** Progress of a live switch between custom-chain links while connected (update18). */
sealed class LinkSwapState {
    data object Idle : LinkSwapState()
    data object Swapping : LinkSwapState()
    data class Done(val at: Long) : LinkSwapState()
    /** [reason] is the engine's own (English) text; [restored]: the previous link is running again. */
    data class Failed(val reason: String, val restored: Boolean, val at: Long) : LinkSwapState()
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
        if (newState !is ConnectionState.Connected && newState !is ConnectionState.Connecting) {
            _active.value = null
            _linkSwap.value = LinkSwapState.Idle
        }
    }

    /**
     * update19: is Android's "Block connections without VPN" (lockdown) on for this app? null = not known (no VPN running,
     * or Android older than 10). The Kill Switch holds traffic only while the app's process lives; if Android kills the
     * process, only lockdown keeps the phone from using the raw network. Read ONCE per connect, no polling.
     */
    private val _lockdown = MutableStateFlow<Boolean?>(null)
    val lockdown = _lockdown.asStateFlow()
    fun setLockdown(v: Boolean?) { _lockdown.value = v }

    private val _linkSwap = MutableStateFlow<LinkSwapState>(LinkSwapState.Idle)
    val linkSwap = _linkSwap.asStateFlow()
    fun setLinkSwap(s: LinkSwapState) { _linkSwap.value = s }

    /**
     * "The saved custom link changed while connected": the running service compares it with the link in use and, when
     * they differ, switches sing-box over without reconnecting (see [ChainLinkSwapper]). Nothing happens when no service
     * is running; the next connect reads the saved link anyway.
     */
    private val _swapRequests = MutableSharedFlow<Unit>(extraBufferCapacity = 4, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    val linkSwapRequests = _swapRequests.asSharedFlow()
    fun requestLinkSwap() { _swapRequests.tryEmit(Unit) }

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
