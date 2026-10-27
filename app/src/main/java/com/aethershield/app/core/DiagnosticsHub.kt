package com.aethershield.app.core

import com.aethershield.app.util.LogRedactor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Small in-memory meeting point between the services and the Diagnostics page.
 *
 *  - [lastExit]: why the engine last stopped on its own. Only the last few lines, already passed through
 *    [LogRedactor], kept in memory only (never written anywhere). It is the one deliberate exception to
 *    "everything is wiped on disconnect", so the cause of a crash survives the restart that follows it.
 *    A disconnect pressed by the user clears it again, like the rest of the log.
 *  - [engineCpuTicks]: how the page asks the running service for the engine's CPU time, only while the
 *    page is open. Set by the service while it runs, null otherwise.
 *  - [udpView]: same pattern for the UDP section (update20).
 */
object DiagnosticsHub {
    data class LastExit(val atMs: Long, val reason: String, val tail: List<String>)

    private const val MAX_TAIL = 30

    private val _lastExit = MutableStateFlow<LastExit?>(null)
    val lastExit = _lastExit.asStateFlow()

    @Volatile var engineCpuTicks: (() -> Long?)? = null

    /** What UDP is doing in the running tunnel: [udpCarried] (null = no front runs) and the counters. Set while a service runs. */
    class UdpView(val carried: Boolean?, val stats: UdpStats?)
    @Volatile var udpView: (() -> UdpView)? = null

    fun recordExit(reason: String, tail: List<String>) {
        _lastExit.value = LastExit(
            System.currentTimeMillis(),
            LogRedactor.redact(reason),
            LogRedactor.redactLines(tail.takeLast(MAX_TAIL))
        )
    }

    fun clear() {
        _lastExit.value = null
    }
}
