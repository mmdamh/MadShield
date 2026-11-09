package com.madshield.app.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger

/** One exit-address question: not asked, being asked, answered, or not answered. */
sealed class ExitCheck {
    data object Idle : ExitCheck()
    data object Loading : ExitCheck()
    data class Ok(val info: ExitInfo, val atMs: Long) : ExitCheck()
    data class Unreachable(val atMs: Long) : ExitCheck()
}

/**
 * The last answer of [ExitIpProbe] for the Home chip and its details sheet (update41). Memory only, wiped when the
 * connection ends. Nothing here runs by itself: the UI asks once per connection and when the user taps "check again".
 */
object ExitIpHub {
    private val _v4 = MutableStateFlow<ExitCheck>(ExitCheck.Idle)
    val v4 = _v4.asStateFlow()
    private val _v6 = MutableStateFlow<ExitCheck>(ExitCheck.Idle)
    val v6 = _v6.asStateFlow()

    /** Bumped by [reset], so an answer that arrives after the connection ended is dropped. */
    private val generation = AtomicInteger(0)

    /** The connection the answers belong to (its start time). */
    @Volatile private var owner = 0L

    /** Call with the running connection's start time: a different one (a reconnect) wipes the answers of the old one. */
    fun forConnection(sinceMs: Long) {
        if (owner != sinceMs) { owner = sinceMs; reset() }
    }

    /** No connection: forget everything. */
    fun clear() {
        owner = 0L
        reset()
    }

    fun reset() {
        generation.incrementAndGet()
        _v4.value = ExitCheck.Idle
        _v6.value = ExitCheck.Idle
    }

    /** Asks over the IPv4 path ([ipv6] false) or the IPv6 path. Skips when the same question is already running. */
    suspend fun check(socksPort: Int, ipv6: Boolean, tries: Int = 1) {
        val flow = if (ipv6) _v6 else _v4
        if (flow.value is ExitCheck.Loading) return
        val gen = generation.get()
        flow.value = ExitCheck.Loading
        try {
            var info: ExitInfo? = null
            for (n in 0 until tries) {
                if (gen != generation.get()) return
                if (n > 0) delay(RETRY_PAUSE_MS)
                info = withContext(Dispatchers.IO) { ExitIpProbe.fetch(socksPort, UpstreamLogin.forPort(socksPort), ipv6) }
                if (info != null) break
            }
            if (gen != generation.get()) return
            val now = System.currentTimeMillis()
            flow.value = if (info != null) ExitCheck.Ok(info, now) else ExitCheck.Unreachable(now)
        } finally {
            // Cancelled while asking (the screen went away): do not stay on "Loading" forever.
            if (gen == generation.get() && flow.value is ExitCheck.Loading) flow.value = ExitCheck.Idle
        }
    }

    private const val RETRY_PAUSE_MS = 3_000L
}
