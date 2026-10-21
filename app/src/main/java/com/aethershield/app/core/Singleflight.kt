package com.aethershield.app.core

import java.io.IOException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Concurrent callers asking for the same key share ONE piece of work: the first caller runs it, the others
 * wait for its result (or its failure). The entry is removed as soon as the work ends, success or not, so
 * nothing accumulates and a failed lookup is retried by the next caller. Pure JVM, blocking.
 */
class Singleflight<K : Any, V : Any>(private val waitMs: Long = 20_000L) {
    private val inflight = HashMap<K, CompletableFuture<V>>()

    /** Number of keys currently in flight (for tests: must be 0 when everything is done). */
    val pending: Int @Synchronized get() = inflight.size

    @Throws(Exception::class)
    fun execute(key: K, work: () -> V): V {
        val mine: CompletableFuture<V>
        val leader: Boolean
        synchronized(this) {
            val existing = inflight[key]
            if (existing != null) { mine = existing; leader = false }
            else { mine = CompletableFuture(); inflight[key] = mine; leader = true }
        }
        if (leader) {
            try {
                val v = work()
                synchronized(this) { inflight.remove(key) }
                mine.complete(v)
                return v
            } catch (t: Throwable) {
                synchronized(this) { inflight.remove(key) }
                mine.completeExceptionally(t)
                throw t
            }
        }
        try {
            return mine.get(waitMs, TimeUnit.MILLISECONDS)
        } catch (e: ExecutionException) {
            throw (e.cause as? Exception) ?: IOException(e.cause?.message ?: "lookup failed")
        } catch (_: TimeoutException) {
            throw IOException("timed out waiting for a lookup that is already running")
        }
    }
}
