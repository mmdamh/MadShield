package com.madshield.app.core

/**
 * Meeting point between the running service and the Connections / Usage pages, like [DiagnosticsHub]. The
 * service sets the hooks while it runs and clears them when it ends; the pages call them only while on screen.
 * A null hook means "no service is running".
 */
object InsightHub {
    /** The open connections, or null when no service runs or no routing front exists (see [FrontPlan]). */
    @Volatile var connections: (() -> ConnSnapshot?)? = null

    @Volatile var closeConnection: ((Long) -> Unit)? = null

    @Volatile var closeAllConnections: (() -> Int)? = null

    /** Writes the current usage totals to disk now, so the Usage page reads up-to-date numbers. */
    @Volatile var flushUsage: (() -> Unit)? = null

    fun clear() {
        connections = null
        closeConnection = null
        closeAllConnections = null
        flushUsage = null
    }
}
