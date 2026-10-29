package com.madshield.app.vpn

import android.os.ParcelFileDescriptor
import com.madshield.app.core.EngineConfig
import com.madshield.app.core.StartResult
import com.madshield.app.core.TunCounters
import com.madshield.app.core.TunEngineId

/** The program that reads the TUN device the VPN service owns. See [TunEngineId]; the service never closes or hands over ownership of the fd. */
interface TunEngine {
    val id: TunEngineId

    /** Hands the TUN device [tunFd] to the engine and waits until it is really running. The service keeps owning the fd. */
    suspend fun start(tunFd: ParcelFileDescriptor, config: EngineConfig): StartResult

    /** Stops the engine; harmless when it is not running. */
    fun stop()

    fun isRunning(): Boolean

    /** null = unknown. Never zeros for "unknown": the idle logic and the speed line treat null differently from 0. */
    fun counters(): TunCounters?
}
