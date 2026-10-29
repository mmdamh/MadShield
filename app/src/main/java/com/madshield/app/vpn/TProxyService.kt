package com.madshield.app.vpn

import com.madshield.app.util.RingLogBuffer

/**
 * JNI binding for hev-socks5-tunnel via our own bridge (libaethertun.so,
 * built from scripts/aethertun-jni.c). See that file's header comment for
 * the full root-cause story; short version: we do NOT rely on
 * hev-socks5-tunnel's own bundled JNI layer, because its exact signatures
 * drift across upstream versions and a mismatch throws UnsatisfiedLinkError
 * at System.loadLibrary() time -- which used to take the whole app down
 * with it, since UnsatisfiedLinkError is an Error, not an Exception, and
 * silently escapes a plain `catch (e: Exception)`.
 *
 * IMPORTANT: this object must not be renamed or moved to another package --
 * the bridge's exported symbols encode the exact name
 * "com/madshield/app/vpn/TProxyService". If you do rename it, update the
 * Java_com_madshield_app_vpn_TProxyService_* symbols in
 * scripts/aethertun-jni.c to match, or loading will fail again the same way.
 */
object TProxyService {
    @Volatile
    var available: Boolean = false
        private set

    @Volatile
    var loadFailure: String? = null
        private set

    init {
        available = try {
            // Loads libaethertun.so; the linker pulls in its DT_NEEDED
            // dependency libhev-socks5-tunnel.so from the same jniLibs dir.
            System.loadLibrary("aethertun")
            RingLogBuffer.append("[tun2socks] libaethertun loaded")
            loadFailure = null
            true
        } catch (t: Throwable) {
            // Catching Throwable, not Exception, is deliberate:
            // UnsatisfiedLinkError extends Error. A plain `catch (Exception)`
            // here would NOT catch it, and it would propagate up and crash
            // the whole app process -- which is exactly the failure mode
            // this class exists to prevent.
            loadFailure = "${t::class.java.simpleName}: ${t.message ?: "unknown native loader error"}"
            RingLogBuffer.append("[tun2socks] FATAL: could not load libaethertun.so: $loadFailure")
            false
        }
    }

    @JvmStatic
    @Suppress("FunctionName")
    external fun TProxyStartService(configPath: String, fd: Int): Boolean

    @JvmStatic
    @Suppress("FunctionName")
    external fun TProxyStopService()

    /** True while hev's native thread is alive (a start is a silent no-op while it still is). */
    @JvmStatic
    @Suppress("FunctionName")
    external fun TProxyIsRunning(): Boolean

    /** [tx_packets, tx_bytes, rx_packets, rx_bytes] */
    @JvmStatic
    @Suppress("FunctionName")
    external fun TProxyGetStats(): LongArray?
}
