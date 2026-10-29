package com.aethershield.app.core

/**
 * Where the app hands the TUN file descriptor to the sing-box TUN process: a unix socket file in the app's private
 * cache directory (same user, the directory is not reachable by other apps). A unix socket path is limited to 107 bytes
 * (sockaddr_un.sun_path), so longer ones are refused up front instead of failing inside bind().
 */
object TunFdChannel {
    const val SOCKET_NAME = "tunfd.sock"
    const val MAX_PATH = 100
    /** Environment variable the patched sing-box reads (native/singbox-patches/tun-fd). */
    const val ENV_VAR = "MADSHIELD_TUN_FD_SOCKET"

    fun socketPath(dir: String): String {
        val path = "${dir.trimEnd('/')}/$SOCKET_NAME"
        require(path.length <= MAX_PATH) { "socket path too long (${path.length} > $MAX_PATH): $path" }
        return path
    }
}
