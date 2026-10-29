package com.madshield.app.vpn

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.Closeable
import java.io.File
import java.io.FileDescriptor
import java.io.IOException

/**
 * One-shot unix-socket server that hands ONE file descriptor (the TUN device) to the sing-box TUN process with
 * SCM_RIGHTS (the patched sing-box reads it, see native/singbox-patches/tun-fd). It is a socket in the app's private
 * cache directory; an Android child process does not inherit extra descriptors, so this is the way across.
 *
 * Order matters: [open] first (the socket is listening, so a client that connects early waits in the backlog), then
 * start the process, then [serve].
 */
class TunFdServer(private val path: String) : Closeable {
    private var bound: LocalSocket? = null
    private var server: LocalServerSocket? = null

    @Throws(IOException::class)
    fun open() {
        File(path).delete() // a leftover file from a crashed run would make bind() fail
        val s = LocalSocket(LocalSocket.SOCKET_STREAM)
        try {
            // LocalServerSocket(String) only knows abstract names: a file path needs a bound LocalSocket wrapped by fd
            // (this constructor calls listen() itself).
            s.bind(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
            server = LocalServerSocket(s.fileDescriptor)
            bound = s
        } catch (t: Throwable) {
            runCatching { s.close() }
            throw t
        }
    }

    /**
     * Waits up to [timeoutMs] for the engine to connect, then sends [fd] (plus the one byte every message needs).
     * accept() has no timeout of its own: a helper thread accepts and closing the server ends it.
     * @return false when nobody connected in time or the send failed.
     */
    fun serve(fd: FileDescriptor, timeoutMs: Long): Boolean {
        val srv = server ?: return false
        val accepted = arrayOfNulls<LocalSocket>(1)
        val t = Thread {
            accepted[0] = try { srv.accept() } catch (_: IOException) { null }
        }.also { it.isDaemon = true; it.name = "tunfd-accept"; it.start() }
        t.join(timeoutMs)
        if (t.isAlive) {
            close() // unblocks accept()
            t.join(1_000)
            return false
        }
        val client = accepted[0] ?: return false
        return try {
            client.use { c ->
                c.setFileDescriptorsForSend(arrayOf(fd))
                c.outputStream.write(1) // the descriptor travels with this byte
                c.outputStream.flush()
            }
            true
        } catch (_: IOException) {
            false
        }
    }

    override fun close() {
        runCatching { server?.close() }
        runCatching { bound?.close() }
        server = null
        bound = null
        File(path).delete()
    }
}
