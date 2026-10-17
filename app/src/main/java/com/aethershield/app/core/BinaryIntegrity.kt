package com.aethershield.app.core

import android.content.Context
import java.io.File
import java.security.MessageDigest

/**
 * This does NOT verify that the upstream source is trustworthy -- no on-device
 * check can do that. What it DOES verify: that the libaether.so / libaethertun.so /
 * libhev-socks5-tunnel.so
 * files actually installed on this device are byte-for-byte what your own CI
 * build produced, by comparing against the SHA-256 values CI stamps into
 * BuildConfig at build time (see .github/workflows/build.yml, step
 * "Stamp binary hashes"). If someone hands you a modified APK where the native
 * binary was swapped after your CI signed it, this catches that at first run
 * instead of silently trusting whatever is on disk.
 *
 * The actual trust anchor is upstream: you (or you plus the pinned commit
 * hashes in native/aether-core.pin and native/hev-socks5-tunnel.pin) control
 * what source goes INTO the CI build. This
 * class only guards the step between "CI produced an APK" and "this device is
 * running it unmodified."
 */
object BinaryIntegrity {

    data class Result(val ok: Boolean, val details: List<String>)

    fun verify(context: Context, expected: Map<String, String>): Result {
        if (expected.isEmpty()) {
            return Result(true, listOf("No expected hashes stamped (debug build) -- skipping."))
        }
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val details = mutableListOf<String>()
        var allOk = true
        for ((fileName, expectedHash) in expected) {
            val f = File(nativeDir, fileName)
            if (!f.exists()) {
                allOk = false
                details += "$fileName: MISSING"
                continue
            }
            val actual = sha256(f)
            if (actual.equals(expectedHash, ignoreCase = true)) {
                details += "$fileName: OK"
            } else {
                allOk = false
                details += "$fileName: MISMATCH (expected $expectedHash, got $actual)"
            }
        }
        return Result(allOk, details)
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                digest.update(buf, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
