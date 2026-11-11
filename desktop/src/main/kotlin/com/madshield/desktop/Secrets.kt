package com.madshield.desktop

import java.util.Base64

/**
 * Windows DPAPI (the current user's key) through PowerShell, so a stored link (it holds the server's user id or password)
 * is not readable from the file by another Windows user or by a copy of the file on another machine. Nothing is stored
 * when it fails: the secret then only lives while the app runs.
 */
object Secrets {
    private fun run(script: String, input: String): String? = try {
        val p = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).redirectErrorStream(true).start()
        p.outputStream.use { it.write(input.toByteArray(Charsets.UTF_8)) }
        val out = p.inputStream.readBytes().toString(Charsets.UTF_8).trim()
        if (p.waitFor() == 0 && out.isNotEmpty()) out else null
    } catch (_: Exception) { null }

    private const val PRELUDE = "Add-Type -AssemblyName System.Security; \$in = [Console]::In.ReadToEnd().Trim(); "

    fun protect(plain: String): String? {
        if (plain.isEmpty()) return ""
        val b64 = Base64.getEncoder().encodeToString(plain.toByteArray(Charsets.UTF_8))
        return run(
            PRELUDE + "\$b = [Convert]::FromBase64String(\$in); " +
                "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect(\$b, \$null, 'CurrentUser'))",
            b64
        )
    }

    fun unprotect(cipher: String): String? {
        if (cipher.isEmpty()) return ""
        val out = run(
            PRELUDE + "\$b = [Convert]::FromBase64String(\$in); " +
                "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect(\$b, \$null, 'CurrentUser'))",
            cipher
        ) ?: return null
        return try { String(Base64.getDecoder().decode(out), Charsets.UTF_8) } catch (_: Exception) { null }
    }
}
