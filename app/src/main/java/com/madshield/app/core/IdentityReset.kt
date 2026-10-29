package com.madshield.app.core

import java.io.File

/**
 * Removes the saved WARP identities so the next connect registers fresh ones.
 *
 * The core keeps them beside AETHER_CONFIG (filesDir/aether.toml): the plain WireGuard identity,
 * "<name>-masque.toml" for MASQUE, "<name>-masque-gool.toml" for the WireGuard identity Gool carries,
 * and "<name>-team-<team>.toml" for Zero Trust. A stale identity (made on an old network, or one
 * Cloudflare has since refused) is a common reason a tunnel keeps an unwanted exit.
 * Only files that match those exact names are touched.
 */
object IdentityReset {
    private val NAMES = Regex("aether(-masque(-gool)?|-team-[A-Za-z0-9_.-]+)?\\.toml")

    fun isIdentityFile(name: String): Boolean = NAMES.matches(name)

    /** @return how many identity files were deleted. */
    fun reset(filesDir: File): Int =
        filesDir.listFiles()?.count { it.isFile && isIdentityFile(it.name) && it.delete() } ?: 0
}
