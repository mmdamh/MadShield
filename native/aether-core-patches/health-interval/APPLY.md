# health-interval (optional core patch)

Makes the core's WireGuard health probe interval configurable with `AETHER_WG_HEALTH_SECS`.
The pinned core probes every ~3 s with no setting for it; that keeps the mobile radio awake all day.

* The app's **Battery saver** (Settings, on by default) already sends `AETHER_WG_HEALTH_SECS=10`,
  `AETHER_WG_STALE_SECS=30`, `AETHER_WG_KEEPALIVE=25`, `AETHER_MASQUE_H2_KEEPALIVE_SECS=30`.
* Without this patch the core ignores the first one (harmless) and the other three still apply.
* To build WITH the patch: add an empty file `native/aether-core-patches/health-interval/ENABLED`
  and push. CI runs `apply.py` right after fetching the pinned core. To go back, delete that file.
* `apply.py` changes nothing and fails the build unless the target function is found exactly once.
* Unset, or a value of 3 or less: the core behaves exactly as before.
* This modifies the core you ship (a few lines in `wireguard.rs`). It is not upstream code.
