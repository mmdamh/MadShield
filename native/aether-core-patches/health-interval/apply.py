#!/usr/bin/env python3
"""
Optional core patch: let the WireGuard health probe interval be set with AETHER_WG_HEALTH_SECS.

Why: the pinned core (v2.3.0) sends a data-plane probe every ~3 s on a WireGuard tunnel (wireguard.rs,
WG_HEALTHCHECK_INTERVAL) and the interval has no environment variable. Those probes keep the mobile radio
awake around the clock. The app's "Battery saver" already sends AETHER_WG_HEALTH_SECS=10; an unpatched core
ignores it (so nothing breaks), a patched core really probes every 10 s.

Behaviour when the variable is unset, or <= 3: byte-for-byte the old one (the core's own test that checks the
3 s bounds keeps passing). Values above 3 are capped at 300.

Usage: apply.py <path to native/aether-core>   (exits non-zero, changing nothing, unless the target text
matches EXACTLY once: a changed pin must be reviewed by a human, never patched blindly).
"""
import sys
from pathlib import Path

OLD = """fn health_check_pause() -> Duration {
    let jitter = WG_HEALTHCHECK_JITTER.as_millis() as u64;"""

NEW = """fn health_check_pause() -> Duration {
    // update15 patch: AETHER_WG_HEALTH_SECS (> 3) stretches the probe interval to save battery.
    if let Some(secs) = std::env::var("AETHER_WG_HEALTH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 3)
    {
        let secs = secs.min(300);
        let jitter = WG_HEALTHCHECK_JITTER.as_millis() as u64;
        let offset = rand::rng().random_range(0..=jitter * 2);
        return Duration::from_secs(secs) - WG_HEALTHCHECK_JITTER + Duration::from_millis(offset);
    }
    let jitter = WG_HEALTHCHECK_JITTER.as_millis() as u64;"""


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    target = Path(sys.argv[1]) / "aether" / "src" / "wireguard.rs"
    text = target.read_text(encoding="utf-8")
    if "AETHER_WG_HEALTH_SECS" in text:
        print("already patched, nothing to do")
        return 0
    n = text.count(OLD)
    if n != 1:
        print(f"ERROR: expected the health_check_pause() text exactly once in {target}, found {n}. "
              "The pinned core changed: review the patch by hand.")
        return 1
    target.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print(f"patched {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
