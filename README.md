# AetherShield

A from-scratch Android client (VPN mode + proxy-only mode) around
[CluvexStudio/Aether](https://github.com/CluvexStudio/Aether), a user-space
client for Cloudflare's WARP protocol. Built for full code ownership: no
prebuilt engine binaries are trusted, no analytics, no logs written to disk.

## What this is not

This is a scaffold, not a finished, tested, store-ready app. It was written
without a live Android build environment (no SDK, no device, no network to
actually run `./gradlew assembleDebug`), so treat it as architecture you can
trust and code you should still compile-check yourself before relying on it.
Every place that's a genuine guess rather than a confirmed fact is marked
inline with a comment saying so -- search for "VERIFY" across the repo to
find all of them at once.

## Updated to Aether core v2.3.0

- The app now configures the core **only through `AETHER_*` environment
  variables** (no command-line flags), the same contract the AetherGUI
  reference uses with this core version. `core/EngineProcessManager.kt`
  builds that environment in one pure function.
- **Hang trap avoided:** on v2.3.0, leaving `AETHER_MASQUE_HTTP2` unset makes
  the core stop at an *interactive* "which carrier?" prompt. A background
  service has no stdin, so it would sit at "Connecting" forever. The app
  always sets it for MASQUE/Gool and closes the child's stdin so no prompt
  can ever block.
- **Protocols:** Smart (core picks), MASQUE h3, MASQUE h2, WireGuard,
  **Gool over MASQUE** (v2.3.0's default gool: WireGuard carried inside
  MASQUE, so the exit address is foreign) and Gool classic
  (WireGuard-in-WireGuard).
- **Exit country guard** (`AETHER_EXIT_LOC=!IR`): the core refuses a tunnel
  whose exit lands in Iran, checks through the finished tunnel before the
  proxy opens and again every minute, and replaces a tunnel that moves.
- **UI:** animated connection orb, uptime counter, live up/down speed
  (VPN mode), cancel-while-connecting. Ideas from AetherGUI, re-implemented
  from scratch in Compose; no code copied.
- **DoH:** the optional patch in `native/aether-core-patches/` targets
  v1.5.0 and is **not** part of this build (see its APPLY.md banner).

### What was and was not taken from the AetherGUI zip

Reviewed before borrowing anything: no analytics/telemetry SDK; dependencies
are AndroidX/Material/WorkManager only; the only third-party hosts are
GitHub (update checks and release downloads), `ipwho.is` / `ipapi.co` /
`api.country.is` (exit-IP lookups) and a Telegram link. Its release
downloads are verified against pinned SHA-256 values.
**Deliberately not taken:** its in-app self-updater (`REQUEST_INSTALL_PACKAGES`
plus downloading and installing APKs is an attack surface you asked to avoid)
and its third-party exit-IP lookups (they would tell a third party your exit
address); the core's own `AETHER_EXIT_LOC` check is used instead.
Also not taken for now: Psiphon/Tor chains, LAN sharing, Quick Settings tile.

## Source review (2026-08-03, against the actual v1.5.0 source)

You asked for a real security review before building on top of this, so
here's what was actually checked -- not a generic "looks fine" -- against
`aether/src/*.rs` (~12,700 lines) and the prebuilt `aether-android-arm64`
binary you provided:

- **Every hardcoded network endpoint in the codebase** (`grep -rn
  "https\?://"` across all 25 source files) resolves to either
  `cloudflareclient.com` or `cloudflareaccess.com` — both genuine
  Cloudflare-owned domains, matching the real WARP/Zero Trust API. No
  telemetry, analytics, or third-party server anywhere in the source.
- The shipped `aether-android-arm64` binary's embedded strings were
  cross-checked against the source: same `aether 1.5.0` version string, same
  `api.cloudflareclient.com` endpoint, and no other network host embedded
  besides two benign, expected ones (`android.googlesource.com`,
  `docs.rs` — both from crate metadata/panic messages, not runtime calls).
  The binary matches the public source.
- Cloudflare's MASQUE edge certs are **pinned** by SHA-256 SPKI hash
  (`consts.rs::MASQUE_PINS`), with a clear comment explaining why
  `SslVerifyMode::NONE` is used at the library level for those specific pins
  (Cloudflare's edge serves self-signed/SNI-dependent certs for this
  protocol) — a real anti-MITM measure, not a red flag.
- DNS responses used for ECH bootstrapping are validated against
  transaction ID, question name, and record type before being trusted
  (`dns.rs`, with tests for spoofed/mismatched replies) — basic but real
  anti-spoofing.
- **SOCKS5 has no authentication whatsoever** — confirmed in
  `socks.rs::handshake()`, which reads the client's offered auth methods and
  always replies "no auth required" regardless. This is fine as long as
  `--bind` stays on `127.0.0.1` (the default); it stops being fine the
  moment anyone binds it to `0.0.0.0` or a LAN address for "share my VPN"
  style features. If you ever add that, put your own auth layer in front of
  it rather than exposing the engine's SOCKS5 directly.
- **DNS resolver support is plain IP/`ip:port` only, in the stock engine** —
  confirmed in `socks.rs::resolver_addresses()`. DoH, DoH3, and
  DNS-over-QUIC are **not** supported out of the box; anything that isn't a
  bare address is silently dropped. This directly answers what you
  originally asked for — it was a real gap in the upstream engine, not
  something fixable from the Android app layer alone. **Update:** DoH is now
  addressed by `native/aether-core-patches/doh-support/` — real new Rust
  code (a DoH client that runs over the same tunneled netstack SOCKS5
  already uses, so queries don't leak outside the tunnel), not a workaround.
  It hasn't been compiled (no Rust toolchain in the sandbox this was written
  in) — see that folder's APPLY.md for exactly what to check before trusting
  it. DoH3/DNS-over-QUIC is a bigger job (would want to reuse the crate's
  existing QUIC/H3 stack rather than a second implementation) and wasn't
  attempted.
- Routing rules (`--routes`, used for your "Iranian sites" bypass list) are
  parsed in `routing.rs`, with real unit tests covering suffix/full/keyword/
  regex/CIDR/port matching and the block-wins-over-direct precedence rule.
  This app writes to that exact `[block]`/`[direct]` file format — see
  `core/RuleFileWriter.kt`.

Caveat, stated plainly: this was a real read of the actual source, not a
rubber stamp, but it is still one read by one reviewer (me), not a
professional security audit. For something you're trusting with real
circumvention risk, an independent second look is worth it before you rely
on this for anything where getting caught has serious consequences.

## Architecture

```
apps -> [VPN mode] Android TUN (AetherVpnService)
              -> TProxyService (our own JNI bridge, libaethertun.so)
              -> hev-socks5-tunnel (libhev-socks5-tunnel.so, native pthread)
              -> 127.0.0.1:1819 (aether core's SOCKS5, --bind)
              -> internet, via Cloudflare WARP (MASQUE/WireGuard)

apps -> [Proxy-only mode] point directly at 127.0.0.1:1819 yourself
              -> aether core -> internet
```

**Why our own JNI bridge (`scripts/aethertun-jni.c`) instead of hev's bundled
one:** hev-socks5-tunnel ships its own JNI glue, but its exact method
signatures have drifted across upstream versions in the past (e.g.
`TProxyStartService` changing from returning `void` to returning `boolean`).
A mismatch throws `UnsatisfiedLinkError` -- an `Error`, not an `Exception` --
which used to escape unguarded and crash the whole app the moment full
VPN mode tried to start, while proxy-only mode (which never touches hev)
kept working. This project's own build strips hev's bundled JNI layer out
entirely and ships a small bridge that binds only hev's *stable* public C
API (`hev_socks5_tunnel_main`/`quit`/`stats`), exports symbols this app
controls, and is verified at CI build time (`llvm-nm`) rather than assumed.
The tunnel event loop also runs on hev's own native pthread, never an
ART-attached Java thread -- doing otherwise corrupts hev-task-system's
stack-swapping coroutines and crashes with a native SIGSEGV.

- **Per-app split tunneling** happens at the Android `VpnService` layer
  (`addAllowedApplication`/`addDisallowedApplication`), never inside the
  engine — confirmed as the intended design from the v1.5.0 release notes
  themselves: "Per-application rules deliberately stay out of the core... It
  belongs in the Android client's VpnService."
- **Kill switch**: the TUN interface is established before the engine is
  confirmed healthy, so traffic is captured (and held/dropped) rather than
  ever silently falling back to the raw network. See `AetherVpnService.kt`
  for the exact sequencing.
- **Zero-log**: `util/RingLogBuffer.kt` is in-memory only, capped, and wiped
  on every disconnect. The one exception: after an unexpected engine stop a
  short tail (IPs and keys removed) stays in memory for the Diagnostics page
  until you clear it or the process ends. `android.util.Log` calls are stripped from release
  builds by ProGuard as a second, independent layer. No analytics or crash
  reporting SDK is in the dependency list at all — check
  `app/build.gradle.kts`, it's short enough to read end to end.
- **Binary integrity**: CI stamps the SHA-256 of every shipped native file
  (`libaether.so`, `libpsiphon.so`, `libhev-socks5-tunnel.so`, `libaethertun.so`)
  into `assets/native_hashes.properties`, and a CI step proves the finished APK
  carries exactly those bytes. At the first engine start of each run,
  `core/BinaryIntegrity.kt` hashes the installed files and refuses to start the
  engine on a mismatch. This catches corruption and a native file swapped after
  the build; it does not stop someone who can re-sign a modified APK, so the
  real trust anchors are the pinned upstream commits and your signing key.
- **CI hardening**: every Action is pinned to a full commit SHA, Rust (1.98.1),
  cargo-ndk (4.1.2), CMake (4.4.4), NDK (r26d) and Gradle (8.9) are fixed
  versions, the workflow is read-only by default, and publishing the Release is
  a separate job that has write access but never sees the signing key.

- **Diagnostics**: Settings > Diagnostics explains probable causes with a
  confidence level and the evidence (DNS, TCP, handshake, stalled tunnel,
  repeated drops, CPU during real transfer versus CPU while idle). Live CPU
  sampling is a switch that is off by default; the connection tests run only
  when you press the button; the shareable report has no log lines, IPs or
  tokens unless you opt in to a redacted log tail.
- **Reconnect policy**: after the engine dies, retries wait 1, 2, 4, 8, 16, 30 s,
  then a slow waiting phase (2 min screen on, 5 min off) that never spins.
  A network change (Wi-Fi to mobile, link back) ends the wait at once.
- **Logs and polling**: appending a log line costs nothing and publishes
  nothing; the log page polls twice a second only while it is visible, and the
  traffic tiles poll every 2.5 s only while the app is in the foreground.
- **Per-app routing**: each app is labelled as going through the VPN,
  connecting directly, or not confirmable right now (disconnected, proxy mode,
  rule changed since connecting). The leak-protection card explains what the
  kill switch cannot cover and links to Android's Always-on VPN lockdown.

## Setup

Build with GitHub Actions only (no Android Studio needed):

1. Create a GitHub repository and push this folder to it (step-by-step for
   Termux on a phone is in the chat guide that came with this project).
2. The push starts the **Build AetherShield APK** workflow. It fetches the two
   engines at pinned commits (see `native/README.md`), builds them with the
   NDK, builds the app and attaches the APK to a GitHub Release.
3. Signing is optional for the first build: without the secrets below the APK
   is signed with the debug key so you always get an installable file.
   For a stable signature later, add the repo secrets `SIGNING_KEY_BASE64`
   (a keystore, base64), `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.
   Changing the signing key later needs one uninstall of the old build.

## Interface

The UI follows the look of ZedSecure (cookie-blob connect button, floating
pill navigation, rounded cards, nine colour themes, Inter + Estedad fonts,
English and Persian with RTL). It is re-implemented from scratch with
Material 3, not copied (ZedSecure is AGPL-3.0). Fonts are OFL, see
`THIRD_PARTY_FONTS.md`.

## Known gaps / next steps

- Launcher icon is a placeholder vector (`res/drawable/ic_launcher_*.xml`) —
  swap for real art whenever.
- Zero Trust settings UI only wires up `team` name + service-token secret;
  `--access-email` and `--access-id` exist in the engine but aren't exposed
  in `SettingsScreen.kt` yet — same pattern, just not built out.
- No automated tests written for the Kotlin/Compose side. The Rust engine's
  own test suite (`cargo test` inside `native/aether-core/aether`) is
  extensive and worth running on its own, independent of anything in this app.
