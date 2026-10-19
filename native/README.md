# Native engines

Nothing in this folder needs to be added by hand. The GitHub Actions workflow
(`.github/workflows/build.yml`) downloads both engines at **pinned commits**
and refuses to build if the downloaded commit differs from the pin:

| Engine | Source | Pinned commit |
|---|---|---|
| aether-core (v2.3.0) | https://github.com/CluvexStudio/Aether | `6175b67df370ab856bcee07fe85b524031903956` |
| hev-socks5-tunnel | https://github.com/heiher/hev-socks5-tunnel | `d9dca26c7ad0e494492244f0309e80ee583e739e` (tag 2.18.0) |

The aether-core commit is the one shown on the official v2.3.0 release page and
the `sourceCommit` pinned by the AetherGUI reference project. (Fetching by SHA
replaces the old git-submodule setup, so a plain `git push` from a phone is enough.)

## Why the engine is linked with a static libc++

The Aether core contains C++ (BoringSSL / quiche). Built the default way it
needs `libc++_shared.so` at run time, which an Android APK does not carry, and
the engine dies at start with `CANNOT LINK EXECUTABLE ... library
"libc++_shared.so" not found`. The workflow therefore sets
`BORING_BSSL_RUST_CPPLIB_<target>=static:-bundle=c++` and then checks the
built file with `llvm-readelf -d`: a `libc++_shared.so` entry fails the build.
The app repeats that check on the phone before starting the engine
(`core/ElfInspector.kt`) and shows a readable message instead of an endless
"Connecting".

## Our own JNI bridge for hev

`scripts/aethertun-jni.c` + `vpn/TProxyService.kt` replace hev's bundled JNI
layer (its signatures drifted between upstream versions). CI verifies the
exported symbols of both libraries with `llvm-nm`.

## Updating a pin

Change the commit in `build.yml` (both the `fetch` step and its `test`), then
re-read aether-core's `cli.rs` (flag names), `routing.rs` (rule file format) and
`socks.rs` (SOCKS5 behaviour, DNS resolver parsing): `core/EngineEnvironment.kt`,
`core/RuleFileWriter.kt` and `core/DnsConfig.kt` are written against those.

## Privacy chains (WARP -> Psiphon / Tor)

* **Tor** is built into the core: the workflow builds it with `--features tor`
  (the same command upstream's Android release job runs).
* **Psiphon** is a separate Go program. The workflow builds it with the core's own
  `psiphon-build.sh` (pinned fork and commit, CGO off => a static ELF), checks that
  it has no dynamic dependencies, and ships it as `libpsiphon.so` so Android extracts
  it next to `libaether.so`. The app passes its path to the core as `AETHER_PSIPHON_BIN`.
* With a chain on, the core's own WARP proxy moves to `127.0.0.1:1823` and the chain
  listens on the normal SOCKS port. In VPN mode hev answers DNS itself (`mapdns`) because
  Psiphon and Tor carry TCP only.
