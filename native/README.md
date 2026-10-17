# Native engines

Nothing in this folder needs to be added by hand. The GitHub Actions workflow
(`.github/workflows/build.yml`) downloads both engines at **pinned commits**
and refuses to build if the downloaded commit differs from the pin:

| Engine | Source | Pinned commit |
|---|---|---|
| aether-core (v2.3.0) | https://github.com/CluvexStudio/Aether | `6175b67df370ab856bcee07fe85b524031903956` |
| hev-socks5-tunnel | https://github.com/heiher/hev-socks5-tunnel | `64cc609f945253b0e9ebc56317d544268f3c68c1` |

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
