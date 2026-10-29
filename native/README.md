# Native engines

Nothing in this folder needs to be added by hand. The GitHub Actions workflow
(`.github/workflows/build.yml`) downloads both engines at **pinned commits**
and refuses to build if the downloaded commit differs from the pin:

| Engine | Source | Pinned commit |
|---|---|---|
| aether-core (v2.4.0) | https://github.com/CluvexStudio/Aether | `d58f9d568083129ce2c767c85054021eb3ee6a38` |
| hev-socks5-tunnel | https://github.com/heiher/hev-socks5-tunnel | `d9dca26c7ad0e494492244f0309e80ee583e739e` (tag 2.18.0) |

The aether-core commit is the one shown on the official v2.4.0 release page and
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

## sing-box (two builds, two pins)

| Binary | Pin file | Version | Used for |
|---|---|---|---|
| `libsingbox.so` | `native/singbox.pin` | v1.14.3 | the custom-link chain (protocol converter on top of the core's SOCKS port) |
| `libsingtun.so` | `native/singbox-tun.pin` | v1.15.0-alpha.13 (`824dbcfb...`) | EXPERIMENTAL "sing-box TUN" tunnel engine (Settings > Tunnel engine); never used unless chosen |

`libsingtun.so` exists because sing-box 1.15 ships sing-tun's own TCP/IP stack (the `stack` option is deprecated and
removed in 1.17.0, so no `stack` key is ever written). 1.15.0 is still an alpha: the pin is deliberate and separate so the
stable chain binary is not affected. Build tags: `badlinkname,tfogo_checklinkname0` (no `with_gvisor`: the new stack needs
none). Patches applied by CI, each fails the build unless its target matches exactly once
(`scripts/test-singbox-patches.sh` checks that against the pin):

- `singbox-patches/no-netlink`: switches off the network-change monitor (netlink is denied to apps on Android 11+).
- `singbox-patches/tun-fd` (only `libsingtun.so`): the `tun` inbound takes the TUN fd the app already owns. The app sends the
  fd over a unix socket (SCM_RIGHTS) whose path is in the environment variable `MADSHIELD_TUN_FD_SOCKET`; sing-box
  receives it, makes it non-blocking and passes it as `tun.Options.FileDescriptor` (sing-tun then skips opening
  `/dev/net/tun` and all netlink work). Without the variable behaviour is upstream's.

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

## Custom link chain (WARP -> your own vless / vmess / trojan / shadowsocks server)

* The app converts the pasted link (`core/ProxyLink.kt`) into a sing-box configuration
  (`core/SingBoxConfig.kt`) and runs the **official** sing-box as a child process, `libsingbox.so`.
  The configuration goes in on **stdin**, so the link's credential is never written to disk.
* sing-box is only a protocol converter here: one SOCKS inbound, one outbound for your server that is dialled
  *through* the Aether core's SOCKS (`detour`), no DNS, no TUN, no rules.
* `native/singbox.pin` is the exact commit (v1.14.3). Build: static ELF, `CGO_ENABLED=0`, tags
  `with_utls,badlinkname,tfogo_checklinkname0`, the linker flags from sing-box's own `release/LDFLAGS`.
  Needs Go 1.25.5 (taken from sing-box's `go.mod`).
* The job is `continue-on-error`: if it fails, the APK is built without `libsingbox.so` and the custom chain says
  so in the app. `singbox-config-check` runs the real `sing-box check` on `tests/pure/golden/*.json`
  (the files the app's builder produces; the pure tests compare them byte for byte).
* Not supported, because the official core does not have them: **XHTTP / SplitHTTP**, Hysteria2, TUIC, SSR and
  Shadowsocks plugins. The app refuses such links with a specific message instead of guessing.
* To change a golden file after editing the builder: `UPDATE_GOLDEN=1 KOTLINC=... bash scripts/run-pure-tests.sh`.
* Updating the pin: change `native/singbox.pin` and `SINGBOX_VERSION` in `build.yml`, then re-read sing-box's
  `option/` Go files for the fields `SingBoxConfig.kt` and `ProxyLink.kt` use.

### sing-box patch: no netlink monitor
Android 11+ forbids netlink sockets for ordinary apps; stock sing-box opens one at start-up
(`initialize network: subscribe netlink groups: permission denied`). `native/singbox-patches/no-netlink/apply.py`
switches off the (unused here) network-change monitor in `route/network.go`; it fails the build unless its target
matches exactly once, so a pin bump is never patched blindly.
