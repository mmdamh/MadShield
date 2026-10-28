# Experimental Tunnel Engine (hev / sing-box TUN) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a persisted, default-off, experimental setting "Tunnel engine: hev (default) / sing-box TUN" so the TUN fd that `AetherVpnService` already owns can be served by sing-box's new in-house TCP/IP stack (sing-tun, sing-box 1.15) instead of hev-socks5-tunnel, with zero change to behaviour while the setting is off.

**Architecture:** `AetherVpnService` keeps creating the TUN (`VpnService.Builder`, Kill Switch, per-app split untouched). A small `TunEngine` seam hides "what reads the TUN fd": `HevEngine` wraps today's `TProxyService` unchanged; `SingBoxTunEngine` starts a second, separate sing-box process (`libsingtun.so`, built from the 1.15 alpha) whose `tun` inbound receives the fd over a unix socket (SCM_RIGHTS) and whose only outbound is the same SOCKS port hev uses today (`config.socksPort`), so front / chain / core / DoH / UDP relay are not touched. The stable chain binary (`libsingbox.so`, v1.14.3) is not rebuilt or bumped.

**Tech Stack:** Kotlin (AetherVpnService, EngineProcessManager, DataStore settings, Compose), `android.net.LocalSocket`, Go patch applied in CI (python `apply.py`, exact-once match), sing-box v1.15.0-alpha.13 / sing-tun v0.9.7-0.20261023115453-611d83b7a57b, GitHub Actions, pure tests (`scripts/run-pure-tests.sh`).

**Spec:** the user's request of 2026-10-28 (experimental choice between hev and sing-tun, no disruption to the app) + project doc `claude/MadShield_singtun_plan.md` (evidence, hop model, Phase 5 deferred) + sing-box 1.15 changelog (new own stack, `stack` option deprecated, removed in 1.17.0).

## Verified facts this plan relies on (sources read on 2026-10-28)

- sing-box 1.15.0 is **still alpha** (latest tag `v1.15.0-alpha.13`, commit `824dbcfb4dd0a95921840b1737b950cde590241e`). Latest stable is v1.14.4. The repo pins v1.14.3 (`native/singbox.pin` = `7054cac5124465ffdb145870d7c01885566711b1`).
- In alpha.13 `tun.NewStack("")` and `"go"` build sing-tun's own stack (`stack_go*.go`, no `with_gvisor` tag needed; `with_gvisor` only affects `gvisor`/`mixed`). In v1.14.4 the default is `system` (or `mixed` with gVisor). So the new stack exists only in 1.15.x.
- The `tun` inbound is registered unconditionally (`include/registry.go`). No `stack` key must be written (deprecated).
- sing-tun `New()` with `Options.FileDescriptor != 0` skips `/dev/net/tun`, TUNSETIFF and netlink configuration (`tun_linux.go`), but does **not** call `SetNonblock` on a supplied fd (only its own `open()` does) while the Go stack polls the fd with epoll. sing-box has **no config field** for the fd; it is set only by `platformInterface.OpenInterface` (libbox). In `protocol/tun/inbound.go` the single call site is `tunInterface, err = tun.New(tunOptions)` on a local copy `tunOptions := t.tunOptions` (occurs exactly once in alpha.13). `route/network.go` still contains the one netlink line the existing `no-netlink` patch targets (exactly once in alpha.13).
- Go stack on Linux probes IFF_VNET_HDR with `TUNGETIFF` and only warns on failure (falls back to no offload). A VpnService fd has no VNET_HDR; whether SELinux allows the ioctl is **not verified** (Task 7 reads the log).
- Android `ProcessBuilder` children do not inherit extra fds (existing plan doc), hence the unix-socket handoff.
- sing-box prints `sing-box started (<n>s)` (box.go:507) at the end of a successful start; the tun inbound's earlier `started at <name>` line comes **before** the stack's PostStart, so it is not a readiness signal.
- Repo facts found while reviewing this plan: (1) `.github/workflows/build.yml` job `singbox-config-check` builds the **pinned v1.14.3** and runs `sing-box check` on every `tests/pure/golden/*.json`, so 1.15 goldens must not live there; (2) `CoreProcessGuard.reapOrphans` kills every own process whose executable is in the `expectedExecutables` set that `EngineProcessManager.start()` passes (~line 178), so adding `libsingtun.so` there would kill a live TUN engine whenever the core restarts; (3) `IdleTracker.onTick(now, screenOn, totalBytes: Long?)` treats `null` bytes with the screen off as "quiet", so unknown counters would end in idle mode forever (`core/PowerPolicy.kt:121-143`); (4) `EngineProcessManager.cpuTicks()` sums only the core, Psiphon and chain sing-box child processes, while hev runs **inside the app process** (JNI), so the "engine cpu" log line cannot compare the two engines as it stands; (5) `SpeedMeterProbe.read` already finds the VPN interface (`NetworkCapabilities.TRANSPORT_VPN` + `LinkProperties.interfaceName`) and reads `TrafficStats.getRx/TxBytes(iface)` only on `SDK_INT >= S`, returning null on negative values.
- hev facts from this repo: `TProxyStartService(cfgPath, fd)`, `TProxyStopService`, `TProxyIsRunning`, `TProxyGetStats() = [txPkts, txBytes, rxPkts, rxBytes]`; config in `AetherVpnService.writeHevConfig` (mtu, `TunnelConfig.TUN_IPV4 = 10.10.14.1`/`TUN_IPV6 = fc00::10:10:14:1`, socks `127.0.0.1:<config.socksPort>` `udp: 'udp'`, optional mapdns `198.18.0.2`, pool `100.64.0.0/255.192.0.0`, cache 10000).

## Global Constraints

- Setting off (hev) must behave exactly like update23 (versionName 1.8.3 / versionCode 23): same hev config text, same call order, same health-loop behaviour.
- Default of the new setting: `HEV`. Applied at the next connect. Never switched automatically; no silent fallback to hev when sing-box TUN fails: show the real reason with Retry (owner's standing rule on honest reporting).
- `native/singbox.pin` and `native/hev-socks5-tunnel.pin` stay unchanged. The TUN binary has its own pin file.
- sing-box TUN binary: arm64-v8a only, `libsingtun.so`, build tags `badlinkname,tfogo_checklinkname0` (no `with_gvisor`, no `with_utls`), `CGO_ENABLED=0`, Go `1.25` (go.mod says `go 1.25.5`), job `continue-on-error: true` so a failed build never blocks the APK.
- Never write a `stack` key into the sing-box config.
- Every Go patch: fail the build unless the target text occurs exactly once; documented in `native/README.md`.
- VpnService.Builder, Kill Switch, per-app split, DNS server, FrontPlan, RouteFront, chains: unchanged.
- UI strings in `values/` and `values-fa/`. Commit messages plain: no Claude name, no Co-Authored-By, no session link; author `mmdamh <you@example.com>` (`git -c user.name=mmdamh -c user.email=you@example.com commit`).
- Android/Compose code cannot be compiled in the sandbox: pure logic goes in `core/` without android imports so `KOTLINC=<kotlinc> bash scripts/run-pure-tests.sh` covers it; CI compiles the rest.
- Out of scope (separate gated milestone, needs the Task 7 numbers and the owner's go): moving routing rules, DoH, UDP policy and the custom-link chain into the sing-box TUN config (project doc Phase 5), unix-socket hops.

## Review Focus

Failure modes the spec implies but no task's happy-path tests cover (each line is pinned by a test or a Task 7 check in the owning task):

1. Quick reconnect / Retry while the previous sing-box TUN process is still exiting: two processes must never own the fd or the handoff socket (Task 4).
2. fd handoff fails (stale socket file, engine never connects, engine dies before receiving): clean `Failed(reason)`, TUN kept open so the Kill Switch holds, no leaked LocalSocket / ParcelFileDescriptor (Task 4).
3. Wi-Fi <-> mobile switch and the "no network" pause/resume in the health loop: the engine must be restartable by the same re-attach path hev uses (Task 6).
4. Tun interface name or counters unavailable (no VPN network found, Android below 12, negative `TrafficStats` values): counters are `null`, never zeros, and with the screen off `IdleTracker` must not drift into idle mode on `null` (`onUnknownCounters`), nor the speed notification show 0 B/s (Tasks 4 and 6).
5. UDP switched off, and DNS with mapped DNS off: the generated config must not hijack DNS or add fakeip when `FrontPlan.mappedDns` is false, and UDP behaviour must equal hev's (front refuses ASSOCIATE) (Task 3 and Task 7).

---

## File Structure

- `native/singbox-tun.pin` (new): commit of the TUN binary's sing-box source.
- `native/singbox-patches/tun-fd/apply.py` (new): adds fd handoff to `protocol/tun`.
- `.github/workflows/build.yml` (modify): job `build-native-singtun`, wiring into `build-apk`, config-check job.
- `app/.../core/BinaryIntegrity.kt` (modify): know `libsingtun.so`.
- `app/.../vpn/TunEngine.kt` (new): interface, `TunCounters`, `StartResult`.
- `app/.../vpn/HevEngine.kt` (new): wraps `TProxyService` + `writeHevConfig` moved verbatim.
- `app/.../vpn/SingBoxTunEngine.kt` (new): process lifecycle + fd handoff + counters.
- `app/.../core/SingBoxTunConfig.kt` (new, pure): renders the sing-box JSON.
- `app/.../core/TunFdChannel.kt` (new, pure part: socket path rules) and `app/.../vpn/TunFdServer.kt` (new, android part: `LocalServerSocket`).
- `app/.../core/EngineConfig.kt`, `core/SettingsStore.kt`, `ui/SettingsScreen.kt`, `ui/DiagnosticsScreen.kt`, `res/values*/strings.xml` (modify): the setting.
- `app/.../vpn/AetherVpnService.kt`, `ui/HomeScreen.kt` (modify): use `TunEngine` instead of `TProxyService`.
- `app/.../core/PowerPolicy.kt` (modify): `IdleTracker.onUnknownCounters`.
- `tests/pure/Tests.kt`, `tests/pure/golden-singtun/singtun-*.json` (modify/new).

---

### Task 1: libsingtun.so — sing-box 1.15 alpha with TUN fd handoff

**Files:**
- Create: `native/singbox-tun.pin` (content: `824dbcfb4dd0a95921840b1737b950cde590241e`), `native/singbox-patches/tun-fd/apply.py`
- Modify: `.github/workflows/build.yml` (new job next to `build-native-singbox` at ~line 227; add to `needs:` of `build-apk` at ~line 525; extend the `libsingbox.so` copy and integrity loops at ~lines 552 and 588 to `libsingtun.so`), `native/README.md`, `app/.../core/BinaryIntegrity.kt`

**Interfaces:**
- Produces: binary `libsingtun.so` (static ELF, arm64) honouring env var `MADSHIELD_TUN_FD_SOCKET=<absolute unix socket path>`: at tun inbound start it connects to that socket, receives one fd via SCM_RIGHTS, calls `unix.SetNonblock(fd, true)`, sets `tunOptions.FileDescriptor = fd`. Without the env var behaviour is upstream's.

- [ ] **Step 1: Write the failing check.** `scripts/test-singbox-patches.sh`: shallow-fetch the pin, run `no-netlink/apply.py` then `tun-fd/apply.py`, assert exit 0 and that the second run on the patched tree exits non-zero ("already patched"), and that running it on a tree whose `inbound.go` has the target line removed exits non-zero.
- [ ] **Step 2: Run it; expect FAIL** (`tun-fd/apply.py` missing).
- [ ] **Step 3: Implement `apply.py <sing-box source dir>`** in the style of `no-netlink/apply.py`: (a) replace the single occurrence of `\t\t\ttunInterface, err = tun.New(tunOptions)\n` in `protocol/tun/inbound.go` with a call to `madshieldOpenTun(&tunOptions)`; (b) write `protocol/tun/madshield_fd.go` with `//go:build linux` and `func madshieldOpenTun(o *tun.Options) (tun.Tun, error)`: if the env var is empty, `return tun.New(*o)`; else dial the unix socket, `unix.Recvmsg` with an oob buffer of `unix.CmsgSpace(4)`, `unix.ParseUnixRights`, close the socket, `SetNonblock`, set `o.FileDescriptor`, `return tun.New(*o)`; 10 s deadline on the receive.
- [ ] **Step 4: Add CI job `build-native-singtun`** cloned from `build-native-singbox` (same fetch-at-pin, same ELF check, artifact `singtun-arm64-v8a`), applying both patches, building with the Global Constraints' tags, `SINGBOX_VERSION` = `1.15.0-alpha.13`, output renamed `libsingtun.so`. Add it to `build-apk.needs`, copy it into `jniLibs` only if present (like libsingbox.so).
- [ ] **Step 5: Extend `BinaryIntegrity`** to include `libsingtun.so` as optional exactly like `libsingbox.so`; document the pin, patch and "alpha, experimental" in `native/README.md`.
- [ ] **Step 6: Verify.** Run `bash scripts/test-singbox-patches.sh` (PASS); push to a branch and confirm the CI job is green and prints "OK: sing-box is a static ELF". If Go 1.25 fails to compile the alpha, switch only this job to Go 1.26 and record why in `native/README.md`.
- [ ] **Step 7: Commit** (`native: sing-box 1.15 alpha TUN binary with fd handoff (experimental)`).

---

### Task 2: TunEngine seam + HevEngine (no behaviour change)

**Files:**
- Create: `app/.../vpn/TunEngine.kt`, `app/.../vpn/HevEngine.kt`
- Modify: `app/.../vpn/AetherVpnService.kt` (call sites at `stopBridge`, `bridgeTunToEngine`, `awaitBridgeStopped`, `writeHevConfig`, health loop ~lines 490/544/573, `runLiveSpeed` ~808), `app/.../ui/HomeScreen.kt:419`, `app/.../ui/DiagnosticsScreen.kt:89,117,118,347`
- Test: `tests/pure/Tests.kt` (pure part: `TunCounters`)

**Interfaces:**
- Produces:
  ```kotlin
  data class TunCounters(val txPackets: Long?, val txBytes: Long, val rxPackets: Long?, val rxBytes: Long)
  sealed interface StartResult { object Ok : StartResult; data class Failed(val reason: String) : StartResult }
  interface TunEngine {
      val id: TunEngineId
      suspend fun start(tunFd: Int, config: EngineConfig): StartResult
      fun stop()
      fun isRunning(): Boolean
      fun counters(): TunCounters?   // null = unknown, never zeros
  }
  enum class TunEngineId { HEV, SINGBOX_TUN }   // in core/EngineConfig.kt scope, pure
  ```
- `HevEngine(context)`: `start` = today's `bridgeTunToEngine` body (write config, wait for old thread, two attempts, 700 ms check) returning `Failed` with the exact strings that today go to `AetherController.setState(ConnectionState.Error(...))`; `counters()` maps `TProxyGetStats()`.

- [ ] **Step 1: Write the failing test** `tunCounters_totalBytes` in `tests/pure/Tests.kt`: `TunCounters(1, 100, 2, 300).totalBytes == 400L` and `TunCounters(null, 5, null, 7).totalBytes == 12L` (add `val totalBytes: Long get() = txBytes + rxBytes`, used by `IdleTracker` and the notification).
- [ ] **Step 2: Run** `KOTLINC=<kotlinc> bash scripts/run-pure-tests.sh`; expect FAIL (class missing).
- [ ] **Step 3: Add `TunEngine.kt` (pure types) and `HevEngine.kt`**; move `writeHevConfig` into `HevEngine` unchanged (same YAML text byte for byte).
- [ ] **Step 4: Replace direct `TProxyService` calls** in the service and the two screens with the engine chosen once per connect (`private var tunEngine: TunEngine`, initially `HevEngine`). Keep `TProxyService.available` check for the HEV path only. Log lines stay identical for hev.
- [ ] **Step 5: Run pure tests; expect PASS.** Diff check: `git diff` shows no change to the hev YAML string or to retry/delay constants.
- [ ] **Step 6: Commit** (`vpn: TunEngine seam, hev behind it (no behaviour change)`).

---

### Task 3: SingBoxTunConfig (pure) + goldens + `sing-box check`

**Files:**
- Create: `app/.../core/SingBoxTunConfig.kt`, `tests/pure/golden-singtun/singtun-plain.json`, `tests/pure/golden-singtun/singtun-mapdns.json` (a **separate directory**: the existing job globs `tests/pure/golden/*.json` with the 1.14.3 binary)
- Modify: `tests/pure/Tests.kt`, `.github/workflows/build.yml` (new job `singtun-config-check`: fetch `native/singbox-tun.pin`, apply both patches, build for the runner with the Task 1 flags, run `sb check -c` on `tests/pure/golden-singtun/*.json`; `continue-on-error: true` like its sibling; leave `singbox-config-check` untouched)

**Interfaces:**
- Consumes: `TunnelConfig` (`TUN_IPV4`, `TUN_IPV4_PREFIX`, `TUN_IPV6`, `TUN_IPV6_PREFIX`, `SOCKS_HOST`), `Chain.MAPDNS_ADDRESS`, `MiniJson`.
- Produces: `object SingBoxTunConfig { fun render(mtu: Int, socksPort: Int, mappedDns: Boolean): String }` — a `tun` inbound (`address` = the two Builder prefixes, `mtu`, `auto_route: false`, no `stack`), one `socks` outbound `127.0.0.1:<socksPort>` version 5, `route.final` = that outbound. When `mappedDns`: DNS hijack plus a fakeip server over `100.64.0.0/10` answering at `198.18.0.2` (hev's values); when not: neither.

- [ ] **Step 1: Write failing tests** in `tests/pure/Tests.kt`: `singTunConfig_hasNoStackKey` (rendered text does not contain `"stack"`), `singTunConfig_addressesMatchTunnelConfig` (contains `10.10.14.1/30` and `fc00::10:10:14:1/126`), `singTunConfig_mtuAndPortFollowInput` (mtu 1500, port 10808 appear), `singTunConfig_fakeipOnlyWithMappedDns` (`100.64.0.0/10` present iff `mappedDns`), and golden comparisons for both files in `tests/pure/golden-singtun/` (`UPDATE_GOLDEN=1` refreshes; extend the golden-directory handling in `Tests.kt` to this second directory).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement `SingBoxTunConfig.render`** with `MiniJson` like `SingBoxConfig`. The exact 1.15 JSON for hijack-dns/fakeip is decided by making `sing-box check -c <golden>` (alpha.13 build) pass; copy nothing from memory into the goldens that `check` rejects.
- [ ] **Step 4: Run pure tests; expect PASS.** Add job `singtun-config-check`; confirm both config-check jobs are green in CI.
- [ ] **Step 5: Commit** (`core: sing-box TUN config builder + goldens`).

---

### Task 4: fd handoff server + SingBoxTunEngine

**Files:**
- Create: `app/.../core/TunFdChannel.kt` (pure), `app/.../vpn/TunFdServer.kt`, `app/.../vpn/SingBoxTunEngine.kt`
- Modify: `app/.../core/EngineProcessManager.kt` (only `cpuTicks()`: add `File(dir, EngineEnv.SINGTUN_BIN)` to its set, and add `const val SINGTUN_BIN = "libsingtun.so"` next to `SINGBOX_BIN` in `EngineEnv`; **do not** touch the `expectedExecutables` set in `start()`, see Verified facts (2)). `SingBoxTunEngine` owns its own `ProcessBuilder`, following `startSingBox` (~line 342): args `run -c stdin -D <cacheDir>/singtun --disable-color`, config written to stdin, stdout+stderr pumped to `RingLogBuffer` with prefix `[singtun]`.
- Test: `tests/pure/Tests.kt`

**Interfaces:**
- Consumes: `TunEngine` (Task 2), `SingBoxTunConfig.render` (Task 3), binary `libsingtun.so` in `nativeDir` (Task 1).
- Produces: `object TunFdChannel { const val MAX_PATH = 100; fun socketPath(dir: String): String /* "<dir>/tunfd.sock", throws IllegalArgumentException if longer than MAX_PATH */ }`; `class TunFdServer(path: String) : Closeable { fun serve(fd: FileDescriptor, timeoutMs: Long): Boolean }`: unlink the stale file; `LocalServerSocket(String)` only takes an abstract name, so bind a plain `LocalSocket` with `LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM)` and wrap it with `LocalServerSocket(localSocket.fileDescriptor)` (this constructor calls `listen`); accept one client with a deadline, `client.setFileDescriptorsForSend(arrayOf(fd))`, write one byte. `class SingBoxTunEngine(context): TunEngine` whose `start`: preflight the binary exists; reap own orphans of **only** `libsingtun.so` via `CoreProcessGuard.reapOrphans`; socket dir `<cacheDir>/singtun`; spawn with env `MADSHIELD_TUN_FD_SOCKET`; serve the fd; wait up to 5 s for a log line containing `sing-box started` or process death; return `Ok` / `Failed(reason incl. the last log lines)`. `stop()` destroys the process and waits for exit before a new start; `isRunning()` = process alive; `counters()` = `TunCounters(null, tx, null, rx)` from `TrafficStats.getTxBytes/getRxBytes(iface)` where `iface` is the `LinkProperties.interfaceName` of the network with `TRANSPORT_VPN` (same lookup as `SpeedMeterProbe.read`; `null` below `Build.VERSION_CODES.S`, when no VPN network is found, or when a value is negative).

- [ ] **Step 1: Write failing tests**: `tunFdChannel_pathUnderLimit` (`socketPath("/data/user/0/com.aethershield.app/cache")` ends with `/tunfd.sock`), `tunFdChannel_rejectsLongPath` (a 120-char dir throws), `tunCounters_unknownIsNullNotZero` (the pure helper `countersOrNull(rx: Long, tx: Long): TunCounters?` returns null when either is `-1L`, i.e. `TrafficStats.UNSUPPORTED`).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement the pure parts, then `TunFdServer` and `SingBoxTunEngine`** per the Interfaces. A second `start` first calls `stop()` and waits for the old process to exit (Review Focus 1); every error path closes the server socket and deletes the socket file (Review Focus 2); the TUN `ParcelFileDescriptor` is never closed by the engine (the service owns it).
- [ ] **Step 4: Run pure tests; expect PASS.** Check by reading the diff that `expectedExecutables` in `EngineProcessManager.start()` is unchanged.
- [ ] **Step 5: Commit** (`vpn: sing-box TUN engine with unix-socket fd handoff`).

---

### Task 5: Setting `tunEngine` (store, UI, Diagnostics, strings)

**Files:**
- Modify: `core/EngineConfig.kt` (field `tunEngine: TunEngineId = TunEngineId.HEV`, near `udpEnabled` ~line 205), `core/SettingsStore.kt` (Keys ~line 59, read ~line 125, write ~line 179, same pattern as `UDP_ENABLED`; stored as string `"hev"` / `"singbox_tun"`, unknown value reads as HEV), `ui/SettingsScreen.kt` (row near the UDP row ~line 247, with an "experimental" helper text and a note that it applies at the next connect), `ui/DiagnosticsScreen.kt` (one line: active engine + running state), `res/values/strings.xml`, `res/values-fa/strings.xml`
- Test: `tests/pure/Tests.kt`

**Interfaces:**
- Produces: `TunEngineId.fromStored(s: String?): TunEngineId`, `TunEngineId.stored: String`.

- [ ] **Step 1: Write failing tests**: `tunEngineId_roundTrip` (both ids), `tunEngineId_unknownIsHev` (`fromStored("x") == HEV`, `fromStored(null) == HEV`).
- [ ] **Step 2: Run; expect FAIL.** **Step 3: Implement** the pure mapping, the store key, the Settings row (disabled with an explanatory line when `libsingtun.so` is not in this build) and the Diagnostics line. **Step 4: Run pure tests; expect PASS.** **Step 5: Commit** (`settings: experimental tunnel engine option`).

---

### Task 6: Wire the chosen engine into AetherVpnService

**Files:**
- Modify: `app/.../vpn/AetherVpnService.kt` (engine selection at connect; `connect()` ~line 224; every `stopBridge()` caller: ~lines 282, 506, 575, 610, 686, 718; health loop ~lines 480-620; `runLiveSpeed` ~line 805; idle bytes ~line 490; CPU sampling ~lines 551-562), `ui/HomeScreen.kt:419`, `core/PowerPolicy.kt` (`IdleTracker`)
- Test: `tests/pure/Tests.kt`

**Interfaces:**
- Consumes: `TunEngine`, `HevEngine`, `SingBoxTunEngine`, `EngineConfig.tunEngine`.
- Produces:
  ```kotlin
  sealed interface EngineSelection {
      data class Use(val id: TunEngineId) : EngineSelection
      data class Unavailable(val reason: String) : EngineSelection
  }
  fun selectTunEngine(requested: TunEngineId, singTunInBuild: Boolean): EngineSelection   // pure, in core/
  fun IdleTracker.onUnknownCounters(): Boolean   // wake(); return false
  ```
  `HEV` is always `Use(HEV)`. `SINGBOX_TUN` without the binary is `Unavailable("This build has no sing-box TUN engine (libsingtun.so missing)")`, which the caller turns into `ConnectionState.Error(reason)`; it is never mapped to hev.

- [ ] **Step 1: Write failing tests**: `selectTunEngine_hevAlwaysUse` (both values of `singTunInBuild`), `selectTunEngine_singTunPresentUse`, `selectTunEngine_singTunMissingIsUnavailableNotHev` (result is `Unavailable` with a non-empty reason), `idleTracker_nullCountersScreenOffEventuallyIdle` (documents today's behaviour: repeated `onTick(.., screenOn=false, null)` over more than `IDLE_AFTER_MS` returns true), `idleTracker_onUnknownCountersNeverIdle` (the same sequence using `onUnknownCounters()` stays false).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement.** Pick the engine once per connect from the config snapshot (nothing collects `configFlow` for `tunEngine`, so a change applies at the next connect; do not add a live collector). Replace `TProxyIsRunning` / `stopBridge` / `bridgeTunToEngine` logic with `TunEngine` calls so the existing re-attach loop restarts either engine, and every `stopBridge()` caller stops the active engine. Idle: when the screen is off and `counters()` is `null`, call `idleTracker.onUnknownCounters()` instead of `onTick` (Review Focus 4); notification speed skips the tick on `null`; the "tunnel counters" log prints packets only when present. CPU: next to the existing `[power] engine cpu` line also log `[power] app cpu` from `/proc/self/stat` via `CpuSampler.parseTicks`, because hev runs inside the app process and the TUN engine in its own process (Task 7 compares the sum).
- [ ] **Step 4: Run pure tests; expect PASS; diff review:** with `HEV` selected, control flow equals the Task 2 result except the added `[power] app cpu` log line.
- [ ] **Step 5: Commit** (`vpn: use the selected tunnel engine`).

---

### Task 7: On-phone gate and test matrix (owner runs, results recorded)

**Files:**
- Create: project doc `claude/MadShield_singtun_results.md`

- [ ] **Step 1: Build and install** the APK from CI; Settings → Tunnel engine = sing-box TUN; reconnect. In the log expect `[singtun] ... sing-box started` and no fatal `TUNGETIFF`/`TUNSETOFFLOAD` error; record any Warn lines (settles the SELinux unknown).
- [ ] **Step 2: Measure** with Diagnostics → Speed meter check (download and upload), hev vs sing-box TUN, same mode: record link / tun / lo / phone-wide factor, throughput, and CPU as the **sum** of the `[power] app cpu` and `[power] engine cpu` log lines (hev's work is in the app process, the TUN engine's is not).
- [ ] **Step 3: Matrix**: WARP, MASQUE h2, Gool classic, Psiphon, Tor, custom link, DoH on/off (incl. Tor switch), UDP on/off (Telegram call), IPv6, Kill Switch (kill the `libsingtun.so` process: traffic must stay blocked and the health loop must re-attach it), per-app include/exclude (incl. "show system apps"), Wi-Fi <-> mobile, data off/on (pause/resume), screen-off idle (idle cadence must still engage with counters, and must NOT engage when counters are unavailable), Proxy Only mode (no TUN: unaffected, check once), Android 17 / One UI 9.
- [ ] **Step 4: Decide.** Acceptance (from the project doc): throughput >= 90% of hev, engine CPU at equal throughput <= hev, no DNS leak, Kill Switch unchanged, idle not worse, setting off = identical to update23. If met, the option stays and the owner decides on Phase 5; if not, report the numbers and the option stays hidden/off.

## Self-Review

- **Spec coverage:** experimental option (Task 5), no disruption when off (Global Constraints, Task 2 diff check, Task 6 diff review), new sing-tun stack (Task 1 pin, Task 3 no `stack` key), honest failure (Tasks 4, 6), measurement gate (Task 7). Phase 5 explicitly deferred.
- **Type consistency:** `TunEngine`, `TunCounters`, `StartResult`, `TunEngineId` are defined in Task 2 (the id enum's stored form in Task 5) and used unchanged in Tasks 4, 6; `SingBoxTunConfig.render(mtu, socksPort, mappedDns)` defined in Task 3, used in Task 4; `EngineSelection` / `selectTunEngine` defined and used in Task 6 only.
- **Review pass:** the nine-agent `android-plan-reviewer` pass hit the account's rate limit before returning; the issues fixed above came from checking the same points directly against the repo and the sing-box sources. Not yet independently re-reviewed.
- **Deviation from the project doc to confirm with the owner:** the doc proposed a hard-wired Phase 0 spike before the refactor; this plan builds Tasks 1-6 first because the setting is default-off and the hev path is untouched, so the cost of building is small and the gate (Task 7) is run on the real feature.
- **Unverified until Task 1 CI / Task 7:** the alpha compiles with Go 1.25 and our tags; exact 1.15 JSON for hijack-dns/fakeip (settled by `sing-box check`); behaviour of the Go stack on a VpnService fd (blocking vs non-blocking is handled by the patch; VNET_HDR probe permission is logged).
