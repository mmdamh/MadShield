# 1.18.3 - Foxy core independence (rename to MadShield_updateN.md when N is known)

Goal: nothing in MadShield's code or docs depends on, or names, the person who wrote the upstream Foxy core; updates and
troubleshooting stay in this project. Scope: Foxy only.

## Done
- CI takes the Foxy core from the repository written in ONE file, `native/fxvpn.source` (the project's own copy once the
  copy exists), at the commit in `native/fxvpn.pin`; the build still fails unless the commit is exactly the pin.
  The checkout folder is now `native/fxcore-src`.
- Incidental references removed: workflow comment, `FxVpn.kt` KDoc, `native/README.md`, `host/main.go` comment, a test
  string, the earlier update note.
- New `THIRD_PARTY_NOTICES.md`: the one place that names the origin and license (GPL-3 requires keeping the notice).
- New pure test: the author's name may appear only in that notice, `native/fxvpn.source`, and the files that import the
  Go module (`host/main.go`, `native/fxvpn/patches/`). Those import paths are the module's name, not a dependency on a service.

## Not possible without a bigger change
Go import paths in the patches and the host program carry the module's name. They disappear only if the core's source is
moved into this repository with its own module name (option C of the audit), which was not chosen.

## One manual step left: the project's own copy
Create the copy once (GitHub: open the upstream repository, Fork, name it `madshield-foxy-core`, under your account; or in
Termux `gh repo fork <upstream> --fork-name madshield-foxy-core --clone=false`). Then replace the single line in
`native/fxvpn.source` with `https://github.com/mmdamh/madshield-foxy-core` and push. Nothing else changes: the pin is the same commit.
This session could not create it (the GitHub proxy refuses repository creation).

## 1.18.4 - the project's own core repository (instead of a fork)
The core was prepared as a repository of its own, `madshield-foxy-core` (built from the pinned source with patches 0001-0003
and `native/fxvpn/host/` folded in as ordinary code, module renamed to `github.com/mmdamh/madshield-foxy-core/core`, desktop-only
parts and Windows resources left out, `NOTICE.md` + `LICENSE` kept). Behaviour is the same as the build tested so far: the
files are identical to the tested ones except for the module path. The newer upstream snapshot that was sent was NOT used as
the base: it differs from the pin in 144 core files and the patches would need porting and testing.
CI (`build.yml`) now accepts both layouts: if the fetched source already has `core/cmd/madshield-fx`, it skips the patch and
entry-point steps. Nothing changes until `native/fxvpn.source` and `native/fxvpn.pin` point at the new repository.
Switch (after the empty public repository exists and the core is pushed to it): set `native/fxvpn.source` to its address,
`native/fxvpn.pin` to its commit, then delete `native/fxvpn/patches/` and `native/fxvpn/host/` here (they live in the new repository).
Not verifiable here: the full core build (Go modules are not reachable); the first real build is CI.

## 1.18.5 - MadShield builds the Foxy core from its own repository
- `native/fxvpn.source` = `https://github.com/mmdamh/madshield-foxy-core`, `native/fxvpn.pin` = `41c65a3f90e70a2777c64ba4a4be5b169112ce21`
  (the core's `main`; later changes there need a new pin here).
- `native/fxvpn/patches/` and `native/fxvpn/host/` are deleted from this repository: they are ordinary code in the core
  repository (`core/cmd/madshield-fx`, `internal/fxa/madshield_*.go`, `internal/service/madshield_*.go`, ...).
- `scripts/fetch-fxcore.sh` fetches the core into `native/fxcore-src` at exactly the pin (fails otherwise); the core build and
  the pure-test job both use it. The CI steps that applied patches and copied the entry point are gone.
- The pure tests that read Go files now read the core (`fxCoreFile`, folder `native/fxcore-src` or `MADSHIELD_FXCORE`); the
  guard on the upstream author's name allows only `THIRD_PARTY_NOTICES.md` and `native/fxvpn.source` (the latter no longer names it).
- THIRD_PARTY_NOTICES.md: origin and GPL-3 notice kept; copyright line for MadShield's own additions: "Copyright (c) 2026 mmdamh".
- Nothing in the app, HEV, sing-box, RouteFront, DNS, UDP, TLS verification or Fastly checks changed.
- Verified here: pure Kotlin tests ALL PASSED (reading the core from the new repository); the fetch script works against the
  real repository. NOT run: the Android build and the native build in CI.
- Licensing: the core stays GPL-3 (derived from GPL-3 code); the upstream license text and notices stay in the core repository.
- Commits are authored as the project owner only, no attribution lines.

## 1.18.6 - Foxy: connection race (servers, handshake shapes, ECH)
Problem seen on one network: TCP to the Fastly masque proxy connects, the TLS handshake gets no answer (Firefox's hello and
Go's both time out, `context deadline exceeded`), in TUN and in Proxy-only mode; other networks connect fast. Later finding by
the owner: on that network only some countries connect. So the block is per server (IP or name), not one hello shape.
`native/fxvpn.pin` = `cb7479c6d3ea7249d7c15bd115feb6184cbddbce` (core `main`). Changes are all in the core repository:
- Servers (the fix for the finding above): the first session is raced. The selected server starts; other servers of the
  location (for the recommended location also other locations', as the existing stand-ins) start after 2.5 s or when the one
  before has failed; the first session established wins, the others are cancelled/closed. At most 3 servers. A winner of the
  location is saved as the choice; a stand-in is used for now and not saved, and the location's own server that did not
  connect is avoided for 15 minutes (`ServerFailover.Avoid`) so the next wake does not wait for it. A country the user chose
  stays that country: only its own servers race. No-network / refused-pass errors end the race at once.
- Handshake shapes: each connection races Firefox's hello, Go's hello, Go's hello with Encrypted Client Hello (only when the
  proxy's name has an ECH key in DNS), and the other hello splits (record, first-byte, off, sni), 500 ms apart or at once when
  one fails. A failure to connect ends it. The shape that worked is kept in `upstream_shape.json` (data folder), so the
  restart the app does after a failure starts with it. `upstreamGoTLS` keeps its meaning (the remembered shape sends Go's hello).
- Logs: every attempt logs address, TCP connect time and time to the first reply byte (`first_reply=none`: the network dropped
  the hello), then `upstream TLS established/failed ... shape=...`, `upstream server did not connect`, `upstream server
  connected first`, `another server connected before the selected one`.
- Not changed: the app, HEV, sing-box, RouteFront, DNS, UDP, TLS verification, Fastly checks. Route through the owner's own
  sing-box link (idea 4) was NOT approved and is not built.
- Verified here: new stdlib-only packages `dialrace` and `handshake` (race, memory file, ECH key cache, real ECH handshake incl.
  stale-key retry, trace) pass with -race; the proxy glue (shape race, server race) was compiled and tested in a temp module
  with Firefox's hello (uTLS) replaced by Go's and the resolver stubbed, together with the old fallback tests (3 connections,
  `upstreamGoTLS`, connect failure). NOT compiled as a whole: `controller.go`, `engine.go`, `daemon.go` (Go modules are not
  reachable here); the first real build is CI. NOT run: anything on a phone.
- Known limits: HTTP/3 dials cannot be cancelled, so a losing H3 attempt runs to its timeout; the ECH lookup asks the
  proxy's plain name (not `_port._https.`), so a proxy on a non-443 port may show no key; failover strikes are still in memory
  only (the winner and the avoidance are what survives a restart).
