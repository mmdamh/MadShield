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
