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
