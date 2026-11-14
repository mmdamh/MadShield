# Third-party notices

MadShield is free software under the GNU General Public License v3 (see `LICENSE`). Fonts are listed in
`THIRD_PARTY_FONTS.md`.

## Foxy engine core

- What: the Go core of an open-source, unofficial Firefox VPN client, built by CI as `libfxvpn.so` (Foxy engine only; the
  APK builds without it).
- Origin: https://github.com/armanlife/firefox-vpn-client, at the commit in `native/fxvpn.pin`.
- License: GNU General Public License v3 (its copyright and license notices stay with the source it ships).
- Where it comes from at build time: the repository named in `native/fxvpn.source`, and only the exact commit in
  `native/fxvpn.pin` (CI fails otherwise).
- MadShield's own changes to it are the patches in `native/fxvpn/patches/` and the program in `native/fxvpn/host/`; they
  are maintained in this repository. Go import paths in them (`github.com/armanlife/...`) are the module's own name, not a
  dependency on any service.
