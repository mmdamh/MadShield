# Third-party notices

MadShield is free software under the GNU General Public License v3 (see `LICENSE`). Fonts are listed in
`THIRD_PARTY_FONTS.md`.

## Foxy engine core

- What: the Go core of an open-source, unofficial Firefox VPN client, built by CI as `libfxvpn.so` (Foxy engine only; the
  APK builds without it).
- Origin: https://github.com/armanlife/firefox-vpn-client, at the commit in `native/fxvpn.pin`.
- License: GNU General Public License v3 (its copyright and license notices stay with the source it ships).
- Where it comes from at build time: the repository named in `native/fxvpn.source` (https://github.com/mmdamh/madshield-foxy-core,
  maintained by mmdamh), and only the exact commit in `native/fxvpn.pin` (CI fails otherwise). That repository keeps the
  original copyright and license notices (`LICENSE`, `NOTICE.md`) and lists MadShield's own changes.
- Copyright of MadShield's own additions (the entry point, the account sign-in and renewal code, the app): Copyright (c) 2026 mmdamh,
  under the same GPL-3.
