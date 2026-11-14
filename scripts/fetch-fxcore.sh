#!/usr/bin/env bash
# Fetches the Foxy core into native/fxcore-src: the repository written in native/fxvpn.source (the project's own core
# repository), at exactly the commit in native/fxvpn.pin. Whatever the repository serves, this fails unless the
# checked-out commit is that pin. Used by the core build and by the pure tests that read the core's Go files.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pin="$(tr -d '[:space:]' < "$ROOT/native/fxvpn.pin")"
src="$(tr -d '[:space:]' < "$ROOT/native/fxvpn.source")"
case "$src" in https://github.com/*/*) ;; *) echo "native/fxvpn.source must be an https://github.com/<owner>/<repo> address"; exit 1;; esac
dst="$ROOT/native/fxcore-src"
rm -rf "$dst"
mkdir -p "$dst"
git -C "$dst" init -q
git -C "$dst" fetch -q --depth 1 "$src" "$pin"
git -C "$dst" checkout -q FETCH_HEAD
test "$(git -C "$dst" rev-parse HEAD)" = "$pin"
echo "Foxy core @ $pin"
