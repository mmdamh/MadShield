#!/usr/bin/env bash
# Checks the sing-box patches against the pinned sources: both apply, a second run refuses, and a drifted tree is
# refused. Needs git and python3; with GO=<go binary> it also compiles the patched tun package for linux/arm64.
# usage: scripts/test-singbox-patches.sh [path to a sing-box checkout at native/singbox-tun.pin]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if [ $# -ge 1 ]; then
  cp -r "$1" "$work/sb"
else
  pin="$(tr -d '[:space:]' < "$ROOT/native/singbox-tun.pin")"
  mkdir "$work/sb"; git -C "$work/sb" init -q
  git -C "$work/sb" fetch -q --depth 1 https://github.com/SagerNet/sing-box "$pin"
  git -C "$work/sb" checkout -q FETCH_HEAD
fi
sb="$work/sb"
python3 "$ROOT/native/singbox-patches/no-netlink/apply.py" "$sb"
python3 "$ROOT/native/singbox-patches/tun-fd/apply.py" "$sb"
grep -q "madshieldOpenTun(&tunOptions)" "$sb/protocol/tun/inbound.go"
if python3 "$ROOT/native/singbox-patches/tun-fd/apply.py" "$sb" 2>/dev/null; then echo "FAIL: second run was accepted"; exit 1; fi
cp -r "$sb" "$work/drift"
sed -i 's/madshieldOpenTun(&tunOptions)/tun.New(tunOptions)/; s/tun.New(tunOptions)/tun.NewX(tunOptions)/' "$work/drift/protocol/tun/inbound.go"
rm -f "$work/drift/protocol/tun/madshield_fd_"*.go
if python3 "$ROOT/native/singbox-patches/tun-fd/apply.py" "$work/drift" 2>/dev/null; then echo "FAIL: a drifted tree was accepted"; exit 1; fi
echo "OK: patches apply once and refuse drift"
if [ -n "${GO:-}" ]; then
  (cd "$sb" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$GO" vet -tags "badlinkname,tfogo_checklinkname0" ./protocol/tun/ && echo "OK: protocol/tun compiles for linux/arm64")
fi
