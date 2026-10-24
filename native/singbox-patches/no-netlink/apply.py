#!/usr/bin/env python3
"""Turns off sing-box's network-change monitor (route/network.go).

Why: on Android 11+ an ordinary app is not allowed to open a netlink socket, and sing-box's monitor does so at
start-up ("start service: initialize network: subscribe netlink groups: permission denied"). The monitor only
serves auto_detect_interface / interface binding / network-change resets, none of which this app uses: sing-box
runs here purely as a protocol converter on top of the Aether core's SOCKS port. The same code path already exists
for platforms without a monitor (it is what monitor_other.go triggers by returning os.ErrInvalid).

Safety: the target text must occur EXACTLY once or the script exits non-zero and the build fails; nothing is
patched blindly after a version bump.

usage: apply.py <sing-box source dir>
"""
import sys, pathlib

root = pathlib.Path(sys.argv[1])
f = root / "route" / "network.go"
s = f.read_text()
old = "\t\tnetworkMonitor, err := tun.NewNetworkUpdateMonitor(logger)\n"
new = old + "\t\terr = os.ErrInvalid // MadShield: no netlink monitor (denied to apps on Android 11+), see native/singbox-patches/no-netlink\n"
if s.count(old) != 1:
    sys.exit(f"ERROR: expected exactly one match in {f}, found {s.count(old)}; the pinned sing-box changed, re-check this patch")
if "MadShield: no netlink monitor" in s:
    sys.exit("already patched")
f.write_text(s.replace(old, new, 1))
print("patched", f)
