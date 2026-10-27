#!/usr/bin/env python3
"""
MadShield speed-indicator check -- run it in Termux ON THE PHONE while the VPN is connected AND a speed test is running.

    python net-speed-check.py          # measures for 12 seconds
    python net-speed-check.py 20       # or any number of seconds

Why: status-bar speed meters (Good Lock "Network Speed" and similar) read the phone's byte counters. If the meter shows
several times the real speed, this shows WHICH interface the extra bytes come from:
  tunnel    the VPN interface the apps write into (counted once, by every VPN app, sing-box included)
  loopback  traffic between the app's own parts on 127.0.0.1 (tunnel bridge -> front -> chain -> core)
  physical  the real Wi-Fi / mobile interface (what a speed test really moves)
It only reads /proc/net/dev and changes nothing. Python standard library only.
"""
import sys
import time


def read_dev():
    """{interface: (rx_bytes, tx_bytes)} from /proc/net/dev."""
    out = {}
    with open("/proc/net/dev") as f:
        for line in f.read().splitlines()[2:]:
            name, _, rest = line.partition(":")
            v = rest.split()
            if len(v) >= 9:
                out[name.strip()] = (int(v[0]), int(v[8]))
    return out


def kind(name):
    if name == "lo":
        return "loopback"
    if name.startswith("tun"):
        return "tunnel"
    if name.startswith(("wlan", "rmnet", "ccmni", "eth", "p2p")):
        return "physical"
    return "other"


def main():
    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    try:
        before = read_dev()
    except OSError as e:
        print("Cannot read /proc/net/dev here (%s). Android blocks it for some apps." % e)
        print("Tell Claude: the same measurement can be added inside MadShield (Diagnostics).")
        return 2
    print("Measuring %d s ... start your speed test NOW (download)." % secs)
    t0 = time.time()
    time.sleep(secs)
    after = read_dev()
    dt = max(time.time() - t0, 0.001)

    rows = []
    for name, (rx1, tx1) in after.items():
        rx0, tx0 = before.get(name, (rx1, tx1))
        rx, tx = max(rx1 - rx0, 0) / dt / 1e6, max(tx1 - tx0, 0) / dt / 1e6
        if rx >= 0.01 or tx >= 0.01:
            rows.append((kind(name), name, rx, tx))
    rows.sort()

    print("\n%-9s %-16s %10s %10s   (MB/s, average)" % ("kind", "interface", "down", "up"))
    for k, name, rx, tx in rows:
        print("%-9s %-16s %10.2f %10.2f" % (k, name, rx, tx))

    def total(kinds, idx):
        return sum(r[idx] for r in rows if r[0] in kinds)

    phys = total({"physical"}, 2)
    if phys < 0.05:
        print("\nAlmost no traffic on the real interface: was the speed test running?")
        return 1
    everything = total({"physical", "tunnel", "loopback", "other"}, 2)
    no_lo = total({"physical", "tunnel", "other"}, 2)
    print("\nDownload seen by the phone's counters, compared with the real interface (%.2f MB/s = 1.0x):" % phys)
    print("  physical + tunnel                  %.1fx   (what almost every VPN shows: tunnel and real link both count)" % (no_lo / phys))
    print("  physical + tunnel + loopback       %.1fx   (a meter that counts loopback too)" % (everything / phys))
    print("  loopback alone                     %.1fx   (roughly the number of local hops inside the app)" % (total({"loopback"}, 2) / phys))
    return 0


if __name__ == "__main__":
    sys.exit(main())
