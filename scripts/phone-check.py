#!/usr/bin/env python3
"""
MadShield phone check -- run it in Termux ON THE PHONE while the VPN (or Proxy Only) is connected.

    pkg install python
    python phone-check.py            # default port 1819
    python phone-check.py 1819

It only talks to 127.0.0.1 and, through the app's own SOCKS port, to a few public services. It changes nothing.
Python standard library only.

What it measures (these are the things any OTHER app on the phone could do, because the ports are open to every app):
  1. Which of the app's local ports answer a SOCKS5 greeting, and whether they ask for a password (they do not).
  2. The exit address seen through the TCP path of the app's SOCKS port.
  3. Whether UDP works through the app: a DNS question sent with SOCKS5 UDP ASSOCIATE.
        refused 0x07  -> the app itself refuses UDP: UDP Support is off in Settings, or the chain is Psiphon/Tor (see FrontPlan.kt)
        no answer     -> the app passed it on, but the chain/server dropped it (typical for a vless server on Workers)
        answer        -> UDP works; the exit address of the UDP path is printed too
     UDP is what Telegram voice calls, WhatsApp calls, games and QUIC need.
  4. Manual steps for the Kill Switch (printed at the end; they need your fingers, not a script).
"""
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
TIMEOUT = 6.0


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def greeting(port):
    """Open the port, offer 'no authentication' only. Returns the method byte the server picks, or None."""
    try:
        s = socket.create_connection((HOST, port), timeout=2.0)
    except OSError:
        return "closed"
    try:
        s.settimeout(3.0)
        s.sendall(b"\x05\x01\x00")
        rep = recv_exact(s, 2)
        if rep[0] != 5:
            return "not-socks"
        return rep[1]
    except (OSError, ConnectionError):
        return "no-answer"
    finally:
        s.close()


def socks_connect_name(port, name, dport):
    s = socket.create_connection((HOST, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        raise ConnectionError("server wants authentication or refused")
    nb = name.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(nb)]) + nb + struct.pack(">H", dport))
    head = recv_exact(s, 4)
    if head[1] != 0:
        raise ConnectionError("CONNECT refused, reply code 0x%02x" % head[1])
    atyp = head[3]
    recv_exact(s, {1: 4, 4: 16}.get(atyp, 0) if atyp != 3 else recv_exact(s, 1)[0])
    recv_exact(s, 2)
    return s


def http_get_ip(port):
    last = "no answer"
    for host in ("api.ipify.org", "ifconfig.me"):
        try:
            c = socks_connect_name(port, host, 80)
            c.sendall(("GET /ip HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n" % host).encode()
                      if host == "ifconfig.me" else
                      ("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
            buf = b""
            while True:
                try:
                    d = c.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                buf += d
            c.close()
            body = buf.split(b"\r\n\r\n", 1)[-1].strip().decode(errors="replace")
            if body:
                return body.splitlines()[-1].strip(), None
        except (OSError, ConnectionError) as e:
            last = str(e)
    return None, last


def dns_query(name, qtype):
    tid = 0x4D53
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1), tid


def parse_dns_txt_or_a(msg):
    """Return the first TXT string or A address in the answer section, or None."""
    try:
        an = struct.unpack(">H", msg[6:8])[0]
        i = 12
        qd = struct.unpack(">H", msg[4:6])[0]
        for _ in range(qd):
            while msg[i] != 0:
                i += 1 + msg[i]
            i += 5
        for _ in range(an):
            if msg[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while msg[i] != 0:
                    i += 1 + msg[i]
                i += 1
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
            i += 10
            rd = msg[i:i + rdlen]
            i += rdlen
            if rtype == 16 and rd:
                return rd[1:1 + rd[0]].decode(errors="replace")
            if rtype == 1 and len(rd) == 4:
                return ".".join(str(b) for b in rd)
    except (IndexError, struct.error):
        return None
    return None


def udp_dns(port, server, name, qtype):
    """SOCKS5 UDP ASSOCIATE, then one DNS question to server:53. Returns (status, text)."""
    ctrl = socket.create_connection((HOST, port), timeout=TIMEOUT)
    ctrl.settimeout(TIMEOUT)
    try:
        ctrl.sendall(b"\x05\x01\x00")
        if recv_exact(ctrl, 2) != b"\x05\x00":
            return "error", "server wants authentication"
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        head = recv_exact(ctrl, 4)
        if head[1] != 0:
            return "refused", "reply code 0x%02x" % head[1]
        atyp = head[3]
        if atyp == 1:
            baddr = socket.inet_ntoa(recv_exact(ctrl, 4))
        elif atyp == 4:
            baddr = socket.inet_ntop(socket.AF_INET6, recv_exact(ctrl, 16))
        else:
            recv_exact(ctrl, recv_exact(ctrl, 1)[0])
            baddr = HOST
        bport = struct.unpack(">H", recv_exact(ctrl, 2))[0]
        if baddr in ("0.0.0.0", "::"):
            baddr = HOST
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(TIMEOUT)
        query, tid = dns_query(name, qtype)
        dst = socket.inet_aton(server)
        u.sendto(b"\x00\x00\x00\x01" + dst + struct.pack(">H", 53) + query, (baddr, bport))
        try:
            data, _ = u.recvfrom(4096)
        except socket.timeout:
            return "silent", "no answer within %ds" % TIMEOUT
        finally:
            u.close()
        # strip the SOCKS5 UDP header (RSV RSV FRAG ATYP ADDR PORT)
        a = data[3]
        off = 4 + (4 if a == 1 else 16 if a == 4 else 1 + data[4]) + 2
        txt = parse_dns_txt_or_a(data[off:])
        return "answer", txt or "(answer without a readable record)"
    except (OSError, ConnectionError) as e:
        return "error", str(e)
    finally:
        ctrl.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1819
    print("MadShield phone check, SOCKS port %d\n" % port)

    print("1) Local ports (answer a SOCKS5 greeting without any password?)")
    open_ports = []
    for p in sorted({1819, 1823, 1824, port}):
        g = greeting(p)
        if g == 0:
            print("   %5d  OPEN, no password asked   <- any app on this phone can use it" % p)
            open_ports.append(p)
        elif g == "closed":
            print("   %5d  closed (normal for ports that this mode does not use)" % p)
        elif g == 0xFF:
            print("   %5d  refuses 'no authentication' (good)" % p)
        else:
            print("   %5d  %s" % (p, g))
    if port not in open_ports:
        print("\nPort %d is not open without a password: connect first, or pass the port as an argument." % port)
        return

    print("\n2) TCP exit address through port %d" % port)
    ip, err = http_get_ip(port)
    print("   exit address: %s" % (ip if ip else "failed (%s)" % err))

    print("\n3) UDP through port %d (DNS question over SOCKS5 UDP ASSOCIATE)" % port)
    results = []
    for server in ("1.1.1.1", "8.8.8.8"):
        status, text = udp_dns(port, server, "example.com", 1)
        print("   example.com A via %-8s -> %s: %s" % (server, status, text))
        results.append(status)
    status, text = udp_dns(port, "8.8.8.8", "o-o.myaddr.l.google.com", 16)
    print("   UDP exit address (Google DNS view) -> %s: %s" % (status, text))
    if ip and status == "answer" and text and text.split(",")[0].strip().strip('"') == ip:
        print("   -> the UDP path leaves from the SAME address as TCP (no UDP leak)")
    elif ip and status == "answer":
        print("   -> UDP leaves from a DIFFERENT address than TCP: check that the UDP path is the tunnel")

    print()
    if all(r == "answer" for r in results):
        print("Result: UDP works through the app.")
    elif "refused" in results:
        print("Result: the app REFUSES UDP (reply 0x07): UDP Support is off, or the chain is Psiphon/Tor. Calls over UDP cannot connect.")
        print("        Chain + DoH or routing rules turn the front on; see FrontPlan.kt. Turn DoH and the rules off to test.")
    elif "silent" in results:
        print("Result: UDP was accepted by the app but nothing came back: the chain or the server drops UDP.")
        print("        A vless server on Cloudflare Workers usually carries UDP DNS at most, not call traffic.")
    else:
        print("Result: UDP test failed (%s)." % ", ".join(results))

    print("""
4) Kill Switch checks that need you (the script cannot do them):
   a. Connect with Kill Switch ON. Open any page that shows your IP address and note it.
   b. Android Settings > Apps > MadShield > Force stop. Look at the same site again.
      If it now shows your REAL address, the Kill Switch died with the app process. Only Android's
      'Always-on VPN' + 'Block connections without VPN' prevents that (Settings > Protection shows a hint).
   c. Open MadShield again and connect; switch Always-on + Block on and repeat b: the site must not load at all.
""")


if __name__ == "__main__":
    main()
