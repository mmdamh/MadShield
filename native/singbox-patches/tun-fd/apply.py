#!/usr/bin/env python3
"""Lets sing-box's `tun` inbound use a TUN file descriptor that the Android app already owns.

Why: on Android the app (VpnService) creates the TUN device; sing-box has no config field for an existing fd
(only libbox's platform interface sets tun.Options.FileDescriptor). sing-box runs here as a separate process
(an Android ProcessBuilder child does not inherit extra fds), so the app sends the fd over a unix socket
(SCM_RIGHTS) and this patch receives it right before the TUN device is opened.

Behaviour: when the environment variable MADSHIELD_TUN_FD_SOCKET holds a socket path, the inbound connects to
it, receives ONE fd, makes it non-blocking (sing-tun's own stack polls it with epoll and does not do that for a
fd it did not open) and passes it as tun.Options.FileDescriptor. Without the variable nothing changes.

Safety: the target text must occur EXACTLY once or the script exits non-zero and the build fails; nothing is
patched blindly after a pin bump.

usage: apply.py <sing-box source dir>
"""
import sys, pathlib

root = pathlib.Path(sys.argv[1])
inbound = root / "protocol" / "tun" / "inbound.go"
s = inbound.read_text()
old = "\t\t\ttunInterface, err = tun.New(tunOptions)\n"
new = "\t\t\ttunInterface, err = madshieldOpenTun(&tunOptions) // MadShield: tun fd handoff, see native/singbox-patches/tun-fd\n"
if "madshieldOpenTun" in s:
    sys.exit("already patched")
if s.count(old) != 1:
    sys.exit(f"ERROR: expected exactly one match in {inbound}, found {s.count(old)}; the pinned sing-box changed, re-check this patch")
inbound.write_text(s.replace(old, new, 1))

LINUX = '''//go:build linux

package tun

import (
	"net"
	"os"
	"time"

	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// MadShield: see native/singbox-patches/tun-fd/apply.py.
func madshieldOpenTun(options *tun.Options) (tun.Tun, error) {
	path := os.Getenv("MADSHIELD_TUN_FD_SOCKET")
	if path == "" {
		return tun.New(*options)
	}
	fd, err := madshieldReceiveTunFD(path)
	if err != nil {
		return nil, E.Cause(err, "receive tun fd from the app")
	}
	options.FileDescriptor = fd
	// A VpnService fd has no IFF_VNET_HDR: do not even try the GSO ioctls.
	options.GSO = false
	return tun.New(*options)
}

func madshieldReceiveTunFD(path string) (int, error) {
	conn, err := net.DialTimeout("unix", path, 10*time.Second)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, E.New("not a unix connection")
	}
	_ = unixConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unixConn.ReadMsgUnix(data, oob)
	if err != nil {
		return -1, err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	received := -1
	for i := range messages {
		fds, err := unix.ParseUnixRights(&messages[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if received == -1 {
				received = fd
			} else {
				_ = unix.Close(fd)
			}
		}
	}
	if received == -1 {
		return -1, E.New("no file descriptor in the message")
	}
	err = unix.SetNonblock(received, true)
	if err != nil {
		_ = unix.Close(received)
		return -1, err
	}
	return received, nil
}
'''
OTHER = '''//go:build !linux

package tun

import tun "github.com/sagernet/sing-tun"

// MadShield: the fd handoff is Linux/Android only.
func madshieldOpenTun(options *tun.Options) (tun.Tun, error) {
	return tun.New(*options)
}
'''
(root / "protocol" / "tun" / "madshield_fd_linux.go").write_text(LINUX)
(root / "protocol" / "tun" / "madshield_fd_other.go").write_text(OTHER)
print("patched", inbound, "and added madshield_fd_linux.go / madshield_fd_other.go")
