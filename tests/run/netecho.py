#!/usr/bin/env python3
"""netecho.py — the net leg's TCP echo server (tests/run/run.sh net).

Binds an ephemeral port on host loopback, writes the port number to the
file named by argv[1] (the leg reads it and hands it to the guest over
fw_cfg — tools/qemu.sh NET_ECHO_PORT), then echoes every connection's
bytes back until killed. The guest reaches it through slirp's host alias
10.0.2.2 (pinned QEMU docs/system/devices/net.rst, "Using the user mode
network stack").

stdlib only, like every tests/run helper.
"""

import socket
import sys
import threading


def serve(conn):
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)


def main():
    portfile = sys.argv[1]
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    with open(portfile, "w", encoding="ascii") as handle:
        handle.write("%d\n" % server.getsockname()[1])
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
