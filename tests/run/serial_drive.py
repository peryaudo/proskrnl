#!/usr/bin/env python3
"""serial_drive.py <serial-sock> <log> <fifo> — hold the guest's serial
console open for a leg that also drives QMP.

tools/qemu.sh with SERIAL_SOCK gives the guest's console a unix socket
instead of a log file, and something on the host has to read it or the guest
blocks on a full pipe. console_expect.py does that for the legs whose whole
interaction is a script; this is for the legs that need the console AND the
QMP monitor at the same time (tests/flash), where a single scripted
conversation cannot express "type this, now screendump, now type that".

So: read the socket forever and tee it into <log>, exactly as
console_expect.py does, so the caller's existing greps and tools/qemu.sh's
verdict grep are unchanged; and send anything that appears on <fifo>, so the
caller types with a plain `echo 'dir' > "$fifo"`.

One process holds the connection because a QEMU socket chardev serves one
client at a time -- a second connection would be refused, which is why the
caller cannot simply open the socket itself for each line it wants to send.

Exits 0 when the socket closes (the guest powered off), which is the normal
end of a run.
"""
import os
import socket
import sys
import threading


def main():
    if len(sys.argv) != 4:
        print("usage: serial_drive.py <serial-sock> <log> <fifo>", file=sys.stderr)
        return 2
    sock_path, log_path, fifo_path = sys.argv[1:4]

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)

    if not os.path.exists(fifo_path):
        os.mkfifo(fifo_path)

    def pump():
        # Opening a fifo for reading blocks until a writer appears, and read()
        # returns empty every time the last writer closes -- so reopen rather
        # than treating that as end of input. The caller's `echo` is one such
        # writer per line.
        while True:
            try:
                with open(fifo_path, "rb") as fifo:
                    for line in fifo:
                        sock.sendall(line)
            except OSError:
                return

    threading.Thread(target=pump, daemon=True).start()

    with open(log_path, "wb") as log:
        while True:
            try:
                data = sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            log.write(data)
            log.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
