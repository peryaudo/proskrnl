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
verdict grep are unchanged; and send anything that appears on <fifo>.

The caller writes a line TERMINATED WITH CR, not LF: conhost's line editor
submits on VK_RETURN, and a received '\n' arrives as VK_RETURN with
LEFT_CTRL_PRESSED, which misses the only keymap carrying VK_RETURN and gets
inserted into the line as a character instead. Whatever the caller writes is
forwarded verbatim, so getting that wrong looks exactly like a guest that
ignored the command.

One process holds the connection because a QEMU socket chardev serves one
client at a time -- a second connection would be refused, which is why the
caller cannot simply open the socket itself for each line it wants to send.

Exits 0 when the socket closes (the guest powered off), which is the normal
end of a run.
"""
import os
import socket
import sys
import time
import threading


def main():
    if len(sys.argv) != 4:
        print("usage: serial_drive.py <serial-sock> <log> <fifo>", file=sys.stderr)
        return 2
    sock_path, log_path, fifo_path = sys.argv[1:4]

    # Retry the connect, and say so if it never lands. The caller's readiness
    # test is "the socket file exists", which becomes true at QEMU's bind() --
    # a connect() landing before listen() is refused. Exiting silently there
    # is worse than the failed trial it causes: the caller's next write to the
    # fifo blocks in open(O_WRONLY) waiting for a reader that will never come,
    # and the whole trial loop wedges with no output. console_expect.py:34-44
    # retries for the same reason.
    deadline = 60
    sock = None
    for _ in range(deadline * 4):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sock_path)
            break
        except OSError:
            sock.close()
            sock = None
            time.sleep(0.25)
    if sock is None:
        print("serial_drive: cannot connect to %s after %ds" % (sock_path, deadline),
              file=sys.stderr)
        return 1

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
