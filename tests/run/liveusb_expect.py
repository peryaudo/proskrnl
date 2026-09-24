#!/usr/bin/env python3
"""liveusb_expect.py - drive the LIVE-1 stick's serial cmd.exe (docs/02 "LIVE-1").

The liveusb leg (tests/run/run.sh liveusb) boots the product stick as a USB
drive with the desktop stack up and the session on the serial console
(GUEST_INTERACTIVE=1 GUEST_SERIAL=1 -- the `make rungui` session with a
prompt instead of explorer, so a script can type at it). This connects to
QEMU's serial unix socket, tees every byte into the log (the harness greps
the kernel's own lines out of it afterwards), and at the prompt:

  1. writes a file on C: -- the memdisk -- through a pipe whose transform
     only the guest can apply (upcase.exe), and reads it back: the RAM copy
     takes writes;
  2. starts two applets off the `make rungui` shelf, notepad and winemine,
     each of which must become a desktop client, put a window of its own on
     the framebuffer, and still be running afterwards (tasklist);
  3. types `exit`: smss returns and the kernel powers the machine off
     (ACPI S5), which is what lets the harness compare the stick's bytes
     after the boot with the bytes before it.

Every asserted string is chosen so the TYPED command line cannot supply it
(console_expect.py's rule; conhost's screen diff interleaves escapes, so
matching is the same ordered-subsequence test).

Exit 0 = every step seen; 1 = timeout/mismatch (stderr names the miss).
"""

import os
import re
import socket
import sys
import time

def subsequence(needle: bytes, hay: bytes) -> bool:
    """TRUE when needle's bytes appear in hay in order (greedy, O(len(hay)):
    console_expect.py's Tolerant, for the same backtracking reason)."""
    i = 0
    for j in range(len(needle)):
        i = hay.find(needle[j:j + 1], i)
        if i < 0:
            return False
        i += 1
    return True


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: liveusb_expect.py <serial-sock> <log>", file=sys.stderr)
        return 2
    sock_path, log_path = sys.argv[1], sys.argv[2]

    # A VIRGIN boot: the stick's system disk has never run, so the firstboot
    # INF pass (minutes under TCG) sits in front of the prompt -- every live
    # boot pays it, because nothing a boot writes survives it.
    deadline = time.monotonic() + float(os.environ.get("EXPECT_DEADLINE", "1200"))
    sock = None
    while time.monotonic() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(sock_path)
            break
        except OSError:
            sock = None
            time.sleep(0.2)
    if sock is None:
        print("liveusb_expect: cannot connect to the serial socket", file=sys.stderr)
        return 1
    sock.settimeout(0.5)

    log = open(log_path, "wb")
    buffered = bytearray()
    closed = False

    def pump_until(predicate, what: str, quiet: bool = False) -> bool:
        nonlocal closed
        while time.monotonic() < deadline and not closed:
            if predicate(buffered):
                return True
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                closed = True
                break
            if not data:
                closed = True
                break
            buffered.extend(data)
            log.write(data)
            log.flush()
        if predicate(buffered):
            return True
        if not quiet:
            print(f"liveusb_expect: never saw {what}", file=sys.stderr)
        return False

    def expect_after(mark: int, text: bytes, what: str) -> bool:
        return pump_until(lambda b: subsequence(text, bytes(b[mark:])), what)

    def command(cmdline: bytes, expect: bytes, what: str) -> bool:
        mark = len(buffered)
        sock.sendall(cmdline + b"\r")
        return expect_after(mark, expect, what)

    if not pump_until(lambda b: b"interactive console - starting cmd.exe" in b,
                      "the serial console session"):
        return 1
    if not expect_after(0, b"C:\\>", "the first prompt"):
        return 1

    # 1. A write to the memdisk and the read back. Typed lower case; only
    #    upcase.exe can put the upper-case word on the volume.
    if not command(b"echo liveproof | C:\\upcase.exe > C:\\live.txt", b"C:\\>",
                   "the prompt after the write"):
        return 1
    if not command(b"type C:\\live.txt", b"LIVEPROOF", "the file read back off the memdisk"):
        return 1

    # 2. Two applets off the shelf (the whole shelf's presence is checked
    #    on the stick's system disk by the harness, where no screen diff
    #    stands between the listing and the check).
    # `start` is itself a desktop client (start.exe attaches and leaves), so
    # the applet is the SECOND attach after the typed line, and its window
    # is told apart from the ones already up by its size: each applet must
    # flush a window of a size no earlier window had (winefb's window line
    # carries no owner; notepad's frame and winemine's board differ).
    window_re = re.compile(rb"\[KTEST\] gui2 window rect=-?\d+,-?\d+,(\d+x\d+) ")
    attach = b"[KTEST] gui3 client attached pid="
    seen_sizes = set(window_re.findall(bytes(buffered)))
    for applet in (b"notepad", b"winemine"):
        name = applet.decode()
        mark = len(buffered)
        sock.sendall(b"start " + applet + b"\r")
        if not pump_until(lambda b: bytes(b[mark:]).count(attach) >= 2,
                          f"{name} attaching to the desktop"):
            return 1
        if not pump_until(lambda b: any(size not in seen_sizes
                                        for size in window_re.findall(bytes(b[mark:]))),
                          f"a window of {name}'s own"):
            return 1
        seen_sizes |= set(window_re.findall(bytes(buffered)))

    # Both still running (neither died after its first paint): tasklist's
    # rows, matched as literal image names -- conhost draws a row's text
    # contiguously, and an ordered-subsequence test over a whole listing
    # would be satisfied by the serial noise alone.
    mark = len(buffered)
    sock.sendall(b"tasklist\r")
    for image in (b"notepad.exe", b"winemine.exe"):
        if not pump_until(lambda b: image in bytes(b[mark:]).lower(),
                          f"{image.decode()} in tasklist"):
            return 1

    # 3. Power off. The socket closes when QEMU exits.
    sock.sendall(b"exit\r")
    pump_until(lambda b: False, "EOF", quiet=True)  # drain to EOF / the deadline
    if not closed:
        print("liveusb_expect: the machine never powered off after exit", file=sys.stderr)
        return 1
    print("liveusb_expect: all steps seen", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
