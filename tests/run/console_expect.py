#!/usr/bin/env python3
"""console_expect.py - drive the M9 interactive serial console (docs/02).

Connects to the QEMU serial unix socket (tools/qemu.sh SERIAL_SOCK), tees
every byte it reads into the log file (so tools/qemu.sh's verdict grep works
unchanged - the docs/08 loop keeps its shape), waits for m9_echo's ready
marker, types "ping\\r", and asserts:

  1. conhost's line-discipline ECHO puts the typed characters back on the
     wire (ANSI escapes may interleave - the regex tolerates them);
  2. the cooked line reaches m9_echo ("m9_echo: got ping");
  3. the boot suite's [KTEST] M9 PASS verdict was emitted.

Exit 0 = all three seen; 1 = timeout/mismatch (the log names the miss).
"""

import re
import socket
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: console_expect.py <serial-sock> <log>", file=sys.stderr)
        return 2
    sock_path, log_path = sys.argv[1], sys.argv[2]

    deadline = time.monotonic() + float(60)
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
        print("console_expect: cannot connect to the serial socket", file=sys.stderr)
        return 1
    sock.settimeout(0.5)

    log = open(log_path, "wb")
    buffered = bytearray()

    def pump_until(predicate, what: str) -> bool:
        while time.monotonic() < deadline:
            if predicate(buffered):
                return True
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buffered.extend(data)
            log.write(data)
            log.flush()
        ok = predicate(buffered)
        if not ok:
            print(f"console_expect: never saw {what}", file=sys.stderr)
        return ok

    if not pump_until(lambda b: b"m9_echo: ready" in b, "the ready marker"):
        return 1
    mark = len(buffered)

    sock.sendall(b"ping\r")

    # conhost echoes the keystrokes (escape sequences may interleave).
    echo_re = re.compile(rb"p[^i]*?i[^n]*?n[^g]*?g")
    if not pump_until(lambda b: echo_re.search(b[mark:]) is not None, "the conhost echo"):
        return 1
    # The cooked-line proof is m9_echo's own verdict: it exits 0 only when
    # ReadFile handed it exactly "ping" (conhost's screen-diff renderer does
    # not replay literal bytes, so the wire text is not asserted directly).
    if not pump_until(lambda b: b"[KTEST] module m9_echo.exe PASS" in b, "the echo verdict"):
        return 1
    if not pump_until(lambda b: b"[KTEST] M9 PASS" in b, "the M9 verdict"):
        return 1

    # Drain until QEMU exits so the log carries the whole run.
    end = time.monotonic() + 10
    while time.monotonic() < end:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        log.write(data)
        log.flush()
    print("console_expect: echo + cooked line + verdict all seen")
    return 0


if __name__ == "__main__":
    sys.exit(main())
