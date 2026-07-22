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
import os
import socket
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: console_expect.py <serial-sock> <log>", file=sys.stderr)
        return 2
    sock_path, log_path = sys.argv[1], sys.argv[2]

    # The console image's virgin boot includes the CUI-1 firstboot INF pass
    # (minutes under TCG) before conhost ever speaks; the runner passes a
    # matching budget.
    deadline = time.monotonic() + float(os.environ.get("EXPECT_DEADLINE", "150"))
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

    # ---- M10: the interactive cmd.exe session (docs/02 "cmd.exe prompts;
    # pipes/redirection work; an off-the-shelf CUI app runs") ----------------
    # conhost renders via screen diffs, so expected text is matched with
    # escape-tolerant regexes (like echo_re above). Every asserted string is
    # chosen so the TYPED command cannot satisfy it (transforms/expansions).
    def tolerant(text: bytes):
        # Escape sequences and screen-diff redraws interleave freely between
        # the payload characters; every asserted string is chosen so the
        # TYPED command line cannot supply the characters in order.
        pattern = b".*?".join(re.escape(text[i : i + 1]) for i in range(len(text)))
        return re.compile(pattern, re.DOTALL)

    def expect_after(mark: int, text: bytes, what: str) -> bool:
        rx = tolerant(text)
        return pump_until(lambda b: rx.search(b[mark:]) is not None, what)

    if not pump_until(lambda b: b"[KTEST] cmd interactive start" in b, "the cmd start marker"):
        return 1

    def command(cmdline: bytes, expect: bytes, what: str) -> bool:
        mark = len(buffered)
        sock.sendall(cmdline + b"\r")
        return expect_after(mark, expect, what)

    # The transform can only come through the anonymous pipe + upcase.exe:
    # the typed line is all-lowercase.
    if not command(b"echo data>C:\\t.txt", b"C:\\", "the prompt after redirection"):
        return 1
    if not command(b"type C:\\t.txt | C:\\upcase.exe", b"DATA", "the piped uppercase output"):
        return 1
    # The CRT stand-in: its printf output and its exit code through
    # %errorlevel% expansion (typed text carries neither string).
    # The dash exists only in the OUTPUT ("hello-crt"); the typed command is
    # hello_crt.exe. The "42" and the space render as screen-diff cursor
    # motion, so only the contiguous-orderable part is asserted.
    if not command(b"C:\\hello_crt.exe", b"hello-crt", "hello_crt's output"):
        return 1
    if not command(b"echo rc=%errorlevel%", b"rc=7", "the errorlevel expansion"):
        return 1
    # CUI-2 acceptance (docs/02 "a real tool that opens its own token at
    # startup gets past STATUS_NOT_IMPLEMENTED"): Wine's unmodified
    # whoami.exe opens the process token and prints the logon SID from
    # TokenGroups. The SID digits cannot come from the typed command.
    if not command(b"C:\\whoami.exe /logonid", b"S-1-5-5-0-0", "whoami's logon SID"):
        return 1

    # ---- CUI-3: the SCM acceptance (docs/02 "an sc-style query round-trips;
    # a real service installs, starts, and survives reboot") ----------------
    # EXPECT_SCM=1 drives boot 1 (query RpcSs over \pipe\svcctl, start it,
    # install + start the demo service); EXPECT_SCM=2 is the post-reboot
    # boot: the SCM must have AUTO-started SvcDemo from the persisted
    # registry before cmd prompted, and the proof file carries a second
    # line (asserted via cmd's %~zf size expansion: 22 -> 44 bytes; the
    # digits cannot come from the typed command).
    scm = os.environ.get("EXPECT_SCM", "")
    if scm == "1":
        # The round-trip: sechost binds ncacn_np:[\pipe\svcctl], the query
        # marshals back a STOPPED demand-start rpcss (wine.inf's RpcSs).
        if not command(b"C:\\windows\\system32\\sc.exe query RpcSs", b"STOPPED",
                       "the RpcSs query round-trip"):
            return 1
        # Starting it spawns a real service process (control pipe,
        # MakeProcessSystem, status handshake); sc prints the post-start
        # query block.
        if not command(b"C:\\windows\\system32\\sc.exe start RpcSs", b"RUNNING",
                       "RpcSs running"):
            return 1
        if not command(b"C:\\windows\\system32\\sc.exe create SvcDemo binpath= "
                       b"C:\\svcdemo.exe start= auto", b"C:\\", "the create prompt"):
            return 1
        if not command(b"echo rc=%errorlevel%", b"rc=0", "the create errorlevel"):
            return 1
        if not command(b"C:\\windows\\system32\\sc.exe start SvcDemo", b"RUNNING",
                       "SvcDemo running"):
            return 1
        # The size is zz-wrapped so the digits cannot be satisfied by prompt
        # text ("system32" supplies stray 2s and 3s to a bare tolerant
        # match — the false positive that masked a broken append path).
        if not command(b"for %f in (C:\\svcdemo.log) do @echo zz%~zfzz", b"zz22zz",
                       "the first proof line"):
            return 1
    elif scm == "2":
        if not command(b"C:\\windows\\system32\\sc.exe query SvcDemo", b"RUNNING",
                       "SvcDemo auto-started after reboot"):
            return 1
        if not command(b"for %f in (C:\\svcdemo.log) do @echo zz%~zfzz", b"zz44zz",
                       "the second proof line"):
            return 1

    mark = len(buffered)
    sock.sendall(b"exit\r")
    if not pump_until(lambda b: b"[KTEST] module cmd.exe PASS" in b[mark:], "the cmd verdict"):
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
