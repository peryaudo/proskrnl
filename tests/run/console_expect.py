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

    def pump_until(predicate, what: str, until: float | None = None,
                   quiet: bool = False) -> bool:
        stop = deadline if until is None else min(deadline, until)
        while time.monotonic() < stop:
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
        if not ok and not quiet:
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

    def command_poll(cmdline: bytes, expect: bytes, what: str) -> bool:
        # For state that CONVERGES rather than prints once: retype the
        # command until its output matches. NT's start contract makes the
        # single-shot form a race — StartServiceW may return while the
        # service is still START_PENDING (services.c
        # service_wait_for_startup accepts it), and sc.exe queries exactly
        # once — so the old expect only passed when the service body beat
        # sc's two \pipe\svcctl round-trips (it lost once the CUI-8 await
        # park let sc run during the service's disk append). A real client
        # polls; so does this.
        rx = tolerant(expect)
        while time.monotonic() < deadline:
            mark = len(buffered)
            sock.sendall(cmdline + b"\r")
            if pump_until(lambda b: rx.search(b[mark:]) is not None, what,
                          until=time.monotonic() + 5.0, quiet=True):
                # Settle: a retyped attempt may still be executing when a
                # late previous answer matched; absorb its tail so the next
                # command's mark starts clean.
                pump_until(lambda b: False, what,
                           until=time.monotonic() + 1.0, quiet=True)
                return True
        print(f"console_expect: never saw {what}", file=sys.stderr)
        return False

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
    # boot: the SCM must AUTO-start SvcDemo from the persisted registry
    # with no start typed here, and the proof file carries a second
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
        # query block (WAIT_HINT closes it in every state — the typed line
        # cannot supply the underscore), then a query poll convicts
        # RUNNING: sc's one-shot post-start query may legally see
        # START_PENDING (command_poll above).
        if not command(b"C:\\windows\\system32\\sc.exe start RpcSs", b"WAIT_HINT",
                       "the RpcSs start status block"):
            return 1
        if not command_poll(b"C:\\windows\\system32\\sc.exe query RpcSs", b"RUNNING",
                            "RpcSs running"):
            return 1
        if not command(b"C:\\windows\\system32\\sc.exe create SvcDemo binpath= "
                       b"C:\\svcdemo.exe start= auto", b"C:\\", "the create prompt"):
            return 1
        if not command(b"echo rc=%errorlevel%", b"rc=0", "the create errorlevel"):
            return 1
        if not command(b"C:\\windows\\system32\\sc.exe start SvcDemo", b"WAIT_HINT",
                       "the SvcDemo start status block"):
            return 1
        if not command_poll(b"C:\\windows\\system32\\sc.exe query SvcDemo", b"RUNNING",
                            "SvcDemo running"):
            return 1
        # The size is zz-wrapped so the digits cannot be satisfied by prompt
        # text ("system32" supplies stray 2s and 3s to a bare tolerant
        # match — the false positive that masked a broken append path).
        if not command(b"for %f in (C:\\svcdemo.log) do @echo zz%~zfzz", b"zz22zz",
                       "the first proof line"):
            return 1
    elif scm == "2":
        # The autostart runs concurrently with the console session's own
        # startup — nothing serializes it before cmd's prompt, so poll.
        # Only the SCM can move SvcDemo to RUNNING (nothing here types a
        # start), so the poll still convicts the registry-driven autostart.
        if not command_poll(b"C:\\windows\\system32\\sc.exe query SvcDemo", b"RUNNING",
                            "SvcDemo auto-started after reboot"):
            return 1
        if not command(b"for %f in (C:\\svcdemo.log) do @echo zz%~zfzz", b"zz44zz",
                       "the second proof line"):
            return 1

    # ---- CUI-4: the process ecosystem (docs/02 "a tasklist/taskkill pair
    # works against live processes; Ctrl+C interrupts a loop under cmd.exe;
    # a job-object-using build tool completes") ----------------------------
    if os.environ.get("EXPECT_PROCS", ""):
        # 1. Ctrl+C interrupts a BUSY loop. looper.exe installs a console
        #    control handler and then spins without any blocking call, so
        #    only the real delivery path can reach it: the kernel sees ^C on
        #    the console transport and starts a thread in the process at
        #    ntdll's __wine_ctrl_routine. The handler prints the marker; its
        #    digits and dashes cannot come from the typed command line.
        mark = len(buffered)
        sock.sendall(b"C:\\looper.exe\r")
        if not expect_after(mark, b"loop-alive", "the looper's start marker"):
            return 1
        mark = len(buffered)
        sock.sendall(b"\x03")
        if not expect_after(mark, b"loop-caught-1", "the Ctrl+C handler marker"):
            return 1
        # cmd survives the interrupt and keeps prompting; the looper's exit
        # code (77, set by its handler) proves it died through the handler
        # rather than by any other route.
        if not command(b"echo rc=%errorlevel%", b"rc=77", "the interrupted exit code"):
            return 1

        # 2. tasklist lists live processes — its parent cmd among them.
        #    tasklist prints each image name as the process carries it, so
        #    this one is lowercase. The typed line
        #    ("C:\windows\system32\tasklist.exe") holds no lowercase 'c', so
        #    it cannot supply "cmd.exe" in order under the tolerant match.
        if not command(b"C:\\windows\\system32\\tasklist.exe", b"cmd.exe",
                       "tasklist listing cmd.exe"):
            return 1

        # 3. taskkill /f kills a live process. The looper detaches a copy of
        #    itself (`--spawn`) so the shell gets its prompt back with a live
        #    process to kill — cmd's `start` cannot serve, it delegates to
        #    system32\start.exe, which proskrnl does not bake. The kill goes
        #    by image name; taskkill resolves it through the same snapshot
        #    tasklist walks.
        mark = len(buffered)
        sock.sendall(b"C:\\looper.exe --spawn\r")
        if not expect_after(mark, b"loop-alive", "the background looper"):
            return 1
        if not command(b"C:\\windows\\system32\\taskkill.exe /f /im looper.exe", b"C:\\",
                       "the prompt after taskkill"):
            return 1
        if not command(b"echo rc=%errorlevel%", b"rc=0", "taskkill's exit code"):
            return 1
        # The killed looper is gone: a second kill finds nothing. Asserted in
        # two steps — cmd expands %errorlevel% when it PARSES the line, so a
        # `cmd & echo %errorlevel%` one-liner reports the PREVIOUS command's
        # code, not this one's. "Could not find" is unsatisfiable by the typed
        # line, which holds no 'u'.
        if not command(b"C:\\windows\\system32\\taskkill.exe /f /im looper.exe",
                       b"Could not find", "taskkill reporting no such process"):
            return 1
        if not command(b"echo zz%errorlevel%zz", b"zz128zz",
                       "taskkill's not-found exit code"):
            return 1

        # 4. The job-object build tool: children assigned to a job with
        #    KILL_ON_JOB_CLOSE, read back through the job's own accounting,
        #    then reaped by closing the last job handle.
        mark = len(buffered)
        sock.sendall(b"C:\\jobtool.exe\r")
        if not expect_after(mark, b"jobtool-active-2", "the job's live member count"):
            return 1
        if not expect_after(mark, b"jobtool-done-2", "the kill-on-close cleanup"):
            return 1

    # ---- CUI-5: the file-surface acceptance (docs/02 "move/ren work under
    # cmd.exe; a write-tmp-then-rename tool completes") ---------------------
    if os.environ.get("EXPECT_FILES", ""):
        # 1. ren: the proof travels through the RENAMED name. The dash in
        #    "ren-proof" cannot come from any typed line below.
        if not command(b"echo ren-proof>C:\\renin.txt", b"C:\\", "the prompt after ren setup"):
            return 1
        if not command(b"ren C:\\renin.txt renout.txt", b"C:\\", "the prompt after ren"):
            return 1
        if not command(b"type C:\\renout.txt", b"ren-proof", "the renamed file's content"):
            return 1
        # The old name is gone (type fails; the digit cannot come from the
        # typed line — the scm block's zz-wrap pattern).
        if not command(b"type C:\\renin.txt", b"C:\\", "the prompt after the stale type"):
            return 1
        if not command(b"echo zz%errorlevel%zz", b"zz1zz", "the stale name's errorlevel"):
            return 1
        # 2. move across directories (kernelbase MoveFileW ->
        #    FileRenameInformation; the FAT '..' rewrite rides along).
        if not command(b"mkdir C:\\mvdir", b"C:\\", "the prompt after mkdir"):
            return 1
        if not command(b"move C:\\renout.txt C:\\mvdir\\moved.txt", b"C:\\",
                       "the prompt after move"):
            return 1
        if not command(b"type C:\\mvdir\\moved.txt", b"ren-proof", "the moved file's content"):
            return 1
        # 3. The write-tmp-then-rename shape: the replace (`move /Y`) must
        #    land the NEW content under the OLD name ("new-data"'s 'w' cannot
        #    come from the typed type line).
        if not command(b"echo old-data>C:\\cfg.txt", b"C:\\", "the target setup"):
            return 1
        if not command(b"echo new-data>C:\\cfg.tmp", b"C:\\", "the tmp setup"):
            return 1
        if not command(b"move /Y C:\\cfg.tmp C:\\cfg.txt", b"C:\\", "the prompt after replace"):
            return 1
        if not command(b"type C:\\cfg.txt", b"new-data", "the replaced content"):
            return 1

    # ---- CUI-6: the handle/identity acceptance (docs/02 "a handle-
    # inheritance redirect chain round-trips; a timeit-style tool reads real
    # process/thread times; a restricted-token launch works") -------------
    if os.environ.get("EXPECT_CUI6", ""):
        # 1. timeit: a spawned child burns CPU; the parent reads
        #    GetProcessTimes/GetThreadTimes back. "timeit-cpu-1" means real
        #    accounting (the digit cannot come from the typed line).
        mark = len(buffered)
        sock.sendall(b"C:\\timeit.exe\r")
        if not expect_after(mark, b"timeit-cpu-1", "the child's accounted CPU time"):
            return 1
        if not expect_after(mark, b"timeit-order-1", "create <= exit"):
            return 1
        if not expect_after(mark, b"timeit-done", "the timeit completion"):
            return 1
        # 2. redirchain: an inheritable file handle wired as a child's
        #    stdout carries the marker back; inherit then flips off.
        mark = len(buffered)
        sock.sendall(b"C:\\redirchain.exe\r")
        if not expect_after(mark, b"redirchain-ok", "the inherited-handle round trip"):
            return 1
        # 3. restricted: a CreateRestrictedToken launch whose child confirms
        #    the dropped privilege is gone.
        mark = len(buffered)
        sock.sendall(b"C:\\restricted.exe\r")
        if not expect_after(mark, b"restricted-child-ok", "the restricted child's check"):
            return 1
        if not expect_after(mark, b"restricted-ok", "the restricted-token launch"):
            return 1

    # ---- CUI-7: the registry save/load + write-watch acceptance (docs/02
    # "reg save/load round-trips and survives reboot; an app on the
    # VirtualAlloc2/write-watch path runs") --------------------------------
    if os.environ.get("EXPECT_CUI7", ""):
        # 1. seed + save + load + notify: the reg round trip's first boot.
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe seed\r")
        if not expect_after(mark, b"regtool-seed-ok", "the seeded key"):
            return 1
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe save\r")
        if not expect_after(mark, b"regtool-save-ok", "the saved hive file"):
            return 1
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe load\r")
        if not expect_after(mark, b"regtool-load-ok", "the loaded hive's content"):
            return 1
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe watch\r")
        if not expect_after(mark, b"regtool-watch-ok", "the change notification"):
            return 1
        # 2. watchapp: VirtualAlloc2 placement + write-watch end to end.
        mark = len(buffered)
        sock.sendall(b"C:\\watchapp.exe\r")
        if not expect_after(mark, b"watchapp-watch-3", "the stride's dirty pages"):
            return 1
        if not expect_after(mark, b"watchapp-read-ok", "the kernel-write marking"):
            return 1
        if not expect_after(mark, b"watchapp-done", "the watchapp completion"):
            return 1

    if os.environ.get("EXPECT_CUI9", ""):
        # The CUI-9 step-1 measurement (docs/17 §2): mmceiling spawns
        # resident copies of itself until process creation refuses, prints
        # the ceiling and the per-process cost, terminates its children and
        # says done. The refusal loop is the long pole (one full private
        # image-copy set per spawn), so this uses the whole deadline.
        mark = len(buffered)
        sock.sendall(b"C:\\mmceiling.exe\r")
        if not expect_after(mark, b"mmceiling-refused", "the creation refusal"):
            return 1
        if not expect_after(mark, b"mmceiling-done", "the measurement completion"):
            return 1

    if os.environ.get("EXPECT_CUI7_VERIFY", ""):
        # Boot 2: the seeded key and the saved hive file both survived the
        # power cycle; then the machine ends itself through ring-3
        # NtShutdownSystem (no `exit` — the clean QEMU exit IS the verdict,
        # checked by the cui7 leg in tests/run/run.sh).
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe verify\r")
        if not expect_after(mark, b"regtool-verify-ok", "the reboot-surviving registry"):
            return 1
        mark = len(buffered)
        sock.sendall(b"C:\\regtool.exe shutdown\r")
        if not expect_after(mark, b"regtool-shutdown-go", "the shutdown handoff"):
            return 1
        # Drain until the guest's poweroff closes the socket so the kernel's
        # own "[KTEST] shutdown action=2" line lands in the log (the cui7
        # leg greps it as the live arm's verdict).
        end = time.monotonic() + 30
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
        print("console_expect: cui7 verify + shutdown handed off")
        return 0

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
