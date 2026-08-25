#!/usr/bin/env python3
"""qmpctl.py — drive a running QEMU over its QMP socket (GUI-1, docs/02).

    qmpctl.py <socket> screendump <out.ppm>
    qmpctl.py <socket> sendkey <qcode> [<qcode>...]
    qmpctl.py <socket> type <text>
    qmpctl.py <socket> absmove <x> <y>
    qmpctl.py <socket> button <name> <down|up>
    qmpctl.py <socket> nmi
    qmpctl.py <socket> quit

The gui legs need what QEMU only offers through its monitor: a copy of
what the display adapter is actually scanning out, a way to press a key
or move the pointer, and a way to end a guest that is deliberately never
going to power itself off. Commands and argument names follow the pinned
tree's qapi/ui.json (screendump, send-key, input-send-event: InputMoveEvent
axis/value, InputBtnEvent button/down, InputButton names) and
qapi/control.json (quit); QMP rather than HMP because the replies parse
without screen-scraping.

`absmove` takes tablet coordinates, 0..0x7fff on both axes (the
InputMoveEvent contract for absolute coordinates). The value arrives in
the guest verbatim: qmp_input_send_event forwards abs events without
scaling (pinned tree ui/input.c), and both axes ride one command, so the
guest sees one report ended by one SYN — injection is exactly
deterministic, which the gui4 leg's arithmetic relies on. No `device`
argument: event-mask routing finds the tablet for abs/btn and the
keyboard for keys.

`screendump` is the whole point of the framebuffer verdict: the pixels
come back out of QEMU's own device model, so the kernel is never grading
its own homework (Art. 6).

`nmi` (qapi/machine.json inject-nmi in the pinned tree) is the wedge
interrogator: nothing in the guest raises an NMI on its own, so the kernel
answers one with its full fatal dump — every thread's state, wait objects
and armed timeout — on serial (kernel/init/panic.c). tools/qemu.sh sends it
when a run burns its whole TIMEOUT without a verdict, so a silently hung
boot convicts itself in the log it leaves behind instead of dying mute.

`type` (GUI-5, the gui5con leg) spells a command line as send-key chords:
one send-key per character (shift held for the shifted US-layout glyphs),
paced ~50 ms apart because the guest's whole input path — virtio ring,
reader thread, server queue, conhost's window proc — is being exercised,
not benchmarked. The mapping is the US layout the guest's kbdus tables
implement; only the characters the leg actually types are mapped, and an
unmapped character is a hard error, never a silent skip.
"""
import json
import socket
import sys
import time


class Qmp:
    def __init__(self, path, timeout=60.0):
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(path)
                break
            except OSError:
                # The gui leg starts qmpctl as soon as the guest reports
                # progress on serial; QEMU may still be creating the socket.
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        self.sock.settimeout(timeout)
        self.stream = self.sock.makefile("rwb")
        self._read()  # the greeting banner
        self.execute("qmp_capabilities")

    def _read(self):
        """Return the next message that is not an asynchronous event."""
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("qmpctl: QMP connection closed")
            message = json.loads(line)
            if "event" not in message:
                return message

    def execute(self, command, **arguments):
        request = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        self.stream.write((json.dumps(request) + "\r\n").encode())
        self.stream.flush()
        reply = self._read()
        if "error" in reply:
            raise RuntimeError(f"qmpctl: {command} failed: {reply['error']}")
        return reply.get("return")


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path, command, arguments = argv[1], argv[2], argv[3:]
    qmp = Qmp(path)

    if command == "screendump":
        if len(arguments) != 1:
            print("qmpctl: screendump takes one output path", file=sys.stderr)
            return 2
        # PPM is screendump's only format in the pinned tree (the optional
        # `format` argument arrived later); the file is written by the time
        # the reply lands.
        qmp.execute("screendump", filename=arguments[0])
    elif command == "sendkey":
        if not arguments:
            print("qmpctl: sendkey takes at least one key", file=sys.stderr)
            return 2
        # qapi/ui.json send-key: a list of KeyValue, each {type, data}; the
        # "qcode" flavour names keys symbolically (QKeyCode), which is what
        # QEMU maps to the guest's Linux evdev codes for virtio-input.
        keys = [{"type": "qcode", "data": key} for key in arguments]
        qmp.execute("send-key", keys=keys)
    elif command == "type":
        if len(arguments) != 1:
            print("qmpctl: type takes one text argument", file=sys.stderr)
            return 2
        # US-layout spellings for the characters the gui5con leg types.
        plain = {c: c for c in "abcdefghijklmnopqrstuvwxyz0123456789"}
        plain.update({" ": "spc", ".": "dot", "-": "minus", "/": "slash",
                      "\\": "backslash", ";": "semicolon", "'": "apostrophe",
                      "=": "equal", ",": "comma", "\n": "ret"})
        shifted = {">": "dot", ":": "semicolon", "<": "comma", "?": "slash",
                   "_": "minus", "+": "equal", '"': "apostrophe", "|": "backslash"}
        shifted.update({c: c.lower() for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"})
        for char in arguments[0]:
            if char in plain:
                keys = [{"type": "qcode", "data": plain[char]}]
            elif char in shifted:
                keys = [{"type": "qcode", "data": "shift"},
                        {"type": "qcode", "data": shifted[char]}]
            else:
                print(f"qmpctl: no key mapping for character {char!r}", file=sys.stderr)
                return 2
            qmp.execute("send-key", keys=keys)
            # 250 ms per character, not 50: QEMU's virtio-input eventq holds
            # 64 events and each typed character is ~6 (press+release+SYN per
            # key, doubled for a shifted one), so the pacing bounds how long
            # the guest may go without draining before keys fall off the
            # ring. Measured on the gui5con leg under TCG: cmd.exe's
            # per-process GDI init (the font sweep every console client runs)
            # can hold the reader off the CPU for ~1-2 s, which at 50 ms/char
            # queued ~18 characters (~108 events) and silently lost the
            # overflow; at 250 ms a 2 s stall queues 8 (~48 events), inside
            # the ring. Typing stays far inside every guest-side bound the
            # legs rely on (looper's busy loop alone allows 60 s).
            time.sleep(0.25)
    elif command == "absmove":
        if len(arguments) != 2:
            print("qmpctl: absmove takes x y (0..32767)", file=sys.stderr)
            return 2
        x, y = int(arguments[0]), int(arguments[1])
        events = [
            {"type": "abs", "data": {"axis": "x", "value": x}},
            {"type": "abs", "data": {"axis": "y", "value": y}},
        ]
        qmp.execute("input-send-event", events=events)
    elif command == "button":
        if len(arguments) != 2 or arguments[1] not in ("down", "up"):
            print("qmpctl: button takes an InputButton name and down|up", file=sys.stderr)
            return 2
        events = [{"type": "btn", "data": {"button": arguments[0], "down": arguments[1] == "down"}}]
        qmp.execute("input-send-event", events=events)
    elif command == "nmi":
        # qapi/machine.json inject-nmi: an NMI on every CPU (one, here). The
        # kernel's vector-2 branch prints the fatal dump and halts.
        qmp.execute("inject-nmi")
    elif command == "quit":
        try:
            qmp.execute("quit")
        except (RuntimeError, OSError):
            # QEMU may drop the connection before the reply is flushed;
            # the process ending is the outcome we wanted either way.
            pass
    else:
        print(f"qmpctl: unknown command '{command}'", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
