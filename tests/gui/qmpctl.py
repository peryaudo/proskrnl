#!/usr/bin/env python3
"""qmpctl.py — drive a running QEMU over its QMP socket (GUI-1, docs/02).

    qmpctl.py <socket> screendump <out.ppm>
    qmpctl.py <socket> sendkey <qcode> [<qcode>...]
    qmpctl.py <socket> quit

The gui leg needs three things QEMU only offers through its monitor:
a copy of what the display adapter is actually scanning out, a way to
press a key, and a way to end a guest that is deliberately never going to
power itself off. Commands and argument names follow the pinned tree's
qapi/ui.json (screendump, send-key) and qapi/control.json (quit); QMP
rather than HMP because the replies parse without screen-scraping.

`screendump` is the whole point of the framebuffer verdict: the pixels
come back out of QEMU's own device model, so the kernel is never grading
its own homework (Art. 6).
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
