#!/usr/bin/env python3
# regdump.py — dump a registry tree to one canonical text form (CUI-1's
# registry differential, docs/02 "a registry differential vs. the oracle's
# prefix is green"). Two input formats, ONE output shape, so regdiff.py
# compares apples to apples:
#
#   - the proskrnl hive ("PHV1"): the kernel's own on-disk format, spec'd by
#     the normative comment in kernel/cm/hive.c (the trusted source, G8).
#     Extracted from the FAT32 boot volume by tests/run/run.sh firstboot.
#   - a Wine text registry file ("WINE REGISTRY Version 2"): the oracle
#     prefix's system.reg, written by the pinned wineserver
#     (third_party/wine/server/registry.c dump_value/dump_strW — the escape
#     rules below mirror that code).
#
# Output: one line per key and one per value, sorted, lower-cased for the
# case-insensitive NT namespace, with python-repr quoting so embedded
# separators cannot corrupt the framing:
#
#   key <path-repr>
#   val <path-repr> <name-repr> <TYPE> <data-repr>
#
# Wine paths are relative to HKLM (system.reg's ";; All keys relative to
# \\Machine"); they are emitted under the same "machine\..." prefix the
# proskrnl hive uses, so the two dumps share a namespace. The proskrnl dump
# is restricted to the Machine subtree with --subtree.
#
# Data canonicalization (both sides; the compare unit is the USER-OBSERVABLE
# value, not the raw bytes): REG_SZ/EXPAND/LINK decode UTF-16LE and drop the
# terminating NUL (wineserver's text form does the same); REG_MULTI_SZ
# becomes its string list; REG_DWORD/QWORD become integers; everything else
# (and any undecodable string) stays raw hex.
import struct
import sys

TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


def type_name(t):
    return TYPE_NAMES.get(t, "type%d" % t)


def canon_data(regtype, data):
    """bytes -> the canonical comparable representation (see file comment)."""
    if regtype in (1, 2, 6):  # REG_SZ / REG_EXPAND_SZ / REG_LINK
        if len(data) % 2 == 0:
            try:
                s = data.decode("utf-16-le")
            except UnicodeDecodeError:
                return "hex:" + data.hex()
            if s.endswith("\0"):
                s = s[:-1]
            return repr(s)
        return "hex:" + data.hex()
    if regtype == 7:  # REG_MULTI_SZ
        if len(data) % 2 == 0:
            try:
                s = data.decode("utf-16-le")
            except UnicodeDecodeError:
                return "hex:" + data.hex()
            return repr(s.rstrip("\0").split("\0") if s.rstrip("\0") else [])
        return "hex:" + data.hex()
    if regtype == 4 and len(data) == 4:  # REG_DWORD
        return "0x%08x" % struct.unpack("<I", data)[0]
    if regtype == 5 and len(data) == 4:  # REG_DWORD_BIG_ENDIAN
        return "0x%08x" % struct.unpack(">I", data)[0]
    if regtype == 11 and len(data) == 8:  # REG_QWORD
        return "0x%016x" % struct.unpack("<Q", data)[0]
    return "hex:" + data.hex()


class RegTree:
    """keys: set of lower-cased paths; values: {(path, name): (TYPE, data)}."""

    def __init__(self):
        self.keys = set()
        self.values = {}

    def add_key(self, path):
        self.keys.add(path.lower())

    def add_value(self, path, name, regtype, data):
        self.values[(path.lower(), name.lower())] = (type_name(regtype), canon_data(regtype, data))


# --- the proskrnl hive (PHV1) — format spec: kernel/cm/hive.c ---------------


def parse_phv1(blob):
    magic, version, total, _ = struct.unpack_from("<IIII", blob, 0)
    if magic != 0x31564850 or version != 1:
        raise ValueError("not a PHV1 hive (magic %#x version %d)" % (magic, version))
    if total != len(blob):
        raise ValueError("PHV1 totalBytes %d != file size %d" % (total, len(blob)))

    tree = RegTree()
    pos = 16

    def take(n):
        nonlocal pos
        if len(blob) - pos < n:
            raise ValueError("PHV1 truncated at offset %d" % pos)
        out = blob[pos : pos + n]
        pos += n
        return out

    def parse_key_body(path, value_count):
        nonlocal pos
        for _ in range(value_count):
            rec = take(12)
            if rec[0] != ord("V"):
                raise ValueError("PHV1 bad value tag at %d" % (pos - 12))
            name_chars, regtype, data_bytes = struct.unpack_from("<xxHII", rec, 0)
            name = take(name_chars * 2).decode("utf-16-le")
            data = take(data_bytes)
            if data_bytes % 2:
                take(1)
            tree.add_value(path, name, regtype, data)
        while True:
            rec = take(2)
            if rec[0] == ord("E"):
                if rec[1] != 0:
                    raise ValueError("PHV1 bad end record at %d" % (pos - 2))
                return
            if rec[0] != ord("K"):
                raise ValueError("PHV1 bad key tag at %d" % (pos - 2))
            header = take(14)
            name_chars, _, child_values = struct.unpack_from("<HQI", header, 0)
            if name_chars == 0:
                raise ValueError("PHV1 nested key with empty name at %d" % (pos - 14))
            name = take(name_chars * 2).decode("utf-16-le")
            child = path + "\\" + name if path else name
            tree.add_key(child)
            parse_key_body(child, child_values)

    root = take(16)
    if root[0] != ord("K") or struct.unpack_from("<H", root, 2)[0] != 0:
        raise ValueError("PHV1 bad root record")
    parse_key_body("", struct.unpack_from("<I", root, 12)[0])
    if pos != len(blob):
        raise ValueError("PHV1 trailing bytes after root record")
    return tree


# --- the Wine text registry (server/registry.c) ------------------------------

_ESCAPES = {"a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def unescape(s, i, terminators):
    """Parse from s[i] until an unescaped terminator; mirror the wineserver
    load-side rules: \\xH..H (<=4 hex digits), \\O..O (<=3 octal), the named
    C escapes, and \\<any> -> the char itself."""
    out = []
    while i < len(s):
        c = s[i]
        if c in terminators:
            return "".join(out), i
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(s):
            break
        c = s[i]
        if c == "x":
            j = i + 1
            while j < len(s) and j <= i + 4 and s[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 1:
                out.append(chr(int(s[i + 1 : j], 16)))
                i = j
                continue
            out.append("x")
            i += 1
        elif c in "01234567":
            j = i
            while j < len(s) and j < i + 3 and s[j] in "01234567":
                j += 1
            out.append(chr(int(s[i:j], 8)))
            i = j
        elif c in _ESCAPES:
            out.append(_ESCAPES[c])
            i += 1
        else:
            out.append(c)
            i += 1
    raise ValueError("unterminated string: %r" % s)


def parse_winereg(text, prefix):
    lines = text.split("\n")
    if not lines or not lines[0].startswith("WINE REGISTRY Version 2"):
        raise ValueError("not a WINE REGISTRY Version 2 file")

    tree = RegTree()
    path = None
    i = 1
    while i < len(lines):
        line = lines[i].rstrip("\r")
        # hex continuations end with a backslash; splice them here
        while line.endswith("\\") and not line.endswith("\\\\"):
            i += 1
            line = line[:-1] + lines[i].strip().rstrip("\r")
        i += 1
        if not line or line[0] in ";#":
            continue
        if line[0] == "[":
            raw, _ = unescape(line, 1, "]")
            path = prefix + "\\" + raw if raw else prefix
            tree.add_key(path)
            continue
        if path is None:
            raise ValueError("value line before any key: %r" % line)
        if line[0] == "@":
            name, j = "", 1
        elif line[0] == '"':
            name, j = unescape(line, 1, '"')
            j += 1
        else:
            raise ValueError("unrecognized line: %r" % line)
        if j >= len(line) or line[j] != "=":
            raise ValueError("missing '=' in: %r" % line)
        data = line[j + 1 :]

        if data.startswith('"'):
            s, _ = unescape(data, 1, '"')
            tree.add_value(path, name, 1, (s + "\0").encode("utf-16-le"))
        elif data.startswith("str("):
            # dump_value writes len-1 WCHARs (drops the terminating NUL);
            # re-appending one NUL reconstructs the data for every string
            # type, REG_MULTI_SZ's double-NUL included.
            regtype = int(data[4 : data.index(")")], 16)
            s, _ = unescape(data, data.index(":") + 2, '"')
            tree.add_value(path, name, regtype, (s + "\0").encode("utf-16-le"))
        elif data.startswith("dword:"):
            tree.add_value(path, name, 4, struct.pack("<I", int(data[6:], 16)))
        elif data.startswith("hex"):
            regtype = 3 if data[3] == ":" else int(data[4 : data.index(")")], 16)
            hexpart = data[data.index(":") + 1 :].replace(",", "").strip()
            tree.add_value(path, name, regtype, bytes.fromhex(hexpart))
        else:
            raise ValueError("unrecognized data: %r" % data)
    return tree


# --- driver ------------------------------------------------------------------


def load(filename, subtree=None):
    with open(filename, "rb") as f:
        blob = f.read()
    if blob[:4] == b"PHV1":
        tree = parse_phv1(blob)
    else:
        tree = parse_winereg(blob.decode("utf-8", errors="replace"), "machine")
    if subtree:
        want = subtree.lower()
        pruned = RegTree()
        pruned.keys = {k for k in tree.keys if k == want or k.startswith(want + "\\")}
        pruned.values = {
            (p, n): v
            for (p, n), v in tree.values.items()
            if p == want or p.startswith(want + "\\")
        }
        tree = pruned
    return tree


def main():
    args = sys.argv[1:]
    subtree = None
    if args and args[0] == "--subtree":
        subtree = args[1]
        args = args[2:]
    if len(args) != 1:
        sys.stderr.write("usage: regdump.py [--subtree machine] <SYSTEM-hive | system.reg>\n")
        return 2
    tree = load(args[0], subtree)
    for k in sorted(tree.keys):
        print("key %r" % k)
    for (p, n), (t, d) in sorted(tree.values.items()):
        print("val %r %r %s %s" % (p, n, t, d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
