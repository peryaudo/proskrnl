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
import zlib
import sys

# Registry value types: fixed by the Windows SDK contract; re-verify against
# the pinned tree's include/winnt.h (REG_NONE..REG_QWORD).
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


# --- the proskrnl hive (PHV2) — format spec: kernel/cm/hive.c ---------------

PHV2_MAGIC = 0x32564850
PHV2_RECORD_HEADER = 24
PHV2_VALUE_HEADER = 12

OP_CREATE_KEY, OP_DELETE_KEY, OP_SET_VALUES, OP_DELETE_VALUE, OP_RENAME_KEY = 1, 2, 3, 4, 5


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def _round8(n):
    return (n + 7) & ~7


def parse_phv2(blob):
    """Replay a PHV2 record log into a RegTree.

    The kernel's own reader stops at the first record that fails its length,
    bounds or CRC check and keeps the prefix (a torn append costs one record).
    This mirrors that exactly -- if it did not, a legitimately torn hive would
    read here as a whole-file diff rather than as one missing key.
    """
    magic, version = struct.unpack_from("<II", blob, 0)
    if magic != PHV2_MAGIC or version != 2:
        raise ValueError("not a PHV2 hive (magic %#x version %d)" % (magic, version))

    tree = RegTree()
    pos = 16
    while len(blob) - pos >= PHV2_RECORD_HEADER:
        length, crc = struct.unpack_from("<II", blob, pos)
        if length < PHV2_RECORD_HEADER or length % 8 or length > len(blob) - pos:
            break
        rec = blob[pos : pos + length]
        if _crc32(rec[8:]) != crc:
            break
        op, _flags, path_chars, shared, value_count = struct.unpack_from("<BBHHH", rec, 8)
        if shared != 0:                       # reserved; a reader must refuse it
            break
        path_bytes = path_chars * 2
        tail_at = _round8(PHV2_RECORD_HEADER + path_bytes)
        if tail_at > length:
            break
        path = rec[PHV2_RECORD_HEADER : PHV2_RECORD_HEADER + path_bytes].decode("utf-16-le")
        pos += length

        if op == OP_CREATE_KEY:
            if path:                           # the image's own top key is not a key IN it
                tree.add_key(path)
        elif op == OP_DELETE_KEY:
            tree.keys.discard(path.lower())
            dead = path.lower()
            for key in [k for k in tree.values if k[0] == dead]:
                del tree.values[key]
        elif op == OP_SET_VALUES:
            at = tail_at
            for _ in range(value_count):
                name_chars, regtype, data_bytes = struct.unpack_from("<HxxII", rec, at)
                name_at = at + PHV2_VALUE_HEADER
                name = rec[name_at : name_at + name_chars * 2].decode("utf-16-le")
                data_at = name_at + name_chars * 2
                tree.add_value(path, name, regtype, rec[data_at : data_at + data_bytes])
                at += _round8(PHV2_VALUE_HEADER + name_chars * 2 + data_bytes)
        elif op == OP_DELETE_VALUE:
            (name_chars,) = struct.unpack_from("<H", rec, tail_at)
            name_at = tail_at + 4
            name = rec[name_at : name_at + name_chars * 2].decode("utf-16-le")
            tree.values.pop((path.lower(), name.lower()), None)
        elif op == OP_RENAME_KEY:
            (name_chars,) = struct.unpack_from("<H", rec, tail_at)
            name_at = tail_at + 4
            new_name = rec[name_at : name_at + name_chars * 2].decode("utf-16-le")
            parent = path.rsplit("\\", 1)[0] if "\\" in path else ""
            dst = (parent + "\\" + new_name) if parent else new_name
            _rename_subtree(tree, path, dst)
        else:
            break                              # an op this reader does not know ends the log
    return tree


def _rename_subtree(tree, src, dst):
    """Move src and everything under it to dst, as replay does."""
    src_l, dst_l = src.lower(), dst.lower()
    moved = {k for k in tree.keys if k == src_l or k.startswith(src_l + "\\")}
    tree.keys -= moved
    for k in moved:
        tree.keys.add(dst_l + k[len(src_l) :])
    for (kpath, vname), v in list(tree.values.items()):
        if kpath == src_l or kpath.startswith(src_l + "\\"):
            del tree.values[(kpath, vname)]
            tree.values[(dst_l + kpath[len(src_l) :], vname)] = v


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
            # Parents with subkeys but no values are only IMPLIED by the
            # save format (server/registry.c save_subkeys: "keys with no
            # values but subkeys are saved implicitly"); materialize them
            # so key-existence compares see them.
            parent = path.rsplit("\\", 1)[0]
            while parent and parent.lower() not in tree.keys:
                tree.add_key(parent)
                parent = parent.rsplit("\\", 1)[0]
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
        tree = parse_phv2(blob)
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
