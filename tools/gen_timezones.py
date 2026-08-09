#!/usr/bin/env python3
r"""Generate kernel/cm/timezones.h — the HKLM time-zone table, from the pin.

kernelbase resolves a time zone by OPENING
`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time Zones\<key name>` and
reading `Std`/`Dlt`/`MUI_*`/`TZI` out of it, with the per-year rules one level
down in a `Dynamic DST` subkey (dlls/kernelbase/locale.c,
GetDynamicTimeZoneInformation and GetTimeZoneInformationForYear). On the
oracle that whole table is PREFIX furniture: it lives in a WINE_REGISTRY
resource inside kernelbase itself (dlls/kernelbase/kernelbase.rgs, named by
dlls/kernelbase/kernelbase.rc) and is applied at `wineboot --init` by
dlls/setupapi/fakedll.c `register_resource`.

proskrnl has no prefix and no wineboot on the hermetic images, so CmInitialize
(kernel/cm/registry.c) seeds the same payload — the Session Manager /
LicenseInformation precedent — and it is PARSED out of the pin rather than
transcribed, for the reason gen_license.py records: a hand-copied subset is a
claim about which lines matter, the claim is invisible in the code that makes
it, and it goes stale silently. Here the subset was one zone (UTC) out of 139,
and kernel32:time measured the cost at fourteen assertions.

The .rgs grammar is ATL's registrar script, and this parser is written against
the pinned tree's own implementation (dlls/atl/registrar.c, `get_word` and
`do_process_key`) rather than against the format's documentation:

    'quoted name'  or  bare-name        a key; '' inside quotes is one quote
    val 'name' = s 'text'               REG_SZ, terminator included
    val 'name' = d 2000                 REG_DWORD, wcstoul(..., 10) — DECIMAL
    val 'name' = b a1b2c3               REG_BINARY, (len + 1) / 2 bytes
    { ... }                             the key's body

`NoRemove` / `ForceRemove` / `Delete` are registrar verbs the file uses on the
way DOWN to the Time Zones key and never inside it, and a key may carry an
unnamed default value. Both forms are parsed, so the walk is exact, and both
are then refused if one ever appears inside the emitted subtree — silently
dropping a form is how the payload would diverge again. So is a
`%replacement%`, which the registrar expands before parsing (`do_preprocess`)
and which nothing in this subtree uses.

What is NOT emitted, and why: the sibling `Software\Wine\Time Zones\TZ Mapping`
subtree in the same .rgs maps IANA zone names onto these key names, and its
only consumer is Wine's UNIX-side zone detection (dlls/ntdll/unix/system.c
`find_reg_tz_info`) — the half proskrnl replaces with a syscall. The NLS
subtrees below it are a different subject again.

The REG_BINARY payloads are pooled and de-duplicated by exact bytes: the 1558
TZI blobs across the table are 368 distinct 44-byte values, and identical
bytes are identical bytes, so this is a representation choice rather than a
claim about the data.

Usage:
    gen_timezones.py              # rewrite kernel/cm/timezones.h
    gen_timezones.py --check      # fail if the checked-in file is stale
"""

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RGS = ROOT / "third_party" / "wine" / "dlls" / "kernelbase" / "kernelbase.rgs"
OUT = ROOT / "kernel" / "cm" / "timezones.h"

# The path from the script's root key down to the subtree that is emitted.
# Matched case-insensitively, as RegCreateKeyW is.
TZ_PATH = ["HKLM", "Software", "Microsoft", "Windows NT", "CurrentVersion", "Time Zones"]

# dlls/atl/registrar.c do_process_key: the words that prefix a name rather
# than being one. `val` introduces a value; the other three are key verbs.
VERBS = ("noremove", "forceremove", "val", "delete")


class Tokenizer:
    """dlls/atl/registrar.c `get_word`, verbatim in behaviour.

    Words are whitespace-separated; `{`, `}` and `=` are single-character
    words; a word starting with `'` runs to the next unpaired `'`, with `''`
    standing for one literal quote.
    """

    def __init__(self, text, path):
        self.text = text
        self.path = path
        self.pos = 0

    def fail(self, message):
        raise SystemExit(
            "%s:%d: %s" % (self.path, self.text.count("\n", 0, self.pos) + 1, message)
        )

    def word(self):
        """Return (text, wasQuoted), or (None, False) at end of input."""
        text = self.text
        n = len(text)
        i = self.pos
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            self.pos = i
            return None, False
        if text[i] in "}={":
            self.pos = i + 1
            return text[i], False
        if text[i] == "'":
            out = []
            while True:
                start = i + 1
                i = text.find("'", start)
                if i < 0:
                    self.pos = n
                    self.fail("unterminated quoted word")
                out.append(text[start:i])
                if i + 1 < n and text[i + 1] == "'":
                    out.append("'")
                    i += 1
                    continue
                break
            self.pos = i + 1
            return "".join(out), True
        start = i
        while i < n and not text[i].isspace():
            i += 1
        self.pos = i
        return text[start:i], False


class Key:
    def __init__(self, name, verb):
        self.name = name
        self.verb = verb  # None, "noremove", "forceremove" or "delete"
        self.values = []  # (name, (type, payload)); name "" is the default value
        self.subkeys = []


def parse_body(tok, key):
    """Parse the token stream after a `{`, up to its matching `}`."""
    while True:
        word, quoted = tok.word()
        if word is None:
            tok.fail("unterminated key body")
        if word == "}" and not quoted:
            return
        verb = None
        if not quoted and word.lower() in VERBS:
            verb = word.lower()
            word, quoted = tok.word()
            if word is None:
                tok.fail("%s with no name" % verb)
        name = word
        if "%" in name:
            tok.fail("%%replacement in %r — the registrar expands these and this does not" % name)

        child = None
        if verb != "val":
            child = Key(name, verb)
            key.subkeys.append(child)

        peek = tok.pos
        nxt, nxtQuoted = tok.word()
        if nxt == "=" and not nxtQuoted and verb != "delete":
            typeWord, _ = tok.word()
            payloadWord, _ = tok.word()
            if typeWord is None or payloadWord is None:
                tok.fail("value %r has no payload" % name)
            if "%" in payloadWord:
                tok.fail("%%replacement in the payload of %r" % name)
            value = (name if verb == "val" else "", decode_value(tok, typeWord, payloadWord))
            (key if verb == "val" else child).values.append(value)
            peek = tok.pos
            nxt, nxtQuoted = tok.word()

        if nxt == "{" and not nxtQuoted:
            if child is None:
                tok.fail("a `val` with a body")
            parse_body(tok, child)
            continue
        # Not a body: push the lookahead back for the next iteration.
        tok.pos = peek


def decode_value(tok, typeWord, payload):
    """(type, data) for one value, per dlls/atl/registrar.c's switch."""
    if typeWord == "s":
        return ("REG_SZ", payload)
    if typeWord == "d":
        # `wcstoul(buf->str, NULL, 10)` — base ten, not the C prefix rules.
        if not payload.isdigit():
            tok.fail("REG_DWORD payload %r is not decimal" % payload)
        return ("REG_DWORD", int(payload, 10))
    if typeWord == "b":
        # `count = (lstrlenW(buf->str) + 1) / 2` — an odd nibble count would
        # read past the string, so refuse one rather than guess.
        if len(payload) % 2 != 0:
            tok.fail("REG_BINARY payload %r has an odd nibble count" % payload)
        try:
            return ("REG_BINARY", bytes.fromhex(payload))
        except ValueError:
            tok.fail("REG_BINARY payload %r is not hex" % payload)
    tok.fail("unhandled value type %r — gen_timezones.py knows s, d and b" % typeWord)
    return None


def parse_rgs(path):
    """Return the root Key of the .rgs, with the whole tree under it."""
    text = pathlib.Path(path).read_text(encoding="utf-8")
    tok = Tokenizer(text, path)
    root = Key("", None)
    while True:
        word, quoted = tok.word()
        if word is None:
            return root
        if word in "{}=" and not quoted:
            tok.fail("a body with no key name")
        child = Key(word, None)
        root.subkeys.append(child)
        nxt, nxtQuoted = tok.word()
        if nxt != "{" or nxtQuoted:
            tok.fail("root key %r without a body" % word)
        parse_body(tok, child)


def find_path(root, path):
    node = root
    for segment in path:
        match = [k for k in node.subkeys if k.name.lower() == segment.lower()]
        if len(match) != 1:
            raise SystemExit(
                "%s: %d keys named %r under %r — the .rgs shape moved"
                % (RGS, len(match), segment, node.name)
            )
        node = match[0]
    return node


def flatten(key, prefix, rows):
    """Depth-first: one row per key, `prefix` relative to the Time Zones key.

    Every key gets a row, values or not, so the seed creates it either way.
    Subkeys are walked in name order so the output is stable whatever order
    the .rgs happens to list them in.
    """
    if key.verb is not None:
        raise SystemExit(
            "%s: registrar verb %r on %r inside the emitted subtree — "
            "gen_timezones.py must be taught it rather than dropping it"
            % (RGS, key.verb, prefix)
        )
    if "\\" in key.name:
        # The emitted path is '\'-separated because CmpWalkPath reads it that
        # way, so a key whose own NAME contains one would seed two nested keys
        # where the registrar (RegCreateKeyW, which does the same splitting)
        # and the oracle's prefix have — well, the same two. Refuse rather than
        # rely on that agreement: `--check` compares the header to the .rgs and
        # would stay green either way.
        raise SystemExit(
            "%s: key name %r contains the path separator — gen_timezones.py "
            "must be taught it rather than splitting it silently" % (RGS, key.name)
        )
    for name, _ in key.values:
        if name == "":
            raise SystemExit(
                "%s: %r carries an unnamed default value — the kernel seed has no "
                "spelling for one" % (RGS, prefix)
            )
    rows.append((prefix, key.values))
    for child in sorted(key.subkeys, key=lambda k: k.name):
        flatten(child, prefix + "\\" + child.name, rows)


def cstr(text):
    """A WSTR() literal. Backslash is escaped (paths use it as the separator);
    anything this cannot render exactly is a hard error rather than a guess."""
    if '"' in text or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
        raise SystemExit("%r is not renderable as a plain C literal" % text)
    return 'WSTR("%s")' % text.replace("\\", "\\\\")


def render(rows):
    # Pool the REG_BINARY payloads, de-duplicated by exact bytes.
    blobs = {}
    pool = bytearray()
    for _, values in rows:
        for _, (type_, data) in values:
            if type_ == "REG_BINARY" and data not in blobs:
                blobs[data] = len(pool)
                pool.extend(data)

    valueRows = []
    keyRows = []
    for path, values in rows:
        keyRows.append((path, len(valueRows), len(values)))
        for name, (type_, data) in values:
            if type_ == "REG_SZ":
                valueRows.append("    {%s, REG_SZ, %s, 0, 0, 0}," % (cstr(name), cstr(data)))
            elif type_ == "REG_DWORD":
                valueRows.append("    {%s, REG_DWORD, 0, %u, 0, 0}," % (cstr(name), data))
            else:
                valueRows.append(
                    "    {%s, REG_BINARY, 0, 0, %u, %u}," % (cstr(name), blobs[data], len(data))
                )

    lines = [
        "/* kernel/cm/timezones.h - GENERATED by tools/gen_timezones.py from",
        " * third_party/wine/dlls/kernelbase/kernelbase.rgs — the WINE_REGISTRY",
        r" * resource that writes HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time",
        " * Zones into the pinned oracle's prefix at `wineboot --init`",
        " * (dlls/setupapi/fakedll.c register_resource), and so the table kernelbase",
        " * resolves a zone out of on that leg (dlls/kernelbase/locale.c).",
        " * DO NOT EDIT BY HAND (Constitution Art. 4 / gate G4). Regenerate with:",
        " *     python3 tools/gen_timezones.py",
        " *",
        " * proskrnl has no prefix, so CmInitialize (kernel/cm/registry.c) seeds this",
        " * table into the same key — which is what makes the two legs of",
        " * kernel32:time and of tests/ntapi/sem_reg/timezone_keys.c read the SAME",
        " * table rather than each inventing a plausible one.",
        " *",
        r" * Paths are relative to the Time Zones key, '\'-separated the way",
        " * CmpWalkPath reads them, and parents precede their children. The",
        " * REG_BINARY payloads are pooled and shared by exact bytes;",
        " * `binaryOffset`/`binaryBytes` index CmpTimeZoneBinary.",
        " *",
        " * kernel/cm/registry.c is the ONE includer, which is what makes `static",
        " * const` right here (the kernel/cm/license.h precedent): a second includer",
        " * would get its own silent copy, and there is one seed site, not two.",
        " */",
        "/* clang-format off — `make format` REWRITES what it touches, and on a",
        " * generated file that means the checked-in copy and the generator's output",
        " * drift apart on the next --check (the hazard kernel/cm/license.h's header",
        " * records, here with 3600 lines of table to reflow rather than one",
        " * identifier). The layout below is the generator's, and it is the only",
        " * layout this file has. */",
        "// clang-format off",
        "#ifndef PROSKRNL_KERNEL_CM_TIMEZONES_H",
        "#define PROSKRNL_KERNEL_CM_TIMEZONES_H",
        "",
        '#include "abi/ntdef.h"',
        '#include "abi/ntregapi.h"',
        '#include "kernel/lib/rtl.h"',
        "",
        "/* One value. `type` says which payload member carries it; the others are",
        " * zero. */",
        "typedef struct CMP_TIMEZONE_VALUE",
        "{",
        "    PCWSTR name;",
        "    ULONG type;",
        "    PCWSTR string;",
        "    ULONG dword;",
        "    ULONG binaryOffset;",
        "    ULONG binaryBytes;",
        "} CMP_TIMEZONE_VALUE;",
        "",
        "/* One key, and the run of values that belong to it. */",
        "typedef struct CMP_TIMEZONE_KEY",
        "{",
        "    PCWSTR path;",
        "    ULONG firstValue;",
        "    ULONG valueCount;",
        "} CMP_TIMEZONE_KEY;",
        "",
        f"#define CMP_TIMEZONE_KEY_COUNT {len(keyRows)}",
        f"#define CMP_TIMEZONE_VALUE_COUNT {len(valueRows)}",
        f"#define CMP_TIMEZONE_BINARY_BYTES {len(pool)}",
        "",
        "static const UCHAR CmpTimeZoneBinary[CMP_TIMEZONE_BINARY_BYTES] = {",
    ]
    for i in range(0, len(pool), 22):
        lines.append("    " + " ".join("0x%02x," % b for b in pool[i : i + 22]))
    lines += [
        "};",
        "",
        "static const CMP_TIMEZONE_VALUE CmpTimeZoneValues[CMP_TIMEZONE_VALUE_COUNT] = {",
    ]
    lines += valueRows
    lines += [
        "};",
        "",
        "static const CMP_TIMEZONE_KEY CmpTimeZoneKeys[CMP_TIMEZONE_KEY_COUNT] = {",
    ]
    for path, first, count in keyRows:
        lines.append("    {%s, %u, %u}," % (cstr(path), first, count))
    lines += [
        "};",
        "",
        "#endif /* PROSKRNL_KERNEL_CM_TIMEZONES_H */",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the output is stale")
    parser.add_argument("--rgs", default=None)
    args = parser.parse_args()

    rgs = pathlib.Path(args.rgs) if args.rgs else RGS
    if not rgs.exists():
        sys.exit(f"{rgs} missing — build the pinned Wine tree first (tools/setup_linux.sh)")

    root = parse_rgs(rgs)
    zones = find_path(root, TZ_PATH)
    rows = []
    for zone in sorted(zones.subkeys, key=lambda k: k.name):
        flatten(zone, zone.name, rows)
    if not rows:
        sys.exit(f"{rgs}: no Time Zones payload found")
    text = render(rows)

    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            sys.exit(f"{OUT} is stale — run: python3 tools/gen_timezones.py")
        print(f"{OUT}: up to date ({len(rows)} keys)")
        return
    OUT.write_text(text)
    print(f"{OUT}: {len(rows)} keys from {rgs}")


if __name__ == "__main__":
    main()
