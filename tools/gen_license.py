#!/usr/bin/env python3
"""Generate kernel/cm/license.h — the license values, from the pinned tree.

NtQueryLicenseValue is a named lookup in ONE key,
`HKLM\\Software\\Wine\\LicenseInformation` (the oracle names it literally:
`dlls/ntdll/unix/registry.c` NtQueryLicenseValue). On the oracle that key is
prefix furniture, written by `loader/wine.inf`'s `[LicenseInformation]`
section at `wineboot --init` time. proskrnl has no prefix, and the images that
carry no Wine userland have no wineboot either, so the same payload is seeded
by the kernel
(kernel/cm/registry.c, the Session Manager / time-zone precedent) — and a
differential gate whose two legs disagree about that key measures the
environment rather than the boundary. ntdll:reg measured exactly that: 12
failures, every one of them `Kernel-MUI-Number-Allowed` answering
STATUS_OBJECT_NAME_NOT_FOUND because the kernel seeded the string value and
not the DWORD one.

So the payload is PARSED out of the pin rather than transcribed — the
gen_sysini.py precedent one layer down (the hive rather than the volume), and
the same reason: a hand-copied subset is a claim about which lines matter,
and the claim goes stale silently. The whole SECTION is emitted, so what the
generator asserts is checkable ("the kernel's key is what wine.inf writes")
rather than a selection nobody can re-derive.

The INF AddReg line shape (`[LicenseInformation]` uses two forms and only
two):

    HKLM,<key>,"<value>",,"<string>"            -> REG_SZ    (no type flag)
    HKLM,<key>,"<value>",0x10001,<number>       -> REG_DWORD

Both flag words are setupapi's own, spelled as `include/setupapi.h` in the
pinned tree spells them (re-verify there): FLG_ADDREG_TYPE_SZ is 0 and
FLG_ADDREG_TYPE_DWORD is `0x00010000 | FLG_ADDREG_BINVALUETYPE` = 0x10001 —
the type bit is NOT the whole word, and a constant named for the type but
holding only 0x00010000 would never match a line. An unrecognised flag word
is a hard error rather than a skip: silently dropping a form is how the
payload would diverge again.

Usage:
    gen_license.py                # rewrite kernel/cm/license.h
    gen_license.py --check        # fail if the checked-in file is stale
"""

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INF = ROOT / "third_party" / "wine" / "loader" / "wine.inf"
OUT = ROOT / "kernel" / "cm" / "license.h"

SECTION = "[licenseinformation]"
KEY = r"Software\Wine\LicenseInformation"

# `HKLM,<key>,"<value name>",<flags>,<data>` — the AddReg row. The data
# column is taken verbatim (quoted for a string, bare for a number) and
# decoded per flags below.
ROW_RE = re.compile(r'^HKLM\s*,\s*([^,]+?)\s*,\s*"([^"]*)"\s*,\s*([^,]*?)\s*,\s*(.*?)\s*$')

# third_party/wine/include/setupapi.h:1032,1041,1045 — verbatim, including
# the OR that is part of the DWORD symbol's own definition there.
FLG_ADDREG_BINVALUETYPE = 0x00000001
FLG_ADDREG_TYPE_SZ = 0x00000000
FLG_ADDREG_TYPE_DWORD = 0x00010000 | FLG_ADDREG_BINVALUETYPE


def parse_license(infPath):
    """Return [(name, "REG_SZ"|"REG_DWORD", payload), ...] in file order."""
    # wine.inf is plain ASCII in the pinned tree; latin-1 keeps any stray
    # byte round-trippable rather than raising on it (gen_sysini.py's rule).
    lines = pathlib.Path(infPath).read_text(encoding="latin-1").splitlines()
    out = []
    inSection = False
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("["):
            inSection = stripped.lower() == SECTION
            continue
        if not inSection or not stripped or stripped.startswith(";"):
            continue
        m = ROW_RE.match(stripped)
        if not m:
            raise SystemExit(
                "%s:%d: unhandled AddReg form %r — gen_license.py must be taught it "
                "rather than dropping it" % (infPath, lineno, stripped)
            )
        key, name, flags, data = m.groups()
        if key != KEY:
            raise SystemExit(
                "%s:%d: [LicenseInformation] writes outside %s (%r); the kernel seeds "
                "one key and gen_license.py must be taught the second"
                % (infPath, lineno, KEY, key)
            )
        flagWord = int(flags, 0) if flags else 0
        if flagWord == FLG_ADDREG_TYPE_SZ:
            if not (data.startswith('"') and data.endswith('"')):
                raise SystemExit("%s:%d: REG_SZ row without a quoted value" % (infPath, lineno))
            out.append((name, "REG_SZ", data[1:-1]))
        elif flagWord == FLG_ADDREG_TYPE_DWORD:
            out.append((name, "REG_DWORD", int(data, 0)))
        else:
            raise SystemExit(
                "%s:%d: unhandled AddReg type flags %#x — gen_license.py knows REG_SZ "
                "and REG_DWORD only" % (infPath, lineno, flagWord)
            )
    if not out:
        raise SystemExit("%s: no [LicenseInformation] payload found" % infPath)
    return out


def render(values):
    lines = [
        "/* kernel/cm/license.h - GENERATED by tools/gen_license.py from",
        " * third_party/wine/loader/wine.inf's [LicenseInformation] section — the",
        " * payload that writes HKLM\\Software\\Wine\\LicenseInformation into the",
        " * pinned oracle's prefix, and so the payload NtQueryLicenseValue answers",
        " * out of on that leg (dlls/ntdll/unix/registry.c names the key literally).",
        " * DO NOT EDIT BY HAND (Constitution Art. 4 / gate G4). Regenerate with:",
        " *     python3 tools/gen_license.py",
        " *",
        " * proskrnl has no prefix, so CmInitialize (kernel/cm/registry.c) seeds this",
        " * table into the same key — which is what makes the two legs of ntdll:reg",
        " * and of tests/ntapi/sem_reg/license_value.c read the SAME data rather than",
        " * each inventing a plausible one.",
        " *",
        " * kernel/cm/registry.c is the ONE includer, which is what makes `static",
        " * const` right here (the kernel/lib/upcase.h precedent): a second includer",
        " * would get its own silent copy, and there is one seed site, not two.",
        " */",
        "#ifndef PROSKRNL_KERNEL_CM_LICENSE_H",
        "#define PROSKRNL_KERNEL_CM_LICENSE_H",
        "",
        '#include "abi/ntdef.h"',
        '#include "abi/ntregapi.h"',
        '#include "kernel/lib/rtl.h"',
        "",
        "/* One row of the INF section. REG_SZ rows carry `string` and REG_DWORD rows",
        " * carry `dword`; the unused member is zero, and `type` is what says which. */",
        # No leading underscore on the tag: that spelling is a reserved
        # identifier and `make format`'s clang-tidy rewrites it in place,
        # which on a GENERATED file means the checked-in copy and the
        # generator's output drift apart on the next --check.
        "typedef struct CMP_LICENSE_VALUE",
        "{",
        "    PCWSTR name;",
        "    ULONG type;",
        "    PCWSTR string;",
        "    ULONG dword;",
        "} CMP_LICENSE_VALUE;",
        "",
        f"#define CMP_LICENSE_VALUE_COUNT {len(values)}",
        "",
        "static const CMP_LICENSE_VALUE CmpLicenseValues[CMP_LICENSE_VALUE_COUNT] = {",
    ]
    for name, type_, payload in values:
        if type_ == "REG_SZ":
            lines.append('    {WSTR("%s"), REG_SZ, WSTR("%s"), 0},' % (name, payload))
        else:
            lines.append('    {WSTR("%s"), REG_DWORD, 0, %u},' % (name, payload))
    lines += [
        "};",
        "",
        "#endif /* PROSKRNL_KERNEL_CM_LICENSE_H */",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the output is stale")
    parser.add_argument("--inf", default=None)
    args = parser.parse_args()

    inf = pathlib.Path(args.inf) if args.inf else INF
    if not inf.exists():
        sys.exit(f"{inf} missing — build the pinned Wine tree first (tools/setup_linux.sh)")
    values = parse_license(inf)
    text = render(values)

    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            sys.exit(f"{OUT} is stale — run: python3 tools/gen_license.py")
        print(f"{OUT}: up to date ({len(values)} values)")
        return
    OUT.write_text(text)
    print(f"{OUT}: {len(values)} values from {inf}")


if __name__ == "__main__":
    main()
