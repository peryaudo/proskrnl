#!/usr/bin/env python3
"""Generate the %windir% .ini furniture wineboot would have written.

No proskrnl image gets `[SystemIni]`. On the hermetic ntapi image nothing
runs it at all — user/smss/smss.c skips firstboot when wineboot.exe is
absent — and on an image that DOES run `wineboot --init` (the `make run` set,
which the winetest leg bakes too) the baked wine.inf is the registry-only
filter, whose `UpdateInis=` lines tools/filter_inf.py drops so that their
failure on absent source media cannot abort the AddReg pass behind them. So
C:\\windows\\win.ini and C:\\windows\\system.ini do not exist on either. The
pinned oracle runs in a wineprefix where they DO, and a differential gate
whose two legs disagree about the environment measures the environment
rather than the boundary (tests/winetest/manifest.txt's header records the
same lesson for the host locale and the uid).

The payload is not recalled and not transcribed — it is PARSED out of the
pinned tree at bake time: `third_party/wine/loader/wine.inf`'s
`[SystemIni]` section, which
`[BaseInstall]` applies with `UpdateInis=SystemIni`. Each line there has the
INF UpdateInis shape

    <ini-file>, <section>, <old-entry>, <new-entry>[, <flags>]

and Wine uses only the "append <new-entry> to [<section>]" form, so the
generated file is the new-entry column grouped by section, in file order,
CRLF-terminated — byte-identical to what a wineprefix's own
drive_c/windows/{win,system}.ini contains. `--check <prefix>` asserts that
against a real prefix.

Usage:
    gen_sysini.py <outdir> [--inf <wine.inf>]
    gen_sysini.py --check <wineprefix> [--inf <wine.inf>]
"""

import argparse
import pathlib
import re
import sys

# `<file>, <section>,<old>,"<new>"` — the only UpdateInis form [SystemIni]
# uses. A line that does not match is NOT silently skipped: an unhandled
# form would drop payload and the image would quietly diverge again.
LINE_RE = re.compile(r'^\s*([\w.]+)\s*,\s*([^,]+?)\s*,\s*([^,]*?)\s*,\s*"(.*)"\s*$')


def parse_system_ini(inf_path):
    """Return {ini filename: [(section, entry), ...]} from [SystemIni]."""
    # wine.inf is written in the INF file's own encoding; it is plain ASCII
    # in the pinned tree, and latin-1 keeps any stray byte round-trippable.
    lines = pathlib.Path(inf_path).read_text(encoding="latin-1").splitlines()
    out = {}
    inSection = False
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("["):
            inSection = stripped.lower() == "[systemini]"
            continue
        if not inSection or not stripped or stripped.startswith(";"):
            continue
        m = LINE_RE.match(stripped)
        if not m:
            raise SystemExit(
                "%s:%d: unhandled UpdateInis form %r — gen_sysini.py must be "
                "taught it rather than dropping it" % (inf_path, lineno, stripped))
        iniFile, section, oldEntry, newEntry = m.groups()
        if oldEntry:
            raise SystemExit(
                "%s:%d: UpdateInis old-entry replacement is not implemented "
                "(the pinned tree does not use it): %r" % (inf_path, lineno, stripped))
        out.setdefault(iniFile.lower(), []).append((section, newEntry))
    if not out:
        raise SystemExit("%s: no [SystemIni] payload found" % inf_path)
    return out


def render(name, entries):
    """entries -> the .ini text, CRLF, sections in first-seen order."""
    text = []
    seen = []
    current = None
    for section, entry in entries:
        if section != current:
            if section in seen:
                # A re-opened section would emit a second [section] header,
                # which a real prefix's file does not have — the same quiet
                # divergence the parser refuses an unknown FORM for. Merging
                # is the other legal answer; refuse until a pin needs one.
                raise SystemExit(
                    "%s: [%s] is re-opened after another section — gen_sysini.py "
                    "must be taught how a prefix renders that" % (name, section))
            text.append("[%s]" % section)
            seen.append(section)
            current = section
        text.append(entry)
    return "".join(line + "\r\n" for line in text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", nargs="?")
    ap.add_argument("--inf", default=None)
    ap.add_argument("--check", metavar="WINEPREFIX")
    args = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    inf = args.inf or (root / "third_party" / "wine" / "loader" / "wine.inf")
    files = parse_system_ini(inf)

    if args.check:
        windir = pathlib.Path(args.check) / "drive_c" / "windows"
        bad = 0
        for name, entries in sorted(files.items()):
            want = render(name, entries).encode("latin-1")
            got = (windir / name).read_bytes()
            if want != got:
                print("gen_sysini: %s differs from %s" % (name, windir / name))
                bad = 1
        if not bad:
            print("gen_sysini: %s match the prefix at %s"
                  % ("+".join(sorted(files)), args.check))
        return bad

    if not args.outdir:
        ap.error("an output directory is required without --check")
    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    for name, entries in sorted(files.items()):
        (outdir / name).write_bytes(render(name, entries).encode("latin-1"))
        print(outdir / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
