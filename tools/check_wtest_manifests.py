#!/usr/bin/env python3
"""tools/check_wtest_manifests.py - the winetest manifests are EXHAUSTIVE.

The two manifests (tests/winetest/manifest.txt for the CUI legs,
manifest-gui.txt for winetest-gui) state a rule about themselves: coverage is
the comments, the gate is the active list. Every subtest the covered modules
have is written down - active if it is green, parked with its triage if it is
not - so the frontier is a list rather than an absence, and nothing is lost by
being quietly omitted. That rule is only worth what enforces it: a pinned-tree
bump that ADDS a subtest silently shrinks the coverage the manifests claim,
and a subtest that is renamed away leaves a pair nobody can run.

So this asks the pin, not a reviewer:

  * which modules are covered comes from the Makefile - the WT_<MODULE>_D
    variables (the CUI test binaries this tree links) plus WTEST_USER32 (the
    GUI module, which the pinned tree builds itself). One authority for "what
    the project builds test binaries for", and it is the file that builds them.
  * which subtests each module HAS comes from the pinned tree's own
    dlls/<mod>/tests/Makefile.in: every .c in SOURCES except the helper DLLs
    (a .c with a matching .spec is a runtime-loaded module, not a subtest).
  * which manifest a module belongs in is the CUI/GUI split below.

Then: every pair exists in exactly one manifest, every pair a manifest names
exists in the tree, and every ACTIVE line parses under the shared grammar
`<exe>:<subtest>[:<budget>][:<timeout_s>]` with the same bounds both real
parsers use (tests/run/run.sh wtest_parse_manifest, user/smss/session.c
SessionParseWtestManifest) - so a manifest that would die on the image cannot
pass a style gate first.

A PARKED pair is a comment line whose text is a pair: `# ntdll_test.exe:alpc`.
Nothing here requires it to carry a TODO - manifest.txt's category (2) is
pairs that are deliberately out of scope and deliberately have none.

Its input is TRACKED files of the pinned tree, so it runs with the other checks
that read the pin (`make gen-check`, via `make wtest-manifest-check`) and not
with `make format`, which runs on a bare checkout where third_party/wine is not
present at all.

Usage:
    tools/check_wtest_manifests.py            check (exit 1 on any finding)
    tools/check_wtest_manifests.py --report   print the coverage table
"""

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CUI_MANIFEST = os.path.join("tests", "winetest", "manifest.txt")
GUI_MANIFEST = os.path.join("tests", "winetest", "manifest-gui.txt")

# The GUI leg's modules. Everything else the Makefile names goes in the CUI
# manifest -- including the audio modules, which need a GUI boot but are the
# CUI gate's pairs by decision (manifest.txt's AUD-2 amendment).
GUI_MODULES = {"user32_test.exe"}

# The bounds both parsers apply, so a line this accepts is a line they accept.
BUDGET_MAX = 65535
TIMEOUT_MAX = 100000

PAIR_RE = re.compile(r"^([A-Za-z0-9_.]+\.exe):([A-Za-z0-9_]+)(?::([0-9]*))?(?::([0-9]*))?$")


def test_dirs():
    """The pinned-tree test directories the Makefile names, as {exe: dir}."""
    makefile = open(os.path.join(ROOT, "Makefile"), encoding="utf-8").read()
    # The WT_*_D variables point at the BUILD subdirectory (…/tests/
    # x86_64-windows) because that is where the linked objects are; Makefile.in
    # is one level up, with the sources.
    dirs = [
        os.path.dirname(d) if os.path.basename(d) == "x86_64-windows" else d
        for d in re.findall(r"^WT_[A-Z0-9_]+_D\s*:=\s*(\S+)$", makefile, re.M)
    ]
    user32 = re.search(r"^WTEST_USER32\s*:=\s*(\S+)$", makefile, re.M)
    if user32:
        # .../dlls/user32/tests/x86_64-windows/user32_test.exe -> .../tests
        dirs.append(os.path.dirname(os.path.dirname(user32.group(1))))
    if not dirs:
        sys.exit("check_wtest_manifests: the Makefile names no WT_*_D test directory")
    out = {}
    for rel in dirs:
        makefile_in = os.path.join(ROOT, rel, "Makefile.in")
        if not os.path.exists(makefile_in):
            sys.exit(
                "check_wtest_manifests: %s missing.\n"
                "The pinned Wine tree is what says which subtests exist; check it out\n"
                "(git submodule update --init --depth 1 third_party/wine) and re-run."
                % os.path.relpath(makefile_in, ROOT)
            )
        out[module_exe(makefile_in, rel)] = rel
    return out


def module_exe(makefile_in, rel):
    """The test binary's name, the way winemaker spells it: <module>_test.exe,
    the module being TESTDLL without a .dll tail (cmd.exe keeps its .exe, hence
    cmd.exe_test.exe)."""
    text = open(makefile_in, encoding="utf-8").read()
    match = re.search(r"^TESTDLL\s*=\s*(\S+)$", text, re.M)
    if not match:
        sys.exit("check_wtest_manifests: %s/Makefile.in names no TESTDLL" % rel)
    module = match.group(1)
    if module.endswith(".dll"):
        module = module[: -len(".dll")]
    return module + "_test.exe"


def module_subtests(rel):
    """Every subtest the module has: the .c files of SOURCES, minus the helper
    DLLs (a .c with a matching .spec is a separate module the tests LOAD)."""
    text = open(os.path.join(ROOT, rel, "Makefile.in"), encoding="utf-8").read()
    match = re.search(r"^SOURCES\s*=\s*((?:.*\\\n)*.*)$", text, re.M)
    if not match:
        sys.exit("check_wtest_manifests: %s/Makefile.in names no SOURCES" % rel)
    names = match.group(1).replace("\\\n", " ").split()
    specs = {os.path.splitext(n)[0] for n in names if n.endswith(".spec")}
    return sorted(
        os.path.splitext(n)[0]
        for n in names
        if n.endswith(".c") and os.path.splitext(n)[0] not in specs
    )


def read_manifest(rel):
    """{(exe, subtest): (lineno, active)} plus a list of grammar findings."""
    pairs, findings = {}, []
    path = os.path.join(ROOT, rel)
    for lineno, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.rstrip("\n").rstrip("\r").rstrip()
        active = not line.startswith("#")
        if not active:
            # A comment is a PARKED pair only if its text is exactly a pair;
            # every other comment is prose and is not read as anything.
            line = line.lstrip("#").strip()
            if not PAIR_RE.match(line):
                continue
        if not line:
            continue
        match = PAIR_RE.match(line)
        if not match:
            if active:
                findings.append(
                    "%s:%d: malformed line %r "
                    "(want <exe>:<subtest>[:<budget>][:<timeout_s>])" % (rel, lineno, line)
                )
            continue
        exe, subtest, budget, timeout = match.groups()
        if active:
            if budget not in (None, "") and int(budget) > BUDGET_MAX:
                findings.append("%s:%d: budget %s is past %d" % (rel, lineno, budget, BUDGET_MAX))
            if timeout not in (None, ""):
                if int(timeout) < 1 or int(timeout) > TIMEOUT_MAX:
                    findings.append(
                        "%s:%d: timeout %s is not in 1..%d" % (rel, lineno, timeout, TIMEOUT_MAX)
                    )
        key = (exe, subtest)
        if key in pairs:
            findings.append(
                "%s:%d: %s:%s is already declared at line %d"
                % (rel, lineno, exe, subtest, pairs[key][0])
            )
            continue
        pairs[key] = (lineno, active)
    return pairs, findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the coverage table")
    args = parser.parse_args()

    dirs = test_dirs()
    cui, findings = read_manifest(CUI_MANIFEST)
    gui, gui_findings = read_manifest(GUI_MANIFEST)
    findings += gui_findings

    declared = {}
    for key in cui:
        declared[key] = CUI_MANIFEST
    for key, value in gui.items():
        if key in declared:
            findings.append(
                "%s:%s is declared in BOTH manifests (%s and %s)"
                % (key[0], key[1], CUI_MANIFEST, GUI_MANIFEST)
            )
        declared[key] = GUI_MANIFEST

    rows = []
    upstream = set()
    for exe in sorted(dirs):
        want = GUI_MANIFEST if exe in GUI_MODULES else CUI_MANIFEST
        subtests = module_subtests(dirs[exe])
        active = 0
        for subtest in subtests:
            key = (exe, subtest)
            upstream.add(key)
            where = declared.get(key)
            if where is None:
                findings.append(
                    "%s:%s exists in %s but is in neither manifest — add it to %s, active or "
                    "parked with its triage" % (exe, subtest, dirs[exe], want)
                )
            elif where != want:
                findings.append(
                    "%s:%s is declared in %s but belongs in %s" % (exe, subtest, where, want)
                )
            elif (cui if want == CUI_MANIFEST else gui)[key][1]:
                active += 1
        rows.append((exe, want, len(subtests), active))

    for key, where in sorted(declared.items()):
        if key not in upstream:
            findings.append(
                "%s: %s:%s is not a subtest of the pinned tree — a typo, or the pin renamed it"
                % (where, key[0], key[1])
            )

    if args.report:
        print("%-22s %-30s %5s %7s" % ("module", "manifest", "pairs", "active"))
        for exe, want, total, active in rows:
            print("%-22s %-30s %5d %7d" % (exe, want, total, active))

    for finding in findings:
        print("check_wtest_manifests: " + finding, file=sys.stderr)
    print(
        "== wtest-manifest check: %d failing (%d pairs over %d modules) =="
        % (len(findings), len(upstream), len(rows))
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
