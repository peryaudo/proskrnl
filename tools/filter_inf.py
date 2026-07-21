#!/usr/bin/env python3
"""filter_inf.py - stage a registry-only wine.inf for the proskrnl disk (CUI-1).

The baked image drives wine.inf through the unmodified setupapi INF engine
(rundll32 InstallHinfSection, spawned by wineboot --init). Two of its
directive families are landmines on a disk that has no INF source media:

  WineFakeDlls=  setupapi's fake-dll machinery truncates any destination
                 carrying the "Wine builtin DLL" signature BEFORE reading the
                 (absent) source - a naive run deletes the baked system32.
  CopyFiles=/DelFiles=/RenFiles=
                 the file queue fails on the absent source media and aborts
                 SetupInstallFromInfSectionW before its AddReg pass.
  UpdateInis=    SetupInstallFromInfSectionW runs SPINST_INIFILES BEFORE
                 SPINST_REGISTRY; BaseInstall opens with UpdateInis=SystemIni,
                 and a failure there returns FALSE before its ~500-line AddReg
                 ever runs. Dropping it lets the machine-state payload apply.
  RegisterDlls=  self-registration loads GUI DLLs the disk does not bake.
  ProfileItems=  Start Menu shortcuts; profile_items_callback calls
                 shell32 SHGetFolderPathW (GUI scope, not baked).

This filter drops exactly those directive lines (with their backslash
continuations) at image-bake time. The INF is input data staged by the image
builder - the oracle keeps consuming its own full wine.inf, and no Wine byte
changes (docs/03 CUI-1 notes). Everything else - AddReg/DelReg (the ~500-line
machine-state payload) and the .Services sections - is kept.

Usage: filter_inf.py <wine.inf> <output.inf>
"""

import re
import sys

DROPPED = ("WineFakeDlls", "RegisterDlls", "CopyFiles", "DelFiles", "RenFiles", "UpdateInis",
           "ProfileItems")
DIRECTIVE = re.compile(
    r"^\s*(" + "|".join(DROPPED) + r")\s*=", re.IGNORECASE
)


def filter_inf(text: str) -> str:
    out = []
    dropping = False
    for line in text.splitlines(keepends=True):
        if dropping:
            # Swallow the continuation lines of a dropped directive.
            dropping = line.rstrip("\r\n").rstrip().endswith("\\")
            continue
        if DIRECTIVE.match(line):
            dropping = line.rstrip("\r\n").rstrip().endswith("\\")
            continue
        out.append(line)
    return "".join(out)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: filter_inf.py <wine.inf> <output.inf>")
    source, destination = sys.argv[1], sys.argv[2]
    # wine.inf is plain ASCII/UTF-8; keep bytes as-is via latin-1 round-trip.
    with open(source, encoding="latin-1", newline="") as handle:
        text = handle.read()
    filtered = filter_inf(text)
    kept = sum(1 for l in filtered.splitlines() if l.strip())
    dropped = sum(1 for l in text.splitlines() if l.strip()) - kept
    with open(destination, "w", encoding="latin-1", newline="") as handle:
        handle.write(filtered)
    print(f"filter_inf: {destination}: dropped {dropped} lines "
          f"({', '.join(DROPPED)})", file=sys.stderr)


if __name__ == "__main__":
    main()
