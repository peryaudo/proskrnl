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

Usage: filter_inf.py [--keep NAME[,NAME...]] [--add-register DLL[,DLL...]]
       <wine.inf> <output.inf>

--keep exempts directive families from the drop list. The registry
differential's oracle leg (tests/run/run.sh firstboot) uses
--keep WineFakeDlls: on the oracle host the fake-dll sources exist and a
prefix WITHOUT fake dlls cannot launch any non-bootstrap process (the
initial process's null dll-load-path never falls back to builtins), while
the directive writes no registry - so keeping it changes no compared state.

--add-register appends `11,,<dll>,1` entries to [RegisterDllsSection] (with
--keep RegisterDlls so the directive survives). AUD-2's audio images need
mmdevapi's COM classes in the hive, and mmdevapi is NOT in wine.inf's own
RegisterDlls list - in a real prefix its CLSID lands via the fake-dll
registrar (WINE_REGISTRY resources), a path this filter drops. Injecting
the entry runs the DLL's own DllRegisterServer through Wine's own
registrar at firstboot (setupapi + atl100, the GUI-6 shell recipe) - one
authority, never a hand-typed CLSID seed (Art. 11 / gate G8).
"""

import re
import sys

DROPPED = ("WineFakeDlls", "RegisterDlls", "CopyFiles", "DelFiles", "RenFiles", "UpdateInis",
           "ProfileItems")


def filter_inf(text: str, dropped=DROPPED) -> str:
    directive = re.compile(r"^\s*(" + "|".join(dropped) + r")\s*=", re.IGNORECASE)
    out = []
    dropping = False
    for line in text.splitlines(keepends=True):
        if dropping:
            # Swallow the continuation lines of a dropped directive.
            dropping = line.rstrip("\r\n").rstrip().endswith("\\")
            continue
        if directive.match(line):
            dropping = line.rstrip("\r\n").rstrip().endswith("\\")
            continue
        out.append(line)
    return "".join(out)


def add_register(text: str, dlls) -> str:
    """Append 11,,<dll>,1 lines to [RegisterDllsSection] (11 = system32)."""
    out = []
    in_section = False
    added = False
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            if in_section and not added:
                sys.exit("filter_inf: [RegisterDllsSection] vanished mid-file")
            if in_section:
                in_section = False
            if stripped.lower() == "[registerdllssection]":
                in_section = True
                out.append(line)
                for dll in dlls:
                    out.append(f"11,,{dll},1\r\n" if line.endswith("\r\n") else f"11,,{dll},1\n")
                added = True
                continue
        out.append(line)
    if not added:
        sys.exit("filter_inf: no [RegisterDllsSection] to --add-register into")
    return "".join(out)


def main() -> None:
    args = sys.argv[1:]
    directives = DROPPED
    registered = ()
    while args and args[0] in ("--keep", "--add-register"):
        if args[0] == "--keep":
            exempt = {name.lower() for name in args[1].split(",")}
            directives = tuple(d for d in DROPPED if d.lower() not in exempt)
        else:
            registered = tuple(args[1].split(","))
        args = args[2:]
    if len(args) != 2:
        sys.exit("usage: filter_inf.py [--keep NAME[,NAME...]] "
                 "[--add-register DLL[,DLL...]] <wine.inf> <output.inf>")
    if registered and "registerdlls" not in {d.lower() for d in DROPPED} - {d.lower() for d in directives}:
        sys.exit("filter_inf: --add-register needs --keep RegisterDlls "
                 "(the injected entries would be dropped)")
    source, destination = args[0], args[1]
    # wine.inf is plain ASCII/UTF-8; keep bytes as-is via latin-1 round-trip.
    with open(source, encoding="latin-1", newline="") as handle:
        text = handle.read()
    filtered = filter_inf(text, directives)
    if registered:
        filtered = add_register(filtered, registered)
    kept = sum(1 for l in filtered.splitlines() if l.strip())
    dropped = sum(1 for l in text.splitlines() if l.strip()) - kept
    with open(destination, "w", encoding="latin-1", newline="") as handle:
        handle.write(filtered)
    print(f"filter_inf: {destination}: dropped {dropped} lines "
          f"({', '.join(directives)})", file=sys.stderr)


if __name__ == "__main__":
    main()
