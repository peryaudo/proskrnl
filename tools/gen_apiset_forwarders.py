#!/usr/bin/env python3
"""Generate the api-set forwarder DLLs an off-the-shelf UCRT binary imports
(Net-3, the acceptance tool's loader closure).

Real NT resolves api-ms-* names through the PEB's ApiSetMap; the pinned
Wine loader does the same and, with no map (proskrnl builds none), falls
back to loading the literal DLL name (dlls/ntdll/loader.c
build_import_name: STATUS_APISET_NOT_PRESENT leaves the buffer as-is).
This script makes those literal names real: for every api-ms-*/ext-* DLL
the given PE imports, it emits a tiny forwarder DLL whose every export
forwards to ucrtbase — nothing is recalled (G4/G8 spirit): the SET of
dlls and the SET of names come from the binary's own import table
(objdump), and the target is the one UCRT host DLL. A function ucrtbase
does not export fails the LOAD loudly in the guest, never silently.

Usage: gen_apiset_forwarders.py <pe> <outdir> [--mingw prefix]
Writes <outdir>/<apiset>.dll ... and <outdir>/specs.txt with one
`win:<path>=windows/system32/<apiset>.dll` line per DLL (mkimage food).
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe")
    parser.add_argument("outdir")
    parser.add_argument("--mingw", default="x86_64-w64-mingw32")
    args = parser.parse_args()

    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    dump = subprocess.run(
        [args.mingw + "-objdump", "-p", args.pe], capture_output=True, text=True, check=True
    ).stdout

    # objdump -p import listing: a "DLL Name: <name>" header, then indented
    # "<vma> <hint> <name>" rows until the next header/blank section.
    sets: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in dump.splitlines():
        header = re.match(r"\s*DLL Name: (\S+)", line)
        if header:
            name = header.group(1)
            low = name.lower()
            if low.startswith("api-ms-") or low.startswith("ext-ms-"):
                current = sets.setdefault(low, [])
            else:
                current = None
            continue
        if current is None:
            continue
        row = re.match(r"\s*[0-9a-f]+\s+\d+\s+(\S+)\s*$", line)
        if row:
            current.append(row.group(1))

    if not sets:
        sys.exit("gen_apiset_forwarders: no api-ms imports found (wrong binary?)")

    empty_c = out / "empty.c"
    empty_c.write_text("/* forwarder shell: every export forwards (see the .def) */\n")

    specs = []
    for dll, names in sorted(sets.items()):
        base = dll[: -len(".dll")] if dll.endswith(".dll") else dll
        def_path = out / (base + ".def")
        dll_path = out / (base + ".dll")
        lines = [f'LIBRARY "{dll}"', "EXPORTS"]
        lines += [f"  {name} = ucrtbase.{name}" for name in sorted(set(names))]
        def_path.write_text("\n".join(lines) + "\n")
        subprocess.run(
            [
                args.mingw + "-gcc",
                "-shared",
                "-nostdlib",
                "-nostartfiles",
                "-Wl,--entry=0",
                str(empty_c),
                str(def_path),
                "-o",
                str(dll_path),
            ],
            check=True,
        )
        specs.append(f"win:{dll_path}=windows/system32/{dll}")
        print(f"gen_apiset_forwarders: {dll} ({len(set(names))} forwards)")

    (out / "specs.txt").write_text("\n".join(specs) + "\n")


if __name__ == "__main__":
    main()
