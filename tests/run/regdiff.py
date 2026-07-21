#!/usr/bin/env python3
# regdiff.py — CUI-1's conviction gate (Art. 6: only a differential test
# convicts). Compare the machine hive proskrnl's firstboot produced against
# the registry the SAME wineboot/wine.inf payload produces in a fresh prefix
# under the pinned oracle wine:
#
#   regdiff.py <proskrnl-SYSTEM-hive> <oracle-system.reg>
#
# Both files are parsed by regdump.py into one canonical form and compared
# key-for-key, value-for-value over HKLM. Divergences print one line each;
# exit 0 iff none remain after the exclusion list below.
#
# The exclusion list is the docs/03 "CUI-1 firstboot notes" scope, spelled
# out here so every excluded delta is a WRITTEN-DOWN deviation, not a silent
# one. Anything not covered by an entry below is a conviction.
import sys

import regdump

# --- the exclusion list ------------------------------------------------------
# Subtree prefixes (lower-cased, under machine\); a trailing \ means the key
# itself AND everything below it.
EXCLUDED_SUBTREES = [
    # WOW64's 32-bit view: proskrnl has no WOW64 (far-future milestone); the
    # oracle's win64 prefix mirrors Software into Wow6432Node (docs/03).
    # Matched as a path component anywhere, see excluded() below.

    # The oracle's wineserver seeds HKLM\System\Setup itself on prefix
    # creation (registry.c create_default_keys? — observed empirically);
    # proskrnl-side wineboot writes it too; kept in the compare unless found
    # divergent for machine-specific reasons.

    # proskrnl test artifact: the M8 persistence module seeds
    # HKLM\Software\prsk_m8_persist on every test boot (user/init-tests/
    # m8_persist.c); not firstboot state.
    "machine\\software\\prsk_m8_persist",
    # Host-machine state the oracle's wineboot derives from the Unix host
    # (CPU identity, host name), where proskrnl's kernel seeds fixed names
    # (kernel/cm/registry.c CmInitialize) or QEMU supplies the hardware:
    # compared values would encode the build host, not the boundary.
    "machine\\hardware",
    "machine\\system\\currentcontrolset\\control\\computername",
    "machine\\system\\currentcontrolset\\services\\tcpip\\parameters",
    # The environment key mixes wine.inf constants (compared: see
    # VALUE_EXCEPTIONS carve-outs) with host-CPU-derived values.
    # (handled per-value below, not as a subtree)
]

# Path-component exclusions: any key whose path CONTAINS this component.
EXCLUDED_COMPONENTS = [
    # WOW64 32-bit registry view (docs/03: ~52 warn-and-continue failures on
    # proskrnl; WOW64 is out of scope until its milestone).
    "wow6432node",
]

# (path suffix, value name) pairs excluded from the value compare; either
# side. Lower-cased. A None name excludes every value directly under that
# exact key path.
EXCLUDED_VALUES = [
    # Host-CPU identity wineboot derives from the running machine
    # (create_environment_registry_keys): differs between the oracle host
    # and QEMU's -cpu max by design.
    ("machine\\system\\currentcontrolset\\control\\session manager\\environment",
     "processor_architecture"),
    ("machine\\system\\currentcontrolset\\control\\session manager\\environment",
     "processor_identifier"),
    ("machine\\system\\currentcontrolset\\control\\session manager\\environment",
     "processor_level"),
    ("machine\\system\\currentcontrolset\\control\\session manager\\environment",
     "processor_revision"),
    ("machine\\system\\currentcontrolset\\control\\session manager\\environment",
     "number_of_processors"),
]


def excluded_key(path):
    for prefix in EXCLUDED_SUBTREES:
        if path == prefix or path.startswith(prefix + "\\"):
            return True
    parts = path.split("\\")
    return any(c in parts for c in EXCLUDED_COMPONENTS)


def excluded_value(path, name):
    if excluded_key(path):
        return True
    return (path, name) in EXCLUDED_VALUES


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: regdiff.py <proskrnl-SYSTEM-hive> <oracle-system.reg>\n")
        return 2
    ours = regdump.load(sys.argv[1], subtree="machine")
    oracle = regdump.load(sys.argv[2], subtree="machine")

    divergences = 0

    def report(kind, what):
        nonlocal divergences
        divergences += 1
        print("regdiff: %s %s" % (kind, what))

    for path in sorted(oracle.keys - ours.keys):
        if not excluded_key(path):
            report("missing key", path)
    for path in sorted(ours.keys - oracle.keys):
        if not excluded_key(path):
            report("extra key", path)

    for (path, name) in sorted(set(oracle.values) | set(ours.values)):
        if excluded_value(path, name):
            continue
        theirs = oracle.values.get((path, name))
        mine = ours.values.get((path, name))
        if theirs is None:
            report("extra value", "%s ! %s = %s %s" % (path, name, mine[0], mine[1]))
        elif mine is None:
            report("missing value", "%s ! %s = %s %s" % (path, name, theirs[0], theirs[1]))
        elif mine != theirs:
            report("differing value",
                   "%s ! %s: proskrnl %s %s != oracle %s %s"
                   % (path, name, mine[0], mine[1], theirs[0], theirs[1]))

    print("regdiff: %d divergence(s)" % divergences)
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
