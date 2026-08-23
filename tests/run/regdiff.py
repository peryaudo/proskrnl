#!/usr/bin/env python3
# regdiff.py — CUI-1's conviction gate (Art. 6: only a differential test
# convicts). Compare the machine hive proskrnl's firstboot produced against
# the registry the SAME filtered wine.inf payload produces in a fresh prefix
# under the pinned oracle wine:
#
#   regdiff.py <proskrnl-SYSTEM-hive> <oracle-system.reg> <filtered-wine.inf>
#
# The INF is the payload's own spec, so it also DEFINES the compared scope:
# every key an AddReg line writes must exist on both sides with identical
# values (regdump.py canonicalizes both formats). Scoping to the INF is what
# makes the compare honest on both flanks:
#
#   - the ORACLE side carries registry state proskrnl legitimately never has
#     (each fake dll's embedded REGINST registration resource — thousands of
#     Software\Classes entries applied by setupapi's fake-dll machinery,
#     which the filtered INF drops; wineserver's own prefix furniture), and
#   - the PROSKRNL side must not contain anything BEYOND the payload + the
#     documented dynamic writers — an "extra keys" sweep convicts that.
#
# Exclusions are the docs/03 "CUI-1 firstboot notes" scope, spelled out here
# so every excluded delta is a WRITTEN-DOWN deviation, not a silent one.
import re
import sys

import regdump

# --- the exclusion list ------------------------------------------------------

# NT keeps numbered control sets (System\ControlSet001) selected through the
# System\Select key, with CurrentControlSet a REG_LINK onto the chosen one —
# and so does the oracle's wineserver. proskrnl has exactly one control set
# and its kernel skeleton names the key CurrentControlSet literally (the
# skeleton predates wine.inf; registry symlinks themselves are built as of
# GUI-2, docs/03 M8 notes). Fold the oracle's numbered set onto the same
# name before comparing.
ORACLE_RENAMES = [
    ("machine\\system\\controlset001", "machine\\system\\currentcontrolset"),
]

# Subtree prefixes (lower-cased); the key itself and everything below it.
EXCLUDED_SUBTREES = [
    # proskrnl test artifact: the M8 persistence module seeds
    # HKLM\Software\prsk_m8_persist on every test boot (tests/boot/
    # m8_persist.c); not firstboot state.
    "machine\\software\\prsk_m8_persist",
    # Host-machine state wineboot derives from the machine it runs on
    # (create_hardware_registry_keys, create_computer_name_keys), where
    # proskrnl's kernel seeds fixed names (kernel/cm/registry.c
    # CmInitialize) or QEMU supplies the hardware: comparing them would
    # encode the build host, not the boundary.
    "machine\\hardware",
    "machine\\system\\currentcontrolset\\control\\computername",
    "machine\\system\\currentcontrolset\\services\\tcpip\\parameters",
    # Device enumeration state (wineboot install_root_pnp_devices): the
    # winebth/winebus/wineusb root devices install fully on the oracle
    # (SetupDi* + winedevice.exe) but only partially on proskrnl (no .inf
    # files, no SCM — docs/03 "warn-and-continue as stock"); PnP is not
    # CUI-1 surface.
    "machine\\system\\currentcontrolset\\enum",
    "machine\\system\\currentcontrolset\\control\\deviceclasses",
    # NT's control-set selection furniture (see ORACLE_RENAMES above):
    # proskrnl has one implicit control set, no Select key.
    "machine\\system\\select",
]

# Path-component exclusions: any key whose path CONTAINS this component.
EXCLUDED_COMPONENTS = [
    # WOW64 32-bit registry view (docs/03: ~52 warn-and-continue failures on
    # proskrnl; WOW64 is out of scope until its milestone).
    "wow6432node",
]

# (path, value name) pairs excluded from the value compare, either side.
EXCLUDED_VALUES = [
    # shell32's DllRegisterServer seeds the two profile directories it owns
    # (ProgramData, Public) into ProfileList. Same reason as the
    # FolderDescriptions subtree below: the oracle's RegisterDlls pass cannot
    # run to completion, so self-registration output is out of scope.
    ("machine\\software\\microsoft\\windows nt\\currentversion\\profilelist", "programdata"),
    ("machine\\software\\microsoft\\windows nt\\currentversion\\profilelist", "public"),
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
    # The CSIDL-dirid degradation of the shell32 seam (docs/03 "CUI-1
    # firstboot notes"): without shell32, setupapi's get_csidl_dir takes the
    # get_unknown_dirid path, so AddReg value data referencing a CSIDL
    # profile directory (Program Files and friends) renders as
    # "...\system32\unknown\..." instead of the oracle host's real folder.
    # The affected values are exactly wine.inf's dirid-16xxx references.
    ("machine\\software\\classes\\rtffile\\shell\\open\\command", ""),
    ("machine\\software\\classes\\rtffile\\shell\\print\\command", ""),
    ("machine\\software\\classes\\wrifile\\shell\\open\\command", ""),
    ("machine\\software\\classes\\wrifile\\shell\\print\\command", ""),
    ("machine\\software\\microsoft\\mediaplayer", "installation directorylfn"),
    ("machine\\software\\microsoft\\windows\\currentversion", "commonfilesdir"),
    ("machine\\software\\microsoft\\windows\\currentversion", "commonfilesdir (x86)"),
    ("machine\\software\\microsoft\\windows\\currentversion", "programfilesdir"),
    ("machine\\software\\microsoft\\windows\\currentversion", "programfilesdir (x86)"),
    # wineboot refreshes the timezone names from the host zone database
    # after the INF writes their empty NOCLOBBER defaults; proskrnl has no
    # zone database below it (the RTC supplies UTC time only, docs/03), so
    # the INF defaults survive there while the oracle host writes its own.
    ("machine\\system\\currentcontrolset\\control\\timezoneinformation", "standardname"),
    ("machine\\system\\currentcontrolset\\control\\timezoneinformation", "timezonekeyname"),
]

# Value names excluded under ANY key: REG_LINK plumbing. Both runners now
# create wine.inf's Time Zones link (registry symlinks are built, GUI-2),
# but both dumps RESOLVE links while walking, so the SymbolicLinkValue value
# itself is only visible through OBJ_OPENLINK opens neither dumper makes;
# the CurrentControlSet link is folded by ORACLE_RENAMES.
EXCLUDED_VALUE_NAMES = [
    "symboliclinkvalue",
]

# proskrnl-side keys that are allowed to exist OUTSIDE the INF payload scope:
# the kernel's own skeleton (kernel/cm/registry.c CmInitialize) and the
# dynamic keys wineboot writes at every boot (create_dynamic_registry_keys,
# create_environment_registry_keys — Session Manager\Environment is also INF
# scope; Windows\CurrentVersion\RunServices* are ProcessRunKeys probes).
ALLOWED_EXTRA_SUBTREES = [
    "machine\\system\\currentcontrolset\\control\\session manager",
    # SELF-REGISTRATION output. $(WINE_INF_FULL) keeps RegisterDlls, so a GUI
    # first boot runs shell32's, mmdevapi's and dsound's own DllRegisterServer
    # through Wine's own registrar; shell32's writes ~120 FolderDescriptions
    # keys. The `firstboot` leg is a CUI boot and applies $(WINE_INF_CUI),
    # which drops the directive -- so on that leg these subtrees are EMPTY on
    # both sides and the allowance is dormant. It is kept because it is the
    # documented statement of what is out of scope, and because this file is
    # also pointed at hives from GUI boots by hand. The leg does not lean on
    # it: run.sh firstboot requires the guest to say it installed the
    # registry-only inf, so a full-inf hive cannot arrive here and be excused.
    #
    # The ORACLE cannot answer for those, and that is measured rather than
    # assumed: with RegisterDlls kept, the oracle prefix's own pass has all
    # 30 fake dlls to register instead of the three the disk carries, and it
    # WEDGES — rundll32 sat at 0% CPU for 18 minutes inside
    # InstallHinfSection and the leg never reached a verdict. So this payload
    # is out of the compared scope, the way each fake dll's embedded REGINST
    # registration is out of it on the oracle side (the header's first
    # flank). What stays in scope is the whole AddReg machine-state payload,
    # which is what CUI-1 is about.
    "machine\\software\\microsoft\\windows\\currentversion\\explorer\\folderdescriptions",
    # msacm32's DRIVER CACHE, built the first time anything enumerates the
    # ACM codecs (dlls/msacm32/driver.c MSACM_ReadCache) — reached during
    # firstboot through the dsound/mmdevapi registration above. Its subject
    # is the .acm modules the image bakes; the oracle's prefix has them as
    # fake dlls and never enumerates them, so the cache exists on one side
    # only. A runtime writer's cache, not machine state the INF specifies.
    "machine\\software\\microsoft\\audiocompressionmanager",
]

# The same allowance in SUFFIX form: shell32's DllRegisterServer adds a
# ShellFolder subkey to each CLSID it registers as a shell folder. The CLSID
# keys themselves ARE payload (wine.inf writes them) and stay compared; the
# ShellFolder child is self-registration output, the FolderDescriptions case
# one level down. Written as a rule rather than as seven literal CLSIDs so a
# wine pin that registers an eighth does not read as a divergence.
def allowed_extra_key(path):
    return (path.startswith("machine\\software\\classes\\clsid\\")
            and path.endswith("\\shellfolder"))


def excluded_key(path):
    for prefix in EXCLUDED_SUBTREES:
        if path == prefix or path.startswith(prefix + "\\"):
            return True
    parts = path.split("\\")
    return any(c in parts for c in EXCLUDED_COMPONENTS)


def excluded_value(path, name):
    if excluded_key(path):
        return True
    if name in EXCLUDED_VALUE_NAMES:
        return True
    return (path, name) in EXCLUDED_VALUES


def rename_path(path):
    for old, new in ORACLE_RENAMES:
        if path == old or path.startswith(old + "\\"):
            return new + path[len(old):]
    return path


def apply_renames(tree):
    renamed = regdump.RegTree()
    renamed.keys = {rename_path(p) for p in tree.keys}
    renamed.values = {(rename_path(p), n): v for (p, n), v in tree.values.items()}
    return renamed


# --- the INF payload scope ---------------------------------------------------

# Registry roots as AddReg spells them (setupapi/install.c append_multi_sz /
# get_root_key): HKCR is the HKLM classes view on the machine side.
INF_ROOTS = {
    "hklm": "machine",
    "hkcr": "machine\\software\\classes",
}


def split_inf_fields(line):
    """Split an INF entry line on commas, honoring double quotes ("" is a
    literal quote inside a quoted field — setupapi's PARSER_IN_STRING rule)."""
    fields = []
    cur = []
    in_quotes = False
    i = 0
    while i < len(line):
        c = line[i]
        if c == '"':
            if in_quotes and i + 1 < len(line) and line[i + 1] == '"':
                cur.append('"')
                i += 2
                continue
            in_quotes = not in_quotes
        elif c == "," and not in_quotes:
            fields.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    fields.append("".join(cur).strip())
    return fields


def inf_addreg_scope(inf_path):
    """(keys, values): the lower-cased machine-side key paths and
    (path, valuename) pairs the INF's REACHABLE AddReg sections write.

    Reachable = what `InstallHinfSection PreInstall/DefaultInstall` installs
    on an amd64 machine: the undecorated section plus its .nt/.ntamd64
    decorations (SetupDiGetActualSectionToInstall), Needs= recursion, then
    each AddReg= section list. Sections for other architectures (.ntarm64,
    Wow64Install, ...) are installed by NEITHER runner and must not enter
    the scope. Good-enough INF reading for scope purposes: [Strings]
    substitution, quoted fields, HKLM/HKCR roots (HKCU/HKU are out of the
    machine differential; HKR never appears in the kept sections)."""
    with open(inf_path, encoding="latin-1") as f:
        text = f.read()

    # splice continuations, collect lines per section
    sections = {}
    strings = {}
    section = None
    lines = []
    for raw in text.splitlines():
        raw = raw.split(";")[0].rstrip()
        if not raw:
            continue
        if lines and lines[-1].endswith("\\"):
            lines[-1] = lines[-1][:-1] + raw.lstrip()
            continue
        lines.append(raw)
    for line in lines:
        if line.startswith("["):
            section = line[1 : line.index("]")].lower()
            sections.setdefault(section, [])
            continue
        if section is not None:
            sections[section].append(line)
        if section == "strings" and "=" in line:
            name, _, value = line.partition("=")
            strings[name.strip().lower()] = value.strip().strip('"')

    def substitute(s):
        return re.sub(r"%([^%]+)%", lambda m: strings.get(m.group(1).lower(), m.group(0)), s)

    def decorated(name):
        # SetupDiGetActualSectionToInstall: the MOST SPECIFIC existing
        # decoration replaces the others — they never stack.
        for suffix in (".ntamd64", ".nt", ""):
            if name.lower() + suffix in sections:
                return [name.lower() + suffix]
        return []

    # walk PreInstall/DefaultInstall + Needs= to the AddReg section lists
    install = []
    pending = ["PreInstall", "DefaultInstall"]
    seen = set()
    while pending:
        name = pending.pop()
        for sec in decorated(name):
            if sec in seen:
                continue
            seen.add(sec)
            install.append(sec)
            for line in sections[sec]:
                directive, _, value = line.partition("=")
                if directive.strip().lower() == "needs":
                    pending.extend(n.strip() for n in value.split(",") if n.strip())

    addreg = []
    for sec in install:
        for line in sections[sec]:
            directive, _, value = line.partition("=")
            if directive.strip().lower() == "addreg":
                addreg.extend(n.strip().lower() for n in value.split(",") if n.strip())

    keys = set()
    values = set()
    for sec in addreg:
        for line in sections.get(sec, []):
            fields = split_inf_fields(substitute(line))
            if len(fields) < 2:
                continue
            root = INF_ROOTS.get(fields[0].lower())
            if root is None:
                continue  # per-user roots: outside the machine differential
            subkey = fields[1].strip("\\")
            path = (root + "\\" + subkey if subkey else root).lower()
            if excluded_key(path):
                continue
            name = fields[2] if len(fields) > 2 else ""
            try:
                flags = int(fields[3], 0) if len(fields) > 3 and fields[3] else 0
            except ValueError:
                flags = 0
            # AddReg flag bits: pinned tree include/setupapi.h —
            # FLG_ADDREG_KEYONLY 0x10; type bits (flags >> 16) << 16 with
            # FLG_ADDREG_TYPE_MULTI_SZ 0x10000 | FLG_ADDREG_TYPE_EXPAND_SZ
            # 0x20000 spelling REG_LINK's 6 as 0x60000 (wine.inf's
            # SymbolicLinkValue lines use exactly that).
            if (flags & 0x60000) == 0x60000:
                continue  # REG_LINK entries are excluded wholesale (docs/03)
            keys.add(path)
            if len(fields) > 2 and not (flags & 0x10):  # FLG_ADDREG_KEYONLY
                values.add((path, name.lower()))
    return keys, values


def ancestors(path):
    parts = path.split("\\")
    return {"\\".join(parts[:i]) for i in range(1, len(parts))}


def main():
    if len(sys.argv) != 4:
        sys.stderr.write(
            "usage: regdiff.py <proskrnl-SYSTEM-hive> <oracle-system.reg> <filtered-wine.inf>\n")
        return 2
    ours = regdump.load(sys.argv[1], subtree="machine")
    oracle = apply_renames(regdump.load(sys.argv[2], subtree="machine"))
    scope_keys, scope_values = inf_addreg_scope(sys.argv[3])

    divergences = 0

    def report(kind, what):
        nonlocal divergences
        divergences += 1
        print("regdiff: %s %s" % (kind, what))

    # --- the payload: every scoped key/value on both sides, data identical --
    # Oracle-side values NOT written by the INF are other oracle writers
    # sharing the key (fake-dll REGINST registration, wineserver furniture)
    # and stay out of the compare; proskrnl-side values not on the oracle
    # AND not in the INF are convictions (who else wrote them?).
    for path in sorted(scope_keys):
        if path not in ours.keys:
            report("missing key", path)
        if path not in oracle.keys:
            report("oracle missing key", path)
    for path, name in sorted(scope_values):
        if excluded_value(path, name):
            continue
        mine = ours.values.get((path, name))
        theirs = oracle.values.get((path, name))
        if mine is None and theirs is None:
            continue  # e.g. DelReg'd later, or NOCLOBBER against absent state
        if theirs is None:
            report("extra value", "%s ! %s = %s %s" % (path, name, mine[0], mine[1]))
        elif mine is None:
            report("missing value", "%s ! %s = %s %s" % (path, name, theirs[0], theirs[1]))
        elif mine != theirs:
            report("differing value",
                   "%s ! %s: proskrnl %s %s != oracle %s %s"
                   % (path, name, mine[0], mine[1], theirs[0], theirs[1]))

    # --- the sweep: proskrnl has nothing beyond payload + documented writers -
    allowed = set(scope_keys)
    for path in scope_keys:
        allowed |= ancestors(path)
    for path in sorted(ours.keys):
        if path in allowed or excluded_key(path):
            continue
        if any(path == p or path.startswith(p + "\\") for p in ALLOWED_EXTRA_SUBTREES):
            continue
        if allowed_extra_key(path):
            continue
        # keys the oracle also has are fine: same writer wrote both sides
        # (wineboot's dynamic keys land identically under both runners)
        if path in oracle.keys:
            continue
        report("unexpected key", path)
    for (path, name), val in sorted(ours.values.items()):
        if path not in scope_keys or (path, name) in scope_values:
            continue
        if excluded_value(path, name):
            continue
        if (path, name) in oracle.values:
            continue
        report("unexpected value", "%s ! %s = %s %s" % (path, name, val[0], val[1]))

    print("regdiff: scope %d keys / %d values; %d divergence(s)"
          % (len(scope_keys), len(scope_values), divergences))
    # An EMPTY scope is a failure, not a clean run. "0 divergences" over 0 keys
    # is what a truncated, unreadable or wrong-path INF produces, and it grades
    # identically to a real green -- the differential comparing nothing with
    # nothing. Nothing else in this tool notices.
    if not scope_keys or not scope_values:
        print("regdiff: FAIL - the INF yielded an empty comparison scope "
              "(%d keys / %d values); nothing was compared" %
              (len(scope_keys), len(scope_values)))
        return 1
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
