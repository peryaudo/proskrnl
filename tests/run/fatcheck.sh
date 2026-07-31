#!/usr/bin/env bash
# fatcheck.sh — the external FAT oracle (docs/08): after any boot that wrote
# the disk, validate the FAT volume with an INDEPENDENT implementation and
# byte-compare what the kernel wrote / must not have touched.
#
#   fatcheck.sh verify <leg> <img>
#
# Three readers that have never met fs/fat32/:
#   fsck.fat -n   dosfstools, read-only, on the dd-extracted partition
#                 (fsck.fat has no offset option — dosfstools 4.2)
#   fatsweep.py   the repo's invariant sweeper (FAT mirroring, cross-links,
#                 chain-vs-size, lost clusters, LFN sanity)
#   mcopy/mdir    mtools extraction + byte-compares against host truth
#
# This breaks the self-consistency trap: the kernel's own readback goes
# through its own cache and its own FAT code; these do not. GPL tools are
# used as test oracles only — nothing links into the kernel (docs/11).
#
# Verdicts follow the host-side protocol (the firstboot-diff precedent):
#   [KTEST] fatcheck-<leg>-<check> PASS|FAIL
# Exit 0 iff every check passed; 2 = usage/tooling error.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERB="${1:?usage: fatcheck.sh verify <leg> <img>}"
LEG="${2:?usage: fatcheck.sh verify <leg> <img>}"
IMG="${3:?usage: fatcheck.sh verify <leg> <img>}"
[[ "$VERB" == "verify" ]] || { echo "fatcheck: unknown verb '$VERB'" >&2; exit 2; }

command -v fsck.fat >/dev/null || {
    echo "fatcheck: fsck.fat missing - rerun tools/setup_linux.sh (dosfstools)" >&2
    exit 2
}

ESP_OFF=2097152     # mkimage.sh: p2 (the FAT32 ESP) at sector 4096
SCRATCH="$ROOT/build/tests/fatcheck"
mkdir -p "$SCRATCH"
FAILS=0

verdict() {   # $1 = check name, $2 = 0|nonzero, $3 = optional detail
    if [[ "$2" -eq 0 ]]; then
        echo "[KTEST] fatcheck-$LEG-$1 PASS"
    else
        echo "[KTEST] fatcheck-$LEG-$1 FAIL${3:+ ($3)}"
        FAILS=$((FAILS + 1))
    fi
}

# --- fsck.fat on the extracted partition -----------------------------------
fsck_check() {
    local part="$SCRATCH/$LEG.fatpart" log="$SCRATCH/$LEG.fsck.log"
    # bs=1048576 skip=2: the 2 MiB ESP offset in the repo's portable dd
    # spelling (mkimage.sh's byte-count idiom).
    dd if="$IMG" of="$part" bs=1048576 skip=2 2>/dev/null
    fsck.fat -n "$part" > "$log" 2>&1
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        verdict fsck 0
        return
    fi
    # Exit 1 = problems found. The ONE acceptable diagnostic: the FSInfo
    # free-cluster count, which the kernel deliberately does not maintain
    # (docs/03 "FSInfo free-count is not maintained"; the spec marks it
    # advisory). Everything else — cross-links, wrong chain lengths,
    # differing FATs, orphaned entries — is a real FAT-writer conviction.
    local noise
    noise="$(grep -vE '^(fsck\.fat |Free cluster summary wrong|  Auto-correcting\.|Leaving filesystem unchanged|.*: [0-9]+ files, [0-9]+/[0-9]+ clusters)' "$log" | grep -v '^$' || true)"
    if [[ $rc -eq 1 && -z "$noise" ]]; then
        verdict fsck 0
    else
        verdict fsck 1 "see $log"
    fi
}

# --- the invariant sweeper ---------------------------------------------------
sweep_check() {
    local log="$SCRATCH/$LEG.sweep.log"
    if python3 "$ROOT/tests/run/fatsweep.py" "$IMG" --offset "$ESP_OFF" > "$log" 2>&1; then
        verdict sweep 0
    else
        verdict sweep 1 "see $log"
    fi
}

# --- mtools content checks ---------------------------------------------------
mfile_cmp() {   # $1 = check name, $2 = ::/fat/path, $3 = expected host file
    local out="$SCRATCH/$LEG.$1.extracted"
    rm -f "$out"
    if mcopy -n -i "$IMG@@$ESP_OFF" "$2" "$out" 2>/dev/null && cmp -s "$out" "$3"; then
        verdict "$1" 0
    else
        verdict "$1" 1 "$2 != $3"
    fi
}

mpath_present() {   # $1 = check name, $2 = ::/fat/path
    if mdir -b -i "$IMG@@$ESP_OFF" "$2" >/dev/null 2>&1; then
        verdict "$1" 0
    else
        verdict "$1" 1 "$2 missing"
    fi
}

mpath_absent() {   # $1 = check name, $2 = ::/fat/path
    if mdir -b -i "$IMG@@$ESP_OFF" "$2" >/dev/null 2>&1; then
        verdict "$1" 1 "$2 still present"
    else
        verdict "$1" 0
    fi
}

# The kmt M6 suite (tests/kmt/m6_io.c) runs on every test boot: it leaves
# C:\kmt6\persist.dat behind — pattern (i*7+3)&0xff over 2*4096+123 bytes,
# the same bytes test_file_roundtrip wrote — and must have really unlinked
# LongMixedCase-Name.data (SFN + LFN slots freed, which mdir would resurrect
# if the delete missed a slot).
kmt6_checks() {
    python3 -c 'import sys; sys.stdout.buffer.write(bytes(((i*7+3)&0xff) for i in range(2*4096+123)))' \
        > "$SCRATCH/kmt6-persist.expected"
    mpath_present kmt6-dir ::/kmt6
    mpath_absent  kmt6-deleted ::/kmt6/LongMixedCase-Name.data
    mfile_cmp     kmt6-persist ::/kmt6/persist.dat "$SCRATCH/kmt6-persist.expected"
}

# Read-only integrity: files the image baked that the kernel only reads or
# maps must come back byte-identical — this convicts writes that corrupted a
# NEIGHBOR of the intended target, which no in-kernel readback can see.
readonly_checks() {
    [[ -f "$ROOT/build/modules/sample.dat" ]] && \
        mfile_cmp sample ::/sample.dat "$ROOT/build/modules/sample.dat"
    [[ -f "$ROOT/build/modules/pe_smoke.exe" ]] && \
        mfile_cmp pe-smoke ::/pe_smoke.exe "$ROOT/build/modules/pe_smoke.exe"
    [[ -f "$ROOT/build/winestrip/ntdll.dll" ]] && \
        mfile_cmp ntdll ::/windows/system32/ntdll.dll "$ROOT/build/winestrip/ntdll.dll"
}

# The write-through hive (kernel/cm/hive.c CMP_HIVE_PATH): present and
# nonempty after any boot that wrote the registry.
hive_check() {
    mpath_present hive ::/windows/system32/config/SYSTEM
}

case "$LEG" in
    test|persist)
        fsck_check
        sweep_check
        kmt6_checks
        readonly_checks
        hive_check
        ;;
    firstboot)
        fsck_check
        sweep_check
        kmt6_checks
        readonly_checks
        hive_check
        ;;
    proskrnl)
        fsck_check
        sweep_check
        kmt6_checks
        readonly_checks
        # The sem_file suite worked under C:\prstest (it scrubs its files,
        # the directories persist) and sem_reg wrote real registry keys.
        mpath_present prstest ::/prstest
        hive_check
        # Sampled ntapi binaries: every one was SEC_IMAGE-mapped by the
        # kernel sweep and must be untouched.
        for name in create_basic read_write query_dir; do
            [[ -f "$ROOT/build/tests/ntapi/$name.exe" ]] && \
                mfile_cmp "ntapi-$name" "::/ntapi/$name.exe" "$ROOT/build/tests/ntapi/$name.exe"
        done
        ;;
    proskrnl-subset|wtest|console|churn|fatinterop|tornwrite)
        # proskrnl-subset is `run.sh proskrnl <subtest>`: the image carries
        # only the named tests, so the full leg's per-test expectations
        # (prstest, the sampled binaries) do not hold — the structural
        # oracles do, and they are what convict a corrupt volume.
        # Structure varies per leg; the two structural oracles always apply.
        fsck_check
        sweep_check
        ;;
    *)
        echo "fatcheck: unknown leg '$LEG'" >&2
        exit 2
        ;;
esac

echo "== fatcheck($LEG): $FAILS failing =="
exit $((FAILS > 0 ? 1 : 0))
