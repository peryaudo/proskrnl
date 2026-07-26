#!/usr/bin/env bash
# qemu.sh — headless, finite-time QEMU run; verdict from the serial log (docs/08).
#
#   qemu.sh <hdd>
#
# macOS ships no `timeout`, so we use a portable background killer. On Apple
# Silicon the x86-64 guest runs under TCG emulation (no HVF) — slower, correct.
#
# ACCEL=kvm|tcg forces the accelerator; the default is KVM when /dev/kvm is
# usable, else TCG. KVM changes no guest-observable semantics the tests
# grep for (the verdict still comes off the same serial log) — it only stops
# emulating every guest instruction in software.
set -uo pipefail

IMG="${1:?usage: qemu.sh <hdd>}"
LOG="${LOG:-build/serial.log}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Prefer the pinned third_party/qemu build (tools/setup_linux.sh) over
# whatever the host has on PATH; $QEMU overrides either way.
find_qemu() {
    if [[ -x "$HERE/../third_party/qemu/build/qemu-system-x86_64" ]]; then
        echo "$HERE/../third_party/qemu/build/qemu-system-x86_64"
    else
        echo "qemu-system-x86_64"
    fi
}
QEMU="${QEMU:-$(find_qemu)}"

# Pick the accelerator: `-accel kvm` needs a Linux host whose /dev/kvm this
# user can open read-write — probing the open (not the mode bits) is what
# catches the group-vs-ACL cases. KVM virtualizes the LAPIC in the host
# kernel, so x2APIC — the kernel's clock — works even when the host's own
# CPUID hides it (an AMD board left in xAPIC compat mode); +x2apic names the
# dependency explicitly so QEMU complains instead of the guest panicking in
# timer calibration if it ever cannot be offered.
find_accel() {
    if [[ "$(uname -s)" == Linux ]] && : 2>/dev/null <>/dev/kvm; then
        echo kvm
    else
        echo tcg
    fi
}
ACCEL="${ACCEL:-$(find_accel)}"
case "$ACCEL" in
kvm)
    ACCEL_ARGS=(-accel kvm -cpu host,+x2apic)
    ;;
tcg)
    # TCG only gained x2APIC in QEMU 9.0 (Ubuntu 24.04 LTS ships 8.2). Fail
    # fast instead of hanging silently in timer calibration. Under KVM the
    # LAPIC comes from the host kernel, so the floor is TCG-only.
    QEMU_MAJOR="$("$QEMU" --version | sed -n 's/.*version \([0-9]*\).*/\1/p' | head -1)"
    if [[ -n "$QEMU_MAJOR" && "$QEMU_MAJOR" -lt 9 ]]; then
        echo "qemu.sh: QEMU $QEMU_MAJOR.x lacks TCG x2APIC (need >= 9.0, README \"Prerequisites\")" >&2
        exit 1
    fi
    ACCEL_ARGS=(-accel tcg -cpu max)
    ;;
*)
    echo "qemu.sh: ACCEL='$ACCEL' is not one of kvm|tcg" >&2
    exit 1
    ;;
esac
# Sized for a virgin full image under TCG on a modest container (the CUI-1
# firstboot INF pass alone is minutes there): a green boot exits through
# isa-debug-exit the moment it is done, so a large default only delays how
# fast a WEDGED run is declared dead, never a passing one.
TIMEOUT="${TIMEOUT:-600}"
MEM="${MEM:-256M}"        # the wtest leg provisions more (no eviction - Art. 3)

# cache=unsafe (and cache.no-flush=on in the blockdev leg): the guest driver
# negotiates neither VIRTIO_BLK_F_FLUSH nor _CONFIG_WCE, so QEMU emulates a
# writethrough disk — every 512-byte sector write carries BDRV_REQ_FUA and
# lands as pwrite+fdatasync (pinned tree: hw/block/virtio-blk.c
# virtio_blk_set_status -> blk_set_enable_write_cache(false);
# block/block-backend.c blk_co_do_pwritev_part sets BDRV_REQ_FUA on every
# write; block/file-posix.c turns that into a device cache flush). On a
# desktop NVMe an honest flush is ~2-3 ms, and the CUI-1 firstboot INF pass
# rewrites the whole hive per registry mutation: a virgin boot measured 380
# sector-writes/s — 10+ minutes of fdatasync — vs 12 s (KVM) / 35 s (TCG)
# with flushes suppressed (CI never hurt: a hosted runner's fdatasync is
# nearly free). Suppressing host-side durability changes nothing the guest
# or the verdict pipeline observes: the bytes sit in host page cache, so
# fatcheck and the tornwrite replay read the same image even after a timeout
# SIGKILL — only a HOST power loss could eat a scratch image, and every
# image here is one.
DRIVE_CACHE="cache=unsafe"

# INTERACTIVE=1 (make run): hand the serial wire to the terminal — QEMU
# multiplexes its monitor onto stdio (Ctrl-A x quits, Ctrl-A c toggles the
# monitor). No timeout, no log, no verdict: a human owns the session, and the
# guest powers off through isa-debug-exit when cmd.exe exits. isa-debug-exit
# can only return odd exit codes ((code<<1)|1), so QEMU's status carries no
# verdict either — always exit 0.
if [[ -n "${INTERACTIVE:-}" ]]; then
    echo "qemu.sh: interactive console — 'exit' at the prompt powers off; Ctrl-A x kills QEMU" >&2
    "$QEMU" \
        -M q35 \
        "${ACCEL_ARGS[@]}" \
        -m "$MEM" \
        -no-reboot \
        -display none \
        -serial mon:stdio \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -drive file="$IMG",format=raw,if=virtio,"$DRIVE_CACHE"
    exit 0
fi
PASS_RE="${PASS_RE:-\[KTEST\] M9 PASS}"
mkdir -p "$(dirname "$LOG")"
: > "$LOG"

# M9 (docs/02): the interactive-console loop swaps the serial log file for a
# unix socket the runner types into (tests/run/console_expect.py), which
# tees everything it reads into $LOG — the verdict grep below is unchanged,
# so the headless finite-time loop keeps its shape (docs/08).
if [[ -n "${SERIAL_SOCK:-}" ]]; then
    rm -f "$SERIAL_SOCK"
    SERIAL_ARGS=(-chardev "socket,id=ser0,path=$SERIAL_SOCK,server=on,wait=off"
                 -serial chardev:ser0)
else
    SERIAL_ARGS=(-serial "file:$LOG")
fi

# WRITE_LOG=<path> (the tornwrite leg): interpose QEMU's blklogwrites block
# driver between virtio-blk and the image, appending every guest write
# (512-byte header + data, the dm-log-writes format) to the log file —
# ground truth for power-loss prefix replay (tests/run/tornreplay.py).
# Options per qapi/block-core.json BlockdevOptionsBlklogwrites in the pinned
# tree; log-super-update-interval=1 keeps the superblock's nr_entries fresh
# after every write (our driver never negotiates FLUSH, and the default only
# updates on flush). The caller pre-creates the log file.
if [[ -n "${WRITE_LOG:-}" ]]; then
    # cache.no-flush=on = the DRIVE_CACHE rationale above in blockdev syntax
    # (qapi/block-core.json BlockdevCacheOptions); the log's ground truth is
    # the guest-issued write sequence, not the host file's sync state.
    DRIVE_ARGS=(-blockdev "driver=file,node-name=tw-img,filename=$IMG,cache.no-flush=on"
                -blockdev "driver=raw,node-name=tw-fmt,file=tw-img"
                -blockdev "driver=file,node-name=tw-logf,filename=$WRITE_LOG,cache.no-flush=on"
                -blockdev "driver=blklogwrites,node-name=tw-top,file=tw-fmt,log=tw-logf,log-append=off,log-super-update-interval=1"
                -device  "virtio-blk-pci,drive=tw-top")
else
    DRIVE_ARGS=(-drive "file=$IMG,format=raw,if=virtio,$DRIVE_CACHE")
fi

"$QEMU" \
    -M q35 \
    "${ACCEL_ARGS[@]}" \
    -m "$MEM" \
    -no-reboot \
    -display none \
    -monitor none \
    "${SERIAL_ARGS[@]}" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    "${DRIVE_ARGS[@]}" &
QPID=$!

# The killer subshell also carries the issue #56 mitigation: a green boot
# occasionally leaves QEMU alive after the guest's isa-debug-exit outb (the
# pinned tree's hw/misc/debugexit.c requests an ASYNCHRONOUS shutdown, and
# the main loop is now and then slow to process it), which burned the whole
# TIMEOUT for a run whose verdict was already on the wire. Once the verdict
# regex appears and the guest has had GRACE seconds to power itself off, we
# kill QEMU and proceed. A WEDGED run never prints the verdict, so it still
# burns the full TIMEOUT — the finite-time verdict semantics (docs/08) are
# unchanged, and no run is ever declared PASS that would not have been.
#
# Only when nothing external is driving the guest: with SERIAL_SOCK a script
# (tests/run/console_expect.py) is still typing at the console long after the
# default M9 verdict scrolls past, and those legs must not lose QEMU
# mid-conversation. That is also the only configuration #56 was ever seen in.
GRACE="${GRACE:-5}"
(
    elapsed=0
    while [[ "$elapsed" -lt "$TIMEOUT" ]]; do
        kill -0 "$QPID" 2>/dev/null || exit 0   # QEMU ended on its own
        if [[ -z "${SERIAL_SOCK:-}" ]] && grep -q "$PASS_RE" "$LOG" 2>/dev/null; then
            sleep "$GRACE"
            kill -9 "$QPID" 2>/dev/null
            exit 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    kill -9 "$QPID" 2>/dev/null
) & KPID=$!
wait "$QPID" 2>/dev/null || true
kill "$KPID" 2>/dev/null || true
wait "$KPID" 2>/dev/null || true

echo "--- serial log ($LOG) ---"
# Display-time symbolization (Art. 9): annotate dump addresses with symbols
# from the build's DWARF. The verdict grep below stays on the RAW log file —
# the symbolizer only decorates what a reader (the LLM loop) sees.
"$HERE/symbolize.py" --kernel "$HERE/../build/proskrnl" \
    --moduledir "$HERE/../build/modules" < "$LOG" || cat "$LOG" || true
echo "--------------------------"
if grep -q "$PASS_RE" "$LOG"; then
    echo "== run: PASS =="
    exit 0
else
    echo "== run: FAIL (verdict '$PASS_RE' not found on serial) =="
    exit 1
fi
