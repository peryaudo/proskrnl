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

IMG="${1:?usage: qemu.sh <hdd> | qemu.sh --print-accel}"
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
# catches the group-vs-ACL cases. The kernel's clock is the LAPIC timer
# reached through the xAPIC MMIO window (arch/x86_64/lapic.c), which every
# QEMU and every accelerator has always offered — so there is no CPU feature
# to request here and no version floor.
#
# Opening the device is necessary but NOT sufficient: an ephemeral container
# can expose a /dev/kvm that opens and then fails at KVM_CREATE_VM, and QEMU
# selected on the strength of the open alone dies before the guest's first
# instruction — every test then "fails" with an empty serial log, which reads
# as a mass kernel regression rather than as a host problem. So the probe ends
# with QEMU itself: boot nothing, under kvm, and see whether it comes back.
find_accel() {
    if [[ "$(uname -s)" != Linux ]] || ! : 2>/dev/null <>/dev/kvm; then
        echo tcg
        return
    fi
    "$QEMU" -accel kvm -display none -no-user-config -nodefaults \
            -machine q35 -m 32 -S >/dev/null 2>&1 </dev/null &
    local probe=$!
    # -S starts the guest halted, so a live PID after the grace period means
    # KVM initialized; a dead one means it did not.
    sleep 0.5
    if kill -0 "$probe" 2>/dev/null; then
        kill "$probe" 2>/dev/null || true
        wait "$probe" 2>/dev/null || true
        echo kvm
        return
    fi
    wait "$probe" 2>/dev/null || true
    echo tcg
}
ACCEL="${ACCEL:-$(find_accel)}"

# `qemu.sh --print-accel` runs the probe above and prints nothing else, so a
# log can RECORD which accelerator a host actually got. The fallback to TCG
# is silent by design (it must be: an accelerator is not guest-observable —
# the verdict still comes off the same serial log), but silent is also how a
# CI runner that quietly lost /dev/kvm looks exactly like a CI runner that
# got slower for no reason. Every leg here redirects qemu.sh's stderr to
# /dev/null, so the answer has to be askable on its own.
if [[ "$IMG" == "--print-accel" ]]; then
    echo "$ACCEL"
    exit 0
fi
case "$ACCEL" in
kvm)
    ACCEL_ARGS=(-accel kvm -cpu host)
    ;;
tcg)
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

# GUI-1 (docs/02): Limine sets a linear framebuffer through the VGA BIOS's
# VBE, and \Device\Fb0 (drivers/fb.c) publishes whatever it was given. "std"
# (QEMU's bochs-display VBE) is already the default VGA for the q35
# default-device set, so this pins today's behaviour rather than changing
# it — but the pin is what keeps a future -nodefaults or a QEMU default
# change from silently taking the framebuffer away. -display none does not
# remove the adapter: the scanout still renders host-side, which is what
# makes the headless `screendump` verification below work at all.
VGA_ARGS=(-vga std)

# GUEST_INTERACTIVE=1: tell the GUEST that a human owns the console, so the
# kernel skips its test suites and smss hands the console to cmd.exe / the
# shell instead of running the acceptance flows. Carried on the QEMU command
# line rather than baked into the image: the kernel reads the fw_cfg item at
# boot and publishes it as \Registry\Machine\Hardware\qemu "Interactive"
# (kernel/cm/registry.c), which both the kernel and smss then read.
#
# Deliberately its own switch and not INTERACTIVE above: that one is about the
# HOST side (where the serial wire and the scanout go), and the two do come
# apart — the gui5con leg (tests/run/run.sh) drives an interactive GUEST
# through QMP with the host side headless and log-backed.
#
# opt/ is the user namespace fw_cfg reserves, opt/RFQDN/ the arrangement it
# recommends: pinned tree docs/specs/fw_cfg.rst, "Externally Provided Items".
#
# PANIC_NOTIMPL=0 opts OUT of Art. 12 dialed to fatal (a ring-3 syscall
# answering STATUS_NOT_IMPLEMENTED panics at the dispatcher instead of
# returning, so a run convicts the first unbuilt service it needed rather than
# limping past it). Only the opt-out is passed here: arming is the KERNEL's
# default for any boot that finds a fw_cfg device (kernel/cm/registry.c
# CmpQemuBootFlags), so every QEMU run is armed whether or not it was launched
# through this script — a hand-rolled qemu line gets the net too, and losing
# it has to be said out loud. Off where there is no fw_cfg device at all: that
# is not a development VM, and a kernel panic on a missing service is not
# something to inflict on an unknown machine.
FWCFG_ARGS=()
if [[ -n "${GUEST_INTERACTIVE:-}" ]]; then
    FWCFG_ARGS+=(-fw_cfg name=opt/org.proskrnl/interactive,string=1)
fi
if [[ "${PANIC_NOTIMPL:-1}" == 0 ]]; then
    FWCFG_ARGS+=(-fw_cfg name=opt/org.proskrnl/panic_not_implemented,string=0)
fi

# INTERACTIVE=1 (make run): hand the serial wire to the terminal — QEMU
# multiplexes its monitor onto stdio (Ctrl-A x quits, Ctrl-A c toggles the
# monitor). No timeout, no log, no verdict: a human owns the session, and the
# guest powers off through isa-debug-exit when cmd.exe exits. isa-debug-exit
# can only return odd exit codes ((code<<1)|1), so QEMU's status carries no
# verdict either — always exit 0.
#
# GUI_DISPLAY=1 (make rungui): same session, but with the scanout visible
# and a virtio keyboard for winefb.drv's input path; serial diagnostics
# stay on the terminal. A host window when this QEMU build has a GUI
# backend (gtk/sdl — tools/setup_linux.sh configures the pinned build
# --enable-gtk; cocoa is the same thing on a macOS host, where that is the
# only native one QEMU offers); otherwise — a build restored from the CI
# cache predating that, or a hand-built one — the scanout is served over
# VNC and the banner says where.
if [[ -n "${INTERACTIVE:-}" ]]; then
    DISPLAY_ARGS=(-display none)
    # Stays empty on the console leg, so every expansion of it below needs
    # the ${a[@]+"${a[@]}"} guard: macOS ships bash 3.2, where set -u treats
    # "${empty[@]}" as an unbound variable (fixed in bash 4.4). Same reason
    # EXTRA_DEVICE_ARGS is expanded that way further down.
    INTERACTIVE_DEVICE_ARGS=()
    if [[ -n "${GUI_DISPLAY:-}" ]]; then
        # Tablet, not mouse: absolute coordinates map the host pointer to
        # the guest 1:1 with no grab (and it is what the gui4 leg drives).
        INTERACTIVE_DEVICE_ARGS=(-device virtio-keyboard-pci -device virtio-tablet-pci)
        GUI_BACKEND="$("$QEMU" -display help 2>/dev/null | grep -m1 -E '^(gtk|sdl|cocoa)$' || true)"
        if [[ -n "$GUI_BACKEND" ]]; then
            DISPLAY_ARGS=(-display "$GUI_BACKEND")
            echo "qemu.sh: interactive GUI ($GUI_BACKEND window) — close it or Ctrl-A x to quit" >&2
        else
            DISPLAY_ARGS=(-display none -vnc 127.0.0.1:0)
            echo "qemu.sh: NO GUI display backend in this QEMU build —" >&2
            echo "         the scanout is a VNC server on 127.0.0.1:5900." >&2
            echo "         Connect a viewer (e.g. apt install tigervnc-viewer;" >&2
            echo "         vncviewer 127.0.0.1:5900), or rebuild the pinned QEMU" >&2
            echo "         with gtk (apt install libgtk-3-dev, re-run" >&2
            echo "         tools/setup_linux.sh after removing third_party/qemu/build)." >&2
        fi
    else
        echo "qemu.sh: interactive console — 'exit' at the prompt powers off; Ctrl-A x kills QEMU" >&2
    fi
    "$QEMU" \
        -M q35 \
        "${ACCEL_ARGS[@]}" \
        -m "$MEM" \
        -no-reboot \
        "${DISPLAY_ARGS[@]}" \
        "${VGA_ARGS[@]}" \
        -serial mon:stdio \
        ${INTERACTIVE_DEVICE_ARGS[@]+"${INTERACTIVE_DEVICE_ARGS[@]}"} \
        ${FWCFG_ARGS[@]+"${FWCFG_ARGS[@]}"} \
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
# GUI-1: QMP_SOCK=<path> exposes a QMP control socket so the gui leg can
# pull the scanout as a PPM (`screendump`, qapi/ui.json in the pinned tree)
# and inject keys (`send-key`) — the framebuffer's verdict is a picture, not
# a serial line, and QEMU renders it from its own device model rather than
# from anything the kernel says about itself (Art. 6). QMP rather than HMP
# because the replies are machine-parseable. Absent QMP_SOCK this is exactly
# the previous `-monitor none` invocation.
if [[ -n "${QMP_SOCK:-}" ]]; then
    rm -f "$QMP_SOCK"
    MON_ARGS=(-monitor none -qmp "unix:$QMP_SOCK,server=on,wait=off")
else
    MON_ARGS=(-monitor none)
fi

# EXTRA_DEVICES="<spec> [<spec>...]" appends one -device per spec; the gui
# leg adds virtio-keyboard-pci this way so no other leg grows a device it
# does not use. Word-split on spaces: a spec may carry comma-separated
# properties, but no spaces.
EXTRA_DEVICE_ARGS=()
if [[ -n "${EXTRA_DEVICES:-}" ]]; then
    read -ra EXTRA_DEVICE_SPECS <<< "$EXTRA_DEVICES"
    for spec in "${EXTRA_DEVICE_SPECS[@]}"; do
        EXTRA_DEVICE_ARGS+=(-device "$spec")
    done
fi

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

# CUI-8 (tests/run/run.sh cui8): DRIVE_THROTTLE=<bytes/s> caps the disk's
# read rate through QEMU's block-layer throttle (pinned third_party/qemu
# blockdev.c: -drive throttling.bps-read -> ThrottleLimits), making device
# latency physically real so the boundary progress test must observe a
# park rather than racing a host-page-cache disk. Never combined with
# WRITE_LOG (no leg needs both).
if [[ -n "${DRIVE_THROTTLE:-}" && -z "${WRITE_LOG:-}" ]]; then
    DRIVE_ARGS=(-drive "file=$IMG,format=raw,if=virtio,$DRIVE_CACHE,throttling.bps-read=${DRIVE_THROTTLE}")
fi

"$QEMU" \
    -M q35 \
    "${ACCEL_ARGS[@]}" \
    -m "$MEM" \
    -no-reboot \
    -display none \
    "${VGA_ARGS[@]}" \
    "${MON_ARGS[@]}" \
    "${SERIAL_ARGS[@]}" \
    ${EXTRA_DEVICE_ARGS[@]+"${EXTRA_DEVICE_ARGS[@]}"} \
    ${FWCFG_ARGS[@]+"${FWCFG_ARGS[@]}"} \
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

# Symbolization (Art. 9): annotate dump addresses with symbols from the
# build's DWARF. Written to a SIDECAR beside the raw log — every leg gets one
# whether or not it reads our stdout (most of tests/run/run.sh redirects it to
# /dev/null, and a red run's uploaded artifacts were raw hex before this).
# "<name>.log" -> "<name>.sym.log" keeps the sidecar under the CI upload's
# *.log glob (.github/actions/serial-logs).
if [[ "$LOG" == *.log ]]; then
    SYMLOG="${LOG%.log}.sym.log"
else
    SYMLOG="$LOG.sym"
fi
# The verdict grep below stays on the RAW log file — the symbolizer only
# decorates what a reader (the LLM loop) sees, and a missing llvm-symbolizer
# or ELF degrades to pass-through (symbolize.py), never to a failed run.
echo "--- serial log ($LOG; symbolized: $SYMLOG) ---"
if "$HERE/symbolize.py" --kernel "$HERE/../build/proskrnl" \
        --moduledir "$HERE/../build/modules" < "$LOG" > "$SYMLOG" 2>/dev/null \
        && [[ -s "$SYMLOG" ]]; then
    cat "$SYMLOG"
else
    cat "$LOG" || true
fi
echo "--------------------------"
if grep -q "$PASS_RE" "$LOG"; then
    echo "== run: PASS =="
    exit 0
else
    echo "== run: FAIL (verdict '$PASS_RE' not found on serial) =="
    exit 1
fi
