#!/usr/bin/env bash
# qemu.sh — headless, finite-time QEMU run; verdict from the serial log (docs/08).
#
#   qemu.sh <hdd>
#
# macOS ships no `timeout`, so we use a portable background killer. On Apple
# Silicon the x86-64 guest runs under TCG emulation (no HVF) — slower, correct.
#
# ACCEL=kvm|tcg forces the accelerator; the default is KVM when /dev/kvm is
# usable, else TCG. No verdict depends on which one runs — every leg's answer
# still comes off the same serial log — but the two are NOT the same machine:
# the CPU model differs with the accelerator (see +invtsc below), and the
# kernel calibrates its clock from a different source under each. ACCEL=tcg is
# therefore how you reproduce CI's configuration on a box that has KVM.
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
# stays silent — no verdict turns on it, and a host with no KVM has no second
# option to offer — but silent is how a CI runner that quietly lost /dev/kvm
# looks exactly like a CI runner that got slower for no reason, and it now
# also changes the CPU model and with it the clock source. Every leg here
# redirects qemu.sh's stderr to /dev/null, so the answer has to be askable on
# its own; the kernel's own boot line names the clock source it ended up with,
# which is the other half of the same question.
if [[ "$IMG" == "--print-accel" ]]; then
    echo "$ACCEL"
    exit 0
fi
# `qemu.sh --probe-slirp` answers whether THIS qemu can serve `-netdev user`
# (slirp compiled in) and prints/does nothing else. The runner's netsmoke
# check (tests/run/run.sh) asks it before any net leg is judged: an
# environment that silently lacks its backend turns every verdict false —
# the fontsmoke/audiosmoke lesson (docs/24 §6c). Asking `-netdev help` asks
# the binary itself, the same truthful marker setup_linux.sh and
# fetch_third_party.sh use.
if [[ "$IMG" == "--probe-slirp" ]]; then
    "$QEMU" -netdev help 2>/dev/null | grep -qx user
    exit $?
fi
# +invtsc under KVM: tell the guest its TSC is invariant, which is what makes
# QEMU publish the hypervisor timing leaf (CPUID 0x40000010, TSC kHz + APIC bus
# kHz). The kernel asks for that leaf before it will fall back to measuring
# against the PIT (arch/x86_64/lapic.c KiQueryReportedRates), and the pinned
# QEMU writes it only under KVM and only when the guest TSC is stable AND known
# — target/i386/kvm/kvm.c tsc_is_stable_and_known, i.e. invariant-TSC exposed
# or an explicit tsc-freq. Plain -cpu host is neither, so before this every KVM
# run measured, and the reported path was reachable only by hand (issue #176).
#
# It is a DEFAULT rather than a probe because a path nothing runs is a path
# that rots: CI has no KVM and takes the PIT gate regardless, so leaving this
# opt-in left the exact-rate path unexercised everywhere. The kernel prints
# both the reported and the measured rate with an agreement verdict on every
# boot, so a machine where the two part company says so in its own log.
#
# Not migratable=off: invtsc IS non-migratable, but an EXPLICITLY requested
# feature is accepted anyway (that property only filters the host model's
# implicit set). On a host CPU without invariant TSC, QEMU warns
# ("host doesn't support requested feature") and carries on with the PIT gate
# — fatal only under -cpu ...,enforce=on, which nothing here sets (pinned tree
# target/i386/cpu.c: x86_cpu_filter_features at 8172, "enforce" default false
# at 8845).
case "$ACCEL" in
kvm)
    CPU_MODEL=host,+invtsc
    ;;
tcg)
    CPU_MODEL=max
    ;;
*)
    echo "qemu.sh: ACCEL='$ACCEL' is not one of kvm|tcg" >&2
    exit 1
    ;;
esac
# CPU_EXTRA="<prop>[,<prop>...]" appends further properties to the -cpu model,
# for exercising a kernel path the default model leaves unreachable — the way
# +invtsc above was reached before it became the default. Nothing in the tree
# sets it.
if [[ -n "${CPU_EXTRA:-}" ]]; then
    CPU_MODEL="$CPU_MODEL,$CPU_EXTRA"
fi
ACCEL_ARGS=(-accel "$ACCEL" -cpu "$CPU_MODEL")
# Sized for a virgin full image under TCG on a modest container (the CUI-1
# firstboot INF pass alone is minutes there): a green boot exits through
# isa-debug-exit the moment it is done, so a large default only delays how
# fast a WEDGED run is declared dead, never a passing one.
TIMEOUT="${TIMEOUT:-600}"
# 384M, up from 256M: one image serving every leg means one conhost, and that
# conhost links the real user32/gdi32 rather than CUI stand-ins — so EVERY boot
# now brings the desktop stack up (win32u, winefb.drv, wineserver-lite, a
# 1280x800 desktop surface) before the leg's own work starts. Measured at the
# cui9 leg's pinned 512M console boot: available memory at the start of the
# sweep fell from 466 MB to 334 MB. With no eviction (Art. 3) that 132 MB is
# standing cost, not pressure the machine can work off, and at 256M it left the
# ntapi sweep close enough to the edge to wedge one CI run mid-test. A green
# boot still exits through isa-debug-exit the moment it is done, so a larger
# default costs nothing but host RSS on a run that was going to pass.
MEM="${MEM:-384M}"        # the wtest leg provisions more (no eviction - Art. 3)

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

# GUEST_GUI=0 opts OUT of the windowed console. One image carries the whole
# userland now, so GUI-vs-CUI is a boot decision like interactivity: the
# kernel's default for any fw_cfg-bearing boot is the windowed console over
# the desktop stack (kernel/cm/registry.c CmpQemuBootFlags), and a leg whose
# verdict rides the SERIAL console — every scripted CUI leg, `make test`,
# `make run` — says so here. Only the opt-out is passed, the
# panic_not_implemented arrangement: a hand-rolled qemu line gets the
# product's console rather than the harness's.
if [[ "${GUEST_GUI:-1}" == 0 ]]; then
    FWCFG_ARGS+=(-fw_cfg name=opt/org.proskrnl/gui,string=0)
fi

# GUEST_LEG=<name> names the TEST LEG the guest's session manager should run
# (user/smss/session.c SessionRun); GUEST_SUBTESTS=<query> is the filter the
# ntapi and winetest sweeps apply to their case lists. Both are fw_cfg
# STRINGS rather than numbers, published as REG_SZ beside the flags above.
#
# They exist so a leg and a subset are properties of the BOOT rather than of
# the media: before this, selecting a leg meant baking a different disk image
# (its probe file present or absent) and filtering a sweep meant baking a
# different set of test binaries — so a dozen images existed whose only
# difference was which client the session manager would find. Unset means the
# empty string, and each consumer's reading of empty is its own default: no
# leg is the plain boot suite, no filter is every case.
# GUEST_SHELL=1 hands the desktop to explorer (the shell arrangement): the
# desktop server leaves its own fixtures off and win32u's get_desktop_window
# auto-launches explorer, which creates and owns the desktop. Off by default —
# the GUI legs run purpose-built clients over the fixtures.
if [[ "${GUEST_SHELL:-0}" != 0 ]]; then
    FWCFG_ARGS+=(-fw_cfg name=opt/org.proskrnl/shell,string=1)
fi

# CUI-8 stress (docs/19 8.1): zero the kernel's device await drain-spin so
# every await parks. Off by default; tests/run/run.sh cui8 asks for it on the
# boots whose whole point is the maximally different legal interleaving. It
# used to be a marker file baked into the image (CUI8_STRESS), which is not a
# property a boot can choose once one image serves every leg.
if [[ "${GUEST_STRESS:-0}" != 0 ]]; then
    FWCFG_ARGS+=(-fw_cfg name=opt/org.proskrnl/stress,string=1)
fi

# The kernel's CMP_QEMU_STRING_MAX (kernel/cm/registry.c), mirrored here so a
# value the guest cannot take is caught BEFORE the boot, naming the item,
# rather than as the guest-side panic that now backs it. Refusing loudly is
# the whole point: this cap was 256 and the winetest gate's pair list grew to
# 1270 bytes, the guest read the refusal as "unspecified", and an empty filter
# means EVERY case — so both boots swept the whole manifest and the gate still
# greened. A harness that cannot say what it wants must not run anyway.
QEMU_STRING_MAX=4096
fwcfg_string() {   # $1 = item name, $2 = value
    if (( ${#2} > QEMU_STRING_MAX )); then
        echo "qemu.sh: $1 is ${#2} bytes, past the guest's $QEMU_STRING_MAX-byte cap" >&2
        echo "         (kernel/cm/registry.c CMP_QEMU_STRING_MAX). The guest would have to" >&2
        echo "         refuse it, and a refused filter is not a missing one — it is a" >&2
        echo "         different run. Shorten the value or raise both caps together." >&2
        exit 2
    fi
    FWCFG_ARGS+=(-fw_cfg "name=$1,string=$2")
}

if [[ -n "${GUEST_LEG:-}" ]]; then
    fwcfg_string opt/org.proskrnl/leg "$GUEST_LEG"
fi
if [[ -n "${GUEST_SUBTESTS:-}" ]]; then
    fwcfg_string opt/org.proskrnl/subtests "$GUEST_SUBTESTS"
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

# AUD-1: AUDIODEV="<spec>" appends one -audiodev — the backend an
# EXTRA_DEVICES sound device names by id. The audio leg passes the wav
# backend (pinned tree audio/wavaudio.c), which records what the guest
# plays into a host WAV file: the audio analog of the QMP screendump
# (docs/23 §6a). No other leg grows an audio backend it does not use.
AUDIODEV_ARGS=()
if [[ -n "${AUDIODEV:-}" ]]; then
    AUDIODEV_ARGS=(-audiodev "$AUDIODEV")
fi

# Both are read by the interactive branch below AND by the headless
# invocation at the end: a device an interactive session wants is spelled
# the same way a leg spells it (Art. 11 — one spelling per thing).

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
#
# NET_USER=1 / SOUND=1 (below): the two devices an interactive session wants
# and no headless leg does — a NIC on slirp and a sound card on the HOST's
# audio backend. The verdict legs pin their own backends instead (a pcap,
# a WAV file), because a verdict must be a recorded artifact rather than
# something that went out a speaker; interactive is the opposite case.
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
    # NET_USER=1: the same slirp backend and virtio-net-pci device the net
    # legs boot (NET_ARGS below), minus the pcap tap — a human reads the
    # guest's own output, not a capture file. Guest-side there is nothing to
    # configure: netd (drivers/net/netd.c) DHCPs against slirp's built-in
    # server the moment it binds a NIC.
    if [[ -n "${NET_USER:-}" ]]; then
        if "$QEMU" -netdev help 2>/dev/null | grep -qx user; then
            INTERACTIVE_DEVICE_ARGS+=(-netdev user,id=net0 -device virtio-net-pci,netdev=net0)
            echo "qemu.sh: networking on (slirp user-mode: guest 10.0.2.15, host 10.0.2.2)" >&2
        else
            echo "qemu.sh: NO slirp in this QEMU build ('-netdev user') — booting" >&2
            echo "         WITHOUT a NIC. Rebuild the pinned QEMU with slirp" >&2
            echo "         (apt install libslirp-dev, remove third_party/qemu/build," >&2
            echo "         re-run tools/setup_linux.sh)." >&2
        fi
    fi
    # SOUND=1: virtio-sound-pci (the device drivers/snd.c binds and every
    # audio leg boots) on the first audio backend that both exists in this
    # QEMU build AND actually opens on this host. Compiled in is not the
    # same as usable — a build carrying pulseaudio on a box with no sound
    # server running dies at device realize, which would take `make rungui`
    # down over a speaker nobody asked for — so the candidates are probed
    # the way find_accel probes KVM: build the device for real, halted, and
    # see whether QEMU survives it. Order is preference among the ones that
    # do: pipewire/pa/sdl/alsa on a Linux desktop, coreaudio/dsound on a
    # macOS/Windows host, oss last. The probe catches a backend that fails
    # realize outright, which is what a box with no sound server does; a
    # backend that fails SLOWLY (a server that times out rather than
    # refusing) would still be picked, and then the real boot says so.
    # `none` is the floor and always works — it clocks the stream and drops
    # the samples, so the guest's whole audio stack still runs, silently,
    # and the banner says so. AUDIODEV names a backend explicitly and skips
    # all of this.
    if [[ -n "${SOUND:-}" && -z "${AUDIODEV:-}" ]]; then
        SND_BACKEND=none
        for candidate in pipewire pa sdl alsa coreaudio dsound oss; do
            "$QEMU" -audiodev help 2>/dev/null | grep -qx "$candidate" || continue
            "$QEMU" -audiodev "$candidate,id=probe" -device virtio-sound-pci,audiodev=probe \
                    -display none -no-user-config -nodefaults -machine q35 -m 32 -S \
                    >/dev/null 2>&1 </dev/null &
            probe=$!
            sleep 0.5
            if kill -0 "$probe" 2>/dev/null; then
                kill "$probe" 2>/dev/null || true
                wait "$probe" 2>/dev/null || true
                SND_BACKEND="$candidate"
                break
            fi
            wait "$probe" 2>/dev/null || true
        done
        if [[ "$SND_BACKEND" == none ]]; then
            echo "qemu.sh: NO usable host audio backend — the guest gets a virtio-snd" >&2
            echo "         device on the 'none' backend (it plays, you hear nothing)." >&2
            echo "         Check that this box has a sound server running, or rebuild" >&2
            echo "         the pinned QEMU with a backend it does have (e.g. apt install" >&2
            echo "         libpulse-dev, remove third_party/qemu/build, re-run" >&2
            echo "         tools/setup_linux.sh)." >&2
        else
            echo "qemu.sh: sound on (virtio-snd -> $SND_BACKEND)" >&2
        fi
        INTERACTIVE_DEVICE_ARGS+=(-audiodev "$SND_BACKEND,id=snd0"
                                  -device virtio-sound-pci,audiodev=snd0)
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
        ${EXTRA_DEVICE_ARGS[@]+"${EXTRA_DEVICE_ARGS[@]}"} \
        ${AUDIODEV_ARGS[@]+"${AUDIODEV_ARGS[@]}"} \
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

# Net-1 (tests/run/run.sh net): NET_PCAP=<path> gives the guest a NIC and
# writes everything on its wire to a host pcap — networking's screendump
# (docs/24 §6b): QEMU's own device model records the frames, not anything
# the kernel says about itself (Art. 6). `-netdev user` is slirp's
# user-mode backend (pinned tree docs/system/devices/net.rst "Using the
# user mode network stack": guest 10.0.2.0/24, host at 10.0.2.2, built-in
# DHCP server); virtio-net-pci is the device the driver binds
# (drivers/virtio/net.c); filter-dump is the pcap tap (pinned tree
# net/dump.c, qapi/net.json).
# NET_ECHO_PORT=<port> tells the GUEST which host port the harness's TCP
# echo server listens on, over fw_cfg like the boot flags above.
NET_ARGS=()
if [[ -n "${NET_PCAP:-}" ]]; then
    NET_ARGS=(-netdev user,id=net0
              -device virtio-net-pci,netdev=net0
              -object "filter-dump,id=netdump,netdev=net0,file=$NET_PCAP")
fi
if [[ -n "${NET_ECHO_PORT:-}" ]]; then
    FWCFG_ARGS+=(-fw_cfg "name=opt/org.proskrnl/netecho,string=$NET_ECHO_PORT")
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
    ${AUDIODEV_ARGS[@]+"${AUDIODEV_ARGS[@]}"} \
    ${NET_ARGS[@]+"${NET_ARGS[@]}"} \
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
