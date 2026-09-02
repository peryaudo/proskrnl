# proskrnl — kernel build + thin superbuild (ADR 0009). Boot: Limine (ADR 0010).
#
#   make            build the bootable test image (build/proskrnl-test.hdd)
#   make test       build + boot in QEMU, check the [KTEST] verdict on serial
#   make fulltest   every leg CI runs, fanned out over this box (tools/fulltest.sh)
#   make run        build + boot the interactive image: cmd.exe on your terminal
#   make clean

# Toolchain: clang + ld.lld (README "Prerequisites"). On macOS, Homebrew's
# llvm is keg-only and not on PATH — point at it explicitly. On Linux, the
# distro clang/lld are on PATH. Override with `make LLVM=/path/to/bin`.
ifeq ($(shell uname -s),Darwin)
LLVM ?= /opt/homebrew/opt/llvm/bin
else
LLVM ?= $(patsubst %/,%,$(dir $(shell command -v clang)))
endif
CC   := $(LLVM)/clang
LD   := ld.lld
CLANG_FORMAT ?= $(LLVM)/clang-format
CLANG_TIDY   ?= $(LLVM)/clang-tidy

BUILD  := build
KERNEL := $(BUILD)/proskrnl

# THE TWO IMAGES. Named up here because `all:` names one of them before the
# rules that build them are read, and make expands a prerequisite list at the
# moment it parses the line.
IMG_TEST := $(BUILD)/proskrnl-test.hdd
IMG_DEV  := $(BUILD)/proskrnl-dev.hdd

# Freestanding, higher-half, no SIMD/red-zone (interrupt-safe), fixed VMA.
# The two third_party include paths are headers only: Limine's boot protocol,
# and Flanterm's API for the boot console (kernel/init/bootvid.c).
CFLAGS := -std=c11 -target x86_64-unknown-none \
          -ffreestanding -fno-stack-protector -fno-stack-check \
          -fno-pie -fno-pic -m64 -march=x86-64 -mno-red-zone -mcmodel=kernel \
          -mno-mmx -mno-sse -mno-sse2 -mno-80387 \
          -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
          -fsanitize=undefined -fsanitize-trap=undefined \
          -O2 -g -Wall -Wextra -Wno-unused-parameter \
          -I. -Ithird_party/limine-protocol/include \
          -Ithird_party/flanterm/src

# Minimal KASAN (M3, docs/08): outline checks only (call-threshold=0) so the
# hooks in kernel/mm/kasan.c can range-check against the pool; stack/global
# instrumentation stays off (only the pool is shadowed). pool.c and kasan.c
# manage the poison and are exempt. clang allows -fsanitize=kernel-address
# only under an OS triple, so instrumented TUs override to linux-gnu — the
# same freestanding-under-a-linux-triple arrangement the Linux kernel builds
# with; codegen (SysV, ELF, kernel code model) is unchanged.
KASAN_FLAGS := -target x86_64-unknown-linux-gnu \
               -fsanitize=kernel-address \
               -mllvm -asan-instrumentation-with-call-threshold=0 \
               -mllvm -asan-stack=0 \
               -mllvm -asan-globals=0
$(BUILD)/kernel/mm/pool.o: KASAN_FLAGS :=
$(BUILD)/kernel/mm/kasan.o: KASAN_FLAGS :=
# string.c checks explicitly via MiKasanCheckRange (the pool memsets memory
# whose shadow is mid-transition, so compiler instrumentation would misfire).
$(BUILD)/kernel/lib/string.o: KASAN_FLAGS :=
# The panic path is the debugger (Art. 9): its best-effort reads (walking an
# overflowed stack's RBP chain across redzones) must never re-enter KASAN.
$(BUILD)/kernel/init/panic.o: KASAN_FLAGS :=

# Invoke the ELF ld.lld directly — the clang driver on a Darwin host defaults to
# the Mach-O ld64.lld flavor even for a bare-metal target.
LDFLAGS := -m elf_x86_64 -static -T arch/x86_64/linker.ld \
           -z max-page-size=0x1000 --build-id=none

CSRC := kernel/init/main.c \
        kernel/init/bootvid.c \
        kernel/init/panic.c \
        kernel/init/trace.c \
        kernel/init/profile.c \
        kernel/init/verify.c \
        kernel/init/initrd.c \
        kernel/lib/dbgprint.c \
        kernel/lib/string.c \
        kernel/lib/rtl.c \
        kernel/lib/crc32.c \
        kernel/mm/phys.c \
        kernel/mm/pool.c \
        kernel/mm/kasan.c \
        kernel/ke/sched.c \
        kernel/ke/thread.c \
        kernel/ke/wait.c \
        kernel/ke/event.c \
        kernel/ke/mutex.c \
        kernel/ke/sema.c \
        kernel/ke/timer.c \
        kernel/ke/apc.c \
        kernel/ke/irq.c \
        kernel/ob/object.c \
        kernel/ob/handle.c \
        kernel/ob/namespace.c \
        kernel/ob/sync.c \
        kernel/ob/wait.c \
        kernel/ob/reserve.c \
        kernel/mm/virtual.c \
        kernel/mm/section.c \
        kernel/mm/pecoff.c \
        kernel/mm/fault.c \
        kernel/mm/pagecache.c \
        kernel/ps/process.c \
        kernel/ps/thread.c \
        kernel/ps/peb.c \
        kernel/ps/wow64.c \
        kernel/ps/usermode.c \
        kernel/ps/query.c \
        kernel/ps/nls.c \
        kernel/ps/job.c \
        kernel/ps/debug.c \
        kernel/ps/ldt.c \
        kernel/ps/atom.c \
        kernel/ps/display.c \
        kernel/se/token.c \
        kernel/se/sd.c \
        kernel/se/access.c \
        kernel/se/secobj.c \
        kernel/io/file.c \
        kernel/io/null.c \
        kernel/io/mountmgr.c \
        kernel/io/rw.c \
        kernel/io/async.c \
        kernel/io/notify.c \
        kernel/io/query.c \
        kernel/io/lock.c \
        kernel/io/completion.c \
        kernel/cm/registry.c \
        kernel/cm/hive.c \
        kernel/cm/notify.c \
        kernel/syscall/table.c \
        kernel/syscall/uaccess.c \
        drivers/pci.c \
        drivers/virtio/pci.c \
        drivers/virtio/virtqueue.c \
        drivers/virtio/blk.c \
        drivers/virtio/input.c \
        drivers/virtio/snd.c \
        drivers/virtio/net.c \
        drivers/net/netd.c \
        drivers/afd.c \
        drivers/nsi.c \
        drivers/condrv.c \
        drivers/fb.c \
        drivers/hid.c \
        drivers/snd.c \
        fs/fat32/fat.c \
        fs/fat32/dir.c \
        fs/fat32/file.c \
        fs/npfs/pipe.c \
        kernel/io/ioctl.c \
        arch/x86_64/serial.c \
        arch/x86_64/rtc.c \
        arch/x86_64/smbios.c \
        arch/x86_64/fwcfg.c \
        arch/x86_64/idt.c \
        arch/x86_64/lapic.c \
        arch/x86_64/gdt.c \
        arch/x86_64/cpu.c \
        arch/x86_64/mmu.c \
        tests/kmt/lib.c \
        tests/kmt/m2_dispatcher.c \
        tests/kmt/m3_ob.c \
        tests/kmt/m4_usermode.c \
        tests/kmt/m5_section.c \
        tests/kmt/m6_io.c \
        tests/kmt/m6_blk.c \
        tests/kmt/net_smoke.c \
        tests/kmt/cui8_async.c \
        tests/kmt/cui9_cow.c \
        tests/kmt/condrv_unwind.c \
        tests/kmt/preventive.c \
        tests/kmt/sched_explore.c \
        tests/kmt/fat_interop.c \
        tests/kmt/fat_churn.c \
        tests/kmt/snd.c
ASRC := arch/x86_64/trap.S \
        arch/x86_64/ctxswitch.S \
        kernel/syscall/entry.S \
        kernel/syscall/recover.S
# The boot console's glyph renderer (kernel/init/bootvid.c): the only
# third_party code compiled into the kernel image, pinned and unmodified
# (docs/11 "Third-party code inside the kernel image"). Kept OUT of CSRC on
# purpose — `make format` runs clang-tidy over $(CSRC) with the docs/15 naming
# rules, which are ours to follow and not upstream's.
FLANTERM_SRC := third_party/flanterm/src/flanterm.c \
                third_party/flanterm/src/flanterm_backends/fb.c

# The pinned lwIP protocol engine (Net-1, docs/24 §3): the second and only
# other third_party code linked into the kernel image (docs/11). Same
# arrangement as Flanterm — out of CSRC so clang-tidy's docs/15 naming rules
# never touch upstream, sanitizers stop at our own TUs — plus the port layer
# (drivers/net/port/: lwipopts.h, arch/cc.h, sys_arch.c, the hosted-header
# shims), which follows lwIP's own naming and stays out of CSRC with it.
# The file list is exactly what lwipopts.h compiles: NO_SYS raw API, DHCP
# without ACD, DNS bookkeeping, dual-stack, no sockets/netconn/altcp/ppp.
LWIP_SRC := third_party/lwip/src/core/init.c \
            third_party/lwip/src/core/def.c \
            third_party/lwip/src/core/dns.c \
            third_party/lwip/src/core/inet_chksum.c \
            third_party/lwip/src/core/ip.c \
            third_party/lwip/src/core/mem.c \
            third_party/lwip/src/core/memp.c \
            third_party/lwip/src/core/netif.c \
            third_party/lwip/src/core/pbuf.c \
            third_party/lwip/src/core/raw.c \
            third_party/lwip/src/core/stats.c \
            third_party/lwip/src/core/sys.c \
            third_party/lwip/src/core/tcp.c \
            third_party/lwip/src/core/tcp_in.c \
            third_party/lwip/src/core/tcp_out.c \
            third_party/lwip/src/core/timeouts.c \
            third_party/lwip/src/core/udp.c \
            third_party/lwip/src/core/ipv4/dhcp.c \
            third_party/lwip/src/core/ipv4/etharp.c \
            third_party/lwip/src/core/ipv4/icmp.c \
            third_party/lwip/src/core/ipv4/ip4.c \
            third_party/lwip/src/core/ipv4/ip4_addr.c \
            third_party/lwip/src/core/ipv4/ip4_frag.c \
            third_party/lwip/src/core/ipv6/ethip6.c \
            third_party/lwip/src/core/ipv6/icmp6.c \
            third_party/lwip/src/core/ipv6/ip6.c \
            third_party/lwip/src/core/ipv6/ip6_addr.c \
            third_party/lwip/src/core/ipv6/ip6_frag.c \
            third_party/lwip/src/core/ipv6/mld6.c \
            third_party/lwip/src/core/ipv6/nd6.c \
            third_party/lwip/src/netif/ethernet.c \
            drivers/net/port/sys_arch.c

OBJ  := $(CSRC:%.c=$(BUILD)/%.o) $(FLANTERM_SRC:%.c=$(BUILD)/%.o) \
        $(LWIP_SRC:%.c=$(BUILD)/%.o) $(ASRC:%.S=$(BUILD)/%.o)

# Sanitizers are for code we can fix. A UBSan trap or a KASAN report raised
# from inside vendored code would kill the machine in the one component whose
# job is to still be printing when everything else is broken (Art. 9), and we
# do not patch third_party (docs/11) — so the checks stop at our own TUs.
$(BUILD)/third_party/flanterm/%.o: CFLAGS += -fno-sanitize=undefined
$(BUILD)/third_party/flanterm/%.o: KASAN_FLAGS :=

# lwIP's headers and the port's shims resolve through these two roots, for
# the upstream TUs, the port, and our own drivers/net/ code alike.
LWIP_INCLUDES := -Ithird_party/lwip/src/include -Idrivers/net/port
$(BUILD)/third_party/lwip/%.o: CFLAGS += $(LWIP_INCLUDES) -fno-sanitize=undefined
$(BUILD)/third_party/lwip/%.o: KASAN_FLAGS :=
$(BUILD)/drivers/net/%.o: CFLAGS += $(LWIP_INCLUDES)
$(BUILD)/drivers/afd.o: CFLAGS += $(LWIP_INCLUDES)
$(BUILD)/drivers/nsi.o: CFLAGS += $(LWIP_INCLUDES)

# --- M4 user-mode flat binaries (boot modules) ---------------------------
# Freestanding ring-3 clients (docs/02: "the test client is a flat binary").
# Same clang cross-target as the kernel, but ring-3 code may keep the red
# zone and needs no kernel code model. Linked at PSP_IMAGE_BASE via user.ld,
# then llvm-objcopy'd to a raw binary the kernel maps and jumps into.
OBJCOPY   := $(LLVM)/llvm-objcopy
UCFLAGS   := -std=c11 -target x86_64-unknown-none -ffreestanding \
             -fno-stack-protector -fno-pie -fno-pic -m64 -march=x86-64 \
             -mno-mmx -mno-sse -mno-sse2 -mno-80387 \
             -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
             -O2 -g -Wall -Wextra -Wno-unused-parameter -I.
ULDFLAGS  := -m elf_x86_64 -static -T tests/boot/user.ld --build-id=none

# crt0 must lead the link so _start lands at image offset 0 (user.ld).
USER_RT   := $(BUILD)/tests/boot/crt0.o \
             $(BUILD)/tests/boot/syscall_stubs.o
MODULES   := $(BUILD)/modules/alloc_wait.bin $(BUILD)/modules/crash.bin \
             $(BUILD)/modules/m8_persist.bin \
             $(BUILD)/modules/pe_smoke.exe $(BUILD)/modules/m7_smoke.exe \
             $(BUILD)/modules/abi_probe.exe \
             $(BUILD)/modules/pe32_probe.exe \
             $(BUILD)/modules/sample.dat
# Each boot module is passed to mkimage as <binary>=<cmdline>; the kernel
# reads the cmdline as the module's expected outcome, or "initrd" for a
# RAM-disk data file that is registered but never run (kernel/init/main.c).
MODULE_SPECS := $(BUILD)/modules/alloc_wait.bin=expect=0 \
                $(BUILD)/modules/crash.bin=expect=av \
                $(BUILD)/modules/m8_persist.bin=expect=0 \
                $(BUILD)/modules/pe_smoke.exe=expect=0 \
                $(BUILD)/modules/m7_smoke.exe=m7 \
                $(BUILD)/modules/abi_probe.exe=abi \
                $(BUILD)/modules/pe32_probe.exe=initrd \
                $(BUILD)/modules/sample.dat=initrd

# --- M5 PE user client + RAM-disk seed data --------------------------------
# The PE client is a real PE32+ image the kernel loads through SEC_IMAGE
# sections (docs/02 M5 "Done when"). mingw provides the PE container;
# -mabi=sysv keeps the code on the SysV calling convention the generated
# syscall stubs use (the NT x64 convention arrives with the M7 ntdll stubs).
# --dynamicbase keeps the .reloc directory so the kmt relocation test has
# something to chew on.
MINGW ?= x86_64-w64-mingw32-gcc
# The PE binutils that go with it. objdump reads the import DIRECTORY, which
# is the only way to tell a symbol this build defines from one the linker
# quietly bound to a DLL import (see the win32u.dll link rule).
MINGW_OBJDUMP ?= x86_64-w64-mingw32-objdump
# The i386 cross, for the one PE32 artifact the image parser is tested
# against (WOW64 milestone). tools/setup_linux.sh installs it.
MINGW32 ?= i686-w64-mingw32-gcc
PECFLAGS := -std=c11 -mabi=sysv -ffreestanding -fno-builtin -nostdlib -nostartfiles \
            -O1 -g0 -Wall -Wextra -Wno-unused-parameter -I. \
            -Wl,--entry=pe_start -Wl,--dynamicbase -Wl,--pic-executable -Wl,--high-entropy-va

all: $(IMG_TEST)

# -MMD/-MP emit a .d beside each .o so a changed header rebuilds its dependents
# (without this, editing e.g. ke.h silently left stale objects — a whole class
# of layout-mismatch bugs).
DEPFLAGS := -MMD -MP

# User client objects (own flags; not the kernel's KASAN/kernel-cmodel build).
# These must precede the generic kernel rules: GNU Make 3.81 (macOS's stock
# make) picks the FIRST matching pattern rule, not the shortest-stem one.
$(BUILD)/tests/boot/%.o: tests/boot/%.c
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/tests/boot/%.o: tests/boot/%.S
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(KASAN_FLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(KERNEL): $(OBJ) arch/x86_64/linker.ld
	@mkdir -p $(dir $@)
	$(LD) $(LDFLAGS) $(OBJ) -o $@

# The generated syscall stubs live under tests/ntapi/syscall (shared with the
# ntapi proskrnl target); build them into the user runtime.
$(BUILD)/tests/boot/syscall_stubs.o: tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) -c $< -o $@

$(BUILD)/modules/%.bin: $(BUILD)/tests/boot/%.o $(USER_RT) tests/boot/user.ld
	@mkdir -p $(dir $@)
	$(LD) $(ULDFLAGS) $(USER_RT) $< -o $(@:.bin=.elf)
	$(OBJCOPY) --set-section-flags .data=alloc,load,contents -O binary $(@:.bin=.elf) $@

$(BUILD)/modules/pe_smoke.exe: tests/boot/pe_smoke.c tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(MINGW) $(PECFLAGS) $^ -o $@

# The PE32 parser fixture (WOW64): a genuine i386 container, carried as an
# initrd file and never executed — see the source. --dynamicbase is what
# makes the linker keep the .reloc directory the kmt case relocates through.
$(BUILD)/modules/pe32_probe.exe: tests/boot/pe32_probe.c
	@mkdir -p $(dir $@)
	$(MINGW32) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. \
	    -Wl,--entry=_pe_start -Wl,--dynamicbase $< -o $@

# The M7 PE client (docs/02 "Done when"): threads, PEB/TEB, the SEH test.
# --export-all-symbols gives the image an export directory so the kernel's
# loader can resolve KiUser{Exception,Apc}Dispatcher from it (as it will from
# ntdll) — kernel/ps/process.c PspResolveUserDispatchers.
$(BUILD)/modules/m7_smoke.exe: tests/boot/m7_smoke.c tests/boot/m7_dispatch.S \
                               tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(MINGW) $(PECFLAGS) -Wl,--export-all-symbols $^ -o $@

# The standing ABI-conformance probe (docs/08): a native PE asserting ring-3
# CONVENTIONS (entry-rsp alignment, FXSAVE seeds, header rebasing, id
# agreement, the cookie, KUSER_SHARED_DATA ticking) on every boot — run by
# kernel/init/main.c KiRunAbiProbe via the "abi" module cmdline. The entry
# stub captures the entry state before any compiler-generated code runs.
$(BUILD)/modules/abi_probe.exe: tests/boot/abi_probe.c tests/boot/abi_probe.S \
                                tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(MINGW) $(PECFLAGS) $^ -o $@

# A deterministic, non-page-multiple data file for the kmt M5 mapped-view /
# read consistency test (any bytes do; the size exercises EOF zero-fill).
$(BUILD)/modules/sample.dat:
	@mkdir -p $(dir $@)
	python3 -c "import sys; sys.stdout.buffer.write((bytes(range(256)) * 20)[:5000] + b'proskrnl-sample-END')" > $@

# --- M7 Wine userland on the boot volume -----------------------------------
# The unmodified Wine PE ntdll (+ kernel32/kernelbase, which its loader_init
# hard-loads) and the NLS files ntdll's locale_init maps, from the pinned
# third_party/wine build (tools/setup_linux.sh; the SAME tree abi/ is
# generated from). Baked onto the FAT boot volume as C:\windows\system32 via
# mkimage's win: specs — not Limine modules. hello.exe is the acceptance
# client: a real MS-ABI PE linked ONLY against Wine's ntdll import library
# (docs/02 M7 "Done when").
WINE_PE   := third_party/wine/dlls
WINE_NLS  := third_party/wine/nls
WINE_PE_DLLS := $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll \
                $(WINE_PE)/kernel32/x86_64-windows/kernel32.dll \
                $(WINE_PE)/kernelbase/x86_64-windows/kernelbase.dll
$(WINE_PE_DLLS):
	@echo "error: $@ missing - build the pinned Wine tree first (tools/setup_linux.sh)" >&2
	@exit 1

HELLO := $(BUILD)/modules/hello.exe
$(HELLO): tests/clients/hello.c tests/clients/hello_seh.S $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=hello_start \
	    tests/clients/hello.c tests/clients/hello_seh.S \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The session manager (docs/02 M8, then some): the ONE user image the kernel
# launches at the end of boot. It starts the servers (wineserver-lite,
# conhost), runs firstboot, and drives every acceptance flow and test sweep
# through NtCreateUserProcess. Same recipe as hello.exe: ntdll-only native PE.
SMSS := $(BUILD)/modules/smss.exe
$(SMSS): user/smss/smss.c user/smss/launch.c user/smss/session.c \
        user/smss/firstboot.c user/smss/smss.h \
        $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=SmssStart \
	    user/smss/smss.c user/smss/launch.c user/smss/session.c user/smss/firstboot.c \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M9 acceptance client (docs/02): threaded blocking pipes + a console
# write through kernelbase -> ConDrv -> conhost. Win32-level on purpose —
# it exercises the same kernelbase paths a real console app takes.
M9SMOKE := $(BUILD)/modules/m9_smoke.exe
$(M9SMOKE): tests/clients/m9_smoke.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -Wl,--entry=m9_start \
	    tests/clients/m9_smoke.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M9 interactive-echo client. It blocks on console input, so it must not
# run on a boot nobody is typing at -- which used to be arranged by keeping it
# off every other image and is now the `console` leg name (user/smss/session.c
# SessionFlowM9Echo). It is baked on the one test image like everything else.
M9ECHO := $(BUILD)/modules/m9_echo.exe
$(M9ECHO): tests/clients/m9_echo.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -Wl,--entry=m9_start \
	    tests/clients/m9_echo.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# Where the per-exe standalone-PE glue lives: one directory per pinned
# program, mirroring third_party/wine/programs/ (docs/04).
PROG_GLUE := user/wine/programs

# The GUI state machine's own tree (docs/04): common/ is taken by both of its
# links, client/ by win32u.dll, server/ by wineserver-lite.exe.
WSRV_DIR := user/wine/wineserver-lite

# The M9 console server: Wine's conhost, compiled DIRECTLY from the pinned
# tree — the wineserver seam lives as a runtime-dormant fork commit on
# proskrnl-target (programs/conhost/proskrnl.{c,h}, taken when
# __wine_unix_call_dispatcher is NULL; Art. 10 / docs/06).
# user/wine/programs/conhost/ carries only the standalone-PE glue: entry +
# mini-CRT (proskrnl_glue.c) and window.c's comctl32 delay-import forwarders
# (window_glue.c).
#
# ONE binary, both consoles. There were two links from these sources — a
# headless one whose user32/window.c references were satisfied by stand-ins
# and a windowed one with the real ones — baked as conhost.exe on different
# images, so which console a boot had was a property of its media. The
# windowed link is the only one now and it picks its mode at BOOT from the
# `gui` flag (proskrnl_glue.c conhost_wants_window, kernel/cm/registry.c).
#
# The pinned window.c and the wrc-compiled conhost resources are linked
# against the real user32/gdi32/advapi32, so no '-DWINUSERAPI=': user32
# references must stay dllimport and bind to the import library. comctl32
# alone is NOT linked: window.c reaches it only from the config dialog, and
# window_glue.c forwards those three entry points by hand (upstream's
# DELAYIMPORT, done without mingw's delay-import machinery —
# '-DWINCOMMCTRLAPI=' makes the declarations plain so the forwarders satisfy
# them).
WINE_CONHOST := third_party/wine/programs/conhost
CONHOST := $(BUILD)/modules/conhost.exe
$(CONHOST): $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/conhost.h \
            $(WINE_CONHOST)/window.c $(WINE_CONHOST)/conhost.res \
            $(WINE_CONHOST)/proskrnl.c $(WINE_CONHOST)/proskrnl.h \
            $(PROG_GLUE)/conhost/proskrnl_glue.c $(PROG_GLUE)/conhost/window_glue.c \
            $(WSRV_DIR)/common/transport.h third_party/wine/include/proskrnl_bootflag.h \
            $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_CONHOST)/conhost.res \
	    $(BUILD)/conhost.res.o
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINCOMMCTRLAPI=' \
	    -I$(WINE_CONHOST) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=conhost_start \
	    $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/window.c $(WINE_CONHOST)/proskrnl.c \
	    $(PROG_GLUE)/conhost/proskrnl_glue.c $(PROG_GLUE)/conhost/window_glue.c \
	    $(BUILD)/conhost.res.o \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/gdi32/x86_64-windows/libgdi32.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# M10: Wine's cmd.exe as a standalone CUI PE. The pinned tree's own PE build
# provides the four cmd objects and the wrc-compiled resources UNMODIFIED
# (programs/cmd/x86_64-windows, built by tools/setup_linux.sh);
# user/wine/programs/cmd/ supplies only the glue — the CRT entry. Its five
# user32 and four shell32 imports were STOOD IN there while a CUI image
# carried neither DLL; one image bakes exactly one of each now, so the real
# import libraries are linked. ucrtbase + advapi32 likewise; every one of
# these DLLs is baked ($(WINFILES) / $(FULLFILES) below).
WINE_CMD := third_party/wine/programs/cmd
CMD := $(BUILD)/modules/cmd.exe
$(CMD): $(PROG_GLUE)/cmd/proskrnl_glue.c $(WINE_CMD)/x86_64-windows/wcmdmain.o \
        $(WINE_CMD)/x86_64-windows/builtins.o $(WINE_CMD)/x86_64-windows/batch.o \
        $(WINE_CMD)/x86_64-windows/directory.o $(WINE_CMD)/cmd.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_CMD)/cmd.res $(BUILD)/cmd.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=cmd_start \
	    $(WINE_CMD)/x86_64-windows/wcmdmain.o $(WINE_CMD)/x86_64-windows/builtins.o \
	    $(WINE_CMD)/x86_64-windows/batch.o $(WINE_CMD)/x86_64-windows/directory.o \
	    $(PROG_GLUE)/cmd/proskrnl_glue.c $(BUILD)/cmd.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/shell32/x86_64-windows/libshell32.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-4: Wine's tasklist.exe / taskkill.exe as standalone CUI PEs — the
# milestone's acceptance pair (docs/02 "a tasklist/taskkill pair works
# against live processes"). The pinned tree's own PE build provides the
# program objects and wrc-compiled resources UNMODIFIED; the tasklist/ and
# taskkill/ glue supplies only the wide CRT entry; their user32 imports were
# stood in there while a CUI image carried no user32 and are the real ones
# now. Same recipe shape as cmd.exe above.
WINE_TASKLIST := third_party/wine/programs/tasklist
TASKLIST := $(BUILD)/modules/tasklist.exe
$(TASKLIST): $(PROG_GLUE)/tasklist/proskrnl_glue.c $(WINE_TASKLIST)/x86_64-windows/tasklist.o \
        $(WINE_TASKLIST)/tasklist.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_TASKLIST)/tasklist.res \
	    $(BUILD)/tasklist.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=tasklist_start \
	    $(WINE_TASKLIST)/x86_64-windows/tasklist.o $(PROG_GLUE)/tasklist/proskrnl_glue.c \
	    $(BUILD)/tasklist.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

WINE_TASKKILL := third_party/wine/programs/taskkill
TASKKILL := $(BUILD)/modules/taskkill.exe
$(TASKKILL): $(PROG_GLUE)/taskkill/proskrnl_glue.c $(WINE_TASKKILL)/x86_64-windows/taskkill.o \
        $(WINE_TASKKILL)/taskkill.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_TASKKILL)/taskkill.res \
	    $(BUILD)/taskkill.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=taskkill_start \
	    $(WINE_TASKKILL)/x86_64-windows/taskkill.o $(PROG_GLUE)/taskkill/proskrnl_glue.c \
	    $(BUILD)/taskkill.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: Wine's rundll32.exe as a standalone PE — wineboot --init's vehicle
# for the `setupapi,InstallHinfSection` children that apply wine.inf (ADR
# 0008's Cm integration exercise). The pinned tree's own PE build provides
# rundll32.o UNMODIFIED; the rundll32/ glue supplies the wide CRT entry. Its
# four user32 imports were headless stand-ins there while a CUI image carried
# no user32; the real import library is linked now.
WINE_RUNDLL32 := third_party/wine/programs/rundll32
RUNDLL32 := $(BUILD)/modules/rundll32.exe
$(RUNDLL32): $(PROG_GLUE)/rundll32/proskrnl_glue.c $(WINE_RUNDLL32)/x86_64-windows/rundll32.o \
        $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=rundll32_start \
	    $(WINE_RUNDLL32)/x86_64-windows/rundll32.o \
	    $(PROG_GLUE)/rundll32/proskrnl_glue.c \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: wineboot.exe as a standalone PE. The pinned tree keeps
# programs/wineboot out of its PE build (x86_64_DISABLED_SUBDIRS, same as
# conhost), so wineboot.c is compiled DIRECTLY from the tree — the conhost
# recipe — with the wineboot/ glue supplying the narrow CRT entry, the
# user32/gdi32 wait-window set, and honest-failure stand-ins for the
# shell32/shlwapi/ws2_32/wininet/newdev legs that degrade gracefully under
# --init (docs/02 CUI-1). setupapi/version/advapi32/rpcrt4/uuid link real:
# their DLLs are baked below. shutdown.c is not compiled — its three
# entry points are glue stubs, unreached under --init.
WINE_WINEBOOT := third_party/wine/programs/wineboot
WINEBOOT := $(BUILD)/modules/wineboot.exe
$(WINEBOOT): $(WINE_WINEBOOT)/wineboot.c $(PROG_GLUE)/wineboot/proskrnl_glue.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINUSERAPI=' '-DWINGDIAPI=' '-DWINBASEAPI=' \
	    -I$(WINE_WINEBOOT) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=wineboot_start \
	    $(WINE_WINEBOOT)/wineboot.c $(PROG_GLUE)/wineboot/proskrnl_glue.c \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/setupapi/x86_64-windows/libsetupapi.a \
	    $(WINE_PE)/version/x86_64-windows/libversion.a \
	    third_party/wine/libs/uuid/x86_64-windows/libuuid.a \
	    $(WINE_PE)/rpcrt4/x86_64-windows/librpcrt4.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: THE baked wine.inf. tools/filter_inf.py strips the fake-dll and
# file-queue directives that need source media the disk does not have, and
# keeps the AddReg machine-state payload; `--keep RegisterDlls` keeps
# SELF-REGISTRATION, with mmdevapi and dsound injected into
# [RegisterDllsSection] — CoCreateInstance of the MMDeviceEnumerator needs its
# CLSID in the hive, which a real prefix gets from the fake-dll registrar this
# filter drops, and mmdevapi is not in wine.inf's own RegisterDlls list.
# Registration then runs each DLL's OWN DllRegisterServer through Wine's own
# registrar (setupapi + atl100), never a hand-typed CLSID seed (Art. 11 / G8).
# Of the section's 30 entries, shell32 and mmdevapi/dsound resolve; the rest
# fail LoadLibrary and are skipped one by one (setupapi do_register_dll — a
# skip, not an abort).
#
# ONE inf, where there were three (registry-only for the CUI images,
# +RegisterDlls for the shell ones, +mmdevapi/dsound for the audio ones), each
# staged as `windows/inf/wine.inf` on its own image family. What a boot
# REGISTERS is now the same everywhere — which is also what the CUI-1 registry
# differential's ORACLE half must apply: tests/run/run.sh firstboot filters the
# prefix's inf the same way, or the guest's self-registration payload reads as
# 122 unexpected keys the oracle never wrote (measured).
WINE_INF_FULL := $(BUILD)/wine-proskrnl-full.inf
$(WINE_INF_FULL): third_party/wine/loader/wine.inf tools/filter_inf.py
	@mkdir -p $(dir $@)
	python3 tools/filter_inf.py --keep RegisterDlls --add-register mmdevapi.dll,dsound.dll \
	    third_party/wine/loader/wine.inf $@

# ...and the registry-only one, for a boot with no DESKTOP. Self-registration
# is COM registration: setupapi runs each DLL's DllRegisterServer, which needs
# an apartment, which needs a message window. A CUI-only boot (`Gui`=0) has no
# desktop, so every one of the section's entries fails its way through
# CreateWindow, CoMarshalInterface and an rpcss that will not start — measured
# at ~150 processes and the whole boot budget, on a machine that has no shell
# to register the shell's classes FOR.
#
# This is the registry-only inf the CUI images carried before the images were
# unified; merging the three into one moved self-registration onto boots that
# had never done it. One image still, and both payloads are on it — what the
# BOOT applies is chosen by smss (user/smss/firstboot.c), which is the same
# rule as everything else here: the boot decides, the media carries.
WINE_INF_CUI := $(BUILD)/wine-proskrnl-cui.inf
$(WINE_INF_CUI): third_party/wine/loader/wine.inf tools/filter_inf.py
	@mkdir -p $(dir $@)
	python3 tools/filter_inf.py third_party/wine/loader/wine.inf $@

# The baked COPIES of the pinned tree's PE dlls are debug-stripped. The
# DWARF sections are never read on-target, and with no COW and no eviction
# (Art. 3) every mapped image is copied whole per process — the mingw-gcc
# -g builds are ~3x the clang ones and firstboot's rundll32 fan-out pushed
# a 256M boot into STATUS_INSUFFICIENT_RESOURCES import failures (observed:
# setupapi's advapi32/cfgmgr32/rpcrt4 imports failing c000009a, silently
# skipping wine.inf's whole AddReg payload). The pinned tree keeps its
# full-symbol dlls for the oracle legs (one tree, three roles, docs/06);
# only the disk payload is lean.
WINESTRIP := $(BUILD)/winestrip
WINESTRIP_NAMES := ntdll kernel32 kernelbase msvcrt ucrtbase advapi32 sechost rpcrt4 version \
                   cryptbase setupapi cfgmgr32 ws2_32 secur32 userenv hid \
                   nsi iphlpapi dnsapi
WINESTRIP_DLLS := $(foreach d,$(WINESTRIP_NAMES),$(WINESTRIP)/$(d).dll)
# One explicit rule per dll (the name appears twice in the source path, which
# a pattern rule's single stem cannot express).
define WINESTRIP_RULE
$(WINESTRIP)/$(1).dll: $(WINE_PE)/$(1)/x86_64-windows/$(1).dll
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach d,$(WINESTRIP_NAMES),$(eval $(call WINESTRIP_RULE,$(d))))

# WOW64: the same treatment for the i386 PE tree, landing under a separate
# prefix because the two arch trees give a dll the SAME file name — the
# guest set goes to windows\syswow64 while system32 keeps the 64-bit one,
# which is the whole naming convention WOW64 rests on
# (get_machine_wow64_dir, third_party/wine dlls/ntdll/unix/loader.c).
# Deliberately a SHORT list: with no COW every wow64 child copies its images
# whole, and the guest stack needs only what ntdll's loader pulls in.
WINESTRIP32 := $(BUILD)/winestrip32
WINESTRIP32_NAMES := ntdll kernel32 kernelbase msvcrt ucrtbase version
WINESTRIP32_DLLS := $(foreach d,$(WINESTRIP32_NAMES),$(WINESTRIP32)/$(d).dll)
define WINESTRIP32_RULE
$(WINESTRIP32)/$(1).dll: $(WINE_PE)/$(1)/i386-windows/$(1).dll
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach d,$(WINESTRIP32_NAMES),$(eval $(call WINESTRIP32_RULE,$(d))))

# The 32-bit CUI programs the guest side runs, and the three x86_64 DLLs
# that IMPLEMENT wow64 (they are host code — 64-bit — and live in system32
# beside ntdll, which is where wow64.dll's load_64bit_module looks).
WINESTRIP32_EXE_NAMES := cmd msinfo32
WINESTRIP32_EXES := $(foreach p,$(WINESTRIP32_EXE_NAMES),$(WINESTRIP32)/$(p).exe)
define WINESTRIP32_EXE_RULE
$(WINESTRIP32)/$(1).exe: third_party/wine/programs/$(1)/i386-windows/$(1).exe
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach p,$(WINESTRIP32_EXE_NAMES),$(eval $(call WINESTRIP32_EXE_RULE,$(p))))

WOW64_HOST_NAMES := wow64 wow64cpu wow64win
WOW64_HOST_DLLS := $(foreach d,$(WOW64_HOST_NAMES),$(WINESTRIP)/$(d).dll)
$(foreach d,$(WOW64_HOST_NAMES),$(eval $(call WINESTRIP_RULE,$(d))))

# system32\win32u.dll is NOT staged from the pinned tree, and that omission is
# load-bearing rather than an oversight. wow64win.dll is the win32u syscall
# thunk table and imports win32u unconditionally, while wow64.dll's
# load_64bit_module TERMINATES the process if wow64win cannot load
# (dlls/wow64/syscall.c) — so a wow64 process needs SOME win32u present to
# start at all. This build's own $(WIN32U) is that file, and the pinned tree's
# stock thunks have the same NAME: stage them and they win the mcopy -o race,
# handing every 64-bit GUI process a win32u whose NtUser* entry points issue
# syscalls at a kernel that mints none — which is exactly what happened when
# a CUI image staged them and a GUI one did not: conhost took a page fault
# inside its first NtUserCreateWindowEx before the console window appeared.
# One image cannot hold both files, so it holds the implementation. wow64win
# is happy either way; the implementation exports every name it imports (see
# WOW64_GUI_NAMES).

# The guest payload as mkimage `win:` specs: the i386 set under syswow64 and
# the wow64 host trio under system32.
WOW64GUESTFILES := $(foreach d,$(WINESTRIP32_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll) \
              $(foreach p,$(WINESTRIP32_EXE_NAMES),win:$(WINESTRIP32)/$(p).exe=windows/syswow64/$(p).exe)
WOW64HOSTFILES := $(foreach d,$(WOW64_HOST_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll)
WOW64_GUEST_PAYLOAD := $(WINESTRIP32_DLLS) $(WINESTRIP32_EXES) $(WOW64_HOST_DLLS)

# CUI-3: the SCM programs — the pinned tree's own UNMODIFIED pure-PE
# binaries (the whoami precedent: prebuilt, no glue, no relink), baked
# debug-stripped like the DLLs (services.exe stays resident; unstripped
# DWARF triples the no-COW memory bill — docs/03 CUI-1 notes).
WINESTRIP_EXE_NAMES := services rpcss sc
WINESTRIP_EXES := $(foreach p,$(WINESTRIP_EXE_NAMES),$(WINESTRIP)/$(p).exe)
define WINESTRIP_EXE_RULE
$(WINESTRIP)/$(1).exe: third_party/wine/programs/$(1)/x86_64-windows/$(1).exe
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach p,$(WINESTRIP_EXE_NAMES),$(eval $(call WINESTRIP_EXE_RULE,$(p))))
winestrip: $(WINESTRIP_DLLS) $(WINESTRIP_EXES)
.PHONY: winestrip

# Defined here, above WINFILES's immediate expansion; the build rule
# lives with the winevsnd recipe below.
WSRESOLV := $(BUILD)/modules/wsresolv.dll

# The DLL half is DERIVED from $(WINESTRIP_NAMES) rather than re-listed:
# the two were separate lists and they drifted, exactly the way the
# print-winfiles note below (beside WINFILES_DEPS) says such pairs do.
# hid.dll was stripped by the one and missing from the other, which nothing
# noticed while the winetest-gui image carried a hand-written DLL list of its
# own that happened to include it. Unified onto one image, user32_test.exe
# could not load and the whole msg gate died with STATUS_DLL_NOT_FOUND
# (0xc0000135). A name is now baked because it is built, and there is no
# second place to forget it.
WINFILES := $(foreach d,$(WINESTRIP_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
            win:$(WINESTRIP)/services.exe=windows/system32/services.exe \
            win:$(WINESTRIP)/rpcss.exe=windows/system32/rpcss.exe \
            win:$(WINESTRIP)/sc.exe=windows/system32/sc.exe \
            win:$(RUNDLL32)=windows/system32/rundll32.exe \
            win:$(WINEBOOT)=windows/system32/wineboot.exe \
            win:$(WINE_INF_FULL)=windows/inf/wine.inf \
            win:$(WINE_INF_CUI)=windows/inf/wine-cui.inf \
            win:$(WINE_NLS)/locale.nls=windows/system32/locale.nls \
            win:$(WINE_NLS)/l_intl.nls=windows/system32/l_intl.nls \
            win:$(WINE_NLS)/c_1252.nls=windows/system32/c_1252.nls \
            win:$(WINE_NLS)/c_437.nls=windows/system32/c_437.nls \
            win:$(WINE_NLS)/c_20127.nls=windows/system32/c_20127.nls \
            win:$(WINE_NLS)/sortdefault.nls=windows/system32/sortdefault.nls \
            win:$(WINE_NLS)/normnfc.nls=windows/system32/normnfc.nls \
            win:$(WINE_NLS)/normnfd.nls=windows/system32/normnfd.nls \
            win:$(WINE_NLS)/normnfkc.nls=windows/system32/normnfkc.nls \
            win:$(WINE_NLS)/normnfkd.nls=windows/system32/normnfkd.nls \
            win:$(WINE_NLS)/normidna.nls=windows/system32/normidna.nls \
            win:$(HELLO)=hello.exe \
            win:$(SMSS)=windows/system32/smss.exe \
            win:$(CONHOST)=windows/system32/conhost.exe \
            win:$(M9SMOKE)=m9_smoke.exe \
            win:$(WSRESOLV)=windows/system32/wsresolv.dll \
            win:third_party/wine/dlls/ws2_32/hosts=windows/system32/drivers/etc/hosts \
            win:third_party/wine/dlls/ws2_32/networks=windows/system32/drivers/etc/networks \
            win:third_party/wine/dlls/ws2_32/protocol=windows/system32/drivers/etc/protocol \
            win:third_party/wine/dlls/ws2_32/services=windows/system32/drivers/etc/services

# Everything $(WINFILES) references that this Makefile BUILDS, as ONE
# prerequisite list: every image target that passes $(WINFILES) to mkimage
# depends on this, never on a hand-copied sublist. The sublists this
# replaced had already drifted — none carried $(WSRESOLV), so a fresh
# checkout (CI) baked images before the resolver was built and mkimage
# failed with "win file missing". (The nls/etc/whoami entries are files of
# the pinned submodule, present after checkout — not products, not listed.)
WINFILES_DEPS := $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(RUNDLL32) $(WINEBOOT) \
                 $(WINE_INF_FULL) $(WINE_INF_CUI) $(WSRESOLV) $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES)

# Everything $(WINFILES) references that this Makefile BUILDS is $(WINFILES_DEPS)
# above; both images depend on it. There is no longer a `print-winfiles` for a
# provisioner outside this Makefile to read, because there is no provisioner
# outside this Makefile: tests/run/run.sh baked its own images, carrying its
# own hand-written list of the DLLs it wanted, and two lists of the same
# userland is how the winetest image drifted into a SHORTER machine than the
# one `make run` booted — no wineboot.exe, so no firstboot and none of
# wine.inf's machine-state payload; no SCM, no setupapi/ws2_32/secur32/…  A
# differential leg whose image is not the product's measures the difference.
# The lists are gone with the images (Art. 11: one authority).

# kernel/lib/upcase.h is checked in (see `gen-nls`), so nothing in the build
# would notice it drifting from the pin it was generated out of. This is what
# notices: it re-runs only when the pinned table, the generator or the output
# changes, and it hangs off the IMAGE rather than off the kernel because a
# third_party/wine prerequisite must not reach `make build/proskrnl` — that
# target is built on hosts (and in the lint job) where the tree is absent.
UPCASE_CHECK := $(BUILD)/upcase.checked
$(UPCASE_CHECK): kernel/lib/upcase.h tools/gen_upcase.py $(WINE_NLS)/l_intl.nls
	@mkdir -p $(dir $@)
	python3 tools/gen_upcase.py --check
	@touch $@

# kernel/cm/license.h is checked in for the same reason and drifts the same
# way — a wine pin that edits [LicenseInformation] moves the ORACLE's answer
# and leaves the kernel's seed where it was, which reads as a divergence.
LICENSE_CHECK := $(BUILD)/license.checked
$(LICENSE_CHECK): kernel/cm/license.h tools/gen_license.py third_party/wine/loader/wine.inf
	@mkdir -p $(dir $@)
	python3 tools/gen_license.py --check
	@touch $@

# kernel/cm/timezones.h likewise: the pinned kernelbase carries the table in a
# WINE_REGISTRY resource, so a pin bump that tracks new tzdata moves the
# ORACLE's answer for every zone and leaves the kernel's seed where it was.
TIMEZONES_CHECK := $(BUILD)/timezones.checked
$(TIMEZONES_CHECK): kernel/cm/timezones.h tools/gen_timezones.py \
                    third_party/wine/dlls/kernelbase/kernelbase.rgs
	@mkdir -p $(dir $@)
	python3 tools/gen_timezones.py --check
	@touch $@

# M10: the MSVC-stand-in CUI apps — plain mingw with its FULL CRT (they
# import msvcrt.dll + kernel32.dll; third-party CRT startup against the
# baked Wine userland). On the test image and the dev image both.
HELLOCRT := $(BUILD)/modules/hello_crt.exe
$(HELLOCRT): tests/cui/hello_crt.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
# WOW64 acceptance (docs/02 "a 32-bit CUI app runs"): the same hello_crt
# shape, built by the i686 cross with its full 32-bit CRT. Nothing in the
# source knows about WOW64 — an ordinary Win32 app is the whole test.
HELLO32 := $(BUILD)/modules/hello32.exe
$(HELLO32): tests/cui/hello32.c
	@mkdir -p $(dir $@)
	$(MINGW32) -O1 -g0 -Wall -o $@ $<
UPCASE := $(BUILD)/modules/upcase.exe
$(UPCASE): tests/cui/upcase.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
# CUI-3 acceptance: a third-party service binary (imports advapi32 for the
# service dispatcher; otherwise the hello_crt shape).
SVCDEMO := $(BUILD)/modules/svcdemo.exe
$(SVCDEMO): tests/cui/svcdemo.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $< -ladvapi32
# CUI-4 acceptance: an interruptible busy loop (console control handler) and
# a job-object-using build tool. Same third-party CUI shape as above.
LOOPER := $(BUILD)/modules/looper.exe
$(LOOPER): tests/cui/looper.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
JOBTOOL := $(BUILD)/modules/jobtool.exe
$(JOBTOOL): tests/cui/jobtool.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
# CUI-6 acceptance: a process/thread-times reader, the handle-inheritance
# stdio-redirect chain, and a restricted-token launcher. Same third-party
# CUI shape (restricted imports advapi32 for the token/restricted-token API).
TIMEIT := $(BUILD)/modules/timeit.exe
$(TIMEIT): tests/cui/timeit.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
REDIRCHAIN := $(BUILD)/modules/redirchain.exe
$(REDIRCHAIN): tests/cui/redirchain.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
RESTRICTED := $(BUILD)/modules/restricted.exe
$(RESTRICTED): tests/cui/restricted.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $< -ladvapi32
# CUI-7 acceptance: the reg save/load round-trip driver (advapi32) and the
# VirtualAlloc2/write-watch app. Same third-party CUI shape as above.
REGTOOL := $(BUILD)/modules/regtool.exe
$(REGTOOL): tests/cui/regtool.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $< -ladvapi32
WATCHAPP := $(BUILD)/modules/watchapp.exe
$(WATCHAPP): tests/cui/watchapp.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
# CUI-9 step 1: the image-copy ceiling measurement (docs/17 §2) — spawns
# resident copies of itself until process creation refuses.
MMCEILING := $(BUILD)/modules/mmceiling.exe
$(MMCEILING): tests/cui/mmceiling.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<

# CUI-2 acceptance: the pinned tree's own UNMODIFIED whoami.exe — a real
# tool whose startup path is OpenProcessToken + GetTokenInformation.
# console_expect.py runs `whoami /logonid` on the `console` leg and greps the
# logon SID (docs/02 CUI-2 "Done when").
WHOAMI := third_party/wine/programs/whoami/x86_64-windows/whoami.exe

# The GUI-1 acceptance client (docs/02 "a user program maps the framebuffer
# and draws a rectangle visible in a screendump; key input is readable").
# ntdll only — it talks to \Device\Fb0 and \Device\Input0 through the Nt*
# surface directly, with no Win32 above it (user32 does not exist until
# GUI-2). -I. so it can include the drivers/*proto.h contracts.
GUISMOKE := $(BUILD)/modules/gui_smoke.exe
$(GUISMOKE): tests/gui/gui_smoke.c drivers/fbproto.h drivers/hidproto.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=gui_start \
	    tests/gui/gui_smoke.c \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The AUD-1 acceptance client (docs/02 "a guest client plays a deterministic
# S16 pattern and the harness finds it sample-exact in the WAV"). ntdll
# only — it talks to \Device\Snd0 through the Nt* surface directly (the
# GUISMOKE recipe). -I. for the drivers/sndproto.h contract.
AUDSMOKE := $(BUILD)/modules/aud_smoke.exe
$(AUDSMOKE): tests/audio/aud_smoke.c drivers/sndproto.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=aud_start \
	    tests/audio/aud_smoke.c \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The AUD-3 device-contract capture client (docs/02 "AUD-3 — capture"):
# same recipe, pointed at the capture node, run on a `none`-audiodev boot
# (the one backend with an input side — tests/run/run.sh audio).
CAPSMOKE := $(BUILD)/modules/cap_smoke.exe
$(CAPSMOKE): tests/audio/cap_smoke.c drivers/sndproto.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=cap_start \
	    tests/audio/cap_smoke.c \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

cap-smoke: $(CAPSMOKE)
.PHONY: cap-smoke

# winevsnd.drv (AUD-2, docs/23 §4b): the PE mmdevapi driver — the winefb
# recipe as a STANDALONE DLL, because mmdevapi's seam LdrLoadDll's it by
# name and resolves its one exported table. Compiled against the pinned
# tree's own headers plus dlls/mmdevapi (the unixlib contract it
# implements) and -I. for drivers/sndproto.h (the HACK-007 wire contract);
# linked above ntdll ONLY — a driver loaded into every audio process must
# not drag kernel32 in below kernel32's own initializers.
VSND_DIR := user/wine/dlls/winevsnd.drv
VSND_SRCS := $(wildcard $(VSND_DIR)/*.c)
VSND_CFLAGS := -std=gnu11 -O2 -g0 -fno-builtin -fno-strict-aliasing -w \
               -D__WINESRC__ -DWINE_NO_LONG_TYPES -D__USE_MINGW_ANSI_STDIO=0 \
               -I$(VSND_DIR) -I. -Ithird_party/wine/dlls/mmdevapi \
               -Ithird_party/wine/include
WINEVSND := $(BUILD)/modules/winevsnd.drv
$(WINEVSND): $(VSND_SRCS) $(VSND_DIR)/winevsnd.h drivers/sndproto.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) $(VSND_CFLAGS) -shared -nostdlib -nostartfiles \
	    -Wl,--entry=DllMainCRTStartup $(VSND_SRCS) \
	    tests/winetest/glue/crt_sections.c \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

winevsnd: $(WINEVSND)
.PHONY: winevsnd

# wsresolv.dll (Net-3, docs/24 §4f): the PE resolver behind ws2_32's
# WS_CALL seam — the winevsnd recipe as a standalone DLL, LdrLoadDll'd by
# name from the fork's one seam commit and dispatched through its exported
# __wine_unix_call_funcs table. Compiled against the pinned tree's own
# headers plus dlls/ws2_32 (the unixlib contract it implements); linked
# above ntdll AND ws2_32 — the DNS client rides ws2_32's public UDP
# surface, which never re-enters the resolver — and never kernel32 (the
# winevsnd rule).
WSRESOLV_DIR := user/wine/dlls/wsresolv
WSRESOLV_SRCS := $(wildcard $(WSRESOLV_DIR)/*.c)
WSRESOLV_CFLAGS := -std=gnu11 -O2 -g0 -fno-builtin -fno-strict-aliasing -w \
               -D__WINESRC__ -DWINE_NO_LONG_TYPES -D__USE_MINGW_ANSI_STDIO=0 \
               -I$(WSRESOLV_DIR) -Ithird_party/wine/dlls/ws2_32 \
               -Ithird_party/wine/include
$(WSRESOLV): $(WSRESOLV_SRCS) $(WSRESOLV_DIR)/wsresolv.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) $(WSRESOLV_CFLAGS) -shared -nostdlib -nostartfiles \
	    -Wl,--entry=DllMainCRTStartup $(WSRESOLV_SRCS) \
	    tests/winetest/glue/crt_sections.c \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    $(WINE_PE)/ws2_32/x86_64-windows/libws2_32.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

wsresolv: $(WSRESOLV)
.PHONY: wsresolv

# The wsresolv unit corpus (tests/resolv/resolv_unit.c): dns.c driven
# through its transport seam with canned/adversarial replies, the literal
# parsers, and the registry-free packing paths — built against the REAL
# wsresolv sources and run under the pinned wine by run.sh's resolvunit
# leg (the winefb_unit precedent: a unit verdict on our code; the
# ws2_32:protocol pair stays the boundary judge).
RESOLV_UNIT := $(BUILD)/tests/resolv_unit.exe
$(RESOLV_UNIT): tests/resolv/resolv_unit.c $(WSRESOLV_SRCS) $(WSRESOLV_DIR)/wsresolv.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) $(WSRESOLV_CFLAGS) -nostdlib -nostartfiles \
	    -Wl,--entry=resolv_unit_start tests/resolv/resolv_unit.c $(WSRESOLV_SRCS) \
	    tests/winetest/glue/crt_sections.c \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    $(WINE_PE)/ws2_32/x86_64-windows/libws2_32.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

resolv-unit: $(RESOLV_UNIT)
.PHONY: resolv-unit

# The audio DLL set (AUD-2): mmdevapi (WASAPI itself) and what rides it —
# winmm above, msacm32 (winmm's format-conversion import) and oleaut32
# (mmdevapi's import) beside. Stripped like every baked dll. ole32/combase/
# coml2/user32/gdi32 are already in the CUI + GUI strip sets.
WINESTRIP_AUDIO_NAMES := mmdevapi winmm msacm32 oleaut32 dsound quartz msvfw32 mcicda
WINESTRIP_AUDIO_DLLS := $(foreach d,$(WINESTRIP_AUDIO_NAMES),$(WINESTRIP)/$(d).dll)
# oleaut32's strip rule is already eval'd with the applet set below; one
# rule per dll (make warns on a duplicate).
$(foreach d,$(filter-out oleaut32,$(WINESTRIP_AUDIO_NAMES)),$(eval $(call WINESTRIP_RULE,$(d))))

# The ACM codec modules winmm's PlaySound decodes through (all pure PE in
# the pinned tree; their drivers32 registry aliases ride wine.inf's kept
# AddReg payload — only the files were missing). Same strip treatment,
# their own suffix.
WINESTRIP_ACM_NAMES := imaadp32 msadp32 msg711 msgsm32 l3codeca
define WINESTRIP_ACM_RULE
$(WINESTRIP)/$(1).acm: $(WINE_PE)/$(1).acm/x86_64-windows/$(1).acm
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach d,$(WINESTRIP_ACM_NAMES),$(eval $(call WINESTRIP_ACM_RULE,$(d))))
WINESTRIP_ACM_FILES := $(foreach d,$(WINESTRIP_ACM_NAMES),$(WINESTRIP)/$(d).acm)

winestrip-audio: $(WINESTRIP_AUDIO_DLLS)
.PHONY: winestrip-audio


# Everything the audio stack adds on top of the CUI + GUI payloads: the audio
# DLL set, the driver and atl100 — the actual registrar behind every Wine
# DllRegisterServer (winecrt0's __wine_register_resources loads atl100.dll for
# AtlCreateRegistrar; absent, mmdevapi's registration answers a silent
# E_NOINTERFACE and its CLSID never lands in the hive). The registering inf is
# $(WINE_INF_FULL) in $(WINFILES), one copy for every consumer.
AUDIOFILES := $(foreach d,$(WINESTRIP_AUDIO_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
              $(foreach d,$(WINESTRIP_ACM_NAMES),win:$(WINESTRIP)/$(d).acm=windows/system32/$(d).acm) \
              win:$(WINEVSND)=windows/system32/winevsnd.drv \
              win:$(WINESTRIP)/atl100.dll=windows/system32/atl100.dll \
              win:$(WINESTRIP)/shlwapi.dll=windows/system32/shlwapi.dll \
              win:$(WINESTRIP)/shcore.dll=windows/system32/shcore.dll
AUDIO_PAYLOAD := $(WINESTRIP_AUDIO_DLLS) $(WINESTRIP_ACM_FILES) $(WINEVSND) $(WINESTRIP)/atl100.dll \
                 $(WINESTRIP)/shlwapi.dll $(WINESTRIP)/shcore.dll

audio-payload: $(AUDIO_PAYLOAD)
.PHONY: audio-payload


# The %windir% .ini furniture that goes with the ACM codecs above: winmm's
# PlaySound reaches a decoder for a non-PCM wav through system.ini's
# [drivers32] aliases, and the baked inf drops the UpdateInis directive
# wineboot would have written them with (tools/gen_sysini.py, which PARSES
# them out of the pinned wine.inf's [SystemIni] rather than transcribing
# them). run.sh's winetest audio image generates the same pair the same
# way; this is the handle for an image the Makefile bakes.
SYSINI_DIR := $(BUILD)/sysini
# One recipe writes both files, so the image rule depends on a stamp rather
# than on either file (a two-target rule would run gen_sysini twice, racing
# under -j). The list below then names the two by hand, so the recipe
# refuses loudly if a pin bump ever grows a third [SystemIni] file rather
# than baking an image quietly missing it.
SYSINI_STAMP := $(SYSINI_DIR)/.stamp
$(SYSINI_STAMP): third_party/wine/loader/wine.inf tools/gen_sysini.py
	@mkdir -p $(SYSINI_DIR)
	python3 tools/gen_sysini.py $(SYSINI_DIR) >/dev/null
	@for f in $(SYSINI_DIR)/*.ini; do \
	    case $$(basename $$f) in win.ini|system.ini) ;; \
	    *) echo "gen_sysini emitted $$f, which SYSINIFILES does not bake" >&2; \
	       exit 1 ;; esac; done
	@touch $@
SYSINIFILES := win:$(SYSINI_DIR)/win.ini=windows/win.ini \
               win:$(SYSINI_DIR)/system.ini=windows/system.ini

# The AUD-2 acceptance client (tests/run/run.sh audio, WASAPI half): the
# same freestanding shape as aud_smoke.exe, but importing ole32 — it plays
# the same pattern through CoCreateInstance -> IAudioClient ->
# IAudioRenderClient over the whole PE audio stack.
WASAPISMOKE := $(BUILD)/modules/wasapi_smoke.exe
$(WASAPISMOKE): tests/audio/wasapi_smoke.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=wasapi_start \
	    tests/audio/wasapi_smoke.c \
	    $(WINE_PE)/ole32/x86_64-windows/libole32.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# The same client, i386 (WOW64 audio): the identical source built by the
# i686 cross against the pinned tree's i386 import libraries, so the leg's
# verdict compares two BITNESSES of one client rather than two clients
# (Art. 11 — the wow64gui precedent). `_wasapi_start`, with the
# underscore: i386 PE decorates cdecl symbols.
WASAPISMOKE32 := $(BUILD)/modules/wasapi_smoke32.exe
$(WASAPISMOKE32): tests/audio/wasapi_smoke.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW32) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=_wasapi_start \
	    tests/audio/wasapi_smoke.c \
	    $(WINE_PE)/ole32/i386-windows/libole32.a \
	    $(WINE_PE)/ntdll/i386-windows/libntdll.a -lgcc -o $@

wasapi-smoke32: $(WASAPISMOKE32)
.PHONY: wasapi-smoke32

wasapi-smoke: $(WASAPISMOKE)
.PHONY: wasapi-smoke

# The AUD-3 WASAPI capture client: the same recipe as wasapi_smoke.exe,
# pointed at the capture endpoint, run on the `none`-audiodev boot.
WASAPICAPSMOKE := $(BUILD)/modules/wasapi_cap_smoke.exe
$(WASAPICAPSMOKE): tests/audio/wasapi_cap_smoke.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=wasapi_cap_start \
	    tests/audio/wasapi_cap_smoke.c \
	    $(WINE_PE)/ole32/x86_64-windows/libole32.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

wasapi-cap-smoke: $(WASAPICAPSMOKE)
.PHONY: wasapi-cap-smoke

# ---------------------------------------------------------------------------
# GUI-2 (docs/02, docs/07 route (a)): win32u as a PE, plus winefb.drv.
#
# Wine ships win32u in two halves — a PE win32u.dll that is nothing but
# syscall thunks, and win32u.so holding the actual implementation. Neither
# half fits: the thunks would issue NtUser*/NtGdi* syscalls at a kernel that
# must never grow them (Art. 2 / docs/07 "no NtUser* syscalls are minted"),
# and there is no unix side to load. So the SECOND half is compiled here as
# the DLL — the same sources, above ntdll instead of above libc — and
# user32/gdi32/imm32 bind to it by name, unmodified, because that is how
# they import win32u in the first place.
#
# The desktop state those sources talk to is the pinned wineserver's own GUI
# object model, compiled into the same DLL and reached through an in-process
# wine_server_call (user/wine/wineserver-lite/). One GUI process, no
# wineserver (GUI-3 is where it becomes a process again).
#
# Nothing in third_party/wine is patched for any of this: user/wine/ carries
# the shims (POSIX headers mingw lacks), the glue (pthreads, the user-mode
# callback pair, ntdll's unix-side helpers) and the display driver. Deleting
# user/wine/dlls/, user/wine/wineserver-lite/ and the two drivers restores the
# CUI kernel (Art. 7) — user/wine/programs/ is the CUI side's own glue and stays.
WINE_W32U := third_party/wine/dlls/win32u
WINE_SRV  := third_party/wine/server
W32U_BUILD := $(BUILD)/win32u

# Everything in win32u's SOURCES except the two files that ARE the syscall
# boundary: main.c (the PE thunks this build replaces) and syscall.c (the
# service-table registration and the pthread-key thread info, both re-done in
# user/wine/dlls/win32u/glue.c).
W32U_SRCS := $(filter-out $(WINE_W32U)/main.c $(WINE_W32U)/syscall.c, \
                 $(wildcard $(WINE_W32U)/*.c) $(wildcard $(WINE_W32U)/dibdrv/*.c))

# The wineserver GUI subset: object/handle plumbing plus the window tree,
# classes, atoms, queues, hooks, clipboard and region algebra. Compiled
# UNMODIFIED — this is the one authority for desktop state (Art. 11), and
# GUI-3 moves this same code behind IPC rather than rewriting it.
SRV_SRCS := $(addprefix $(WINE_SRV)/, object.c handle.c user.c atom.c class.c \
                winstation.c window.c queue.c region.c clipboard.c hook.c)

# Eleven names exist on both sides of the boundary with different meanings
# (win32u's alloc_user_handle asks the server; the server's allocates). In
# Wine they live in different address spaces; here they share one, so the
# server's copies are renamed at compile time. A build-time rename, not a
# source change: third_party/wine is untouched.
SRV_RENAMES := alloc_user_handle free_user_handle destroy_thread_windows \
               get_virtual_screen_rect get_window_thread is_desktop_class \
               is_message_class is_window_visible mirror_region \
               send_notify_message shared_session
SRV_RENAME_FLAGS := $(foreach n,$(SRV_RENAMES),-D$(n)=srv_$(n))

# FreeType comes from third_party/freetype, cross-built as a PE static
# library (tools/build_freetype.sh). PRSK_WITH_FREETYPE is what turns
# dlls/win32u/freetype.c's real body on, through the config.h shadow in
# user/wine/include -- which the PE build needs because it runs no configure
# of its own. Since GUI-3 the pinned Wine is configured --with-freetype
# against the SAME pinned FreeType (built native by the same script), so the
# oracle answers font questions from the code that runs here (docs/03 "the
# font oracle").
FREETYPE := third_party/freetype/x86_64-windows/libfreetype.a
$(FREETYPE):
	tools/build_freetype.sh

W32U_CFLAGS := -std=gnu11 -O2 -g0 -fno-builtin -fno-strict-aliasing -w \
               -D__WINESRC__ -D_WIN32U_ -DWINE_UNIX_LIB -DWINE_NO_LONG_TYPES \
               -D__USE_MINGW_ANSI_STDIO=0 -DPRSK_WITH_FREETYPE \
               -Iuser/wine/include -Ithird_party/freetype/include \
               -I$(W32U_BUILD) -Ithird_party/wine/include

# The DLL's glue. wineserver-lite/ is split so that each of its two links
# names the halves it takes: this link takes client/ (wine_server_call) plus
# srv_glue.c, which is only the WINE_UNIX_LIB shims win32u itself needs; the
# exe takes server/ and common/ (the state machine's environment).
#
# What the DLL does NOT take, since the in-process dispatch mode went away,
# is the state machine: no shim.c, no $(SRV_OBJS), no handler table. Nothing
# in the DLL could reach them -- every request goes out over the transport --
# so linking them shipped a dormant second copy of the desktop object model
# in every GUI process, which is the parallel authority Art. 11 is about. The
# one generated thing it still needs is the request NAMES, for a diagnostic;
# they come out of the generator's second output, which references no handler.
W32U_GLUE_SRCS := $(wildcard user/wine/dlls/win32u/*.c) \
                  $(wildcard user/wine/dlls/winefb.drv/*.c) \
                  $(WSRV_DIR)/common/srv_glue.c \
                  $(wildcard $(WSRV_DIR)/client/*.c)

# The glue objects both links share, named once (Art. 11: one spelling).
WSRV_GLUE := $(W32U_BUILD)/glue/wineserver-lite/common

W32U_OBJS := $(patsubst $(WINE_W32U)/%.c,$(W32U_BUILD)/w32u/%.o,$(W32U_SRCS)) \
             $(patsubst user/wine/%.c,$(W32U_BUILD)/glue/%.o,$(W32U_GLUE_SRCS))

$(W32U_BUILD)/w32u/%.o: $(WINE_W32U)/%.c user/wine/include/wine/unixlib.h
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) -I$(WINE_W32U) -c $< -o $@

$(W32U_BUILD)/srv/%.o: $(WINE_SRV)/%.c
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) $(SRV_RENAME_FLAGS) -I$(WINE_SRV) -I$(WSRV_DIR)/common -c $< -o $@

# The FreeType entry points freetype.c resolves by name, generated from its
# own MAKE_FUNCPTR list so a pin that starts calling a new one fails the
# build rather than the boot (Art. 4 / Art. 12).
FT_SYMS := $(W32U_BUILD)/prsk_freetype_syms.h
$(FT_SYMS): $(WINE_W32U)/freetype.c tools/gen_freetype_syms.py
	@mkdir -p $(dir $@)
	python3 tools/gen_freetype_syms.py $(WINE_W32U)/freetype.c $@

# proskrnl_bootflag.h: the one PE-side reader of a Hardware\qemu boot flag
# (Art. 11). It lives in the WINE tree because win32u asks too and that tree
# has to build standalone under the oracle's own configure/make; every rule
# here already carries -Ithird_party/wine/include.
#
# $(DEPFLAGS) rather than a hand-listed header, for the reason the kernel rules
# carry it (see DEPFLAGS above): these objects ARE the compositor unit suite's
# code under test, and without depfiles a change to winefb.h rebuilt the mocks
# and not compose.o/blit.o -- winefbunit then reported PASS for the previous
# build, in the one leg fast enough to be run constantly.
$(W32U_BUILD)/glue/%.o: user/wine/%.c $(FT_SYMS) third_party/wine/include/proskrnl_bootflag.h
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) $(DEPFLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) -I$(WSRV_DIR)/common \
	    -Iuser/wine/dlls/winefb.drv -c $< -o $@
-include $(patsubst user/wine/%.c,$(W32U_BUILD)/glue/%.d,$(W32U_GLUE_SRCS))

# The compositor unit suite (tests/run/run.sh winefbunit): the SAME
# compose.o/blit.o the win32u.dll link uses, a mocked seam for everything
# they reach (tests/winefb/winefb_mocks.c -- server queries, surfaces,
# scanout, invalidation recorder), gdi32 as the region engine, the ntapi
# harness for the verdict. Runs under the pinned wine in about a second;
# every compositor POLICY bug is pinned here rather than in a QEMU leg.
WINEFB_UNIT := $(BUILD)/tests/winefb_unit.exe
WINEFB_UNIT_DRV := $(W32U_BUILD)/glue/dlls/winefb.drv/compose.o \
                   $(W32U_BUILD)/glue/dlls/winefb.drv/blit.o \
                   $(W32U_BUILD)/glue/dlls/winefb.drv/cursor.o
$(W32U_BUILD)/winefb_mocks.o: tests/winefb/winefb_mocks.c tests/winefb/winefb_unit.h \
        user/wine/dlls/winefb.drv/winefb.h $(FT_SYMS)
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) -I$(WSRV_DIR)/common \
	    -Iuser/wine/dlls/winefb.drv -Itests/winefb -c $< -o $@
$(WINEFB_UNIT): tests/winefb/winefb_unit.c tests/winefb/winefb_unit.h tests/ntapi/ntapi.c \
        tests/ntapi/ntapi.h $(W32U_BUILD)/winefb_mocks.o $(WINEFB_UNIT_DRV) $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Itests/winefb -Wl,--entry=ntapi_start \
	    tests/winefb/winefb_unit.c tests/ntapi/ntapi.c \
	    $(W32U_BUILD)/winefb_mocks.o $(WINEFB_UNIT_DRV) $(GUI3_LIBS) -lgcc -o $@

winefb-unit: $(WINEFB_UNIT)
.PHONY: winefb-unit

# The dispatch table is generated from the pinned tree's own request list and
# from which handlers actually linked: a request whose handler is not part of
# this build gets a NULL slot, which the shim turns into a named refusal
# (tools/gen_server_table.py, Art. 12).
SRV_OBJS := $(patsubst $(WINE_SRV)/%.c,$(W32U_BUILD)/srv/%.o,$(SRV_SRCS))
SRV_TABLE := $(W32U_BUILD)/prsk_request_table.c
# The generator writes the handler table AND, separately, the request names.
# One run, one order, two objects: the server takes both, and win32u takes
# only the names -- it needs them to name an oversized request, and taking
# them from the handler table would drag the whole state machine back into
# the DLL (see W32U_GLUE_SRCS).
SRV_NAMES := $(W32U_BUILD)/prsk_request_names.c
# shim.o joins the generator's inputs (GUI-5): the shim may implement a
# handler whose OWNING server file is not compiled (get_process_idle_event
# lives in server/process.c, which is the process model this build leaves
# out) — the table must see those too, or a linked handler would still get
# a NULL slot.
$(SRV_TABLE) $(SRV_NAMES) &: $(SRV_OBJS) $(WSRV_GLUE)/shim.o tools/gen_server_table.py \
        $(WINE_SRV)/request_handlers.h
	@mkdir -p $(dir $@)
	python3 tools/gen_server_table.py $(WINE_SRV)/request_handlers.h $(SRV_TABLE) \
	    $(SRV_NAMES) $(SRV_OBJS) $(WSRV_GLUE)/shim.o

$(W32U_BUILD)/prsk_request_table.o: $(SRV_TABLE) $(WSRV_DIR)/common/prsk_request_table.h
	$(MINGW) $(W32U_CFLAGS) -I$(WSRV_DIR)/common -c $< -o $@

$(W32U_BUILD)/prsk_request_names.o: $(SRV_NAMES) $(WSRV_DIR)/common/prsk_request_table.h
	$(MINGW) $(W32U_CFLAGS) -I$(WSRV_DIR)/common -c $< -o $@

# The export list comes out of win32u.spec, and the generator also proves the
# shipped importers find every name they need (tools/gen_win32u_def.py).
W32U_DEF := $(W32U_BUILD)/win32u.def
GUI_IMPORTERS := $(WINE_PE)/user32/x86_64-windows/user32.dll \
                 $(WINE_PE)/gdi32/x86_64-windows/gdi32.dll \
                 $(WINE_PE)/imm32/x86_64-windows/imm32.dll
$(W32U_DEF): $(WINE_W32U)/win32u.spec tools/gen_win32u_def.py $(GUI_IMPORTERS)
	@mkdir -p $(dir $@)
	python3 tools/gen_win32u_def.py $(WINE_W32U)/win32u.spec $@ $(GUI_IMPORTERS)

WIN32U := $(BUILD)/modules/win32u.dll
$(WIN32U): $(W32U_OBJS) $(W32U_BUILD)/prsk_request_names.o $(W32U_DEF) $(FREETYPE) \
           $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -shared -nostdlib -nostartfiles -Wl,--entry=prsk_win32u_entry \
	    $(W32U_OBJS) $(W32U_BUILD)/prsk_request_names.o $(W32U_DEF) \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(FREETYPE) \
	    third_party/wine/libs/musl/x86_64-windows/libmusl.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@
	@# No wine_server_* may come from ntdll (Art. 12). The pinned ntdll EXPORTS
	@# the whole family, so any one of them that this build does not define
	@# itself links CLEANLY against the import and starts answering -- turning a
	@# refusal that names itself on serial into a plausible answer, silently, at
	@# link time. That is how wine_server_handle_to_fd stopped refusing when the
	@# state machine left this DLL: nothing failed, winetest-gui just died with no
	@# verdict. The definitions live in wineserver-lite/common/srv_glue.c; this
	@# asserts none of them slipped back to the import.
	@# Scoped to the IMPORT directory: this DLL legitimately EXPORTS
	@# wine_server_call and wine_server_send_fd (win32u.spec), so the export
	@# table must not be read as a violation.
	@imports=$$($(MINGW_OBJDUMP) -p $@ \
	    | awk '/The Import Tables/,/Export Address Table|The Export Tables/' \
	    | grep -oE 'wine_server_[a-z_]+' | sort -u); \
	if [ -n "$$imports" ]; then \
	    echo "win32u.dll imports wine_server_* from ntdll:" >&2; \
	    echo "$$imports" >&2; \
	    echo "define it in user/wine/wineserver-lite/common/srv_glue.c (Art. 12)" >&2; \
	    rm -f $@; exit 1; \
	fi

win32u: $(WIN32U)
.PHONY: win32u

# wineserver-lite.exe (GUI-3, HACK-003): the same GUI object model, linked
# into a process of its own instead of into every GUI client.
#
# This is docs/06's keep-list build: a link over the pinned tree's own
# server objects -- not a stripped copy of server/, which would mutate the
# oracle's wineserver and corrupt the spec.
#
# It is the ONLY link that carries them. The exe takes
# wineserver-lite/common/ (the environment the state machine expects) plus
# wineserver-lite/server/ (its own main.c), and leaves out
# wineserver-lite/client/ -- so the server carries no client of itself; the
# DLL takes client/ and the one shared glue file, and no state machine at
# all. One copy, in one process, so there is nothing to drift (Art. 11).
# SRV_RENAME_FLAGS is still applied because these are the same renamed
# objects the pinned tree's headers expect.
WSRV_BUILD := $(W32U_BUILD)/wineserver-lite
WSRV_SRCS  := $(wildcard $(WSRV_DIR)/server/*.c)
WSRV_OBJS  := $(patsubst $(WSRV_DIR)/server/%.c,$(WSRV_BUILD)/%.o,$(WSRV_SRCS)) \
              $(WSRV_GLUE)/shim.o $(WSRV_GLUE)/srv_glue.o \
              $(W32U_BUILD)/prsk_request_names.o

$(WSRV_BUILD)/%.o: $(WSRV_DIR)/server/%.c
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) $(SRV_RENAME_FLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) \
	    -I$(WSRV_DIR)/common -Iuser/wine/dlls/winefb.drv -c $< -o $@

WINESERVER_LITE := $(BUILD)/modules/wineserver-lite.exe
$(WINESERVER_LITE): $(WSRV_OBJS) $(SRV_OBJS) $(W32U_BUILD)/prsk_request_table.o $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -nostdlib -nostartfiles -Wl,--entry=prsk_server_start \
	    $(WSRV_OBJS) $(SRV_OBJS) $(W32U_BUILD)/prsk_request_table.o \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    third_party/wine/libs/musl/x86_64-windows/libmusl.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

wineserver-lite: $(WINESERVER_LITE)
.PHONY: wineserver-lite

# The Wine GUI DLLs, baked debug-stripped like the rest (no COW: every
# mapped image is copied whole per process, so DWARF is a real memory
# bill -- see WINESTRIP above). user32 pulls in win32u, which this build
# replaces; gdi32 and comctl32 come with winemine, and imm32 is loaded by
# user32's own init. The ole32 chain (ole32 -> combase/coml2; rpcrt4 is
# already in the CUI set, everything else delay-imported) is there for
# imm32's IME apartment spy: CoRegisterInitializeSpy is a DELAYIMPORT whose
# failure hook aborts the process (EXCEPTION_WINE_STUB), and every real
# Windows has ole32.
WINESTRIP_GUI_NAMES := user32 gdi32 comctl32 imm32 ole32 combase coml2
WINESTRIP_GUI_DLLS := $(foreach d,$(WINESTRIP_GUI_NAMES),$(WINESTRIP)/$(d).dll)
$(foreach d,$(WINESTRIP_GUI_NAMES),$(eval $(call WINESTRIP_RULE,$(d))))

# The named handle on that set, for legs that assemble their own image spec
# instead of depending on an IMG_* rule (tests/run/run.sh winetest-gui): without
# it a clean tree stages the CUI set only and mkimage dies on the first
# missing win: file.
winestrip-gui: $(WINESTRIP_GUI_DLLS)
.PHONY: winestrip-gui

WINEMINE := $(WINESTRIP)/winemine.exe
$(WINEMINE): third_party/wine/programs/winemine/x86_64-windows/winemine.exe
	@mkdir -p $(dir $@)
	$(OBJCOPY) --strip-debug $< $@

# The pinned tree's own font files, which its build generates from the .sfd
# sources. win32u's font backend enumerates C:\windows\fonts, and with no
# fontconfig to ask (user/wine/include/config.h) that directory IS the font
# set -- so an empty one means no text at all.
#
# Both extensions, because the ORACLE loads both (GUI-3). Running from its
# build tree, the oracle's win32u calls load_file_system_fonts(), which reads
# C:\windows\fonts AND the build dir's own fonts/ -- and that directory holds
# the generated .fon bitmap fonts (System, Fixedsys, Courier and their
# codepage variants) as well as the .ttf ones. Shipping only the .ttf half
# would leave the two sides enumerating different font sets, which is the one
# thing the font-metrics oracle exists to prevent; the bitmap faces are also
# exactly the ones dialog layout (GUI-5) leans on. The .fon files exist only
# once the pinned tree has been built with fonts enabled -- the same soft
# dependency the .ttf wildcard already has.
WINE_FONTS := $(wildcard third_party/wine/fonts/*.ttf) $(wildcard third_party/wine/fonts/*.fon)
FONTFILES := $(foreach f,$(WINE_FONTS),win:$(f)=windows/fonts/$(notdir $(f)))

# The desktop stack, as ONE list. It used to be re-spelled verbatim at the
# head of GUI2FILES, GUI3FILES, GUI4FILES, GUI5FILES, GUI5CONFILES, GUI6FILES
# and NET3FILES — seven copies of the same four lines, which is what a
# per-leg image costs even before the leg does anything (Art. 11).
GUISTACKFILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe
GUISTACK_PAYLOAD := $(WIN32U) $(WINESTRIP_GUI_DLLS) $(WINESERVER_LITE) $(WINE_FONTS)

# ---------------------------------------------------------------------------
# GUI-3 (docs/02): wineserver-lite as a process, with TWO GUI clients.
#
# The clients are purpose-built rather than stock Wine applets: the verdict
# is what they REPORT (FindWindow found it, the SendMessage answer came back
# derived, the z-order flipped, the foreground moved), and an applet cannot
# report. They link the pinned user32/gdi32 import libs and the ntapi
# harness, so they are ordinary Wine GUI apps over the same unmodified stack
# GUI-2 runs -- nothing about them is privileged.
GUI3_LIBS := $(WINE_PE)/user32/x86_64-windows/libuser32.a \
             $(WINE_PE)/gdi32/x86_64-windows/libgdi32.a \
             $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
             $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
             $(WINE_PE)/ntdll/x86_64-windows/libntdll.a

GUI3A := $(BUILD)/modules/gui3a.exe
GUI3B := $(BUILD)/modules/gui3b.exe

$(BUILD)/modules/gui3%.exe: tests/gui/gui3%.c tests/ntapi/ntapi.c tests/ntapi/ntapi.h \
        $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Wl,--entry=ntapi_start \
	    tests/gui/gui3$*.c tests/ntapi/ntapi.c $(GUI3_LIBS) -lgcc -o $@


# GUI-4 (docs/02 "windows can be grabbed and moved; clicks reach the right
# window"): the gui3 payload shape with two purpose-built clients whose
# windows OVERLAP -- the compositor's pictorial proof -- driven by the
# harness through the tablet and keyboard (tests/run/run.sh gui4). Same
# link rule and libs as the gui3 clients: ordinary Wine GUI apps.
GUI4A := $(BUILD)/modules/gui4a.exe
GUI4B := $(BUILD)/modules/gui4b.exe

$(BUILD)/modules/gui4%.exe: tests/gui/gui4%.c tests/ntapi/ntapi.c tests/ntapi/ntapi.h \
        $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Wl,--entry=ntapi_start \
	    tests/gui/gui4$*.c tests/ntapi/ntapi.c $(GUI3_LIBS) -lgcc -o $@


# GUI-5 (docs/02 "GUI finishing"): clipboard, hooks and AttachThreadInput
# exercised cross-process over the unmodified pinned server, plus the guest
# half of the font-metrics differential. Same link rule and libs as the
# gui3/gui4 clients; fontdiff.exe is the SAME source the oracle leg runs
# (tests/gdi/fontdiff.c), baked here so tests/gui/check_gui5.py can diff the
# guest's metric table against the same committed golden.
GUI5A := $(BUILD)/modules/gui5a.exe
GUI5B := $(BUILD)/modules/gui5b.exe
FONTDIFF := $(BUILD)/modules/fontdiff.exe

$(BUILD)/modules/gui5%.exe: tests/gui/gui5%.c tests/ntapi/ntapi.c tests/ntapi/ntapi.h \
        $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Wl,--entry=ntapi_start \
	    tests/gui/gui5$*.c tests/ntapi/ntapi.c $(GUI3_LIBS) -lgcc -o $@

$(FONTDIFF): tests/gdi/fontdiff.c tests/ntapi/ntapi.c tests/ntapi/ntapi.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Wl,--entry=ntapi_start \
	    tests/gdi/fontdiff.c tests/ntapi/ntapi.c $(GUI3_LIBS) -lgcc -o $@


# For fun (make rungui): the pinned tree's stock applets, launchable from
# the prompt by name (every process is minted PATH=C:\windows\system32 --
# kernel/ps/peb.c), plus the DLL import closure they need beyond the GUI2
# set: comdlg32 -> shell32 -> shlwapi -> shcore; mpr (winefile); riched20
# -> oleaut32 (wordpad's runtime-loaded edit control); uxtheme (the SxS
# comctl32's delay import — absent, its failure hook aborts the process).
# Baked debug-stripped like everything else. Unmodified pure-PE binaries,
# the whoami precedent; an applet that reaches an unbuilt syscall panics
# loudly (Art. 12), which is the point of running them.
WINESTRIP_APPLET_NAMES := comdlg32 shell32 shlwapi shcore mpr oleaut32 riched20 uxtheme
WINESTRIP_APPLET_DLLS := $(foreach d,$(WINESTRIP_APPLET_NAMES),$(WINESTRIP)/$(d).dll)
$(foreach d,$(WINESTRIP_APPLET_NAMES),$(eval $(call WINESTRIP_RULE,$(d))))

WINESTRIP_APPLET_EXE_NAMES := notepad clock winver taskmgr winefile regedit \
                              wordpad winhlp32 progman start
WINESTRIP_APPLET_EXES := $(foreach p,$(WINESTRIP_APPLET_EXE_NAMES),$(WINESTRIP)/$(p).exe)
$(foreach p,$(WINESTRIP_APPLET_EXE_NAMES),$(eval $(call WINESTRIP_EXE_RULE,$(p))))

# The Microsoft.Windows.Common-Controls SxS assembly, laid out exactly as
# wineboot's fakedll installer builds it in a prefix (dir + manifests entry
# name per third_party/wine/dlls/setupapi/fakedll.c create_winsxs_dll_path /
# create_manifest, arch filled in): the applets' comctl32-v6 manifests
# resolve against it, and without it comdlg32's DllMain fails its
# CreateActCtx (14001) and takes the whole applet down. The dll is
# comctl32_v6 renamed comctl32.dll, stripped like everything baked.
# Firstboot cannot create this itself: the fakedll sources live in the
# build tree, not on the image.
SXS_CC_DIR := windows/winsxs/amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef
$(eval $(call WINESTRIP_RULE,comctl32_v6))
$(WINESTRIP)/common-controls.manifest: third_party/wine/dlls/comctl32_v6/comctl32.manifest
	@mkdir -p $(dir $@)
	sed 's/processorArchitecture=""/processorArchitecture="amd64"/' $< > $@

# The Microsoft.VC90.CRT SxS assembly, the same shape one assembly over: the
# manifest is msvcr90's own (third_party/wine/dlls/msvcr90/msvcr90.manifest,
# which fakedll.c extracts from the fake dll's RT_MANIFEST and writes out with
# the arch filled in), and the three files it NAMES ride in the assembly
# directory beside it. Wine's own prefix gets these from the fakedll pass over
# msvcr90/msvcp90/msvcm90; ours cannot, for the reason the block above gives.
#
# The consumer is kernel32:actctx's test_builtin_sxs (actctx.c:3955), which
# builds a manifest depending on microsoft.vc90.crt and then LoadLibrary's
# msvcp90/msvcr90 through it, asserting both resolve UNDER C:\Windows\WinSxS.
# Absent, CreateActCtxA answers ERROR_SXS_CANT_GEN_ACTCTX (14001) -- the same
# number the applets' comctl32 case above produces, and for the same reason.
# They are deliberately NOT in system32: the assertion is about the redirected
# path, so a system32 copy would satisfy the load and fail the check.
SXS_VC90_DIR := windows/winsxs/amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.6161_none_deadbeef
SXS_VC90_NAMES := msvcr90 msvcp90 msvcm90
$(foreach d,$(SXS_VC90_NAMES),$(eval $(call WINESTRIP_RULE,$(d))))
$(WINESTRIP)/vc90-crt.manifest: third_party/wine/dlls/msvcr90/msvcr90.manifest
	@mkdir -p $(dir $@)
	sed 's/processorArchitecture=""/processorArchitecture="amd64"/' $< > $@

SXSFILES := $(foreach d,$(SXS_VC90_NAMES),win:$(WINESTRIP)/$(d).dll=$(SXS_VC90_DIR)/$(d).dll) \
            win:$(WINESTRIP)/vc90-crt.manifest=windows/winsxs/manifests/$(notdir $(SXS_VC90_DIR)).manifest
SXS_PAYLOAD := $(foreach d,$(SXS_VC90_NAMES),$(WINESTRIP)/$(d).dll) \
               $(WINESTRIP)/vc90-crt.manifest

# winemine rides along in system32 (NOT the image root -- C:\winemine.exe
# is the GUI-2 boot trigger, kernel/init/main.c KiRunGui2).
APPLETFILES := $(foreach d,$(WINESTRIP_APPLET_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
               $(foreach p,$(WINESTRIP_APPLET_EXE_NAMES),win:$(WINESTRIP)/$(p).exe=windows/system32/$(p).exe) \
               win:$(WINEMINE)=windows/system32/winemine.exe \
               win:$(WINESTRIP)/comctl32_v6.dll=$(SXS_CC_DIR)/comctl32.dll \
               win:$(WINESTRIP)/common-controls.manifest=windows/winsxs/manifests/$(notdir $(SXS_CC_DIR)).manifest

# The 32-bit half of the same applet shelf, so `make rungui` can run a WOW64
# GUI app (docs/02 WOW64 shipped the CUI half only). Nothing new is BUILT for
# it: the i386 user32/gdi32 import the pinned tree's STOCK win32u.dll, which
# on the guest side is nothing but syscall thunks — wow64cpu takes those
# syscalls into 64-bit code, wow64.dll routes service table 1 to
# wow64win.dll, and wow64win calls this build's own 64-bit win32u.dll, whose
# NtUser*/NtGdi* exports it imports BY NAME (every one of the 483 it asks for
# is exported — checked at link time by tools/gen_win32u_def.py's importer
# proof, extended here to wow64win). So the 32-bit path reaches the one
# desktop authority through the same door user32 does, and no second copy of
# any of it exists (Art. 11).
#
# The name list is the i386 mirror of the WHOLE 64-bit shelf — the CUI set,
# the GUI set and the applet closure — minus what WINESTRIP32_NAMES already
# stages, plus the stock guest win32u. A mirror rather than a computed
# closure because the 64-bit list already encodes what an import scan cannot
# see: cryptbase is reached by a FORWARD from advapi32 (advapi32's
# SystemFunction036 forwards there and appears in no import table), uxtheme
# by a delay import, imm32 by user32's own init, riched20/oleaut32 by
# LoadLibrary. The first cut of this list was the computed closure and the
# guest died on exactly the forward: "module not found for forward
# 'cryptbase.SystemFunction036'". What an applet never loads costs disk and
# nothing else; what it does load costs a master of its own, since a 32-bit
# image shares nothing with the 64-bit file of the same name (CUI-9 keys an
# image master on the file, and these are different files).
WOW64_GUI_NAMES := $(filter-out $(WINESTRIP32_NAMES), \
                       $(WINESTRIP_NAMES) $(WINESTRIP_GUI_NAMES) $(WINESTRIP_APPLET_NAMES)) win32u
WOW64_GUI_DLLS := $(foreach d,$(WOW64_GUI_NAMES),$(WINESTRIP32)/$(d).dll)
$(foreach d,$(WOW64_GUI_NAMES),$(eval $(call WINESTRIP32_RULE,$(d))))

# The applets themselves, the 64-bit shelf's list plus winemine. A 32-bit
# process reaches these by NAME through the file redirector wow64.dll applies
# to every guest syscall (dlls/wow64/file.c get_file_redirect): a guest
# opening C:\windows\system32\notepad.exe gets syswow64\notepad.exe, so the
# minted PATH=C:\windows\system32 resolves to whichever bitness asked.
WOW64_APPLET_EXE_NAMES := $(WINESTRIP_APPLET_EXE_NAMES) winemine
WOW64_APPLET_EXES := $(foreach p,$(WOW64_APPLET_EXE_NAMES),$(WINESTRIP32)/$(p).exe)
$(foreach p,$(WOW64_APPLET_EXE_NAMES),$(eval $(call WINESTRIP32_EXE_RULE,$(p))))

# The x86 arm of the Common-Controls SxS assembly. The 64-bit one above is
# not shared: actctx resolves a dependent assembly against the CURRENT
# process's architecture (third_party/wine dlls/ntdll/actctx.c current_archW
# = L"x86" for i386), so a 32-bit applet looks up an x86_-prefixed directory
# and manifest and dies in comdlg32's CreateActCtx without them.
SXS_CC_DIR32 := windows/winsxs/x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef
$(eval $(call WINESTRIP32_RULE,comctl32_v6))
$(WINESTRIP32)/common-controls.manifest: third_party/wine/dlls/comctl32_v6/comctl32.manifest
	@mkdir -p $(dir $@)
	sed 's/processorArchitecture=""/processorArchitecture="x86"/' $< > $@

# The WOW64 GUI acceptance client (tests/run/run.sh wow64gui): the gui4a
# shape built by the i686 toolchain against the pinned tree's i386 import
# libraries. `_ntapi_start`, with the underscore: i386 PE decorates cdecl
# symbols and the 64-bit spelling links to nothing.
WOW64GUI := $(BUILD)/modules/wow64gui.exe
WOW64GUI_LIBS := $(WINE_PE)/user32/i386-windows/libuser32.a \
                 $(WINE_PE)/gdi32/i386-windows/libgdi32.a \
                 $(WINE_PE)/kernel32/i386-windows/libkernel32.a \
                 $(WINE_PE)/kernelbase/i386-windows/libkernelbase.a \
                 $(WINE_PE)/ntdll/i386-windows/libntdll.a
$(WOW64GUI): tests/gui/wow64gui.c tests/ntapi/ntapi.c tests/ntapi/ntapi.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW32) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles -O1 -g0 \
	    -Wall -Itests/ntapi -Wl,--entry=_ntapi_start \
	    tests/gui/wow64gui.c tests/ntapi/ntapi.c $(WOW64GUI_LIBS) -lgcc -o $@

# $(WOW64GUI) is NOT here and not in the file list below: it is the acceptance
# CLIENT, not part of the 32-bit shelf, and this list rides $(FULLFILES) onto
# the dev image too. It was baked twice -- once here, once in $(TESTFILES) --
# which put a test binary on the product image and made two specs for one file.
WOW64_GUI_PAYLOAD := $(WOW64_GUI_DLLS) $(WOW64_APPLET_EXES) \
                     $(WINESTRIP32)/comctl32_v6.dll $(WINESTRIP32)/common-controls.manifest
WOW64GUIFILES := $(foreach d,$(WOW64_GUI_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll) \
                 $(foreach p,$(WOW64_APPLET_EXE_NAMES),win:$(WINESTRIP32)/$(p).exe=windows/syswow64/$(p).exe) \
                 win:$(WINESTRIP32)/comctl32_v6.dll=$(SXS_CC_DIR32)/comctl32.dll \
                 win:$(WINESTRIP32)/common-controls.manifest=windows/winsxs/manifests/$(notdir $(SXS_CC_DIR32)).manifest

# ---------------------------------------------------------------------------
# The shell payload: explorer.exe at the exact path win32u's auto-launch
# hardcodes (dlls/win32u/winstation.c get_desktop_window), plus atl100 -- the
# actual registrar behind every Wine DllRegisterServer (winecrt0's
# __wine_register_resources loads atl100.dll for AtlCreateRegistrar; absent,
# shell32's registration answers a silent E_NOINTERFACE and
# CLSID_ExplorerBrowser never lands in the hive).
#
# Whether explorer OWNS the desktop is a BOOT flag now (`opt/org.proskrnl/
# shell`, HACK-006; user/wine/wineserver-lite/common/shim.c probe_shell), not
# whether this payload is on the volume: one image carries it either way.
# shell32's COM classes are load-bearing on a shell boot -- explorer's file
# window is shell32's IExplorerBrowser, which exists only if
# DllRegisterServer ran at firstboot, which the ONE baked wine.inf
# ($(WINE_INF_FULL)) arranges for every image.
EXPLORER_EXE := $(WINESTRIP)/explorer.exe
$(eval $(call WINESTRIP_EXE_RULE,explorer))
$(eval $(call WINESTRIP_RULE,atl100))

# TWO copies of explorer.exe, because wine.inf installs two: `10,,explorer.exe`
# (dirid 10 = the Windows directory) beside `11,,explorer.exe` (dirid 11 =
# system32), third_party/wine/loader/wine.inf.in [DefaultInstall.Services] copy
# sections. system32 is the one win32u's auto-launch hardcodes; C:\windows is
# the one a PROGRAM names, and kernel32:actctx names it three times
# (actctx.c:3151, LoadLibraryExA("C:\\windows\\explorer.exe") as a data file).
# The oracle's prefix has both, so an image with only one reads as a kernel
# divergence -- docs/21 §4 trap 6.
SHELLFILES := win:$(EXPLORER_EXE)=windows/system32/explorer.exe \
              win:$(EXPLORER_EXE)=windows/explorer.exe \
              win:$(WINESTRIP)/atl100.dll=windows/system32/atl100.dll
SHELL_PAYLOAD := $(EXPLORER_EXE) $(WINESTRIP)/atl100.dll

# WINDOWED conhost overriding $(WINFILES)'s headless one (same destination,
# listed later; mkimage's mcopy -o makes the later spec win). looper.exe is
# the ^C acceptance's interruptible program (the CUI-4 actor, now
# interrupted through the window's own keyboard path instead of the serial
# hack).
#
# LOCAL (uncommitted): the standalone Flash projector + a movie ride along in
# the image ROOT, so `make rungui` can launch C:\SAFlashPlayer.exe. The
# sources are untracked files in the repo root; each is dropped from the
# image when absent, so the target still builds on a clean tree.
#
# The projector is a PE32 (COFF machine 0x14c), so it runs ONLY through the
# WOW64 shelf above — which the dev image it rides on carries. Its import table names 13 DLLs; the 32-bit
# mirror ($(WOW64_GUI_NAMES)) already stages nine, and the four it adds
# (crypt32, wininet, winmm, wsock32) pull the closure below. Staged under
# the same $(FLASHPRESENT) guard as the sources, so a tree without them
# builds the tracked image unchanged.
FLASHSRC := SAFlashPlayer.exe troubled_windows.swf
FLASHPRESENT := $(wildcard $(FLASHSRC))
FLASH_DLL_NAMES := crypt32 wininet winmm wsock32 \
                   bcrypt ncrypt msacm32 iphlpapi dnsapi nsi
FLASHFILES := $(foreach f,$(FLASHPRESENT),win:$(f)=$(f))
# Stripped by the mingw cross's own objcopy, not $(OBJCOPY): llvm-objcopy
# (checked at 22.1.8) refuses the pinned tree's bcrypt.dll — "invalid
# SymbolTableIndex" — on BOTH arches, alone among all 620 i386 dlls. GNU
# objcopy strips the same file to a sound image (62 exports, reloc directory
# unchanged), so the divergence is llvm's. Confined to this local block; the
# tracked $(WINESTRIP32_RULE) keeps $(OBJCOPY), and if bcrypt ever joins the
# tracked shelf this is the thing that will bite it.
FLASH_OBJCOPY := $(MINGW32:%-gcc=%-objcopy)
define FLASH_STRIP32_RULE
$(WINESTRIP32)/$(1).dll: $(WINE_PE)/$(1)/i386-windows/$(1).dll
	@mkdir -p $$(dir $$@)
	$$(FLASH_OBJCOPY) --strip-debug $$< $$@
endef
ifneq ($(FLASHPRESENT),)
FLASH_DLLS := $(foreach d,$(FLASH_DLL_NAMES),$(WINESTRIP32)/$(d).dll)
$(foreach d,$(FLASH_DLL_NAMES),$(eval $(call FLASH_STRIP32_RULE,$(d))))
FLASHFILES += $(foreach d,$(FLASH_DLL_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll)
# The tests/flash liveness fixtures (tools/gen_swf.py — one color per second
# of movie time, at a frame rate straddling the projector scheduler's 50 ms
# timeSetEvent threshold) plus the RelayInclude seed for winmm relay tracing.
# Ride the same guard: only useful with the projector present.
FLASH_FIXTURES := $(BUILD)/flash/fixture30.swf $(BUILD)/flash/fixture10.swf
$(BUILD)/flash/fixture%.swf: tools/gen_swf.py
	@mkdir -p $(dir $@)
	python3 tools/gen_swf.py $@ $*
FLASH_REG := tests/flash/relay.reg
FLASHFILES += $(foreach f,$(FLASH_FIXTURES),win:$(f)=$(notdir $(f))) \
              win:$(FLASH_REG)=relay.reg
endif

# ---------------------------------------------------------------------------
# The 32-bit half of the audio shelf (WOW64 audio): a guest .exe reaches
# mmdevapi by NAME through wow64.dll's file redirector, so C:\windows\
# system32\mmdevapi.dll resolves to the syswow64 copy — and the whole stack
# below it must be there in i386 form too, or CoCreateInstance of the
# MMDeviceEnumerator dies in the loader. The hive half needs nothing: the
# 64-bit firstboot registration writes the CLSIDs once, and a 32-bit client
# reads the same keys.
#
# The names are the 64-bit set minus whatever already has an i386 strip rule
# (the base guest set, the GUI/applet set, and — only when the projector is
# present — the flash set, which strips with the mingw objcopy for the
# bcrypt reason above). Defining a second recipe for the same file is what
# make warns about, and the two objcopies disagree about exactly one dll.
WOW64_AUDIO_NAMES := $(filter-out $(WINESTRIP32_NAMES) $(WOW64_GUI_NAMES) \
                         $(if $(FLASHPRESENT),$(FLASH_DLL_NAMES)),$(WINESTRIP_AUDIO_NAMES))
$(foreach d,$(WOW64_AUDIO_NAMES),$(eval $(call WINESTRIP32_RULE,$(d))))
define WINESTRIP32_ACM_RULE
$(WINESTRIP32)/$(1).acm: $(WINE_PE)/$(1).acm/i386-windows/$(1).acm
	@mkdir -p $$(dir $$@)
	$$(OBJCOPY) --strip-debug $$< $$@
endef
$(foreach d,$(WINESTRIP_ACM_NAMES),$(eval $(call WINESTRIP32_ACM_RULE,$(d))))
WINESTRIP32_ACM_FILES := $(foreach d,$(WINESTRIP_ACM_NAMES),$(WINESTRIP32)/$(d).acm)

# winevsnd.drv, i386: the SAME sources as the 64-bit driver (Art. 11 — one
# driver, two bitnesses), because mmdevapi LdrLoadDll's its driver into its
# OWN process and a 32-bit mmdevapi can only load a PE32. Nothing in the
# \Device\Snd* wire contract is pointer-shaped (drivers/sndproto.h: fixed
# uint32/uint64 payloads with static_asserts on every size), so the kernel
# sees one protocol from either bitness. Entry symbol decorated —
# _DllMainCRTStartup@12 — because i386 PE decorates stdcall and the
# undecorated 64-bit spelling links to nothing (the wow64gui rule's lesson).
WINEVSND32 := $(BUILD)/modules/winevsnd32.drv
$(WINEVSND32): $(VSND_SRCS) $(VSND_DIR)/winevsnd.h drivers/sndproto.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW32) $(VSND_CFLAGS) -shared -nostdlib -nostartfiles \
	    -Wl,--entry=_DllMainCRTStartup@12 $(VSND_SRCS) \
	    tests/winetest/glue/crt_sections.c \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/i386-windows/libntdll.a \
	    third_party/wine/libs/winecrt0/i386-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

winevsnd32: $(WINEVSND32)
.PHONY: winevsnd32

# Staged under syswow64 with the 64-bit names: the redirector matches on
# path, not on file name, so every one of these keeps the name its 64-bit
# twin has in system32 (winevsnd32.drv is a BUILD name only).
WOW64AUDIOFILES := $(foreach d,$(WINESTRIP_AUDIO_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll) \
                   $(foreach d,$(WINESTRIP_ACM_NAMES),win:$(WINESTRIP32)/$(d).acm=windows/syswow64/$(d).acm) \
                   win:$(WINEVSND32)=windows/syswow64/winevsnd.drv
WOW64_AUDIO_PAYLOAD := $(foreach d,$(WINESTRIP_AUDIO_NAMES),$(WINESTRIP32)/$(d).dll) \
                       $(WINESTRIP32_ACM_FILES) $(WINEVSND32)

wow64-audio-payload: $(WOW64_AUDIO_PAYLOAD)
.PHONY: wow64-audio-payload



# --- the whole userland, once ----------------------------------------------
#
# $(WINFILES) is the CUI machine; this is everything above it — the desktop
# stack, the applet shelf, explorer, both bitnesses of the WOW64 shelf, and
# the audio stack with its .ini furniture. BOTH images carry it, which is
# what makes "which leg runs" a boot flag rather than a bake: a dozen images
# existed whose only difference was which subset of these lists they held
# and which client file the session manager would therefore find.
FULLFILES := $(GUISTACKFILES) \
             win:$(CMD)=windows/system32/cmd.exe \
             win:$(TASKLIST)=windows/system32/tasklist.exe \
             win:$(TASKKILL)=windows/system32/taskkill.exe \
             $(APPLETFILES) \
             $(SXSFILES) \
             $(SHELLFILES) \
             $(WOW64GUESTFILES) $(WOW64HOSTFILES) $(WOW64GUIFILES) \
             $(AUDIOFILES) $(SYSINIFILES) $(WOW64AUDIOFILES)

FULL_PAYLOAD := $(GUISTACK_PAYLOAD) $(CMD) $(TASKLIST) $(TASKKILL) \
                $(WINESTRIP_APPLET_DLLS) $(WINESTRIP_APPLET_EXES) $(WINEMINE) \
                $(WINESTRIP)/comctl32_v6.dll $(WINESTRIP)/common-controls.manifest \
                $(SXS_PAYLOAD) \
                $(SHELL_PAYLOAD) \
                $(WOW64_GUEST_PAYLOAD) $(WOW64_GUI_PAYLOAD) \
                $(AUDIO_PAYLOAD) $(SYSINI_STAMP) $(WOW64_AUDIO_PAYLOAD)

# ---------------------------------------------------------------------------
# Net-3 (docs/02 "an off-the-shelf tool completes an HTTPS fetch over
# virtio-net"; docs/24 §6f): the Net-3 payload. The CUI machine + the
# GUI-2 DLL shelf (curl.exe imports user32) + the UNMODIFIED tool
# (third_party/curlwin, tools/setup_linux.sh's pinned purchase) + the
# api-set forwarder DLLs its UCRT imports name (generated from the
# binary's OWN import table — tools/gen_apiset_forwarders.py; with no
# ApiSetMap the pinned loader falls back to these literal names). The
# per-run job (curl config, test CA, the net3.test hosts row) is mcopy'd
# in by the run.sh net3 leg — nothing per-run is baked here. (C:\net3\job.txt
# used to be the smss PROBE that kept this flow off other images; the leg name
# selects it now and the file is only curl's input.)
NET3_CURL := third_party/curlwin/bin/curl.exe
NET3_APISETS := $(BUILD)/net3/apisets
$(NET3_APISETS)/specs.txt: $(NET3_CURL) tools/gen_apiset_forwarders.py
	python3 tools/gen_apiset_forwarders.py $(NET3_CURL) $(NET3_APISETS) >/dev/null

# curl.exe's measured import closure beyond the CUI + GUI sets: normaliz
# (WinIDN), wldap32 (LDAP URLs; its LDAP engine is vendored PE-side),
# bcrypt (LibreSSL entropy; SymCrypt is vendored PE-side — the docs/02
# scope note's "raw bcrypt works as-is"), crypt32 + its ncrypt import
# (the fork already lets crypt32 load without a unixlib). Unstripped from
# the pinned tree: llvm-objcopy refuses bcrypt (the FLASH_OBJCOPY note),
# and the one test image buys nothing from stripping these five.
NET3_DLL_NAMES := normaliz wldap32 bcrypt ncrypt crypt32
# Dropped when the tool is absent, the $(FLASHPRESENT) way: curl.exe is a
# sha256-pinned PURCHASE tools/setup_linux.sh downloads into a gitignored
# directory, and it has no rule here. Baking it into $(TESTFILES)
# unconditionally made EVERY image build — so `make test` and every leg —
# die on a fresh or offline tree with a bare "No rule to make target
# 'third_party/curlwin/bin/curl.exe'". It is one leg's payload, and that
# leg (tests/run/run.sh net3) already refuses loudly by name when the file
# is missing, which is where the demand belongs.
NET3PRESENT := $(wildcard $(NET3_CURL))
NET3_APISET_SPECS := $(if $(NET3PRESENT),$(NET3_APISETS)/specs.txt)
ifneq ($(NET3PRESENT),)
NET3FILES := $(foreach d,$(NET3_DLL_NAMES),win:$(WINE_PE)/$(d)/x86_64-windows/$(d).dll=windows/system32/$(d).dll) \
             win:$(NET3_CURL)=curl.exe
NET3_PAYLOAD := $(foreach d,$(NET3_DLL_NAMES),$(WINE_PE)/$(d)/x86_64-windows/$(d).dll) \
                $(NET3_CURL) $(NET3_APISETS)/specs.txt
else
NET3FILES :=
NET3_PAYLOAD :=
endif

# ---------------------------------------------------------------------------
# GUI-6 (docs/02 "Desktop"): Wine's explorer owns the desktop. The payload is
# the gui2 stack plus $(SHELLFILES) above (explorer + atl100 + the
# RegisterDlls-keeping wine.inf), plus explorer's delay-import closure
# beyond the GUI-2 set: shell32 -> shlwapi -> shcore, oleaut32 (measured
# from the PE's import + delay-import tables; grow only on a NAMED
# delay-load failure, which is loud), the WinSxS common-controls assembly
# explorer's manifest binds (the comdlg32 lesson: absent, CreateActCtx
# fails with 14001 and takes the process down), and uxtheme, the SxS
# comctl32's own delay import (measured: absent, the systray toolbar's
# OpenThemeData hit the delay-load failure hook and aborted explorer -- the
# wiring the applet-shelf comment above records).
# The leg is selected by name (GUEST_LEG=gui6, user/smss/session.c
# SessionGuiLegs): smss launches explorer /desktop=shell,WxH with a trailing
# `explorer.exe C:\shelf` -- the desktop, then the file window as explorer's
# own CreateProcessW child. It used to be selected by a marker FILE baked on
# an image of its own (C:\gui6.flag), which is the arrangement the leg flag
# replaced.

# The file window's subject: a tiny baked directory whose Details view is
# deterministic — fixed bytes, mtimes pinned by touch -t (mkimage's mcopy -m
# carries them onto the FAT volume) — because the golden is an exact byte
# compare and a view of C:\ would put the bake timestamps and PROSKRNL's own
# size in the picture, moving the golden with every rebuild.
GUI6_SHELF := $(BUILD)/shelf/readme.txt $(BUILD)/shelf/desktop-notes.txt
$(BUILD)/shelf/readme.txt:
	@mkdir -p $(dir $@)
	@printf 'proskrnl GUI-6: the file window of the golden desktop shows this shelf.\n' > $@
	@touch -t 202601010000.00 $@
$(BUILD)/shelf/desktop-notes.txt:
	@mkdir -p $(dir $@)
	@printf 'wallpaper + taskbar: explorer.exe; this window: shell32 IExplorerBrowser.\n' > $@
	@touch -t 202601010000.00 $@

# Everything the gui6 leg needs beyond $(FULLFILES) (which already carries
# explorer, the applet shelf's shell32/shlwapi/shcore/oleaut32/uxtheme and
# the WinSxS common-controls assembly): the shelf the file window shows.
GUI6FILES := win:$(BUILD)/shelf/readme.txt=shelf/readme.txt \
             win:$(BUILD)/shelf/desktop-notes.txt=shelf/desktop-notes.txt

# ---------------------------------------------------------------------------
# M10 stretch (docs/02 "Ideal regression"): standalone binaries for the CUI
# subset of Wine's own test suite, run by tests/run/run.sh winetest against
# the manifest (tests/winetest/manifest.txt) on BOTH the oracle and
# proskrnl. Same discipline as cmd.exe above: the pinned tree's own PE test
# objects (built by tools/setup_linux.sh) are linked UNMODIFIED; the CRT
# entry is the implib's own mainCRTStartup (dlls/msvcrt/crt_main.c — the
# entry winegcc itself picks for CRT exes), so the only glue is
# tests/winetest/glue/user32_stubs.c standing in the user32 imports the ntdll and
# kernel32 test objects reference (user32 is the M12 GUI path, off the image
# per Art. 7; subtests whose assertions need the real user32 fail identically
# on both runners and stay off the manifest).
WTESTS := $(BUILD)/wtests
WT_LINK := $(MINGW) -std=gnu11 -O1 -g0 -fno-builtin -nostdlib -nostartfiles \
    -Wl,--entry=mainCRTStartup
WT_GLUE := tests/winetest/glue/crt_sections.c
WT_LIBS := third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a
WT_CRT_MSVCRT := $(WINE_PE)/msvcrt/x86_64-windows/libmsvcrt.a
WT_CRT_UCRT := $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a

# Test objects per module: every SOURCES entry of the dir's Makefile.in plus
# the makedep-generated testlist.o, MINUS the .spec helper-DLL objects
# (testdll/dummy/threaddll — separate runtime-loaded modules, linked as their
# own DLLs by the pinned tree's build; see WT_*_RES below for how the subtests
# that load them reach them).
WT_NTDLL_D := third_party/wine/dlls/ntdll/tests/x86_64-windows
WT_NTDLL_OBJS := $(addprefix $(WT_NTDLL_D)/, alpc.o atom.o change.o directory.o env.o \
    error.o exception.o file.o generated.o info.o large_int.o om.o path.o pipe.o port.o \
    reg.o rtl.o rtlbitmap.o rtlstr.o string.o sync.o thread.o threadpool.o time.o \
    unwind.o virtual.o wow64.o testlist.o)
WT_KERNEL32_D := third_party/wine/dlls/kernel32/tests/x86_64-windows
WT_KERNEL32_OBJS := $(addprefix $(WT_KERNEL32_D)/, actctx.o atom.o change.o codepage.o \
    comm.o console.o debugger.o directory.o drive.o environ.o fiber.o file.o format_msg.o \
    generated.o heap.o loader.o locale.o mailslot.o module.o path.o pipe.o power.o \
    process.o profile.o resource.o sync.o thread.o time.o timer.o toolhelp.o version.o \
    virtual.o volume.o testlist.o)
WT_MSVCRT_D := third_party/wine/dlls/msvcrt/tests/x86_64-windows
WT_MSVCRT_OBJS := $(addprefix $(WT_MSVCRT_D)/, cpp.o data.o dir.o environ.o file.o heap.o \
    locale.o misc.o printf.o scanf.o signal.o string.o time.o testlist.o)
WT_UCRTBASE_D := third_party/wine/dlls/ucrtbase/tests/x86_64-windows
WT_UCRTBASE_OBJS := $(addprefix $(WT_UCRTBASE_D)/, cpp.o environ.o file.o misc.o printf.o \
    scanf.o string.o thread.o testlist.o)
WT_CMD_D := third_party/wine/programs/cmd/tests/x86_64-windows
WT_CMD_OBJS := $(addprefix $(WT_CMD_D)/, batch.o directory.o testlist.o)
# The audio modules (AUD-2, docs/23 §6c). Unlike the CUI five these link the
# REAL user32/ole32 import libs (their tests genuinely use them: message
# windows, COM apartments), so their pairs run on the audio wtest image
# (GUI stack + audio payload), never the CUI one — the manifest header's
# audio amendment.
WT_MMDEVAPI_D := third_party/wine/dlls/mmdevapi/tests/x86_64-windows
WT_MMDEVAPI_OBJS := $(addprefix $(WT_MMDEVAPI_D)/, capture.o dependency.o mmdevenum.o \
    propstore.o render.o spatialaudio.o testlist.o)
WT_WINMM_D := third_party/wine/dlls/winmm/tests/x86_64-windows
WT_WINMM_OBJS := $(addprefix $(WT_WINMM_D)/, capture.o generated.o joystick.o mci.o mcicda.o \
    midi.o mixer.o mmio.o timer.o wave.o testlist.o)

# Net-2: ws2_32's boundary tests. IMPORTS = iphlpapi ws2_32 user32 —
# ws2_32.dll is real (baked since M10's winestrip set); user32 and iphlpapi
# are stood in by the glue stubs (Art. 7: neither GUI nor the Net-3 NSI
# surface belongs on the CUI image), so their subtests fail identically on
# both runners and park in the manifest.
WT_WS2_32_D := third_party/wine/dlls/ws2_32/tests/x86_64-windows
WT_WS2_32_OBJS := $(addprefix $(WT_WS2_32_D)/, afd.o protocol.o sock.o testlist.o)

# The helper DLLs the .spec SOURCES build are reached through a RESOURCE, not
# an import: ntdll:thread, kernel32:actctx and ucrtbase:thread each call
# extract_resource()/FindResourceA(NULL, "<name>.dll", "TESTDLL") to write the
# module out to %TEMP% and load it from there. The pinned tree's makedep
# generates that resource as <name>.dll.res next to the test objects; linking
# it in is the whole of what those subtests need from the helper module.
WT_RES := x86_64-w64-mingw32-windres -J res -O coff
WT_NTDLL_RES := $(WT_NTDLL_D)/testdll.dll.res
WT_KERNEL32_RES := third_party/wine/dlls/kernel32/tests/resource.res \
    $(WT_KERNEL32_D)/dummy.dll.res
WT_UCRTBASE_RES := $(WT_UCRTBASE_D)/threaddll.dll.res

$(WT_NTDLL_OBJS) $(WT_KERNEL32_OBJS) $(WT_MSVCRT_OBJS) $(WT_UCRTBASE_OBJS) $(WT_CMD_OBJS) \
$(WT_MMDEVAPI_OBJS) $(WT_WINMM_OBJS) third_party/wine/dlls/winmm/tests/rsrc.res \
$(WT_NTDLL_RES) $(WT_KERNEL32_RES) $(WT_UCRTBASE_RES):
	@echo "error: $@ missing - build the pinned Wine test modules first (tools/setup_linux.sh)" >&2
	@exit 1

$(WTESTS)/ntdll_test.exe: $(WT_NTDLL_OBJS) $(WT_NTDLL_RES) \
        tests/winetest/glue/user32_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_RES) $(WT_NTDLL_D)/testdll.dll.res $(WTESTS)/ntdll_testdll.res.o
	$(WT_LINK) $(WT_NTDLL_OBJS) $(WTESTS)/ntdll_testdll.res.o \
	    tests/winetest/glue/user32_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/kernel32_test.exe: $(WT_KERNEL32_OBJS) $(WT_KERNEL32_RES) \
        tests/winetest/glue/user32_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_RES) third_party/wine/dlls/kernel32/tests/resource.res \
	    $(WTESTS)/kernel32_resource.res.o
	$(WT_RES) $(WT_KERNEL32_D)/dummy.dll.res $(WTESTS)/kernel32_dummy.res.o
	$(WT_LINK) $(WT_KERNEL32_OBJS) $(WTESTS)/kernel32_resource.res.o \
	    $(WTESTS)/kernel32_dummy.res.o \
	    tests/winetest/glue/user32_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/msvcrt_test.exe: $(WT_MSVCRT_OBJS) $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_MSVCRT_OBJS) $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/ucrtbase_test.exe: $(WT_UCRTBASE_OBJS) $(WT_UCRTBASE_RES) $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_RES) $(WT_UCRTBASE_D)/threaddll.dll.res $(WTESTS)/ucrtbase_threaddll.res.o
	$(WT_LINK) $(WT_UCRTBASE_OBJS) $(WTESTS)/ucrtbase_threaddll.res.o $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_UCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/cmd.exe_test.exe: $(WT_CMD_OBJS) third_party/wine/programs/cmd/tests/rsrc.res $(WT_GLUE)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff third_party/wine/programs/cmd/tests/rsrc.res \
	    $(WTESTS)/cmd_rsrc.res.o
	$(WT_LINK) $(WT_CMD_OBJS) $(WTESTS)/cmd_rsrc.res.o $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/mmdevapi_test.exe: $(WT_MMDEVAPI_OBJS) $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_MMDEVAPI_OBJS) $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) \
	    $(WINE_PE)/ole32/x86_64-windows/libole32.a \
	    $(WINE_PE)/version/x86_64-windows/libversion.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/winmm/x86_64-windows/libwinmm.a \
	    -Wl,--end-group -lgcc -o $@

$(WTESTS)/winmm_test.exe: $(WT_WINMM_OBJS) third_party/wine/dlls/winmm/tests/rsrc.res $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_RES) third_party/wine/dlls/winmm/tests/rsrc.res $(WTESTS)/winmm_rsrc.res.o
	$(WT_LINK) $(WT_WINMM_OBJS) $(WTESTS)/winmm_rsrc.res.o $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) \
	    $(WINE_PE)/winmm/x86_64-windows/libwinmm.a \
	    $(WINE_PE)/ole32/x86_64-windows/libole32.a \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    -Wl,--end-group -lgcc -o $@

# Net-3: iphlpapi is REAL now — the binary links the pinned import lib
# (the DLL and its nsi/dnsapi deps ride every image since the resolver
# furniture landed), so the adapter-table rows exercise \Device\Nsi
# through the whole client instead of dying in a glue stub. user32 keeps
# its stand-ins (Art. 7: GUI off the CUI image).
$(WTESTS)/ws2_32_test.exe: $(WT_WS2_32_OBJS) tests/winetest/glue/user32_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_WS2_32_OBJS) tests/winetest/glue/user32_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WINE_PE)/ws2_32/x86_64-windows/libws2_32.a \
	    $(WINE_PE)/iphlpapi/x86_64-windows/libiphlpapi.a \
	    $(WT_LIBS) -Wl,--end-group -lgcc -o $@

wtests: $(WTESTS)/ntdll_test.exe $(WTESTS)/kernel32_test.exe $(WTESTS)/msvcrt_test.exe \
    $(WTESTS)/ucrtbase_test.exe $(WTESTS)/cmd.exe_test.exe $(WTESTS)/ws2_32_test.exe \
    $(WTESTS)/mmdevapi_test.exe $(WTESTS)/winmm_test.exe
.PHONY: wtests

# ---------------------------------------------------------------------------
# The tests/ntapi suite as baked binaries (docs/14): ONE PE .exe per test
# source, CRT-less, linked against the pinned Wine import libraries so the
# SAME binary runs under the oracle (tests/run/run.sh oracle) and on the
# boot volume under C:\ntapi.
#
# Built HERE rather than by the runner script, which is what made a filtered
# run a different IMAGE: run.sh compiled the selected subset and baked only
# those, so the media recorded which subset had last been asked for. The
# whole suite is baked on every test image now and the boot's `subtests`
# filter picks (user/smss/session.c). run.sh's own build path is this rule,
# reached through make, so there is one recipe for a test .exe (Art. 11).
NTAPI_DIR  := tests/ntapi
NTAPI_SRCS := $(shell find $(NTAPI_DIR) -name '*.c' ! -name ntapi.c ! -path '*/dll/*' 2>/dev/null | sort)
# The `find` is silenced, so a failure (a missing tree, a permission error)
# yields an EMPTY list -- no per-exe rules, a `ntapi-tests` phony with no
# prerequisites, and on a tree that still has yesterday's .exe files every case
# runs the previous build's binary and grades green. Refuse instead.
ifeq ($(strip $(NTAPI_SRCS)),)
$(error no ntapi test sources found under $(NTAPI_DIR) -- the suite cannot be empty)
endif
NTAPI_OUT  := $(BUILD)/tests/ntapi
NTAPI_EXES := $(foreach src,$(NTAPI_SRCS),$(NTAPI_OUT)/$(notdir $(src:.c=.exe)))
NTAPI_LIBS := $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
              $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
              $(WINE_PE)/ntdll/x86_64-windows/libntdll.a
NTAPI_CFLAGS := -std=c11 -O1 -g -Wall -Wextra -I. -I$(NTAPI_DIR)

# Base names are unique across the buckets (run.sh's filter relies on it
# too), so one rule per source keyed on the base name is unambiguous. The
# bucket's own headers and .inc files are prerequisites: a bucket's util.h is
# included by every test in it and syscall/torture_matrix.inc is GENERATED,
# so without them a regenerated matrix re-runs the previous build's .exe and
# reports its verdict as this one's (measured, run.sh build_test).
define NTAPI_RULE
$(NTAPI_OUT)/$(notdir $(1:.c=.exe)): $(1) $(NTAPI_DIR)/ntapi.c $(NTAPI_DIR)/ntapi.h \
        $(wildcard $(dir $(1))*.h) $(wildcard $(dir $(1))*.inc) $(WINE_PE_DLLS)
	@mkdir -p $$(dir $$@)
	$(MINGW) $(NTAPI_CFLAGS) -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=ntapi_start $(1) $(NTAPI_DIR)/ntapi.c $(NTAPI_LIBS) -lgcc -o $$@
endef
$(foreach src,$(NTAPI_SRCS),$(eval $(call NTAPI_RULE,$(src))))

# Base names must stay unique, and this is what says so. They were not:
# sem_reg/rename.c and sem_file/rename.c both built to rename.exe, the later
# compile overwrote the earlier, and the ONE binary's verdict line graded
# BOTH names green — a false green that nothing in the build noticed because
# make merely warns about a duplicate recipe. A name collision now stops the
# build (Art. 12: a harness must not answer plausibly either).
NTAPI_DUP := $(strip $(shell printf '%s\n' $(notdir $(NTAPI_SRCS)) | sort | uniq -d))
ifneq ($(NTAPI_DUP),)
$(error tests/ntapi base names must be unique across buckets; duplicated: $(NTAPI_DUP))
endif

# The search-order probe DLL (sem_ps/dll_load.c): beside the test .exes so a
# bare-name LoadLibrary resolves it from the application directory.
NTAPI_HELPER := $(NTAPI_OUT)/prshelper.dll
$(NTAPI_HELPER): $(NTAPI_DIR)/dll/prshelper.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) $(NTAPI_CFLAGS) -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -shared -Wl,--entry=DllMainCRTStartup $(NTAPI_DIR)/dll/prshelper.c \
	    $(NTAPI_LIBS) -lgcc -o $@

# The GUI-subsystem console probe (sem_console/subsystem_gate.c): the same
# CRT-less recipe with --subsystem,windows — the one property under test.
# Baked at C:\ rather than C:\ntapi so the proskrnl sweep never grades it
# as a test (the m9_smoke.exe arrangement); beside the test .exes for the
# oracle, as a prerequisite of the test that spawns it so a filtered
# `run.sh oracle subsystem_gate` builds both.
NTAPI_CONPROBE := $(NTAPI_OUT)/conprobe_gui.exe
$(NTAPI_CONPROBE): $(NTAPI_DIR)/dll/conprobe_gui.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) $(NTAPI_CFLAGS) -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=gui_start -Wl,--subsystem,windows $(NTAPI_DIR)/dll/conprobe_gui.c \
	    $(NTAPI_LIBS) -lgcc -o $@
$(NTAPI_OUT)/subsystem_gate.exe: $(NTAPI_CONPROBE)

NTAPIFILES := $(foreach e,$(NTAPI_EXES),win:$(e)=ntapi/$(notdir $(e))) \
              win:$(NTAPI_HELPER)=ntapi/prshelper.dll \
              win:$(NTAPI_CONPROBE)=conprobe_gui.exe
NTAPI_PAYLOAD := $(NTAPI_EXES) $(NTAPI_HELPER) $(NTAPI_CONPROBE)

ntapi-tests: $(NTAPI_PAYLOAD)
.PHONY: ntapi-tests

# ---------------------------------------------------------------------------
# The winetest payload: the standalone module binaries above, BOTH curated
# manifests, the FULL nls set, tzres and the .ini furniture.
#
# Both manifests, not one: the CUI gate (manifest.txt) and the GUI-5 trophy
# (manifest-gui.txt) are separate lists, and the boot's leg says which of
# them the sweep reads (user/smss/session.c SessionRun). They used to be
# baked one at a time, each under the name `manifest.txt` on an image of its
# own — and a run that FILTERED the gate baked a generated third file, so the
# image on disk recorded which subset had last run.
#
# The CRT/codepage subtests exercise every codepage the oracle has (a missing
# c_932.nls reads as a divergence), tzres.dll is what RegLoadMUIStringW
# resolves the time-zone MUI_Std/MUI_Dlt strings through, and
# %windir%\{win,system}.ini are what wineboot's [SystemIni] pass would have
# written (the baked wine.inf drops UpdateInis — tools/gen_sysini.py).
WTEST_MODULES := ntdll_test.exe kernel32_test.exe msvcrt_test.exe ucrtbase_test.exe \
                 cmd.exe_test.exe ws2_32_test.exe mmdevapi_test.exe winmm_test.exe
WTEST_EXES := $(foreach m,$(WTEST_MODULES),$(WTESTS)/$(m))

# GUI-5's trophy binary is the pinned tree's OWN user32_test.exe, taken
# unmodified (the whoami precedent: no glue, no relink).
WTEST_USER32 := third_party/wine/dlls/user32/tests/x86_64-windows/user32_test.exe

WTESTFILES := $(foreach m,$(WTEST_MODULES),win:$(WTESTS)/$(m)=wtests/$(m)) \
              win:$(WTEST_USER32)=wtests/user32_test.exe \
              win:tests/winetest/manifest.txt=wtests/manifest.txt \
              win:tests/winetest/manifest-gui.txt=wtests/manifest-gui.txt \
              $(foreach f,$(wildcard $(WINE_NLS)/*.nls),win:$(f)=windows/system32/$(notdir $(f))) \
              win:third_party/wine/dlls/tzres/x86_64-windows/tzres.dll=windows/system32/tzres.dll
WTEST_PAYLOAD := $(WTEST_EXES) $(WTEST_USER32)

# ---------------------------------------------------------------------------
# THE TWO IMAGES (docs/08).
#
# `test`  every leg the harness runs, selected at boot by GUEST_LEG and
#         GUEST_SUBTESTS (tools/qemu.sh); it carries every client, every
#         test binary and both winetest manifests.
# `dev`   `make run` and `make rungui`: the same userland with the test
#         payload left off, plus the LOCAL flash projector when present.
#
# There were fourteen. Each existed because a leg was selected by whether
# its client file was on the volume, so two legs could never share a bake
# and a filtered run was a third image again; the payload lists that made
# them drifted apart (the print-winfiles story above is one instance).
TESTFILES := $(WINFILES) $(FULLFILES) \
             win:$(M9ECHO)=m9_echo.exe \
             win:$(HELLOCRT)=hello_crt.exe \
             win:$(UPCASE)=upcase.exe \
             win:$(WHOAMI)=whoami.exe \
             win:$(SVCDEMO)=svcdemo.exe \
             win:$(LOOPER)=looper.exe \
             win:$(JOBTOOL)=jobtool.exe \
             win:$(TIMEIT)=timeit.exe \
             win:$(REDIRCHAIN)=redirchain.exe \
             win:$(RESTRICTED)=restricted.exe \
             win:$(REGTOOL)=regtool.exe \
             win:$(WATCHAPP)=watchapp.exe \
             win:$(MMCEILING)=mmceiling.exe \
             win:$(HELLO32)=hello32.exe \
             win:$(GUISMOKE)=gui_smoke.exe \
             win:$(AUDSMOKE)=aud_smoke.exe \
             win:$(CAPSMOKE)=cap_smoke.exe \
             win:$(WASAPISMOKE)=wasapi_smoke.exe \
             win:$(WASAPICAPSMOKE)=wasapi_cap_smoke.exe \
             win:$(WASAPISMOKE32)=wasapi_smoke32.exe \
             win:$(WINEMINE)=winemine.exe \
             win:$(GUI3A)=gui3a.exe \
             win:$(GUI3B)=gui3b.exe \
             win:$(GUI4A)=gui4a.exe \
             win:$(GUI4B)=gui4b.exe \
             win:$(GUI5A)=gui5a.exe \
             win:$(GUI5B)=gui5b.exe \
             win:$(FONTDIFF)=fontdiff.exe \
             win:$(WOW64GUI)=wow64gui.exe \
             $(GUI6FILES) $(NET3FILES) $(WTESTFILES) $(NTAPIFILES)

TEST_PAYLOAD := $(WINFILES_DEPS) $(FULL_PAYLOAD) \
                $(M9ECHO) $(HELLOCRT) $(UPCASE) $(SVCDEMO) $(LOOPER) $(JOBTOOL) \
                $(TIMEIT) $(REDIRCHAIN) $(RESTRICTED) $(REGTOOL) $(WATCHAPP) \
                $(MMCEILING) $(HELLO32) \
                $(GUISMOKE) $(AUDSMOKE) $(CAPSMOKE) $(WASAPISMOKE) $(WASAPICAPSMOKE) \
                $(WASAPISMOKE32) \
                $(GUI3A) $(GUI3B) $(GUI4A) $(GUI4B) $(GUI5A) $(GUI5B) $(FONTDIFF) \
                $(WOW64GUI) $(GUI6_SHELF) $(NET3_PAYLOAD) \
                $(WTEST_PAYLOAD) $(NTAPI_PAYLOAD)

# 320 MiB: both bitnesses of the whole shelf, ~170 ntapi binaries and the
# multi-MB winetest modules come to 193 MB measured (`mdir -/`), and the
# headroom is for what the GUEST writes — the hive, the firstboot payload,
# every leg's own files. Sized rather than rounded up because EVERY leg
# copies this file before booting it (test_image_copy), so a CI shard running
# ten legs pays the size ten times on a runner with ~14 GB of disk.
#
# The ESP still starts at sector 4096, so the fixed offset every reader uses
# (tests/run/run.sh, tools/qemu.sh) is unchanged.
# $(NET3_APISET_SPECS) is empty on a tree without the curl purchase (the
# $(NET3PRESENT) guard above), so the image builds without the Net-3 payload
# rather than dying on a missing target; run.sh net3 is what refuses.
$(IMG_TEST): $(KERNEL) $(MODULES) $(TEST_PAYLOAD) $(UPCASE_CHECK) \
        $(LICENSE_CHECK) $(TIMEZONES_CHECK) $(NET3_APISET_SPECS) \
        tests/winetest/manifest.txt tests/winetest/manifest-gui.txt \
        tools/mkimage.sh arch/x86_64/limine.conf
	SIZE_MB=$${SIZE_MB:-320} tools/mkimage.sh $(KERNEL) $(IMG_TEST) $(MODULE_SPECS) \
	    $(TESTFILES) $$(cat $(NET3_APISET_SPECS) /dev/null)

test-img: $(IMG_TEST)
.PHONY: test-img

# THE WARM TEST IMAGE: $(IMG_TEST) with its first boot already paid.
#
# wineboot --init applies wine.inf's whole machine-state payload -- the
# registry, the fake DLLs, the COM self-registration -- and stamps
# C:\windows\.update-timestamp so later boots skip it. On this box that pass
# is ~90 seconds against ~23 for a boot that skips it, and on a CI runner it
# is nearer four minutes.
#
# One image serving every leg is what makes paying it ONCE possible. It also
# made NOT paying it once expensive: before, each leg had its own small bake
# and so its own small firstboot; now every leg would firstboot the whole
# userland, which took the CI critical path from ~27 minutes to ~47.
#
# Warmed on a GUI boot, because that is the payload that is a superset: the
# CUI-only boot's registry-only inf (user/smss/firstboot.c) is the same file
# with [RegisterDllsSection] dropped, and a boot that finds the prefix already
# initialised installs nothing at all.
#
# $(IMG_TEST) itself is never booted -- neither here (the copy is) nor by
# `test` below -- so it stays virgin for the three legs that need a machine
# whose disk has never run: run.sh firstboot and cui9 measure a first boot,
# and persist needs boot 1 to SEED the hive the warm-up boot would already
# have seeded. That is also why six legs no longer rm this file first.
IMG_TEST_WARM := $(BUILD)/proskrnl-test-warm.hdd
# The warm-up is the only VIRGIN boot left in `make test`, and it is judged
# like every other boot rather than by its verdict grep alone. Without the
# three checks below, a kernel-suite FAIL, an [ASSERT], or a ring-0 fault on a
# user address occurring during the firstboot/INF pass is invisible: smss
# prints M9 PASS independently of the kmt suites, so the grep is satisfied and
# the image is published. That pass is exactly the code this boot exists to
# run, and nothing else in `make test` runs it any more.
#
# TIMEOUT is written out below rather than left at qemu.sh's 600s default:
# this is the one VIRGIN boot left, so it pays the whole firstboot INF pass,
# and under tools/fulltest.sh every leg's view runs this rule concurrently on
# a loaded TCG box (fulltest.sh unsets TIMEOUT and exports none for it). A
# warm-up killed at 600s fails the leg that was only trying to copy it.
#
# Every GUEST_* flag is written out, not left to its default: tools/qemu.sh
# reads them from the environment, so an ambient export would otherwise ride
# into THIS boot — the one every leg copies. An exported GUEST_GUI=0 (the
# very variable `make test` and `make run` use) would silently warm the
# master with the registry-only inf, and every GUI/audio/shell leg would then
# inherit a hive with no shell32/mmdevapi self-registration; an exported
# GUEST_LEG or GUEST_INTERACTIVE wedges the warm-up to its whole TIMEOUT.
# The same leak class net3 pins GUEST_GUI=1 against and tools/fulltest.sh
# scrubs — but the scrub protects only fulltest runs, so the rule pins its
# own boot.
$(IMG_TEST_WARM): $(IMG_TEST)
	cp $(IMG_TEST) $@.tmp
	GUEST_GUI=1 GUEST_SERIAL=0 GUEST_STRESS=0 GUEST_INTERACTIVE= \
	    GUEST_LEG= GUEST_SUBTESTS= INTERACTIVE= \
	    LOG=$(BUILD)/warm-serial.log TIMEOUT=1800 tools/qemu.sh $@.tmp
	tests/run/kmtcheck.sh $(BUILD)/warm-serial.log
	tests/run/uacheck.sh $(BUILD)/warm-serial.log
	tests/run/symcheck.sh $(BUILD)/warm-serial.sym.log
	# The external FAT oracle on the warm image, BEFORE it is published and
	# before the strip below removes the artifacts it checks. Every leg copies
	# this volume, and qemu.sh's grace path SIGKILLs QEMU GRACE seconds after
	# the verdict appears -- so without this a torn write at power-off would be
	# published as the master and every leg would inherit it. `test` is the
	# right scope here: this boot is the plain boot suite, the same one
	# `make test` runs.
	tests/run/fatcheck.sh verify test $@.tmp
	# Strip the kmt6 artifacts the warm boot just made, so every consumer's
	# fatcheck still convicts ITS OWN boot. m6_io opens them FILE_OPEN_IF /
	# FILE_OVERWRITE_IF ("keeps reruns on an already-seeded image green"), so
	# leaving them here would let a boot whose disk writes never landed pass
	# the external FAT oracle on the warm-up's bytes -- fatcheck exists
	# precisely so the kernel cannot grade its own homework (docs/08). The
	# hive stays: firstboot wrote it, that IS what this image is for.
	MTOOLS_SKIP_CHECK=1 mdeltree -i $@.tmp@@2097152 ::/kmt6 >/dev/null 2>&1 || true  # 4096*512, tools/mkimage.sh ESP_OFF
	mv $@.tmp $@

test-img-warm: $(IMG_TEST_WARM)
.PHONY: test-img-warm

# The DEV image: the same userland, no test payload. $(FLASHFILES) is the
# LOCAL (uncommitted) standalone Flash projector and its movie, dropped when
# the sources are absent so the target still builds on a clean tree.
DEVFILES := $(WINFILES) $(FULLFILES) \
            win:$(HELLOCRT)=hello_crt.exe \
            win:$(UPCASE)=upcase.exe \
            win:$(LOOPER)=looper.exe \
            $(FLASHFILES)

$(IMG_DEV): $(KERNEL) $(WINFILES_DEPS) $(FULL_PAYLOAD) $(HELLOCRT) $(UPCASE) $(LOOPER) \
        tools/mkimage.sh arch/x86_64/limine.conf \
        $(FLASHPRESENT) $(FLASH_DLLS) $(FLASH_FIXTURES) $(FLASH_REG)
	SIZE_MB=$${SIZE_MB:-256} tools/mkimage.sh $(KERNEL) $(IMG_DEV) $(DEVFILES)

dev-img: $(IMG_DEV)
.PHONY: dev-img

# The headless test boot (docs/08): the standard image's full [KTEST] suite,
# verdict grepped off the serial log by tools/qemu.sh, then kmtcheck (that
# grep names ONE line, so every suite reporting after it needs its verdict
# read too), uacheck (a ring-0 fault on a user address is a defect the
# recovery frame would otherwise turn into a plain STATUS_ACCESS_VIOLATION —
# issue #32 A3), symcheck (the symbolizer still resolves this boot's dumps —
# Art. 9) and the external FAT oracle (fsck.fat + fatsweep + mtools
# byte-compares) on the mutated image — make stops on a failed boot, so all
# four only judge runs whose primary verdict passed.
# The whole GUEST_* set is pinned, not just GUEST_GUI: the flags are read
# from the environment (the warm rule's note above), and an exported
# GUEST_LEG or GUEST_STRESS would otherwise change what this boot runs.
test: $(IMG_TEST_WARM)
	cp $(IMG_TEST_WARM) $(BUILD)/test-run.hdd
	GUEST_GUI=0 GUEST_SERIAL=0 GUEST_STRESS=0 GUEST_INTERACTIVE= \
	    GUEST_LEG= GUEST_SUBTESTS= INTERACTIVE= \
	    tools/qemu.sh $(BUILD)/test-run.hdd
	tests/run/kmtcheck.sh $(BUILD)/serial.log
	tests/run/uacheck.sh $(BUILD)/serial.log
	tests/run/symcheck.sh $(BUILD)/serial.sym.log
	tests/run/fatcheck.sh verify test $(BUILD)/test-run.hdd

# The WHOLE CI suite, on this machine, in parallel (tools/fulltest.sh): the
# same legs .github/workflows/test.yml runs, one sandboxed view each, fanned
# out over the box instead of spread over seven hosted shards. A green run is
# the answer to "would CI be green" without waiting for CI.
#
#   make fulltest                              every leg (the verdict)
#   make fulltest FULLTEST_ARGS="gui4 cui8"    a subset, for iteration only
fulltest:
	tools/fulltest.sh $(FULLTEST_ARGS)
.PHONY: fulltest

# A WEAK second oracle for driver-vs-device-model assumptions (docs/08): the
# same boot under the host's QEMU instead of the pin. A divergence names a
# suspect (spec misreading vs. QEMU behavior); it convicts nothing (Art. 6)
# and never gates a PR. Host QEMU must still be >= 9.0 (qemu.sh enforces).
# Boots a COPY, like every other consumer. Booting $(IMG_TEST) itself would
# warm and mutate the one file three legs depend on never having been a
# running machine's disk (run.sh firstboot, cui9, persist) -- and make would
# not rebuild it afterwards, since a booted image's mtime outruns its
# prerequisites. This target was the last in-place booter of a master.
test-hostqemu: $(IMG_TEST)
	cp $(IMG_TEST) $(BUILD)/test-hostqemu.hdd
	QEMU=qemu-system-x86_64 GUEST_GUI=0 GUEST_SERIAL=0 GUEST_STRESS=0 \
	    GUEST_INTERACTIVE= GUEST_LEG= GUEST_SUBTESTS= INTERACTIVE= \
	    LOG=$(BUILD)/hostqemu-serial.log \
	    tools/qemu.sh $(BUILD)/test-hostqemu.hdd
.PHONY: test-hostqemu

# The interactive boot on the SERIAL console: the dev image with a human at
# the terminal. What makes it interactive, and what makes its console the
# serial one rather than a window, is the QEMU command line — GUEST_INTERACTIVE
# and GUEST_GUI=0, read through fw_cfg (kernel/init/main.c KiIsInteractiveBoot,
# user/smss/smss.c SmssIsGuiBoot) — not anything on the image; the same image
# booted without them runs the ordinary session behind a window. Type at the
# prompt; `exit` powers the VM off; Ctrl-A x kills QEMU.
run: $(IMG_DEV)
	INTERACTIVE=1 GUEST_INTERACTIVE=1 GUEST_GUI=0 MEM=$${MEM:-1024M} \
	    tools/qemu.sh $(IMG_DEV)
.PHONY: run

# GUI-5: the same image with the WINDOWED console — a host window on the
# scanout and a virtio keyboard + tablet: click the console, type, `exit`
# powers the VM off. Serial stays on the terminal carrying the kernel's
# lines (HACK-004's permanent debug role). No GUEST_GUI here: the windowed
# console is the default (tools/qemu.sh).
#
# NET_USER=1 / SOUND=1: the machine a human sits at gets the two devices the
# headless legs pin their own backends for — a virtio-net NIC on slirp
# (netd DHCPs against it with nothing to configure guest-side) and a
# virtio-snd card on whatever audio backend the host QEMU has. Which
# backend, and what to say when there is none, is qemu.sh's business: it is
# the file that knows the host. The image's own half is $(AUDIOFILES) in
# $(FULLFILES); the NIC needs no image payload at all.
#
# The keyboard and tablet are qemu.sh's GUI_DISPLAY defaults, not an
# EXTRA_DEVICES list here — the interactive branch adds them itself.
# No GUEST_GUI and no GUEST_SHELL: a GUI boot HAS a desktop and a shell owns
# it, which is what this target is. smss derives both (SmssIsShellBoot,
# SmssConsoleWantsWindow) from `Gui` and `Interactive`, so an interactive GUI
# boot gets explorer's desktop and the windowed console without either being
# asked for by name. `make run` above passes GUEST_GUI=0, which is CUI-only:
# no desktop, no desktop server, and a user32 call that would create a window
# fails at runtime.
rungui: $(IMG_DEV)
	INTERACTIVE=1 GUEST_INTERACTIVE=1 GUI_DISPLAY=1 NET_USER=1 SOUND=1 \
	    MEM=$${MEM:-1024M} tools/qemu.sh $(IMG_DEV)
.PHONY: rungui

clean:
	rm -rf $(BUILD)

# Regenerate the abi/ contract headers from Wine's headers (Art. 4 / G4).
# Never hand-edit abi/ — this target is the only writer.
gen-abi:
	python3 tools/gen_abi.py
	python3 tools/gen_syscalls.py

# The NLS upcase table kernel/lib/rtl.c folds names through, from the pinned
# tree's own nls/l_intl.nls — the same bytes the oracle folds through. Its own
# target rather than part of `gen-abi` because the source is NLS DATA, not a
# Wine header; the rule against hand-editing is the same one (Art. 4 / G4).
# It is checked in rather than built into $(BUILD) because `make format` runs
# clang-tidy over kernel/ on a bare checkout, where third_party/wine is not
# present. `--check` is what proves it has not drifted from the pin.
gen-nls:
	python3 tools/gen_upcase.py

# The HKLM\Software\Wine\LicenseInformation payload CmInitialize seeds, from
# the pinned tree's own loader/wine.inf — the section that writes that key
# into the oracle's prefix. Its own target for the same reason gen-nls is:
# the source is INF DATA rather than a Wine header. Art. 4 / G4.
gen-license:
	python3 tools/gen_license.py

# The HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time Zones table
# CmInitialize seeds, from the pinned kernelbase's own WINE_REGISTRY resource
# (dlls/kernelbase/kernelbase.rgs) — the payload that writes that key into the
# oracle's prefix. Its own target for the same reason gen-license is: the
# source is registrar-script DATA rather than a Wine header. Art. 4 / G4.
gen-timezones:
	python3 tools/gen_timezones.py

# The generated-source gate (Art. 4 / G4): every checked-in file above must be
# byte-identical to what its generator produces from the CURRENT pin.
#
# WHY IT IS A GATE AND NOT A CONVENTION. `abi/` and the syscall number space
# are checked in, so nothing in a build notices them being wrong: a hand-typed
# constant (G4's forbidden move) compiles, and a Wine pin bump that nobody
# re-ran `make gen-abi` after compiles too — and then the kernel is speaking a
# contract the ORACLE no longer speaks, which surfaces as a mystery divergence
# somewhere far from the edit. This target asks each generator instead of a
# reviewer. It was not hypothetical: five rows of kernel/syscall/table.inc had
# been hand-edited past tools/gen_syscalls.py's IMPLEMENTED list by the time
# it was written.
#
# SCOPE: the generators whose inputs are TRACKED FILES of the pinned tree —
# include/*.h, dlls/ntdll/ntsyscalls.h, nls/l_intl.nls,
# dlls/kernelbase/kernelbase.rgs. That is what lets the style shard run this
# against a shallow submodule checkout, building no image and no wine.
#
# gen_license is deliberately NOT here: its input, loader/wine.inf, is a
# CONFIGURE PRODUCT of the wine tree (the tracked file is wine.inf.in), so on
# an unconfigured checkout it does not exist and this target would be gating
# on tree state rather than on the contract. It keeps the $(LICENSE_CHECK)
# stamp rule above, which every image-building shard takes — so it is still
# checked mechanically, just not here. The other two data generators keep
# their stamp rules too; running them here as well is free and moves their
# verdict minutes earlier.
#
# The winetest-manifest check rides here for the SCOPE sentence above rather
# than because it is a generated file: its input is tracked files of the
# pinned tree (dlls/*/tests/Makefile.in), so it belongs with the checks that
# read the pin and not in `make format`, which runs on a bare checkout where
# third_party/wine is not present at all (the reason gen-nls's output is
# checked in). Same family, same failure it prevents: a pin bump nobody
# re-read leaves the tree claiming a coverage it no longer has.
gen-check: wtest-manifest-check
	python3 tools/gen_abi.py --check
	python3 tools/gen_syscalls.py --check
	python3 tools/gen_upcase.py --check
	python3 tools/gen_timezones.py --check

# Enforce the docs/15 house style — the one style gate, `make format`.
#
# Three passes, in this order: the blocking frontier (G14), clang-format for
# *layout*, then clang-tidy for *naming* (readability-identifier-naming) and
# the correctness lints .clang-tidy enables. user/smss is our own code and
# takes all three; user/wine is the exception (it mirrors the pinned tree's
# Wine style and carries its own DisableFormat/.clang-tidy). smss is a
# user-mode PE, so its TUs are checked under the same mingw target they are
# built for, not the kernel's freestanding-ELF flags.
#
# It REWRITES source: every fix clang-tidy can make (the identifier renames
# above all) is applied in place and re-laid-out through .clang-format. It
# still fails the run — a warning it just fixed is a warning you introduced,
# and the failure is what makes it a gate; re-run to see the tree green and
# `git diff` for what it did. tools/tidy.sh has the parallelism, and the
# reason the fixing pass is the serial one.
SMSS_TIDY_FLAGS := -std=c11 --target=x86_64-windows-gnu -ffreestanding -I.
# Recursively expanded (`=`, not `:=`): the find runs when `format` runs, not
# on every parse of this Makefile.
FORMAT_SRC = $(shell find kernel arch drivers fs user/smss -name '*.[ch]')
format: frontier-check
	@echo "clang-format: $(words $(FORMAT_SRC)) files"
	@$(CLANG_FORMAT) -i $(FORMAT_SRC)
	@tools/tidy.sh $(CLANG_TIDY) "$(CFLAGS)" $(filter-out drivers/net/% drivers/afd.c drivers/nsi.c,$(CSRC))
	@tools/tidy.sh $(CLANG_TIDY) "$(CFLAGS) $(LWIP_INCLUDES)" $(filter drivers/net/% drivers/afd.c drivers/nsi.c,$(CSRC))
	@tools/tidy.sh $(CLANG_TIDY) "$(SMSS_TIDY_FLAGS)" $(wildcard user/smss/*.c)

# The blocking frontier (issue #96 A, the static half): which code can park is
# a call-graph query, so ask the machine rather than a reviewer. `frontier`
# prints it; `frontier-check` (in `format`, so every gate run takes it) fails
# on a service that newly parks without being written into the baseline, and
# on a must-not-block region that grew a path to one.
frontier:
	python3 tools/blocking_frontier.py --report

frontier-check:
	python3 tools/blocking_frontier.py --check

# The winetest manifests are EXHAUSTIVE over the modules this Makefile builds
# test binaries for (tools/check_wtest_manifests.py): every subtest the pinned
# tree has is written down, active or parked, in the manifest its module
# belongs to -- so a pin bump that adds a subtest cannot silently shrink the
# coverage the manifests claim, and a pair no longer in the tree cannot sit
# there unrunnable. `wtest-manifest-report` prints the coverage table;
# `wtest-manifest-check` is a prerequisite of `gen-check` (below), which is
# where the checks that READ THE PIN live.
wtest-manifest-report:
	python3 tools/check_wtest_manifests.py --report

wtest-manifest-check:
	python3 tools/check_wtest_manifests.py

.PHONY: all test run clean format gen-abi gen-nls gen-check frontier frontier-check \
        wtest-manifest-report wtest-manifest-check

# Header dependency files emitted by -MMD (see DEPFLAGS).
-include $(OBJ:.o=.d)
