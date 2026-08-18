# proskrnl — kernel build + thin superbuild (ADR 0009). Boot: Limine (ADR 0010).
#
#   make            build the bootable image (build/proskrnl.hdd)
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
IMG    := $(BUILD)/proskrnl.hdd

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

all: $(IMG)

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

# The M9 interactive-echo client: baked ONLY into the console-mode image
# below (it blocks on console input, which the plain headless loop must
# never do).
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
# mini-CRT (proskrnl_glue.c, shared with the windowed link) and the headless
# user32/window.c stand-ins
# (headless_stubs.c, this link only — the windowed CONHOST_GUI links the
# real user32 and the real window.c instead). Built like the other native
# PEs: mingw, no CRT, Wine import libraries.
WINE_CONHOST := third_party/wine/programs/conhost
CONHOST := $(BUILD)/modules/conhost.exe
$(CONHOST): $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/conhost.h \
            $(WINE_CONHOST)/proskrnl.c $(WINE_CONHOST)/proskrnl.h \
            $(PROG_GLUE)/conhost/proskrnl_glue.c \
            $(PROG_GLUE)/conhost/headless_stubs.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINUSERAPI=' \
	    -I$(WINE_CONHOST) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=conhost_start \
	    $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/proskrnl.c \
	    $(PROG_GLUE)/conhost/proskrnl_glue.c \
	    $(PROG_GLUE)/conhost/headless_stubs.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# GUI-5: the WINDOWED conhost — the same pinned sources plus the real
# window.c and the wrc-compiled conhost resources, linked against the real
# user32/gdi32/advapi32 (so no '-DWINUSERAPI=': user32 references must stay
# dllimport and bind to the import library). comctl32 alone is NOT linked:
# window.c reaches it only from the config dialog, and window_glue.c
# forwards those three entry points by hand (upstream's DELAYIMPORT, done
# without mingw's delay-import machinery — '-DWINCOMMCTRLAPI=' makes the
# declarations plain so the forwarders satisfy them). Baked as conhost.exe
# only on images whose console is a real window (the gui5con leg, make
# rungui); every serial-console image keeps CONHOST above.
CONHOST_GUI := $(BUILD)/modules/conhost-gui.exe
$(CONHOST_GUI): $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/conhost.h \
            $(WINE_CONHOST)/window.c $(WINE_CONHOST)/conhost.res \
            $(WINE_CONHOST)/proskrnl.c $(WINE_CONHOST)/proskrnl.h \
            $(PROG_GLUE)/conhost/proskrnl_glue.c $(PROG_GLUE)/conhost/window_glue.c \
            $(WSRV_DIR)/common/transport.h $(WINE_PE_DLLS)
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
# user/wine/programs/cmd/ supplies only the glue — the CRT entry plus the five
# user32 / four shell32 imports, stood in over ntdll/kernelbase (user32/shell32 are the M12 GUI
# path, additive and absent here per Art. 7). Links the real ucrtbase +
# advapi32 import libraries; both DLLs are baked (WINFILES below).
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
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-4: Wine's tasklist.exe / taskkill.exe as standalone CUI PEs — the
# milestone's acceptance pair (docs/02 "a tasklist/taskkill pair works
# against live processes"). The pinned tree's own PE build provides the
# program objects and wrc-compiled resources UNMODIFIED; the tasklist/ and
# taskkill/ glue supplies only the wide CRT entry and the user32 imports
# (LoadStringW is a resource read; taskkill's window calls fail honestly —
# its /f path does not use them). Same recipe shape as cmd.exe above.
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
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: Wine's rundll32.exe as a standalone PE — wineboot --init's vehicle
# for the `setupapi,InstallHinfSection` children that apply wine.inf (ADR
# 0008's Cm integration exercise). The pinned tree's own PE build provides
# rundll32.o UNMODIFIED; the rundll32/ glue supplies the wide CRT entry plus
# the four user32 imports as headless stand-ins (Art. 7: GUI path stays absent).
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

# CUI-1: the registry-only wine.inf (tools/filter_inf.py strips the fake-dll
# / file-queue / self-registration directives that need source media or GUI
# DLLs the disk does not bake; the AddReg machine-state payload is kept).
WINE_INF := $(BUILD)/wine-proskrnl.inf
$(WINE_INF): third_party/wine/loader/wine.inf tools/filter_inf.py
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
                   cryptbase setupapi cfgmgr32 ws2_32 secur32 userenv hid
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

# win32u rides along with the trio and is NOT a GUI decision: wow64win.dll
# is the win32u syscall thunk table and imports it unconditionally, while
# wow64.dll's load_64bit_module TERMINATES the process if wow64win cannot
# load (dlls/wow64/syscall.c) — so a CUI wow64 process needs it present to
# start at all. The pinned PE win32u imports nothing but ntdll, so it is a
# leaf that no CUI guest ever calls into.
#
# It is listed apart from the trio because on a GUI image it MUST NOT be
# copied: there, system32\win32u.dll is this build's IMPLEMENTATION (the
# $(WIN32U) link above), and the two files have the same name. Staging the
# stock thunks after it wins the mcopy -o race and hands every 64-bit GUI
# process a win32u whose NtUser* entry points issue syscalls at a kernel that
# mints none — which is exactly what it did: conhost took a page fault inside
# its first NtUserCreateWindowEx before the console window ever appeared.
# wow64win is happy either way; the implementation exports every name it
# imports (see WOW64_GUI_NAMES).
WOW64_STOCK_W32U := win:$(WINESTRIP)/win32u.dll=windows/system32/win32u.dll
$(eval $(call WINESTRIP_RULE,win32u))

# The guest payload as mkimage `win:` specs, split so a GUI image can take
# the halves it wants: the i386 set under syswow64, the wow64 host trio under
# system32, and (CUI only) the stock win32u.
WOW64GUESTFILES := $(foreach d,$(WINESTRIP32_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll) \
              $(foreach p,$(WINESTRIP32_EXE_NAMES),win:$(WINESTRIP32)/$(p).exe=windows/syswow64/$(p).exe)
WOW64HOSTFILES := $(foreach d,$(WOW64_HOST_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll)
WOW64FILES := $(WOW64GUESTFILES) $(WOW64HOSTFILES) $(WOW64_STOCK_W32U)
WOW64_GUEST_PAYLOAD := $(WINESTRIP32_DLLS) $(WINESTRIP32_EXES) $(WOW64_HOST_DLLS)
WOW64_PAYLOAD := $(WOW64_GUEST_PAYLOAD) $(WINESTRIP)/win32u.dll

.PHONY: wow64strip
wow64strip: $(WOW64_PAYLOAD)

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

WINFILES := win:$(WINESTRIP)/ntdll.dll=windows/system32/ntdll.dll \
            win:$(WINESTRIP)/kernel32.dll=windows/system32/kernel32.dll \
            win:$(WINESTRIP)/kernelbase.dll=windows/system32/kernelbase.dll \
            win:$(WINESTRIP)/msvcrt.dll=windows/system32/msvcrt.dll \
            win:$(WINESTRIP)/ucrtbase.dll=windows/system32/ucrtbase.dll \
            win:$(WINESTRIP)/advapi32.dll=windows/system32/advapi32.dll \
            win:$(WINESTRIP)/sechost.dll=windows/system32/sechost.dll \
            win:$(WINESTRIP)/rpcrt4.dll=windows/system32/rpcrt4.dll \
            win:$(WINESTRIP)/version.dll=windows/system32/version.dll \
            win:$(WINESTRIP)/cryptbase.dll=windows/system32/cryptbase.dll \
            win:$(WINESTRIP)/setupapi.dll=windows/system32/setupapi.dll \
            win:$(WINESTRIP)/cfgmgr32.dll=windows/system32/cfgmgr32.dll \
            win:$(WINESTRIP)/ws2_32.dll=windows/system32/ws2_32.dll \
            win:$(WINESTRIP)/secur32.dll=windows/system32/secur32.dll \
            win:$(WINESTRIP)/userenv.dll=windows/system32/userenv.dll \
            win:$(WINESTRIP)/services.exe=windows/system32/services.exe \
            win:$(WINESTRIP)/rpcss.exe=windows/system32/rpcss.exe \
            win:$(WINESTRIP)/sc.exe=windows/system32/sc.exe \
            win:$(RUNDLL32)=windows/system32/rundll32.exe \
            win:$(WINEBOOT)=windows/system32/wineboot.exe \
            win:$(WINE_INF)=windows/inf/wine.inf \
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
            win:$(M9SMOKE)=m9_smoke.exe

# The same CUI userland, reachable from a provisioner OUTSIDE this Makefile:
# tests/run/run.sh's winetest leg bakes its own image (the manifest it runs
# is generated per run, so the recipe cannot be a plain target), and used to
# carry its own hand-written list of the DLLs it wanted. Two lists of the
# same userland is how the winetest image drifted into a SHORTER machine than
# the one `make run` boots — no wineboot.exe, so no firstboot and none of
# wine.inf's machine-state payload; no SCM, no setupapi/ws2_32/secur32/…
# — and a differential leg whose image is not the product's measures the
# difference (Art. 11 "one authority", the reason this is not a second list).
#
# `winfiles` builds the payload; `print-winfiles` prints the specs, and
# prints NOTHING else, so a caller can read it with $( ). The paths are
# relative to this directory, as everything in $(WINFILES) is — the caller
# prefixes them (run.sh does).
.PHONY: winfiles print-winfiles
winfiles: $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
          $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES)

print-winfiles:
	@printf '%s\n' $(WINFILES)

# kernel/lib/upcase.h is checked in (see `gen-nls`), so nothing in the build
# would notice it drifting from the pin it was generated out of. This is what
# notices: it re-runs only when the pinned table, the generator or the output
# changes, and it hangs off $(IMG) rather than off the kernel because a
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

$(IMG): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(RUNDLL32) $(WINEBOOT) \
        $(WINE_INF) $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(UPCASE_CHECK) \
        $(LICENSE_CHECK) $(TIMEZONES_CHECK) tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG) $(MODULE_SPECS) $(WINFILES)

# M10: the MSVC-stand-in CUI apps — plain mingw with its FULL CRT (they
# import msvcrt.dll + kernel32.dll; third-party CRT startup against the
# baked Wine userland). Only the console image carries them.
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

# The M9 interactive-console image (tests/run/run.sh console): the standard
# image plus m9_echo.exe, whose presence makes the boot block on console
# input after the M9 verdict (kernel/init/main.c KiRunM9Echo) — and, M10,
# cmd.exe plus the CUI apps for the interactive cmd session that follows
# (KiRunCmdConsole).
# CUI-2 acceptance: the pinned tree's own UNMODIFIED whoami.exe — a real
# tool whose startup path is OpenProcessToken + GetTokenInformation. It
# lands on the console image; console_expect.py runs `whoami /logonid` and
# greps the logon SID (docs/02 CUI-2 "Done when").
WHOAMI := third_party/wine/programs/whoami/x86_64-windows/whoami.exe

IMG_CONSOLE := $(BUILD)/proskrnl-console.hdd
$(IMG_CONSOLE): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(M9ECHO) \
        $(CMD) $(HELLOCRT) $(UPCASE) $(SVCDEMO) $(LOOPER) $(JOBTOOL) $(TASKLIST) $(TASKKILL) \
        $(TIMEIT) $(REDIRCHAIN) $(RESTRICTED) $(REGTOOL) $(WATCHAPP) $(MMCEILING) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_CONSOLE) $(MODULE_SPECS) $(WINFILES) \
	    win:$(M9ECHO)=m9_echo.exe \
	    win:$(CMD)=windows/system32/cmd.exe \
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
	    win:$(TASKLIST)=windows/system32/tasklist.exe \
	    win:$(TASKKILL)=windows/system32/taskkill.exe

console-img: $(IMG_CONSOLE)
.PHONY: console-img

# The WOW64 image (docs/02, the final milestone): the console image's
# payload plus the syswow64 guest stack, the wow64 host trio, and the 32-bit
# acceptance client. Its own image rather than the default one because with
# no COW every wow64 child copies its images whole, and no other leg needs
# to pay that.
IMG_WOW64 := $(BUILD)/tests/wow64.hdd
$(IMG_WOW64): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(CMD) $(HELLO32) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WOW64_PAYLOAD) \
        tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_WOW64) $(MODULE_SPECS) $(WINFILES) $(WOW64FILES) \
	    win:$(CMD)=windows/system32/cmd.exe \
	    win:$(HELLO32)=hello32.exe

wow64-img: $(IMG_WOW64)
.PHONY: wow64-img

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

# The GUI-1 image (tests/run/run.sh gui): the standard image plus
# gui_smoke.exe, whose presence makes the boot paint the framebuffer and
# then block forever on input (kernel/init/main.c KiRunGuiSmoke) — the host
# screendumps it and ends the guest over QMP. No Wine userland beyond ntdll
# is involved, so this image boots in seconds.
IMG_GUI := $(BUILD)/proskrnl-gui.hdd
$(IMG_GUI): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(GUISMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI) $(MODULE_SPECS) $(WINFILES) \
	    win:$(GUISMOKE)=gui_smoke.exe

gui-img: $(IMG_GUI)
.PHONY: gui-img

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

# The audio images' wine.inf: registry-only PLUS self-registration, with
# mmdevapi injected into [RegisterDllsSection] — CoCreateInstance of the
# MMDeviceEnumerator needs its CLSID in the hive, which a real prefix gets
# from the fake-dll registrar this filter drops, and mmdevapi is not in
# wine.inf's own RegisterDlls list. Registration then runs mmdevapi's OWN
# DllRegisterServer through Wine's own registrar (setupapi + atl100 — the
# GUI-6 shell recipe), never a hand-typed CLSID seed (Art. 11 / G8). Of the
# section's entries, exactly shell32 (when baked) and mmdevapi resolve on an
# audio image; the rest fail LoadLibrary and are skipped one by one.
WINE_INF_AUDIO := $(BUILD)/wine-proskrnl-audio.inf
$(WINE_INF_AUDIO): third_party/wine/loader/wine.inf tools/filter_inf.py
	@mkdir -p $(dir $@)
	python3 tools/filter_inf.py --keep RegisterDlls --add-register mmdevapi.dll,dsound.dll \
	    third_party/wine/loader/wine.inf $@

# Everything an audio-capable image adds on top of the CUI + GUI payloads:
# the audio DLL set, the driver, the registrar, and the registering inf
# (overriding $(WINFILES)'s registry-only copy by mcopy -o ordering — the
# gui5con conhost precedent). run.sh audio (WASAPI half) and the winetest
# audio image both take this one list (Art. 11: one spelling).
AUDIOFILES := $(foreach d,$(WINESTRIP_AUDIO_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
              $(foreach d,$(WINESTRIP_ACM_NAMES),win:$(WINESTRIP)/$(d).acm=windows/system32/$(d).acm) \
              win:$(WINEVSND)=windows/system32/winevsnd.drv \
              win:$(WINESTRIP)/atl100.dll=windows/system32/atl100.dll \
              win:$(WINESTRIP)/shlwapi.dll=windows/system32/shlwapi.dll \
              win:$(WINESTRIP)/shcore.dll=windows/system32/shcore.dll \
              win:$(WINE_INF_AUDIO)=windows/inf/wine.inf
AUDIO_PAYLOAD := $(WINESTRIP_AUDIO_DLLS) $(WINESTRIP_ACM_FILES) $(WINEVSND) $(WINESTRIP)/atl100.dll \
                 $(WINESTRIP)/shlwapi.dll $(WINESTRIP)/shcore.dll $(WINE_INF_AUDIO)

audio-payload: $(AUDIO_PAYLOAD)
.PHONY: audio-payload

print-audiofiles:
	@printf '%s\n' $(AUDIOFILES)
.PHONY: print-audiofiles

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

wasapi-smoke: $(WASAPISMOKE)
.PHONY: wasapi-smoke

# The AUD-1 image (tests/run/run.sh audio): the standard image plus
# aud_smoke.exe, whose presence makes smss run it as the session's
# foreground (user/smss/session.c). The virtio-snd device and the wav
# audiodev are the LEG's, not the image's — one image, run-time devices,
# the HACK-006 spirit.
IMG_AUDIO := $(BUILD)/proskrnl-audio.hdd
$(IMG_AUDIO): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(AUDSMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_AUDIO) $(MODULE_SPECS) $(WINFILES) \
	    win:$(AUDSMOKE)=aud_smoke.exe

audio-img: $(IMG_AUDIO)
.PHONY: audio-img

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

$(W32U_BUILD)/glue/%.o: user/wine/%.c $(FT_SYMS)
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) -I$(WSRV_DIR)/common \
	    -Iuser/wine/dlls/winefb.drv -c $< -o $@

# The compositor unit suite (tests/run/run.sh winefbunit): the SAME
# compose.o/blit.o the win32u.dll link uses, a mocked seam for everything
# they reach (tests/winefb/winefb_mocks.c -- server queries, surfaces,
# scanout, invalidation recorder), gdi32 as the region engine, the ntapi
# harness for the verdict. Runs under the pinned wine in about a second;
# every compositor POLICY bug is pinned here rather than in a QEMU leg.
WINEFB_UNIT := $(BUILD)/tests/winefb_unit.exe
WINEFB_UNIT_DRV := $(W32U_BUILD)/glue/dlls/winefb.drv/compose.o \
                   $(W32U_BUILD)/glue/dlls/winefb.drv/blit.o
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
	@# state machine left this DLL: nothing failed, guiwtest just died with no
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
	    -I$(WSRV_DIR)/common -c $< -o $@

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
# instead of depending on an IMG_* rule (tests/run/run.sh guiwtest): without
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

GUI2FILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(WINEMINE)=winemine.exe

# The GUI-2 image (tests/run/run.sh gui2): the standard image plus the Wine
# GUI stack and winemine.exe, whose presence makes the boot run it
# (user/smss/session.c). gui_smoke.exe is deliberately NOT here -- the two
# GUI legs stay disjoint, each convicted by its own client.
#
# The server ships here like it does on every other win32u image (GUI-3
# onward). Until this change it did not, and that ABSENCE was the only thing
# keeping win32u's in-process dispatch mode alive: the mode was probed from
# whether wineserver-lite.exe was on the volume, so this one image was the
# sole remaining caller of an arrangement GUI-3 superseded. What the leg
# convicts is unchanged and is why it stays -- it is the only leg running a
# STOCK unmodified Wine applet end to end onto the scanout, where gui3/4/5
# run purpose-built clients that report. It now convicts that over the
# arrangement the system actually ships.
IMG_GUI2 := $(BUILD)/proskrnl-gui2.hdd
$(IMG_GUI2): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) $(WINEMINE) \
        $(WINESERVER_LITE) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI2) $(MODULE_SPECS) $(WINFILES) $(GUI2FILES)

gui2-img: $(IMG_GUI2)
.PHONY: gui2-img

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

# The gui2 payload minus winemine, plus the server and the two clients.
GUI3FILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(GUI3A)=gui3a.exe \
             win:$(GUI3B)=gui3b.exe

IMG_GUI3 := $(BUILD)/proskrnl-gui3.hdd
$(IMG_GUI3): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(GUI3A) $(GUI3B) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI3) $(MODULE_SPECS) $(WINFILES) $(GUI3FILES)

gui3-img: $(IMG_GUI3)
.PHONY: gui3-img

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

GUI4FILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(GUI4A)=gui4a.exe \
             win:$(GUI4B)=gui4b.exe

IMG_GUI4 := $(BUILD)/proskrnl-gui4.hdd
$(IMG_GUI4): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(GUI4A) $(GUI4B) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI4) $(MODULE_SPECS) $(WINFILES) $(GUI4FILES)

gui4-img: $(IMG_GUI4)
.PHONY: gui4-img

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

GUI5FILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(GUI5A)=gui5a.exe \
             win:$(GUI5B)=gui5b.exe \
             win:$(FONTDIFF)=fontdiff.exe

IMG_GUI5 := $(BUILD)/proskrnl-gui5.hdd
$(IMG_GUI5): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(GUI5A) $(GUI5B) $(FONTDIFF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI5) $(MODULE_SPECS) $(WINFILES) $(GUI5FILES)

gui5-img: $(IMG_GUI5)
.PHONY: gui5-img

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

WOW64_GUI_PAYLOAD := $(WOW64_GUI_DLLS) $(WOW64_APPLET_EXES) $(WOW64GUI) \
                     $(WINESTRIP32)/comctl32_v6.dll $(WINESTRIP32)/common-controls.manifest
WOW64GUIFILES := $(foreach d,$(WOW64_GUI_NAMES),win:$(WINESTRIP32)/$(d).dll=windows/syswow64/$(d).dll) \
                 $(foreach p,$(WOW64_APPLET_EXE_NAMES),win:$(WINESTRIP32)/$(p).exe=windows/syswow64/$(p).exe) \
                 win:$(WINESTRIP32)/comctl32_v6.dll=$(SXS_CC_DIR32)/comctl32.dll \
                 win:$(WINESTRIP32)/common-controls.manifest=windows/winsxs/manifests/$(notdir $(SXS_CC_DIR32)).manifest \
                 win:$(WOW64GUI)=wow64gui.exe

# GUI-5, the windowed conhost (tests/run/run.sh gui5con): an INTERACTIVE
# image (GUEST_INTERACTIVE=1 on the QEMU command line, tools/qemu.sh) — the
# full Wine userland + cmd.exe, exactly the make-run recipe — plus the GUI
# stack, the desktop server, and the
# ---------------------------------------------------------------------------
# The shell payload, shared by every explorer-bearing image (gui5con below --
# `make rungui` -- and gui6): explorer.exe at the exact path win32u's
# auto-launch hardcodes (dlls/win32u/winstation.c get_desktop_window), whose
# presence is also what turns the wineserver-lite desktop fixtures OFF
# (shim.c probe_explorer); atl100, the actual registrar behind every Wine
# DllRegisterServer (winecrt0's __wine_register_resources loads atl100.dll
# for AtlCreateRegistrar; absent, shell32's registration answers a silent
# E_NOINTERFACE and CLSID_ExplorerBrowser never lands in the hive); and a
# wine.inf staged WITH its RegisterDlls directive (the shared $(WINE_INF)
# drops it -- on a CUI disk self-registration only had GUI DLLs to miss).
# Here shell32 IS baked and its COM classes are load-bearing: explorer's
# file window is shell32's IExplorerBrowser, which exists only if
# DllRegisterServer ran at firstboot. Of the section's 30 entries exactly
# shell32.dll is on these images (measured); the rest fail LoadLibrary and
# are skipped one by one (setupapi do_register_dll -- a skip, not an
# abort). The inf spec overrides $(WINFILES)'s copy by mcopy -o ordering,
# the gui5con conhost precedent below.
EXPLORER_EXE := $(WINESTRIP)/explorer.exe
$(eval $(call WINESTRIP_EXE_RULE,explorer))
$(eval $(call WINESTRIP_RULE,atl100))

WINE_INF_SHELL := $(BUILD)/wine-proskrnl-shell.inf
$(WINE_INF_SHELL): third_party/wine/loader/wine.inf tools/filter_inf.py
	@mkdir -p $(dir $@)
	python3 tools/filter_inf.py --keep RegisterDlls third_party/wine/loader/wine.inf $@

SHELLFILES := win:$(EXPLORER_EXE)=windows/system32/explorer.exe \
              win:$(WINESTRIP)/atl100.dll=windows/system32/atl100.dll \
              win:$(WINE_INF_SHELL)=windows/inf/wine.inf
SHELL_PAYLOAD := $(EXPLORER_EXE) $(WINESTRIP)/atl100.dll $(WINE_INF_SHELL)

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
# WOW64 shelf above — which is why this rides on the wow64-enabled gui5con
# image and not on GUI-2's. Its import table names 13 DLLs; the 32-bit
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

GUI5CONFILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(CONHOST_GUI)=windows/system32/conhost.exe \
             win:$(CMD)=windows/system32/cmd.exe \
             win:$(LOOPER)=looper.exe \
             $(APPLETFILES) \
             $(SHELLFILES) \
             $(WOW64GUESTFILES) $(WOW64HOSTFILES) $(WOW64GUIFILES) \
             $(FLASHFILES)

# 128 MiB rather than the default 64: this is the one image carrying both
# bitnesses of the whole shelf, and the 32-bit half does not fit in what the
# 64-bit half leaves (measured — 12 MiB free before, 32 MiB wanted). The ESP
# still starts at sector 4096, so the fixed offset every reader uses
# (tests/run/run.sh, tools/qemu.sh) is unchanged.
IMG_GUI5CON := $(BUILD)/proskrnl-gui5con.hdd
$(IMG_GUI5CON): $(KERNEL) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(CONHOST_GUI) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(CMD) $(LOOPER) \
        $(SHELL_PAYLOAD) \
        $(WINESTRIP_APPLET_DLLS) $(WINESTRIP_APPLET_EXES) $(WINEMINE) \
        $(WINESTRIP)/comctl32_v6.dll $(WINESTRIP)/common-controls.manifest \
        $(WOW64_GUEST_PAYLOAD) $(WOW64_GUI_PAYLOAD) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf $(FLASHPRESENT) $(FLASH_DLLS) $(FLASH_FIXTURES) $(FLASH_REG)
	SIZE_MB=128 tools/mkimage.sh $(KERNEL) $(IMG_GUI5CON) $(WINFILES) $(GUI5CONFILES)

gui5con-img: $(IMG_GUI5CON)
.PHONY: gui5con-img

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
# gui6.flag selects the smss leg (user/smss/session.c SessionGuiLegs), which
# launches explorer /desktop=shell,WxH with a trailing
# `explorer.exe C:\shelf` -- the desktop, then the file window as
# explorer's own CreateProcessW child.
$(BUILD)/gui6.flag:
	@mkdir -p $(BUILD)
	@echo "gui6 leg marker (user/smss/session.c SessionGuiLegs)" > $@

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

GUI6FILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             $(SHELLFILES) \
             win:$(WINESTRIP)/shell32.dll=windows/system32/shell32.dll \
             win:$(WINESTRIP)/shlwapi.dll=windows/system32/shlwapi.dll \
             win:$(WINESTRIP)/shcore.dll=windows/system32/shcore.dll \
             win:$(WINESTRIP)/oleaut32.dll=windows/system32/oleaut32.dll \
             win:$(WINESTRIP)/uxtheme.dll=windows/system32/uxtheme.dll \
             win:$(WINESTRIP)/comctl32_v6.dll=$(SXS_CC_DIR)/comctl32.dll \
             win:$(WINESTRIP)/common-controls.manifest=windows/winsxs/manifests/$(notdir $(SXS_CC_DIR)).manifest \
             win:$(BUILD)/shelf/readme.txt=shelf/readme.txt \
             win:$(BUILD)/shelf/desktop-notes.txt=shelf/desktop-notes.txt \
             win:$(BUILD)/gui6.flag=gui6.flag

# 128 MiB like gui5con: shell32 and friends do not fit in what the base
# payload leaves of 64. The ESP still starts at sector 4096 (fixed offset).
IMG_GUI6 := $(BUILD)/proskrnl-gui6.hdd
$(IMG_GUI6): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(SHELL_PAYLOAD) \
        $(WINESTRIP)/shell32.dll $(WINESTRIP)/shlwapi.dll $(WINESTRIP)/shcore.dll \
        $(WINESTRIP)/oleaut32.dll $(WINESTRIP)/uxtheme.dll \
        $(WINESTRIP)/comctl32_v6.dll $(WINESTRIP)/common-controls.manifest \
        $(GUI6_SHELF) $(BUILD)/gui6.flag \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	SIZE_MB=128 tools/mkimage.sh $(KERNEL) $(IMG_GUI6) $(MODULE_SPECS) $(WINFILES) $(GUI6FILES)

gui6-img: $(IMG_GUI6)
.PHONY: gui6-img

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

$(WTESTS)/ws2_32_test.exe: $(WT_WS2_32_OBJS) tests/winetest/glue/user32_stubs.c \
        tests/winetest/glue/iphlpapi_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_WS2_32_OBJS) tests/winetest/glue/user32_stubs.c \
	    tests/winetest/glue/iphlpapi_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WINE_PE)/ws2_32/x86_64-windows/libws2_32.a \
	    $(WT_LIBS) -Wl,--end-group -lgcc -o $@

wtests: $(WTESTS)/ntdll_test.exe $(WTESTS)/kernel32_test.exe $(WTESTS)/msvcrt_test.exe \
    $(WTESTS)/ucrtbase_test.exe $(WTESTS)/cmd.exe_test.exe $(WTESTS)/ws2_32_test.exe \
    $(WTESTS)/mmdevapi_test.exe $(WTESTS)/winmm_test.exe
.PHONY: wtests

# The headless test boot (docs/08): the standard image's full [KTEST] suite,
# verdict grepped off the serial log by tools/qemu.sh, then kmtcheck (that
# grep names ONE line, so every suite reporting after it needs its verdict
# read too), uacheck (a ring-0 fault on a user address is a defect the
# recovery frame would otherwise turn into a plain STATUS_ACCESS_VIOLATION —
# issue #32 A3), symcheck (the symbolizer still resolves this boot's dumps —
# Art. 9) and the external FAT oracle (fsck.fat + fatsweep + mtools
# byte-compares) on the mutated image — make stops on a failed boot, so all
# four only judge runs whose primary verdict passed.
test: $(IMG)
	tools/qemu.sh $(IMG)
	tests/run/kmtcheck.sh $(BUILD)/serial.log
	tests/run/uacheck.sh $(BUILD)/serial.log
	tests/run/symcheck.sh $(BUILD)/serial.sym.log
	tests/run/fatcheck.sh verify test $(IMG)

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
test-hostqemu: $(IMG)
	QEMU=qemu-system-x86_64 tools/qemu.sh $(IMG)
.PHONY: test-hostqemu

# The interactive boot: the Wine userland + cmd.exe + the CUI apps. What makes
# it interactive is the QEMU command line (GUEST_INTERACTIVE=1 below, read
# through fw_cfg — kernel/init/main.c KiIsInteractiveBoot), not anything on
# the image; the same image booted without it runs the ordinary session. No
# m9_echo (that blocker belongs to the scripted console test) and no test boot
# modules. Serial is your terminal: type at the prompt; `exit` powers the VM
# off; Ctrl-A x kills QEMU.
IMG_RUN := $(BUILD)/proskrnl-run.hdd
$(IMG_RUN): $(KERNEL) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(CMD) $(HELLOCRT) $(UPCASE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) \
        tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_RUN) $(WINFILES) \
	    win:$(CMD)=windows/system32/cmd.exe \
	    win:$(HELLOCRT)=hello_crt.exe \
	    win:$(UPCASE)=upcase.exe

# CUI-3: a resident SCM under no-eviction/no-COW (Art. 3) needs the same
# provisioning the winetest leg always used.
run: $(IMG_RUN)
	INTERACTIVE=1 GUEST_INTERACTIVE=1 MEM=$${MEM:-1024M} tools/qemu.sh $(IMG_RUN)

# GUI-5: the interactive command prompt — the gui5con image (windowed
# conhost + cmd.exe over the whole GUI stack) with a host window on the
# scanout and a virtio keyboard + tablet: click the console, type, `exit`
# powers the VM off. Serial stays on the terminal carrying the kernel's
# lines (HACK-004's permanent debug role).
rungui: $(IMG_GUI5CON)
	INTERACTIVE=1 GUEST_INTERACTIVE=1 GUI_DISPLAY=1 MEM=$${MEM:-1024M} \
	    EXTRA_DEVICES="virtio-keyboard-pci virtio-tablet-pci" tools/qemu.sh $(IMG_GUI5CON)
.PHONY: rungui

# GUI-2's winemine boot, kept under its own name (rungui's old target).
rungui2: $(IMG_GUI2)
	INTERACTIVE=1 GUI_DISPLAY=1 MEM=$${MEM:-1024M} tools/qemu.sh $(IMG_GUI2)
.PHONY: rungui2

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
gen-check:
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
	@tools/tidy.sh $(CLANG_TIDY) "$(CFLAGS)" $(filter-out drivers/net/% drivers/afd.c,$(CSRC))
	@tools/tidy.sh $(CLANG_TIDY) "$(CFLAGS) $(LWIP_INCLUDES)" $(filter drivers/net/% drivers/afd.c,$(CSRC))
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

.PHONY: all test run clean format gen-abi gen-nls gen-check frontier frontier-check

# Header dependency files emitted by -MMD (see DEPFLAGS).
-include $(OBJ:.o=.d)
