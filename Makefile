# proskrnl — kernel build + thin superbuild (ADR 0009). Boot: Limine (ADR 0010).
#
#   make            build the bootable image (build/proskrnl.hdd)
#   make test       build + boot in QEMU, check the [KTEST] verdict on serial
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
CFLAGS := -std=c11 -target x86_64-unknown-none \
          -ffreestanding -fno-stack-protector -fno-stack-check \
          -fno-pie -fno-pic -m64 -march=x86-64 -mno-red-zone -mcmodel=kernel \
          -mno-mmx -mno-sse -mno-sse2 -mno-80387 \
          -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
          -fsanitize=undefined -fsanitize-trap=undefined \
          -O2 -g -Wall -Wextra -Wno-unused-parameter \
          -I. -Ithird_party/limine-protocol/include

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
        kernel/init/panic.c \
        kernel/init/trace.c \
        kernel/init/initrd.c \
        kernel/lib/dbgprint.c \
        kernel/lib/string.c \
        kernel/lib/rtl.c \
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
        kernel/mm/virtual.c \
        kernel/mm/section.c \
        kernel/mm/pecoff.c \
        kernel/mm/fault.c \
        kernel/mm/pagecache.c \
        kernel/ps/process.c \
        kernel/ps/thread.c \
        kernel/ps/peb.c \
        kernel/ps/usermode.c \
        kernel/ps/query.c \
        kernel/ps/atom.c \
        kernel/ps/display.c \
        kernel/io/file.c \
        kernel/io/rw.c \
        kernel/io/query.c \
        kernel/io/lock.c \
        kernel/io/completion.c \
        kernel/cm/registry.c \
        kernel/cm/hive.c \
        kernel/syscall/table.c \
        kernel/syscall/uaccess.c \
        drivers/pci.c \
        drivers/virtio/virtqueue.c \
        drivers/virtio/blk.c \
        drivers/condrv.c \
        fs/fat32/fat.c \
        fs/fat32/dir.c \
        fs/fat32/file.c \
        fs/npfs/pipe.c \
        kernel/io/ioctl.c \
        arch/x86_64/serial.c \
        arch/x86_64/idt.c \
        arch/x86_64/lapic.c \
        arch/x86_64/gdt.c \
        arch/x86_64/mmu.c \
        tests/kmt/lib.c \
        tests/kmt/m2_dispatcher.c \
        tests/kmt/m3_ob.c \
        tests/kmt/m4_usermode.c \
        tests/kmt/m5_section.c \
        tests/kmt/m6_io.c
ASRC := arch/x86_64/trap.S \
        arch/x86_64/ctxswitch.S \
        kernel/syscall/entry.S
OBJ  := $(CSRC:%.c=$(BUILD)/%.o) $(ASRC:%.S=$(BUILD)/%.o)

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
ULDFLAGS  := -m elf_x86_64 -static -T user/init-tests/user.ld --build-id=none

# crt0 must lead the link so _start lands at image offset 0 (user.ld).
USER_RT   := $(BUILD)/user/init-tests/crt0.o \
             $(BUILD)/user/init-tests/syscall_stubs.o
MODULES   := $(BUILD)/modules/alloc_wait.bin $(BUILD)/modules/crash.bin \
             $(BUILD)/modules/m8_persist.bin \
             $(BUILD)/modules/pe_smoke.exe $(BUILD)/modules/m7_smoke.exe \
             $(BUILD)/modules/sample.dat
# Each boot module is passed to mkimage as <binary>=<cmdline>; the kernel
# reads the cmdline as the module's expected outcome, or "initrd" for a
# RAM-disk data file that is registered but never run (kernel/init/main.c).
MODULE_SPECS := $(BUILD)/modules/alloc_wait.bin=expect=0 \
                $(BUILD)/modules/crash.bin=expect=av \
                $(BUILD)/modules/m8_persist.bin=expect=0 \
                $(BUILD)/modules/pe_smoke.exe=expect=0 \
                $(BUILD)/modules/m7_smoke.exe=m7 \
                $(BUILD)/modules/sample.dat=initrd

# --- M5 PE user client + RAM-disk seed data --------------------------------
# The PE client is a real PE32+ image the kernel loads through SEC_IMAGE
# sections (docs/02 M5 "Done when"). mingw provides the PE container;
# -mabi=sysv keeps the code on the SysV calling convention the generated
# syscall stubs use (the NT x64 convention arrives with the M7 ntdll stubs).
# --dynamicbase keeps the .reloc directory so the kmt relocation test has
# something to chew on.
MINGW ?= x86_64-w64-mingw32-gcc
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
$(BUILD)/user/init-tests/%.o: user/init-tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/user/init-tests/%.o: user/init-tests/%.S
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
$(BUILD)/user/init-tests/syscall_stubs.o: tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) -c $< -o $@

$(BUILD)/modules/%.bin: $(BUILD)/user/init-tests/%.o $(USER_RT) user/init-tests/user.ld
	@mkdir -p $(dir $@)
	$(LD) $(ULDFLAGS) $(USER_RT) $< -o $(@:.bin=.elf)
	$(OBJCOPY) -O binary $(@:.bin=.elf) $@

$(BUILD)/modules/pe_smoke.exe: user/init-tests/pe_smoke.c tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(MINGW) $(PECFLAGS) $^ -o $@

# The M7 PE client (docs/02 "Done when"): threads, PEB/TEB, the SEH test.
# --export-all-symbols gives the image an export directory so the kernel's
# loader can resolve KiUser{Exception,Apc}Dispatcher from it (as it will from
# ntdll) — kernel/ps/process.c PspResolveUserDispatchers.
$(BUILD)/modules/m7_smoke.exe: user/init-tests/m7_smoke.c user/init-tests/m7_dispatch.S \
                               tests/ntapi/syscall/syscall_stubs.S
	@mkdir -p $(dir $@)
	$(MINGW) $(PECFLAGS) -Wl,--export-all-symbols $^ -o $@

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
$(HELLO): user/hello/hello.c user/hello/hello_seh.S $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=hello_start \
	    user/hello/hello.c user/hello/hello_seh.S \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M8 smss-equivalent (docs/02): the initial user process — verifies the
# registry from ring 3, spawns hello.exe via NtCreateUserProcess, exits with
# the child's code. Same recipe as hello.exe: ntdll-only native PE.
SMSS := $(BUILD)/modules/smss.exe
$(SMSS): user/smss/smss.c $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=smss_start \
	    user/smss/smss.c \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M9 acceptance client (docs/02): threaded blocking pipes + a console
# write through kernelbase -> ConDrv -> conhost. Win32-level on purpose —
# it exercises the same kernelbase paths a real console app takes.
M9SMOKE := $(BUILD)/modules/m9_smoke.exe
$(M9SMOKE): user/m9/m9_smoke.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -Wl,--entry=m9_start \
	    user/m9/m9_smoke.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M9 interactive-echo client: baked ONLY into the console-mode image
# below (it blocks on console input, which the plain headless loop must
# never do).
M9ECHO := $(BUILD)/modules/m9_echo.exe
$(M9ECHO): user/m9/m9_echo.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -Wl,--entry=m9_start \
	    user/m9/m9_echo.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -o $@

# The M9 console server: Wine's conhost, compiled DIRECTLY from the pinned
# tree — the wineserver seam lives as a runtime-dormant fork commit on
# proskrnl-target (programs/conhost/proskrnl.{c,h}, taken when
# __wine_unix_call_dispatcher is NULL; Art. 10 / docs/06). user/conhost/
# carries only the standalone-PE glue: entry, mini-CRT, headless user32/
# window.c stands-ins. Built like the other native PEs: mingw, no CRT,
# Wine import libraries.
WINE_CONHOST := third_party/wine/programs/conhost
CONHOST := $(BUILD)/modules/conhost.exe
$(CONHOST): $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/conhost.h \
            $(WINE_CONHOST)/proskrnl.c $(WINE_CONHOST)/proskrnl.h \
            user/conhost/proskrnl_glue.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINUSERAPI=' \
	    -I$(WINE_CONHOST) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=conhost_start \
	    $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/proskrnl.c user/conhost/proskrnl_glue.c \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# M10: Wine's cmd.exe as a standalone CUI PE. The pinned tree's own PE build
# provides the four cmd objects and the wrc-compiled resources UNMODIFIED
# (programs/cmd/x86_64-windows, built by tools/setup_linux.sh); user/cmd/
# supplies only the glue — the CRT entry plus the five user32 / four shell32
# imports, stood in over ntdll/kernelbase (user32/shell32 are the M12 GUI
# path, additive and absent here per Art. 7). Links the real ucrtbase +
# advapi32 import libraries; both DLLs are baked (WINFILES below).
WINE_CMD := third_party/wine/programs/cmd
CMD := $(BUILD)/modules/cmd.exe
$(CMD): user/cmd/proskrnl_glue.c $(WINE_CMD)/x86_64-windows/wcmdmain.o \
        $(WINE_CMD)/x86_64-windows/builtins.o $(WINE_CMD)/x86_64-windows/batch.o \
        $(WINE_CMD)/x86_64-windows/directory.o $(WINE_CMD)/cmd.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_CMD)/cmd.res $(BUILD)/cmd.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=cmd_start \
	    $(WINE_CMD)/x86_64-windows/wcmdmain.o $(WINE_CMD)/x86_64-windows/builtins.o \
	    $(WINE_CMD)/x86_64-windows/batch.o $(WINE_CMD)/x86_64-windows/directory.o \
	    user/cmd/proskrnl_glue.c $(BUILD)/cmd.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

WINFILES := win:$(WINE_PE)/ntdll/x86_64-windows/ntdll.dll=windows/system32/ntdll.dll \
            win:$(WINE_PE)/kernel32/x86_64-windows/kernel32.dll=windows/system32/kernel32.dll \
            win:$(WINE_PE)/kernelbase/x86_64-windows/kernelbase.dll=windows/system32/kernelbase.dll \
            win:$(WINE_PE)/msvcrt/x86_64-windows/msvcrt.dll=windows/system32/msvcrt.dll \
            win:$(WINE_PE)/ucrtbase/x86_64-windows/ucrtbase.dll=windows/system32/ucrtbase.dll \
            win:$(WINE_PE)/advapi32/x86_64-windows/advapi32.dll=windows/system32/advapi32.dll \
            win:$(WINE_PE)/sechost/x86_64-windows/sechost.dll=windows/system32/sechost.dll \
            win:$(WINE_PE)/rpcrt4/x86_64-windows/rpcrt4.dll=windows/system32/rpcrt4.dll \
            win:$(WINE_PE)/version/x86_64-windows/version.dll=windows/system32/version.dll \
            win:$(WINE_PE)/cryptbase/x86_64-windows/cryptbase.dll=windows/system32/cryptbase.dll \
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

$(IMG): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(WINE_PE_DLLS) \
        tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG) $(MODULE_SPECS) $(WINFILES)

# M10: the MSVC-stand-in CUI apps — plain mingw with its FULL CRT (they
# import msvcrt.dll + kernel32.dll; third-party CRT startup against the
# baked Wine userland). Only the console image carries them.
HELLOCRT := $(BUILD)/modules/hello_crt.exe
$(HELLOCRT): tests/cui/hello_crt.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<
UPCASE := $(BUILD)/modules/upcase.exe
$(UPCASE): tests/cui/upcase.c
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-gcc -O1 -g0 -Wall -o $@ $<

# The M9 interactive-console image (tests/run/run.sh console): the standard
# image plus m9_echo.exe, whose presence makes the boot block on console
# input after the M9 verdict (kernel/init/main.c KiRunM9Echo) — and, M10,
# cmd.exe plus the CUI apps for the interactive cmd session that follows
# (KiRunCmdConsole).
IMG_CONSOLE := $(BUILD)/proskrnl-console.hdd
$(IMG_CONSOLE): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(M9ECHO) \
        $(CMD) $(HELLOCRT) $(UPCASE) $(WINE_PE_DLLS) tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_CONSOLE) $(MODULE_SPECS) $(WINFILES) \
	    win:$(M9ECHO)=m9_echo.exe \
	    win:$(CMD)=windows/system32/cmd.exe \
	    win:$(HELLOCRT)=hello_crt.exe \
	    win:$(UPCASE)=upcase.exe

console-img: $(IMG_CONSOLE)
.PHONY: console-img

# ---------------------------------------------------------------------------
# M10 stretch (docs/02 "Ideal regression"): standalone binaries for the CUI
# subset of Wine's own test suite, run by tests/run/run.sh winetest against
# the curated manifest (tests/winetest/manifest.txt) on BOTH the oracle and
# proskrnl. Same discipline as cmd.exe above: the pinned tree's own PE test
# objects (built by tools/setup_linux.sh) are linked UNMODIFIED; the CRT
# entry is the implib's own mainCRTStartup (dlls/msvcrt/crt_main.c — the
# entry winegcc itself picks for CRT exes), so the only glue is
# user/wtest/user32_stubs.c standing in the user32 imports the ntdll and
# kernel32 test objects reference (user32 is the M12 GUI path, off the image
# per Art. 7; subtests whose assertions need the real user32 fail identically
# on both runners and stay off the manifest).
WTESTS := $(BUILD)/wtests
WT_LINK := $(MINGW) -std=gnu11 -O1 -g0 -fno-builtin -nostdlib -nostartfiles \
    -Wl,--entry=mainCRTStartup
WT_GLUE := user/wtest/crt_sections.c
WT_LIBS := third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a
WT_CRT_MSVCRT := $(WINE_PE)/msvcrt/x86_64-windows/libmsvcrt.a
WT_CRT_UCRT := $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a

# Test objects per module: every SOURCES entry of the dir's Makefile.in plus
# the makedep-generated testlist.o, MINUS the .spec helper-DLL objects
# (testdll/dummy/threaddll — separate runtime-loaded modules; the subtests
# that load them stay off the manifest).
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

$(WT_NTDLL_OBJS) $(WT_KERNEL32_OBJS) $(WT_MSVCRT_OBJS) $(WT_UCRTBASE_OBJS) $(WT_CMD_OBJS):
	@echo "error: $@ missing - build the pinned Wine test modules first (tools/setup_linux.sh)" >&2
	@exit 1

$(WTESTS)/ntdll_test.exe: $(WT_NTDLL_OBJS) user/wtest/user32_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_NTDLL_OBJS) user/wtest/user32_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/kernel32_test.exe: $(WT_KERNEL32_OBJS) third_party/wine/dlls/kernel32/tests/resource.res \
        user/wtest/user32_stubs.c $(WT_GLUE)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff third_party/wine/dlls/kernel32/tests/resource.res \
	    $(WTESTS)/kernel32_resource.res.o
	$(WT_LINK) $(WT_KERNEL32_OBJS) $(WTESTS)/kernel32_resource.res.o \
	    user/wtest/user32_stubs.c $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/msvcrt_test.exe: $(WT_MSVCRT_OBJS) $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_MSVCRT_OBJS) $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/ucrtbase_test.exe: $(WT_UCRTBASE_OBJS) $(WT_GLUE)
	@mkdir -p $(dir $@)
	$(WT_LINK) $(WT_UCRTBASE_OBJS) $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_UCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

$(WTESTS)/cmd.exe_test.exe: $(WT_CMD_OBJS) third_party/wine/programs/cmd/tests/rsrc.res $(WT_GLUE)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff third_party/wine/programs/cmd/tests/rsrc.res \
	    $(WTESTS)/cmd_rsrc.res.o
	$(WT_LINK) $(WT_CMD_OBJS) $(WTESTS)/cmd_rsrc.res.o $(WT_GLUE) \
	    -Wl,--start-group $(WT_CRT_MSVCRT) $(WT_LIBS) -Wl,--end-group -lgcc -o $@

wtests: $(WTESTS)/ntdll_test.exe $(WTESTS)/kernel32_test.exe $(WTESTS)/msvcrt_test.exe \
    $(WTESTS)/ucrtbase_test.exe $(WTESTS)/cmd.exe_test.exe
.PHONY: wtests

# The headless test boot (docs/08): the standard image's full [KTEST] suite,
# verdict grepped off the serial log by tools/qemu.sh.
test: $(IMG)
	tools/qemu.sh $(IMG)

# The interactive boot: the Wine userland + cmd.exe + the CUI apps, plus the
# interactive.flag marker that makes the kernel skip the test suites and hand
# the serial console straight to cmd.exe (kernel/init/main.c
# KiRunInteractiveCmd). No m9_echo (that blocker belongs to the scripted
# console test) and no test boot modules. Serial is your terminal: type at
# the prompt; `exit` powers the VM off; Ctrl-A x kills QEMU.
IMG_RUN := $(BUILD)/proskrnl-run.hdd
$(BUILD)/interactive.flag:
	@mkdir -p $(BUILD)
	@echo "interactive boot marker (kernel/init/main.c KiIsInteractiveBoot)" > $@

$(IMG_RUN): $(KERNEL) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(CMD) $(HELLOCRT) $(UPCASE) \
        $(WINE_PE_DLLS) $(BUILD)/interactive.flag tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_RUN) $(WINFILES) \
	    win:$(CMD)=windows/system32/cmd.exe \
	    win:$(HELLOCRT)=hello_crt.exe \
	    win:$(UPCASE)=upcase.exe \
	    win:$(BUILD)/interactive.flag=interactive.flag

run: $(IMG_RUN)
	INTERACTIVE=1 tools/qemu.sh $(IMG_RUN)

clean:
	rm -rf $(BUILD)

# Regenerate the abi/ contract headers from Wine's headers (Art. 4 / G4).
# Never hand-edit abi/ — this target is the only writer.
gen-abi:
	python3 tools/gen_abi.py
	python3 tools/gen_syscalls.py

# Enforce the Win32/NT layout (docs/15). clang-format governs layout only;
# naming (PascalCase, NT prefixes) is on you and on review.
format:
	$(CLANG_FORMAT) -i $(shell find kernel arch drivers fs -name '*.[ch]')

# Enforce the docs/15 naming rules (and correctness lints) via clang-tidy.
tidy:
	$(CLANG_TIDY) $(CSRC) -- $(CFLAGS)

.PHONY: all test run clean format tidy gen-abi

# Header dependency files emitted by -MMD (see DEPFLAGS).
-include $(OBJ:.o=.d)
