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
        kernel/init/verify.c \
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
        kernel/ps/job.c \
        kernel/ps/atom.c \
        kernel/ps/display.c \
        kernel/se/token.c \
        kernel/se/sd.c \
        kernel/se/access.c \
        kernel/se/secobj.c \
        kernel/io/file.c \
        kernel/io/rw.c \
        kernel/io/async.c \
        kernel/io/query.c \
        kernel/io/lock.c \
        kernel/io/completion.c \
        kernel/cm/registry.c \
        kernel/cm/hive.c \
        kernel/syscall/table.c \
        kernel/syscall/uaccess.c \
        drivers/pci.c \
        drivers/virtio/pci.c \
        drivers/virtio/virtqueue.c \
        drivers/virtio/blk.c \
        drivers/virtio/input.c \
        drivers/condrv.c \
        drivers/fb.c \
        drivers/hid.c \
        fs/fat32/fat.c \
        fs/fat32/dir.c \
        fs/fat32/file.c \
        fs/npfs/pipe.c \
        kernel/io/ioctl.c \
        arch/x86_64/serial.c \
        arch/x86_64/rtc.c \
        arch/x86_64/smbios.c \
        arch/x86_64/idt.c \
        arch/x86_64/lapic.c \
        arch/x86_64/gdt.c \
        arch/x86_64/mmu.c \
        tests/kmt/lib.c \
        tests/kmt/m2_dispatcher.c \
        tests/kmt/m3_ob.c \
        tests/kmt/m4_usermode.c \
        tests/kmt/m5_section.c \
        tests/kmt/m6_io.c \
        tests/kmt/m6_blk.c \
        tests/kmt/fat_interop.c \
        tests/kmt/fat_churn.c
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
             $(BUILD)/modules/abi_probe.exe \
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

# The standing ABI-conformance probe (docs/08): a native PE asserting ring-3
# CONVENTIONS (entry-rsp alignment, FXSAVE seeds, header rebasing, id
# agreement, the cookie, KUSER_SHARED_DATA ticking) on every boot — run by
# kernel/init/main.c KiRunAbiProbe via the "abi" module cmdline. The entry
# stub captures the entry state before any compiler-generated code runs.
$(BUILD)/modules/abi_probe.exe: user/init-tests/abi_probe.c user/init-tests/abi_probe.S \
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
$(SMSS): user/smss/smss.c user/smss/firstboot.c user/smss/smss.h \
        $(WINE_PE)/ntdll/x86_64-windows/ntdll.dll
	@mkdir -p $(dir $@)
	$(MINGW) -std=c11 -ffreestanding -fno-builtin -nostdlib -nostartfiles \
	    -O1 -g0 -Wall -Wextra -I. -Wl,--entry=smss_start \
	    user/smss/smss.c user/smss/firstboot.c \
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
# carries only the standalone-PE glue: entry + mini-CRT (proskrnl_glue.c,
# shared with the windowed link) and the headless user32/window.c stand-ins
# (headless_stubs.c, this link only — the windowed CONHOST_GUI links the
# real user32 and the real window.c instead). Built like the other native
# PEs: mingw, no CRT, Wine import libraries.
WINE_CONHOST := third_party/wine/programs/conhost
CONHOST := $(BUILD)/modules/conhost.exe
$(CONHOST): $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/conhost.h \
            $(WINE_CONHOST)/proskrnl.c $(WINE_CONHOST)/proskrnl.h \
            user/conhost/proskrnl_glue.c user/conhost/headless_stubs.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINUSERAPI=' \
	    -I$(WINE_CONHOST) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=conhost_start \
	    $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/proskrnl.c user/conhost/proskrnl_glue.c \
	    user/conhost/headless_stubs.c \
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
            user/conhost/proskrnl_glue.c user/conhost/window_glue.c \
            user/wine/server/transport.h $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_CONHOST)/conhost.res \
	    $(BUILD)/conhost.res.o
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINCOMMCTRLAPI=' \
	    -I$(WINE_CONHOST) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=conhost_start \
	    $(WINE_CONHOST)/conhost.c $(WINE_CONHOST)/window.c $(WINE_CONHOST)/proskrnl.c \
	    user/conhost/proskrnl_glue.c user/conhost/window_glue.c $(BUILD)/conhost.res.o \
	    $(WINE_PE)/user32/x86_64-windows/libuser32.a \
	    $(WINE_PE)/gdi32/x86_64-windows/libgdi32.a \
	    $(WINE_PE)/advapi32/x86_64-windows/libadvapi32.a \
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

# CUI-4: Wine's tasklist.exe / taskkill.exe as standalone CUI PEs — the
# milestone's acceptance pair (docs/02 "a tasklist/taskkill pair works
# against live processes"). The pinned tree's own PE build provides the
# program objects and wrc-compiled resources UNMODIFIED; user/tasklist/ and
# user/taskkill/ supply only the wide CRT entry and the user32 imports
# (LoadStringW is a resource read; taskkill's window calls fail honestly —
# its /f path does not use them). Same recipe shape as cmd.exe above.
WINE_TASKLIST := third_party/wine/programs/tasklist
TASKLIST := $(BUILD)/modules/tasklist.exe
$(TASKLIST): user/tasklist/proskrnl_glue.c $(WINE_TASKLIST)/x86_64-windows/tasklist.o \
        $(WINE_TASKLIST)/tasklist.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_TASKLIST)/tasklist.res \
	    $(BUILD)/tasklist.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=tasklist_start \
	    $(WINE_TASKLIST)/x86_64-windows/tasklist.o user/tasklist/proskrnl_glue.c \
	    $(BUILD)/tasklist.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

WINE_TASKKILL := third_party/wine/programs/taskkill
TASKKILL := $(BUILD)/modules/taskkill.exe
$(TASKKILL): user/taskkill/proskrnl_glue.c $(WINE_TASKKILL)/x86_64-windows/taskkill.o \
        $(WINE_TASKKILL)/taskkill.res $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	x86_64-w64-mingw32-windres -J res -O coff $(WINE_TASKKILL)/taskkill.res \
	    $(BUILD)/taskkill.res.o
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=taskkill_start \
	    $(WINE_TASKKILL)/x86_64-windows/taskkill.o user/taskkill/proskrnl_glue.c \
	    $(BUILD)/taskkill.res.o \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: Wine's rundll32.exe as a standalone PE — wineboot --init's vehicle
# for the `setupapi,InstallHinfSection` children that apply wine.inf (ADR
# 0008's Cm integration exercise). The pinned tree's own PE build provides
# rundll32.o UNMODIFIED; user/rundll32/ supplies the wide CRT entry plus the
# four user32 imports as headless stand-ins (Art. 7: GUI path stays absent).
WINE_RUNDLL32 := third_party/wine/programs/rundll32
RUNDLL32 := $(BUILD)/modules/rundll32.exe
$(RUNDLL32): user/rundll32/proskrnl_glue.c $(WINE_RUNDLL32)/x86_64-windows/rundll32.o \
        $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -O1 -g0 -Wall -fno-builtin -nostdlib -nostartfiles \
	    -Wl,--entry=rundll32_start \
	    $(WINE_RUNDLL32)/x86_64-windows/rundll32.o \
	    user/rundll32/proskrnl_glue.c \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(WINE_PE)/kernel32/x86_64-windows/libkernel32.a \
	    $(WINE_PE)/kernelbase/x86_64-windows/libkernelbase.a \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a -lgcc -o $@

# CUI-1: wineboot.exe as a standalone PE. The pinned tree keeps
# programs/wineboot out of its PE build (x86_64_DISABLED_SUBDIRS, same as
# conhost), so wineboot.c is compiled DIRECTLY from the tree — the conhost
# recipe — with user/wineboot/ supplying the narrow CRT entry, the
# user32/gdi32 wait-window set, and honest-failure stand-ins for the
# shell32/shlwapi/ws2_32/wininet/newdev legs that degrade gracefully under
# --init (docs/02 CUI-1). setupapi/version/advapi32/rpcrt4/uuid link real:
# their DLLs are baked below. shutdown.c is not compiled — its three
# entry points are glue stubs, unreached under --init.
WINE_WINEBOOT := third_party/wine/programs/wineboot
WINEBOOT := $(BUILD)/modules/wineboot.exe
$(WINEBOOT): $(WINE_WINEBOOT)/wineboot.c user/wineboot/proskrnl_glue.c $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -std=gnu11 -fno-builtin -nostdlib -nostartfiles -O1 -g0 -Wall -DNDEBUG \
	    -D__WINESRC__ '-D_ACRTIMP=' '-DWINUSERAPI=' '-DWINGDIAPI=' '-DWINBASEAPI=' \
	    -I$(WINE_WINEBOOT) -Ithird_party/wine/include -Ithird_party/wine/include/msvcrt \
	    -Wl,--entry=wineboot_start \
	    $(WINE_WINEBOOT)/wineboot.c user/wineboot/proskrnl_glue.c \
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

$(IMG): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) $(RUNDLL32) $(WINEBOOT) \
        $(WINE_INF) $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) tools/mkimage.sh \
        arch/x86_64/limine.conf
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
	    win:$(TASKLIST)=windows/system32/tasklist.exe \
	    win:$(TASKKILL)=windows/system32/taskkill.exe

console-img: $(IMG_CONSOLE)
.PHONY: console-img

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
# wine_server_call (user/wine/server/). One GUI process, no wineserver
# (GUI-3 is where it becomes a process again).
#
# Nothing in third_party/wine is patched for any of this: user/wine/ carries
# the shims (POSIX headers mingw lacks), the glue (pthreads, the user-mode
# callback pair, ntdll's unix-side helpers) and the display driver. Deleting
# user/wine/ and the two drivers restores the CUI kernel (Art. 7).
WINE_W32U := third_party/wine/dlls/win32u
WINE_SRV  := third_party/wine/server
W32U_BUILD := $(BUILD)/win32u

# Everything in win32u's SOURCES except the two files that ARE the syscall
# boundary: main.c (the PE thunks this build replaces) and syscall.c (the
# service-table registration and the pthread-key thread info, both re-done in
# user/wine/win32u/glue.c).
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

# The glue, minus the server process's own main: user/wine/wineserver/ is
# the wineserver-lite.exe link, not part of the DLL (see WINESERVER_LITE).
W32U_GLUE_SRCS := $(filter-out user/wine/wineserver/%.c,$(wildcard user/wine/*/*.c))

W32U_OBJS := $(patsubst $(WINE_W32U)/%.c,$(W32U_BUILD)/w32u/%.o,$(W32U_SRCS)) \
             $(patsubst $(WINE_SRV)/%.c,$(W32U_BUILD)/srv/%.o,$(SRV_SRCS)) \
             $(patsubst user/wine/%.c,$(W32U_BUILD)/glue/%.o,$(W32U_GLUE_SRCS))

$(W32U_BUILD)/w32u/%.o: $(WINE_W32U)/%.c user/wine/include/wine/unixlib.h
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) -I$(WINE_W32U) -c $< -o $@

$(W32U_BUILD)/srv/%.o: $(WINE_SRV)/%.c
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) $(SRV_RENAME_FLAGS) -I$(WINE_SRV) -Iuser/wine/server -c $< -o $@

# The FreeType entry points freetype.c resolves by name, generated from its
# own MAKE_FUNCPTR list so a pin that starts calling a new one fails the
# build rather than the boot (Art. 4 / Art. 12).
FT_SYMS := $(W32U_BUILD)/prsk_freetype_syms.h
$(FT_SYMS): $(WINE_W32U)/freetype.c tools/gen_freetype_syms.py
	@mkdir -p $(dir $@)
	python3 tools/gen_freetype_syms.py $(WINE_W32U)/freetype.c $@

$(W32U_BUILD)/glue/%.o: user/wine/%.c $(FT_SYMS)
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) -Iuser/wine/server \
	    -Iuser/wine/winefb.drv -c $< -o $@

# The dispatch table is generated from the pinned tree's own request list and
# from which handlers actually linked: a request whose handler is not part of
# this build gets a NULL slot, which the shim turns into a named refusal
# (tools/gen_server_table.py, Art. 12).
SRV_OBJS := $(patsubst $(WINE_SRV)/%.c,$(W32U_BUILD)/srv/%.o,$(SRV_SRCS))
SRV_TABLE := $(W32U_BUILD)/prsk_request_table.c
# shim.o joins the generator's inputs (GUI-5): the shim may implement a
# handler whose OWNING server file is not compiled (get_process_idle_event
# lives in server/process.c, which is the process model this build leaves
# out) — the table must see those too, or a linked handler would still get
# a NULL slot.
$(SRV_TABLE): $(SRV_OBJS) $(W32U_BUILD)/glue/server/shim.o tools/gen_server_table.py \
        $(WINE_SRV)/request_handlers.h
	@mkdir -p $(dir $@)
	python3 tools/gen_server_table.py $(WINE_SRV)/request_handlers.h $@ $(SRV_OBJS) \
	    $(W32U_BUILD)/glue/server/shim.o

$(W32U_BUILD)/prsk_request_table.o: $(SRV_TABLE) user/wine/server/prsk_request_table.h
	$(MINGW) $(W32U_CFLAGS) -Iuser/wine/server -c $< -o $@

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
$(WIN32U): $(W32U_OBJS) $(W32U_BUILD)/prsk_request_table.o $(W32U_DEF) $(FREETYPE) \
           $(WINE_PE_DLLS)
	@mkdir -p $(dir $@)
	$(MINGW) -shared -nostdlib -nostartfiles -Wl,--entry=prsk_win32u_entry \
	    $(W32U_OBJS) $(W32U_BUILD)/prsk_request_table.o $(W32U_DEF) \
	    -Wl,--start-group \
	    $(WINE_PE)/ntdll/x86_64-windows/libntdll.a \
	    $(WINE_PE)/ucrtbase/x86_64-windows/libucrtbase.a \
	    $(FREETYPE) \
	    third_party/wine/libs/musl/x86_64-windows/libmusl.a \
	    third_party/wine/libs/winecrt0/x86_64-windows/libwinecrt0.a \
	    -Wl,--end-group -lgcc -o $@

win32u: $(WIN32U)
.PHONY: win32u

# wineserver-lite.exe (GUI-3, HACK-003): the same GUI object model, linked
# into a process of its own instead of into every GUI client.
#
# This is docs/06's keep-list build: a NEW link over the very same
# $(W32U_BUILD)/srv/*.o objects and the same generated request table the DLL
# uses -- not a stripped copy of server/, which would mutate the oracle's
# wineserver and corrupt the spec. Because the objects are literally shared,
# the two modes cannot drift into two state machines (Art. 11).
#
# What differs is only which halves come along: the server takes shim.c (the
# environment the state machine expects) and its own main.c, and leaves out
# call.c, which is the CLIENT half -- so the server carries no client of
# itself. The DLL takes call.c and leaves out main.c. SRV_RENAME_FLAGS is
# still applied because these are the same renamed objects.
WSRV_BUILD := $(W32U_BUILD)/wineserver
WSRV_SRCS  := $(wildcard user/wine/wineserver/*.c)
WSRV_OBJS  := $(patsubst user/wine/wineserver/%.c,$(WSRV_BUILD)/%.o,$(WSRV_SRCS)) \
              $(W32U_BUILD)/glue/server/shim.o $(W32U_BUILD)/glue/server/srv_glue.o

$(WSRV_BUILD)/%.o: user/wine/wineserver/%.c
	@mkdir -p $(dir $@)
	$(MINGW) $(W32U_CFLAGS) $(SRV_RENAME_FLAGS) -I. -I$(WINE_W32U) -I$(WINE_SRV) \
	    -Iuser/wine/server -c $< -o $@

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
             win:$(WINEMINE)=winemine.exe

# The GUI-2 image (tests/run/run.sh gui2): the standard image plus the Wine
# GUI stack and winemine.exe, whose presence makes the boot run it
# (kernel/init/main.c KiRunGui2). gui_smoke.exe is deliberately NOT here --
# the two GUI legs stay disjoint, each convicted by its own client.
IMG_GUI2 := $(BUILD)/proskrnl-gui2.hdd
$(IMG_GUI2): $(KERNEL) $(MODULES) $(HELLO) $(SMSS) $(CONHOST) $(M9SMOKE) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) $(WINEMINE) \
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

# GUI-5, the windowed conhost (tests/run/run.sh gui5con): an INTERACTIVE
# image — the full Wine userland + cmd.exe + interactive.flag, exactly the
# make-run recipe — plus the GUI stack, the desktop server, and the
# WINDOWED conhost overriding $(WINFILES)'s headless one (same destination,
# listed later; mkimage's mcopy -o makes the later spec win). looper.exe is
# the ^C acceptance's interruptible program (the CUI-4 actor, now
# interrupted through the window's own keyboard path instead of the serial
# hack).
GUI5CONFILES := win:$(WIN32U)=windows/system32/win32u.dll \
             $(foreach d,$(WINESTRIP_GUI_NAMES),win:$(WINESTRIP)/$(d).dll=windows/system32/$(d).dll) \
             $(FONTFILES) \
             win:$(WINESERVER_LITE)=windows/system32/wineserver-lite.exe \
             win:$(CONHOST_GUI)=windows/system32/conhost.exe \
             win:$(CMD)=windows/system32/cmd.exe \
             win:$(LOOPER)=looper.exe \
             win:$(BUILD)/interactive.flag=interactive.flag

IMG_GUI5CON := $(BUILD)/proskrnl-gui5con.hdd
$(IMG_GUI5CON): $(KERNEL) $(HELLO) $(SMSS) $(CONHOST) $(CONHOST_GUI) \
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) $(WIN32U) $(WINESTRIP_GUI_DLLS) \
        $(WINESERVER_LITE) $(CMD) $(LOOPER) $(BUILD)/interactive.flag \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(WINE_FONTS) tools/mkimage.sh \
        arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_GUI5CON) $(WINFILES) $(GUI5CONFILES)

gui5con-img: $(IMG_GUI5CON)
.PHONY: gui5con-img

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
# verdict grepped off the serial log by tools/qemu.sh, then the external FAT
# oracle (fsck.fat + fatsweep + mtools byte-compares) on the mutated image —
# make stops on a failed boot, so fatcheck only judges runs whose primary
# verdict passed.
test: $(IMG)
	tools/qemu.sh $(IMG)
	tests/run/fatcheck.sh verify test $(IMG)

# A WEAK second oracle for driver-vs-device-model assumptions (docs/08): the
# same boot under the host's QEMU instead of the pin. A divergence names a
# suspect (spec misreading vs. QEMU behavior); it convicts nothing (Art. 6)
# and never gates a PR. Host QEMU must still be >= 9.0 (qemu.sh enforces).
test-hostqemu: $(IMG)
	QEMU=qemu-system-x86_64 tools/qemu.sh $(IMG)
.PHONY: test-hostqemu

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
        $(RUNDLL32) $(WINEBOOT) $(WINE_INF) \
        $(WINE_PE_DLLS) $(WINESTRIP_DLLS) $(WINESTRIP_EXES) $(BUILD)/interactive.flag \
        tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG_RUN) $(WINFILES) \
	    win:$(CMD)=windows/system32/cmd.exe \
	    win:$(HELLOCRT)=hello_crt.exe \
	    win:$(UPCASE)=upcase.exe \
	    win:$(BUILD)/interactive.flag=interactive.flag

# CUI-3: a resident SCM under no-eviction/no-COW (Art. 3) needs the same
# provisioning the winetest leg always used.
run: $(IMG_RUN)
	INTERACTIVE=1 MEM=$${MEM:-1024M} tools/qemu.sh $(IMG_RUN)

# GUI-5: the interactive command prompt — the gui5con image (windowed
# conhost + cmd.exe over the whole GUI stack) with a host window on the
# scanout and a virtio keyboard + tablet: click the console, type, `exit`
# powers the VM off. Serial stays on the terminal carrying the kernel's
# lines (HACK-004's permanent debug role).
rungui: $(IMG_GUI5CON)
	INTERACTIVE=1 GUI_DISPLAY=1 MEM=$${MEM:-1024M} \
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
