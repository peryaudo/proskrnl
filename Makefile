# proskrnl — kernel build + thin superbuild (ADR 0009). Boot: Limine (ADR 0010).
#
#   make            build the bootable image (build/proskrnl.hdd)
#   make run        build + boot in QEMU, check the [KTEST] verdict on serial
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
        kernel/ps/display.c \
        kernel/io/file.c \
        kernel/io/rw.c \
        kernel/io/query.c \
        kernel/io/lock.c \
        kernel/syscall/table.c \
        kernel/syscall/uaccess.c \
        drivers/pci.c \
        drivers/virtio/virtqueue.c \
        drivers/virtio/blk.c \
        fs/fat32/fat.c \
        fs/fat32/dir.c \
        fs/fat32/file.c \
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
             $(BUILD)/modules/pe_smoke.exe $(BUILD)/modules/m7_smoke.exe \
             $(BUILD)/modules/sample.dat
# Each boot module is passed to mkimage as <binary>=<cmdline>; the kernel
# reads the cmdline as the module's expected outcome, or "initrd" for a
# RAM-disk data file that is registered but never run (kernel/init/main.c).
MODULE_SPECS := $(BUILD)/modules/alloc_wait.bin=expect=0 \
                $(BUILD)/modules/crash.bin=expect=av \
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

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(KASAN_FLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(KERNEL): $(OBJ) arch/x86_64/linker.ld
	@mkdir -p $(dir $@)
	$(LD) $(LDFLAGS) $(OBJ) -o $@

# User client objects (own flags; not the kernel's KASAN/kernel-cmodel build).
$(BUILD)/user/init-tests/%.o: user/init-tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD)/user/init-tests/%.o: user/init-tests/%.S
	@mkdir -p $(dir $@)
	$(CC) $(UCFLAGS) -c $< -o $@

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

WINFILES := win:$(WINE_PE)/ntdll/x86_64-windows/ntdll.dll=windows/system32/ntdll.dll \
            win:$(WINE_PE)/kernel32/x86_64-windows/kernel32.dll=windows/system32/kernel32.dll \
            win:$(WINE_PE)/kernelbase/x86_64-windows/kernelbase.dll=windows/system32/kernelbase.dll \
            win:$(WINE_NLS)/locale.nls=windows/system32/locale.nls \
            win:$(WINE_NLS)/l_intl.nls=windows/system32/l_intl.nls \
            win:$(WINE_NLS)/c_1252.nls=windows/system32/c_1252.nls \
            win:$(WINE_NLS)/c_437.nls=windows/system32/c_437.nls \
            win:$(WINE_NLS)/sortdefault.nls=windows/system32/sortdefault.nls \
            win:$(WINE_NLS)/normnfc.nls=windows/system32/normnfc.nls \
            win:$(WINE_NLS)/normnfd.nls=windows/system32/normnfd.nls \
            win:$(WINE_NLS)/normnfkc.nls=windows/system32/normnfkc.nls \
            win:$(WINE_NLS)/normnfkd.nls=windows/system32/normnfkd.nls \
            win:$(WINE_NLS)/normidna.nls=windows/system32/normidna.nls \
            win:$(HELLO)=hello.exe

$(IMG): $(KERNEL) $(MODULES) $(HELLO) $(WINE_PE_DLLS) tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG) $(MODULE_SPECS) $(WINFILES)

run: $(IMG)
	tools/qemu.sh $(IMG)

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

.PHONY: all run clean format tidy gen-abi

# Header dependency files emitted by -MMD (see DEPFLAGS).
-include $(OBJ:.o=.d)
