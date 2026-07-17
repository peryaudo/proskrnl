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

# Invoke the ELF ld.lld directly — the clang driver on a Darwin host defaults to
# the Mach-O ld64.lld flavor even for a bare-metal target.
LDFLAGS := -m elf_x86_64 -static -T arch/x86_64/linker.ld \
           -z max-page-size=0x1000 --build-id=none

CSRC := kernel/init/main.c \
        kernel/init/panic.c \
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
        kernel/ke/irq.c \
        kernel/ob/object.c \
        kernel/ob/handle.c \
        kernel/ob/namespace.c \
        kernel/ob/sync.c \
        kernel/ob/wait.c \
        kernel/mm/virtual.c \
        kernel/ps/process.c \
        kernel/ps/display.c \
        kernel/syscall/table.c \
        kernel/syscall/uaccess.c \
        arch/x86_64/serial.c \
        arch/x86_64/idt.c \
        arch/x86_64/lapic.c \
        arch/x86_64/gdt.c \
        arch/x86_64/mmu.c \
        tests/kmt/m2_dispatcher.c \
        tests/kmt/m3_ob.c \
        tests/kmt/m4_usermode.c
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
             -O2 -g -Wall -Wextra -Wno-unused-parameter -I.
ULDFLAGS  := -m elf_x86_64 -static -T user/init-tests/user.ld --build-id=none

# crt0 must lead the link so _start lands at image offset 0 (user.ld).
USER_RT   := $(BUILD)/user/init-tests/crt0.o \
             $(BUILD)/user/init-tests/syscall_stubs.o
MODULES   := $(BUILD)/modules/alloc_wait.bin $(BUILD)/modules/crash.bin
# Each boot module is passed to mkimage as <binary>=<cmdline>; the kernel
# reads the cmdline as the module's expected outcome (kernel/init/main.c).
MODULE_SPECS := $(BUILD)/modules/alloc_wait.bin=expect=0 \
                $(BUILD)/modules/crash.bin=expect=av

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

$(IMG): $(KERNEL) $(MODULES) tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG) $(MODULE_SPECS)

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
	$(CLANG_FORMAT) -i $(shell find kernel arch -name '*.[ch]')

# Enforce the docs/15 naming rules (and correctness lints) via clang-tidy.
tidy:
	$(CLANG_TIDY) $(CSRC) -- $(CFLAGS)

.PHONY: all run clean format tidy gen-abi

# Header dependency files emitted by -MMD (see DEPFLAGS).
-include $(OBJ:.o=.d)
