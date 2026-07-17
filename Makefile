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
          -I. -Ithird_party/limine

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
        arch/x86_64/serial.c \
        arch/x86_64/idt.c \
        arch/x86_64/lapic.c \
        arch/x86_64/mmu.c \
        tests/kmt/m2_dispatcher.c
ASRC := arch/x86_64/trap.S \
        arch/x86_64/ctxswitch.S
OBJ  := $(CSRC:%.c=$(BUILD)/%.o) $(ASRC:%.S=$(BUILD)/%.o)

all: $(IMG)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL): $(OBJ) arch/x86_64/linker.ld
	@mkdir -p $(dir $@)
	$(LD) $(LDFLAGS) $(OBJ) -o $@

$(IMG): $(KERNEL) tools/mkimage.sh arch/x86_64/limine.conf
	tools/mkimage.sh $(KERNEL) $(IMG)

run: $(IMG)
	tools/qemu.sh $(IMG)

clean:
	rm -rf $(BUILD)

# Regenerate the abi/ contract headers from Wine's headers (Art. 4 / G4).
# Never hand-edit abi/ — this target is the only writer.
gen-abi:
	python3 tools/gen_abi.py

# Enforce the Win32/NT layout (docs/15). clang-format governs layout only;
# naming (PascalCase, NT prefixes) is on you and on review.
format:
	$(CLANG_FORMAT) -i $(shell find kernel arch -name '*.[ch]')

# Enforce the docs/15 naming rules (and correctness lints) via clang-tidy.
tidy:
	$(CLANG_TIDY) $(CSRC) -- $(CFLAGS)

.PHONY: all run clean format tidy gen-abi
