#!/usr/bin/env python3
# symbolize.py — annotate serial-log addresses with symbols (Art. 9).
#
# The panic/assert/trace dumps print raw hex addresses (the kernel embeds no
# symbol table — the simplest thing that works, docs/09 Art. 3); the DWARF to
# resolve them already exists on the host in build/proskrnl and in each user
# module's .elf kept beside its .bin. This filter runs at display time
# (tools/qemu.sh pipes the log through it) and APPENDS "Name+0xoff (file:line)"
# after every address it can resolve, never replacing text — the raw log and
# every [KTEST]/[PANIC]/[ASSERT] grep contract stay byte-identical.
#
#   symbolize.py --kernel build/proskrnl [--moduledir build/modules ...] < log
#
# Degrades gracefully: missing ELFs or llvm tools mean the text passes through
# unchanged (exit 0), so the harness never fails because of the symbolizer.

import argparse
import bisect
import re
import shutil
import subprocess
import sys

# Kernel text lives in the -2 GiB code-model region (arch/x86_64/linker.ld:
# image base 0xffffffff80000000). Dumps print %#018lx, so a kernel address is
# always exactly "0xffffffff8" + 7 hex digits.
KERNEL_ADDR_RE = re.compile(r"0xffffffff8[0-9a-f]{7}\b")

# Flat user binaries link at PSP_IMAGE_BASE 0x400000 (kernel/ps/ps.h); only
# annotate them on lines that are user-dump output to avoid false hits.
USER_ADDR_RE = re.compile(r"0x0{10}[4-7][0-9a-f]{5}\b")
USER_LINE_RE = re.compile(r"\[USERFAULT\]|\[TRACE\]|^\s+u\[\d+\]")

# Return addresses point after the call site: symbolize addr-1 there so the
# annotation names the caller line, not the next one. Stack-trace entries and
# KASAN's "caller" are the return-address shapes the kernel prints.
RET_ADDR_LINE_RE = re.compile(r"^\s+u?\[\d+\]|caller ")

IMAGE_NAME_RE = re.compile(r"image[= ]'([^']+)'")


def load_exec_ranges(readelf, elf):
    """[start, end) of every executable section — llvm-symbolizer happily
    attributes .rodata addresses to the nearest (sizeless asm) text label,
    so only addresses inside these ranges get annotated at all."""
    try:
        out = subprocess.run([readelf, "--sections", "--wide", elf],
                             check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    ranges = []
    for line in out.splitlines():
        match = re.match(
            r"\s*\[\s*\d+\]\s+\S+\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+"
            r"([0-9a-f]+)\s+\S+\s+(\S+)", line)
        if match and "X" in match.group(3):
            start = int(match.group(1), 16)
            ranges.append((start, start + int(match.group(2), 16)))
    return ranges or None


def load_nm_symbols(nm, elf):
    """Sorted (address, name) list of defined text symbols, for +0xoff."""
    try:
        out = subprocess.run([nm, "-n", "--defined-only", elf], check=True,
                             capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    symbols = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t", "W", "w"):
            symbols.append((int(parts[0], 16), parts[2]))
    return symbols


class Resolver:
    def __init__(self, symbolizer, nm, readelf, elf):
        self.symbolizer = symbolizer
        self.elf = elf
        self.nm_symbols = load_nm_symbols(nm, elf)
        self.exec_ranges = load_exec_ranges(readelf, elf)
        self.cache = {}

    def resolve(self, address):
        """'Name+0xoff (file:line)' or None if the address has no symbol."""
        if address in self.cache:
            return self.cache[address]
        if self.exec_ranges is not None and not any(
                start <= address < end for start, end in self.exec_ranges):
            self.cache[address] = None
            return None
        annotation = None
        try:
            out = subprocess.run(
                [self.symbolizer, "--obj=" + self.elf, "--no-inlines",
                 "--functions", "--relativenames", "--output-style=GNU",
                 hex(address)],
                check=True, capture_output=True, text=True).stdout
            lines = [l for l in out.splitlines() if l.strip()]
            function = lines[0].strip() if lines else "??"
            location = lines[1].strip() if len(lines) > 1 else "??"
            if function not in ("??", ""):
                offset = ""
                index = bisect.bisect_right(self.nm_symbols,
                                            (address, "￿")) - 1
                if index >= 0 and self.nm_symbols[index][1] == function:
                    offset = "+%#x" % (address - self.nm_symbols[index][0])
                if location.startswith("??"):
                    annotation = "%s%s" % (function, offset)
                else:
                    location = location.split(" ")[0]  # drop discriminators
                    annotation = "%s%s (%s)" % (function, offset, location)
        except (OSError, subprocess.CalledProcessError):
            pass
        self.cache[address] = annotation
        return annotation


def find_module_elf(image_name, module_dirs):
    """The ELF linked beside a flat .bin ('crash.bin' -> crash.elf)."""
    if not image_name.endswith(".bin"):
        return None  # PE modules load at a dynamic base; skip
    stem = image_name[: -len(".bin")]
    for directory in module_dirs:
        candidate = "%s/%s.elf" % (directory, stem)
        try:
            with open(candidate, "rb"):
                return candidate
        except OSError:
            continue
    return None


def nearest_image_name(lines, index):
    """The image name of the dump block around line `index` (the
    "image '<name>'" line prints at the end of a [USERFAULT] dump)."""
    for line in lines[index : index + 24]:
        match = IMAGE_NAME_RE.search(line)
        if match:
            return match.group(1)
    for line in reversed(lines[max(0, index - 24) : index]):
        match = IMAGE_NAME_RE.search(line)
        if match:
            return match.group(1)
    return None


def annotate_line(line, addr_re, resolver, is_return_address):
    def replacement(match):
        address = int(match.group(0), 16)
        lookup = address - 1 if is_return_address and address > 0 else address
        annotation = resolver.resolve(lookup)
        if annotation is None:
            return match.group(0)
        return "%s %s" % (match.group(0), annotation)

    return addr_re.sub(replacement, line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", default="build/proskrnl")
    parser.add_argument("--moduledir", action="append", default=[])
    args = parser.parse_args()

    text = sys.stdin.read()
    lines = text.splitlines(keepends=True)

    symbolizer = shutil.which("llvm-symbolizer")
    nm = shutil.which("llvm-nm")
    readelf = shutil.which("llvm-readelf")
    if symbolizer is None or nm is None:
        sys.stdout.write(text)
        return 0

    kernel_resolver = None
    try:
        with open(args.kernel, "rb"):
            kernel_resolver = Resolver(symbolizer, nm, readelf, args.kernel)
    except OSError:
        pass
    module_resolvers = {}

    for index, line in enumerate(lines):
        is_return_address = RET_ADDR_LINE_RE.search(line) is not None
        if kernel_resolver is not None and KERNEL_ADDR_RE.search(line):
            line = annotate_line(line, KERNEL_ADDR_RE, kernel_resolver,
                                 is_return_address)
        if args.moduledir and USER_LINE_RE.search(line) \
                and USER_ADDR_RE.search(line):
            image = nearest_image_name(lines, index)
            if image is not None:
                if image not in module_resolvers:
                    elf = find_module_elf(image, args.moduledir)
                    module_resolvers[image] = (
                        Resolver(symbolizer, nm, readelf, elf) if elf
                        else None)
                resolver = module_resolvers[image]
                if resolver is not None:
                    line = annotate_line(line, USER_ADDR_RE, resolver,
                                         is_return_address)
        sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
