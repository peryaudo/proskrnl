/* user/init-tests/user.ld — flat-binary layout for M4 user clients.
 *
 * The kernel maps a boot module at PSP_IMAGE_BASE (0x400000) and jumps to its
 * first byte (kernel/ps: "its entry point is its first byte"). So _start must
 * be at offset 0 — crt0.o leads the link — and the whole image is one
 * contiguous run from 0x400000. There is no PE header yet (M5/M7); this is a
 * raw binary via llvm-objcopy -O binary. .bss input sections are placed in
 * the PROGBITS .data output so their zero bytes are genuinely emitted: a
 * standalone .bss output would stay NOBITS and objcopy -O binary would
 * truncate it, leaving any static past the file tail unmapped at run time
 * (faults the moment a test carries more than a page-tail of statics —
 * caught by sem_mm/section_stress). */
ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : { *(.text._start) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) }
    . = ALIGN(16);
    _end = .;

    /DISCARD/ : { *(.note.* .comment .eh_frame .eh_frame_hdr) }
}
