/* tests/boot/user.ld — flat-binary layout for M4 user clients.
 *
 * The kernel maps a boot module at PSP_IMAGE_BASE (0x400000) and jumps to its
 * first byte (kernel/ps: "its entry point is its first byte"). So _start must
 * be at offset 0 — crt0.o leads the link — and the whole image is one
 * contiguous run from 0x400000. There is no PE header yet (M5/M7); this is a
 * raw binary via llvm-objcopy -O binary. .bss input sections are placed in
 * the .data output so their zero bytes are genuinely emitted — but that
 * placement alone is NOT enough: when no real .data input exists, lld types
 * the all-.bss output section NOBITS anyway (a BYTE(0) data command does not
 * change that), objcopy -O binary truncates it, and any static past the
 * file tail is unmapped at run time. A client whose statics ended within
 * the last file page's slack survived by luck until a header reshuffle
 * pushed them across the page boundary (CUI-5: torn_workload's block
 * buffer landed exactly at file-end). The Makefile's
 * `--set-section-flags .data=alloc,load,contents` forces the section to
 * PROGBITS at objcopy time, so the zeros always reach the .bin. */
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
