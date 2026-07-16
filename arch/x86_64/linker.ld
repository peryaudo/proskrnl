/* proskrnl higher-half kernel link script (Limine, x86-64). ADR 0010.
 * Limine loads the ELF at -2GiB and enters at ENTRY in 64-bit long mode. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(KiSystemStartup)

PHDRS
{
    text    PT_LOAD FLAGS((1 << 0) | (1 << 2)); /* Execute + Read  */
    rodata  PT_LOAD FLAGS((1 << 2));            /* Read            */
    data    PT_LOAD FLAGS((1 << 1) | (1 << 2)); /* Write + Read    */
}

SECTIONS
{
    /* Top -2GiB: required for -mcmodel=kernel. */
    . = 0xffffffff80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* Limine scans these markers to find requests; keep order + presence. */
    .limine_requests : {
        KEEP(*(.limine_requests_start_marker))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end_marker))
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
        *(.comment)
    }
}
