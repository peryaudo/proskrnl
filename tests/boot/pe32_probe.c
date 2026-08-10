/* tests/boot/pe32_probe.c — a real PE32 (i386) image for the kernel's image
 * parser to chew on (WOW64 milestone, docs/02).
 *
 * Unlike pe_smoke.exe this is never RUN: it rides the RAM disk as an initrd
 * file so kernel/mm's parser and relocation engine have a genuine 32-bit
 * container to be tested against (tests/kmt/m5_section.c). Running it would
 * need the whole WOW64 process path; parsing it needs only the file.
 *
 * Built with i686-w64-mingw32-gcc (see the Makefile). The absolute pointer
 * in .data is the point: it forces the linker to emit a .reloc directory
 * with an IMAGE_REL_BASED_HIGHLOW fixup, which is the 32-bit relocation the
 * kmt case checks the engine applies — and it makes the image's ImageBase
 * writeback observable, the field whose width differs between PE32 and
 * PE32+ (kernel/mm/section.c).
 */

static int reloc_anchor = 0x5a5a5a5a;
int *volatile pe32_reloc_pointer = &reloc_anchor;

/* No CRT and never entered; the linker still wants an entry symbol. */
int pe_start(void)
{
    return *pe32_reloc_pointer;
}
