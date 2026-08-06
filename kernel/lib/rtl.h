/* kernel/lib/rtl.h — the little slice of Rtl the kernel needs (M3).
 *
 * Counted UTF-16 string helpers for the Ob namespace. Signatures per Wine's
 * winternl.h exports (docs/15: a real NT name keeps its real signature);
 * comparison is culture-free, upcasing ASCII only — object names the kernel
 * itself creates are ASCII, and NT's own upcase table is data we do not
 * carry (docs/03).
 */
#ifndef PROSKRNL_KERNEL_LIB_RTL_H
#define PROSKRNL_KERNEL_LIB_RTL_H

#include "abi/ntdef.h"

/* char16_t (2-byte) string literal; a plain u"..." prefix does not survive
 * clang-format, which splits it from the string. */
#define WSTR(s) u##s

/* ASCII-only upcase — the one authority for case folding in this kernel
 * (Art. 11): the Ob namespace, the I/O directory-mask matcher and the FAT32
 * name comparison all fold through it, so they cannot disagree about what
 * two names mean. NT folds through a 64 KiB upcase table we deliberately do
 * not carry (docs/03 "Name case folding"), so every character outside a-z
 * comes back unchanged. */
WCHAR RtlUpcaseUnicodeChar(WCHAR c);

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source);
BOOLEAN RtlEqualUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                              BOOLEAN caseInsensitive);
LONG RtlCompareUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                             BOOLEAN caseInsensitive);
void RtlCopyUnicodeString(UNICODE_STRING *target, const UNICODE_STRING *source);

/* The ONE answer to "is this already an 8.3 name" — see rtl.c for why it is
 * not fs/fat32's FatBuildExact83. Both out-params must be NULL. */
BOOLEAN RtlIsNameLegalDOS8Dot3(const UNICODE_STRING *name, POEM_STRING oemName,
                               PBOOLEAN spacesFound);

#endif /* PROSKRNL_KERNEL_LIB_RTL_H */
