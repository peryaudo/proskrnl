/* kernel/lib/rtl.c — counted UTF-16 string helpers (M3). See rtl.h. */
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

void RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    target->Buffer = (PWSTR)source;
    if (source == 0)
    {
        target->Length = 0;
        target->MaximumLength = 0;
        return;
    }
    ULONG length = (ULONG)KiWideStringLength(source);
    ASSERT(length * sizeof(WCHAR) <= 0xFFFF - sizeof(WCHAR));
    target->Length = (USHORT)(length * sizeof(WCHAR));
    target->MaximumLength = (USHORT)(target->Length + sizeof(WCHAR));
}

WCHAR RtlUpcaseUnicodeChar(WCHAR c)
{
    if (c >= 'a' && c <= 'z')
    {
        return (WCHAR)(c - 'a' + 'A');
    }
    return c;
}

BOOLEAN RtlEqualUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                              BOOLEAN caseInsensitive)
{
    if (s1->Length != s2->Length)
    {
        return FALSE;
    }
    ULONG count = s1->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < count; i++)
    {
        WCHAR c1 = s1->Buffer[i];
        WCHAR c2 = s2->Buffer[i];
        if (caseInsensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* Ordering compare (M8: Cm keeps subkeys/values sorted). Signature per
 * wine/include/winternl.h; semantics as wine's own: char-by-char difference,
 * then the length difference. */
LONG RtlCompareUnicodeString(const UNICODE_STRING *s1, const UNICODE_STRING *s2,
                             BOOLEAN caseInsensitive)
{
    ULONG count1 = s1->Length / sizeof(WCHAR);
    ULONG count2 = s2->Length / sizeof(WCHAR);
    ULONG count = count1 < count2 ? count1 : count2;
    for (ULONG i = 0; i < count; i++)
    {
        WCHAR c1 = s1->Buffer[i];
        WCHAR c2 = s2->Buffer[i];
        if (caseInsensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
        {
            return (LONG)c1 - (LONG)c2;
        }
    }
    return (LONG)(s1->Length) - (LONG)(s2->Length);
}

void RtlCopyUnicodeString(UNICODE_STRING *target, const UNICODE_STRING *source)
{
    if (source == 0)
    {
        target->Length = 0;
        return;
    }
    USHORT length = source->Length;
    if (length > target->MaximumLength)
    {
        length = target->MaximumLength;
    }
    memcpy(target->Buffer, source->Buffer, length);
    target->Length = length;
    /* Append the terminator when there is room, exactly as the oracle does
     * (third_party/wine dlls/ntdll/rtlstr.c RtlCopyUnicodeString:
     * `if (len < dst->MaximumLength) dst->Buffer[len / sizeof(WCHAR)] = 0;`).
     * Not terminating was latent -- only a test called this -- but this is
     * the shared authority other departments reach for, and one of them
     * (kernel/ob/handle.c) had already hand-rolled its own terminator
     * instead (docs/review-2026-07 §9). */
    if (length < target->MaximumLength)
    {
        target->Buffer[length / sizeof(WCHAR)] = 0;
    }
}
