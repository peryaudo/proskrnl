/*
 * bootflag.h — the one PE-side reader of a QEMU boot flag (Art. 11).
 *
 * The kernel publishes what the QEMU command line carried as REG_DWORD
 * values under the volatile \Registry\Machine\Hardware\qemu (HACK-006,
 * kernel/cm/registry.c CmpSeedQemuBootFlags).  Three PE modules ask it a
 * question each — conhost "Gui", winefb.drv and wineserver-lite "Shell" —
 * and each had grown its own copy of the same twenty lines: open the key,
 * NtQueryValueKey the value as KeyValuePartialInformation into a
 * {header + 4 bytes} buffer, type-check REG_DWORD.  Copies of a rule drift
 * even while they still agree, which is what Art. 11 is about.
 *
 * The one thing that legitimately differs between askers is the answer when
 * there is NO `qemu` key — the boot is not a QEMU guest at all, nothing said
 * either way, and each flag's own default applies (`Gui` is on, `Shell` is
 * off).  That is the `whenNotQemu` parameter, so a difference between two
 * callers is a value at the call site rather than a divergence buried in a
 * copied body.  Every OTHER failure — the key exists but the value is
 * absent, or is not a REG_DWORD, or is the wrong size — is QEMU having
 * decided, so it reads as 0 for everyone.
 *
 * Header-only and static inline because the three callers are three separate
 * PE images with no shared library between them; smss asks the same question
 * through SmssQemuFlag (user/smss/smss.c), which is the same rule written
 * for a program that includes none of the Wine headers this one needs.
 *
 * Nothing here is an NT contract.  Requires winternl.h/winnt.h (UNICODE_STRING,
 * OBJECT_ATTRIBUTES, NtOpenKey, NtQueryValueKey, REG_DWORD) already included.
 */
#ifndef PRSK_WINE_COMMON_BOOTFLAG_H
#define PRSK_WINE_COMMON_BOOTFLAG_H

static inline ULONG prsk_qemu_boot_flag( const WCHAR *value_name, ULONG when_not_qemu )
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    HANDLE key;
    struct
    {
        KEY_VALUE_PARTIAL_INFORMATION info;
        UCHAR tail[sizeof(ULONG)];
    } buffer;
    ULONG result_length = 0, value = 0;

    RtlInitUnicodeString( &name, L"\\Registry\\Machine\\Hardware\\qemu" );
    InitializeObjectAttributes( &attr, &name, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenKey( &key, KEY_QUERY_VALUE, &attr )) return when_not_qemu;

    RtlInitUnicodeString( &name, (WCHAR *)value_name );
    if (!NtQueryValueKey( key, &name, KeyValuePartialInformation, &buffer, sizeof(buffer),
                          &result_length ) &&
        buffer.info.Type == REG_DWORD && buffer.info.DataLength == sizeof(ULONG))
        memcpy( &value, buffer.info.Data, sizeof(value) );
    NtClose( key );
    return value;
}

#endif /* PRSK_WINE_COMMON_BOOTFLAG_H */
