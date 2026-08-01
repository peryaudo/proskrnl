/* kernel/ps/nls.c — the default locale / UI language state (CUI-7).
 *
 * Three process-wide slots, exactly the oracle's shape (wine
 * dlls/ntdll/unix/env.c: user_lcid, system_lcid, user_ui_language; pinned by
 * tests/ntapi/sem_ps/locale.c): NtQueryDefaultLocale reads one of the two
 * LCIDs by its userProfile argument, the setters store, and the install UI
 * language has no state of its own — it DERIVES from the system LCID.
 *
 * Where the oracle seeds from the host locale, proskrnl seeds from the same
 * registry state real NT reads: the machine side from
 * HKLM\System\CurrentControlSet\Control\Nls\Language "Default" (written at
 * first boot by wine.inf — loader/wine.inf.in), the user side from
 * HKCU\Control Panel\International "Locale", each a REG_SZ hex string, with
 * the en-US 0x0409 fallback when absent. Reads go through the Cm services
 * with kernel-mode previous mode — the PspQueryGlobalFlag precedent
 * (kernel/ps/peb.c; G10: through Cm, never the hive). Sets are in-memory
 * only, as the oracle's are (docs/03 "CUI-7" notes).
 */
#include "kernel/ps/ps.h"

#include "abi/ntregapi.h"
#include "kernel/ke/ke.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"
#include "kernel/syscall/uaccess.h"

static LCID PspUserLcid = 0x0409;
static LCID PspSystemLcid = 0x0409;
static LANGID PspUserUiLanguage = 0x0409;

/* Parse a REG_SZ hex string ("0409" / "00000409") into an LCID; 0 = no. */
static BOOLEAN PspParseHexLcid(const WCHAR *text, ULONG bytes, LCID *out)
{
    ULONG value = 0;
    ULONG digits = 0;
    for (ULONG i = 0; i < bytes / sizeof(WCHAR); i++)
    {
        WCHAR c = text[i];
        if (c == 0)
        {
            break;
        }
        ULONG digit;
        if (c >= '0' && c <= '9')
        {
            digit = c - '0';
        }
        else if (c >= 'a' && c <= 'f')
        {
            digit = c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F')
        {
            digit = c - 'A' + 10;
        }
        else
        {
            return FALSE;
        }
        value = value * 16 + digit;
        digits++;
    }
    if (digits == 0 || value == 0)
    {
        return FALSE;
    }
    *out = (LCID)value;
    return TRUE;
}

/* Read one REG_SZ value from an absolute registry path into *out. */
static BOOLEAN PspReadLcidValue(PCWSTR keyPath, PCWSTR valueName, LCID *out)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    RtlInitUnicodeString(&name, keyPath);
    HANDLE key;
    if (!NT_SUCCESS(NtOpenKey(&key, KEY_QUERY_VALUE, &attributes)))
    {
        return FALSE;
    }
    UNICODE_STRING value;
    RtlInitUnicodeString(&value, valueName);
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 16 * sizeof(WCHAR)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    DWORD resultLength = 0;
    NTSTATUS status = NtQueryValueKey(key, &value, KeyValuePartialInformation, buffer,
                                      sizeof(buffer), &resultLength);
    NtClose(key);
    if (!NT_SUCCESS(status) || info->Type != REG_SZ)
    {
        return FALSE;
    }
    return PspParseHexLcid((const WCHAR *)info->Data, info->DataLength, out);
}

void PspInitializeLanguage(void)
{
    /* Kernel-mode previous mode: every pointer here is a kernel pointer
     * (the PspQueryGlobalFlag precedent). */
    PKTHREAD thread = KeGetCurrentThread();
    KPROCESSOR_MODE saved = thread->previousMode;
    thread->previousMode = KernelMode;

    LCID lcid;
    if (PspReadLcidValue(
            WSTR("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language"),
            WSTR("Default"), &lcid))
    {
        PspSystemLcid = lcid;
    }
    PspUserLcid = PspSystemLcid;
    if (PspReadLcidValue(WSTR("\\Registry\\User\\S-1-5-21-0-0-0-1000\\Control Panel")
                             WSTR("\\International"),
                         WSTR("Locale"), &lcid))
    {
        PspUserLcid = lcid;
    }
    PspUserUiLanguage = LANGIDFROMLCID(PspUserLcid);

    thread->previousMode = saved;
}

NTSTATUS NtQueryDefaultLocale(BOOLEAN userProfile, LCID *lcid)
{
    NTSTATUS status = KiProbeForWrite(lcid, sizeof(*lcid), sizeof(*lcid));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    LCID value = userProfile ? PspUserLcid : PspSystemLcid;
    memcpy(lcid, &value, sizeof(value));
    return STATUS_SUCCESS;
}

NTSTATUS NtSetDefaultLocale(BOOLEAN userProfile, LCID lcid)
{
    if (userProfile)
    {
        PspUserLcid = lcid;
    }
    else
    {
        PspSystemLcid = lcid;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryDefaultUILanguage(LANGID *language)
{
    NTSTATUS status = KiProbeForWrite(language, sizeof(*language), sizeof(*language));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(language, &PspUserUiLanguage, sizeof(*language));
    return STATUS_SUCCESS;
}

NTSTATUS NtSetDefaultUILanguage(LANGID language)
{
    PspUserUiLanguage = language;
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryInstallUILanguage(LANGID *language)
{
    NTSTATUS status = KiProbeForWrite(language, sizeof(*language), sizeof(*language));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* No setter of its own: derived from the system LCID (the oracle's
     * LANGIDFROMLCID(system_lcid) — dlls/ntdll/unix/env.c). */
    LANGID value = LANGIDFROMLCID(PspSystemLcid);
    memcpy(language, &value, sizeof(value));
    return STATUS_SUCCESS;
}
