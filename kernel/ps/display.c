/* kernel/ps/display.c — NtDisplayString (M4).
 *
 * NT's boot-time text sink: user mode hands a counted UTF-16 string, the
 * kernel writes it to the console. Here that console is the serial port —
 * plus the boot console while it holds the framebuffer, the same two
 * channels DbgPrint uses (docs/08) — which is exactly what
 * the ntapi proskrnl harness needs for its verdict lines (docs/14). The
 * string is captured through the uaccess probes; non-ASCII units degrade to
 * '?' (the kernel carries no Unicode tables — docs/03).
 */
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/dbgprint.h"

#include "abi/ntstatus.h"

NTSTATUS NtDisplayString(PUNICODE_STRING string)
{
    UNICODE_STRING captured;
    NTSTATUS status = KiCopyFromUser(&captured, string, sizeof(captured));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if ((captured.Length & 1) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = KiProbeForRead(captured.Buffer, captured.Length, sizeof(WCHAR));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    for (USHORT i = 0; i < captured.Length / sizeof(WCHAR); i++)
    {
        WCHAR unit = captured.Buffer[i];
        DbgPutChar(unit < 0x80 ? (char)unit : '?');
    }
    return STATUS_SUCCESS;
}
