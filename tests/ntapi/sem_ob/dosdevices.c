/*
 * sem_ob/dosdevices.c — \DosDevices is a symbolic link to \??.
 *
 * Convicted by the winetest gate: kernel32:drive's GetLogicalDrives opens
 * `\DosDevices` as a DIRECTORY and enumerates it looking for two-character
 * `X:` names (dlls/kernelbase/volume.c). proskrnl had no such name at all,
 * so the open failed, the bitmask came back 0, and the pair lost twelve
 * assertions behind it — including every DRIVE_NO_ROOT_DIR check, which
 * reads "this drive letter does not exist" off that same zero.
 *
 * \DosDevices is NT's older name for the per-session DOS device directory
 * that \?? also names, and it is a SYMBOLIC LINK rather than a second
 * directory. That distinction is the whole content of this pin: two
 * directories would drift — a drive letter defined through one would be
 * invisible through the other — and the enumeration above would then
 * disagree with every path resolution in the system. One object, two
 * names.
 *
 * So the assertions here are all about identity rather than about
 * contents: the link resolves, a name created under \?? is visible through
 * \DosDevices, and a handle opened either way lists the same set.
 *
 * Oracle-first (G5).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);

START_TEST(dosdevices)
{
    NTSTATUS status;
    HANDLE handle = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* --- it opens as a DIRECTORY, which is what GetLogicalDrives does ---- */
    init_ustr(&name, W("\\DosDevices"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenDirectoryObject(&handle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &attr);
    ok(status == STATUS_SUCCESS, "open \\DosDevices as a directory -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
        NtClose(handle);

    /* --- and it IS a link, not a directory of its own -------------------- */
    handle = NULL;
    init_ustr(&name, W("\\DosDevices"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenSymbolicLinkObject(&handle, SYMBOLIC_LINK_QUERY, &attr);
    ok(status == STATUS_SUCCESS, "open \\DosDevices as a link -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        WCHAR targetBuffer[64];
        UNICODE_STRING target;
        ULONG returned = 0;
        target.Buffer = targetBuffer;
        target.Length = 0;
        target.MaximumLength = sizeof(targetBuffer);
        status = NtQuerySymbolicLinkObject(handle, &target, &returned);
        ok(status == STATUS_SUCCESS, "query the link -> %08lx", (unsigned long)status);
        ok(target.Length == 3 * sizeof(WCHAR),
           "the link target is %u units, expected 3", (unsigned)(target.Length / sizeof(WCHAR)));
        ok(target.Length >= 3 * sizeof(WCHAR) && target.Buffer[0] == '\\' &&
               target.Buffer[1] == '?' && target.Buffer[2] == '?',
           "the link does not point at \\??");
        NtClose(handle);
    }

    /* --- ONE object under two names: a path through \DosDevices resolves
     * to whatever \?? holds. \??\C: is the boot volume on both runners, so
     * this is the identity check that a second directory would fail. */
    {
        HANDLE viaDos = NULL, viaQq = NULL;
        init_ustr(&name, W("\\DosDevices\\C:"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenSymbolicLinkObject(&viaDos, SYMBOLIC_LINK_QUERY, &attr);
        ok(status == STATUS_SUCCESS, "\\DosDevices\\C: -> %08lx", (unsigned long)status);

        init_ustr(&name, W("\\??\\C:"));
        init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
        status = NtOpenSymbolicLinkObject(&viaQq, SYMBOLIC_LINK_QUERY, &attr);
        ok(status == STATUS_SUCCESS, "\\??\\C: -> %08lx", (unsigned long)status);

        if (viaDos != NULL && viaQq != NULL)
        {
            WCHAR a[64], b[64];
            UNICODE_STRING ta, tb;
            ULONG ra = 0, rb = 0;
            ta.Buffer = a;
            ta.Length = 0;
            ta.MaximumLength = sizeof(a);
            tb.Buffer = b;
            tb.Length = 0;
            tb.MaximumLength = sizeof(b);
            ok(NtQuerySymbolicLinkObject(viaDos, &ta, &ra) == STATUS_SUCCESS,
               "query via DosDevices");
            ok(NtQuerySymbolicLinkObject(viaQq, &tb, &rb) == STATUS_SUCCESS, "query via ??");
            ok(ta.Length == tb.Length && memcmp(a, b, ta.Length) == 0,
               "the two names resolve to different targets");
        }
        if (viaDos != NULL)
            NtClose(viaDos);
        if (viaQq != NULL)
            NtClose(viaQq);
    }
}
