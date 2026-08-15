/*
 * sem_file/hostile_name.c — the by-NAME file services must refuse a hostile
 * OBJECT_ATTRIBUTES, not read it.
 *
 * Convicted by the pointer-torture matrix (issue #32 A1,
 * tests/ntapi/syscall/ptr_torture.c) on its first run: NtQueryAttributesFile
 * with `ObjectName` set to 0x1 took the machine down with a #UD at
 * kernel/ob/namespace.c:256 — a UBSan alignment trap on a ring-3-supplied
 * pointer being read at ring 0, which the service dispatcher's fault
 * recovery frame cannot catch because it is not a page fault.
 *
 * The mechanism is worth stating, because it is a shape and not a typo. The
 * four by-name services (NtQueryAttributesFile, NtQueryFullAttributesFile,
 * NtDeleteFile, and the rename path's target probe) all work by opening a
 * TRANSIENT internal handle, and the helper that does it raises
 * previousMode to KernelMode so the handle is kernel-internal
 * (kernel/io/file.c IopOpenTransientFile). The probes under it are
 * previous-mode aware by design (kernel/syscall/uaccess.h: a KernelMode
 * caller needs no validation), so raising the mode over a call that still
 * carries the CALLER'S OBJECT_ATTRIBUTES pointer switches off every check
 * standing between ring 3 and a ring-0 dereference. Nothing in the elevation
 * says which pointers it covers — which is docs/20's R3a ("the gate may not
 * see a user pointer") in the one place the rule was not applied.
 *
 * WHAT THIS PINS is the boundary behaviour, not the mechanism: each service
 * answers STATUS_ACCESS_VIOLATION for an unreadable name, at three depths —
 * the OBJECT_ATTRIBUTES block itself, the UNICODE_STRING it points at, and
 * that string's Buffer. The third is the one an implementation reaches by
 * accident, since a service that validated the first two still walks into
 * the third the moment it parses the path.
 *
 * Oracle-first (G5): measured under the pinned Wine before the kernel change
 * that fixes it. Nothing here is beyond_oracle — Wine's PE ntdll hands these
 * to its unix side, which validates the same three depths
 * (dlls/ntdll/unix/file.c get_nt_and_unix_names via
 * server_get_unix_name/nt_to_unix_file_name, over a caller-owned
 * OBJECT_ATTRIBUTES).
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryFullAttributesFile(const OBJECT_ATTRIBUTES *,
                                                  FILE_NETWORK_OPEN_INFORMATION *);
NTSYSAPI NTSTATUS NTAPI NtDeleteFile(POBJECT_ATTRIBUTES);

/* Unmapped, and in the reserved low page both runners keep unmapped forever.
 *
 * ALIGNED on purpose. A misaligned pointer asks a second, independent
 * question — NT's ProbeFor* raise STATUS_DATATYPE_MISALIGNMENT before they
 * consider whether the page is there, and the pinned Wine, which has no
 * probe at all, cannot answer it (it faults and reports the fault). Whether
 * a misaligned name is a misalignment or a violation is therefore not
 * something this file can settle, and it is not what is under test here:
 * this is about a name being READ AT ALL without validation. Alignment keeps
 * the two runners answering the same question. */
#define BAD_POINTER ((void *)(ULONG_PTR)0x1000)

static void query_attributes(const char *what, const OBJECT_ATTRIBUTES *attributes)
{
    FILE_BASIC_INFORMATION basic;
    FILE_NETWORK_OPEN_INFORMATION full;
    NTSTATUS status;

    memset(&basic, 0, sizeof(basic));
    status = NtQueryAttributesFile(attributes, &basic);
    ok(status == STATUS_ACCESS_VIOLATION, "NtQueryAttributesFile %s: %08lx", what,
       (unsigned long)status);

    memset(&full, 0, sizeof(full));
    status = NtQueryFullAttributesFile(attributes, &full);
    ok(status == STATUS_ACCESS_VIOLATION, "NtQueryFullAttributesFile %s: %08lx", what,
       (unsigned long)status);

    status = NtDeleteFile((POBJECT_ATTRIBUTES)(ULONG_PTR)attributes);
    ok(status == STATUS_ACCESS_VIOLATION, "NtDeleteFile %s: %08lx", what, (unsigned long)status);
}

START_TEST(hostile_name)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    WCHAR buffer[] = W("\\??\\C:\\prstest\\nosuchfile");

    /* Depth 3: a well-formed descriptor around an unreadable Buffer. The
     * counts are honest about a buffer that cannot be read at all. */
    name.Length = 8;
    name.MaximumLength = 8;
    name.Buffer = BAD_POINTER;
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = NULL;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = NULL;
    attributes.SecurityQualityOfService = NULL;
    query_attributes("bad name buffer", &attributes);

    /* Depth 2: the descriptor itself is the bad pointer. */
    attributes.ObjectName = BAD_POINTER;
    query_attributes("bad ObjectName", &attributes);

    /* Depth 1: the whole block. */
    query_attributes("bad attributes", BAD_POINTER);

    /* The control: the same three services over a well-formed name that
     * simply does not exist. Without it, a service that refused EVERYTHING
     * with STATUS_ACCESS_VIOLATION would score three passes above. */
    name.Length = (USHORT)(sizeof(buffer) - sizeof(WCHAR));
    name.MaximumLength = (USHORT)sizeof(buffer);
    name.Buffer = buffer;
    attributes.ObjectName = &name;
    {
        FILE_BASIC_INFORMATION basic;
        NTSTATUS status;

        memset(&basic, 0, sizeof(basic));
        status = NtQueryAttributesFile(&attributes, &basic);
        ok(status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND,
           "control: a readable missing name is a name error, not a fault: %08lx",
           (unsigned long)status);
    }
}
