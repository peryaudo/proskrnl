/*
 * sem_pipe/pipe_hostile_name.c — NtCreateNamedPipeFile must refuse a hostile
 * OBJECT_ATTRIBUTES, not read it.
 *
 * Convicted by the pointer-torture matrix (issue #32 A1,
 * tests/ntapi/syscall/ptr_torture.c): the create validates its
 * IO_STATUS_BLOCK and then reads `attributes->ObjectName` with the block
 * itself never probed (fs/npfs/pipe.c). A misaligned block took the machine
 * down with a #UD — a UBSan alignment trap, which the service dispatcher's
 * recovery frame cannot turn into a status because it is not a page fault —
 * and an unmapped one only survived because that frame caught it.
 *
 * This is the review's §1a shape exactly: the validating call exists
 * (ObProbeObjectAttributes, which the Io create path does use — see
 * sem_file/hostile_name.c), the rule was never written down, and the pipe
 * create is one of the sites that did not get it. That is why the fix is a
 * call to the SHARED probe rather than a check of its own (G11: one
 * authority per question).
 *
 * Oracle-first (G5): measured under the pinned Wine before the kernel
 * change. The name is the ONE argument here that must be read before
 * anything can be resolved, so this is where the boundary answer is
 * STATUS_ACCESS_VIOLATION rather than one of the create's many refusals.
 */
#include "util.h"

/* Unmapped, and ALIGNED on purpose — sem_file/hostile_name.c explains why a
 * misaligned pointer asks a different question that the pinned Wine (which
 * has no probe at all) cannot answer. */
#define BAD_POINTER ((void *)(ULONG_PTR)0x1000)

static void create_pipe_with(const char *what, const OBJECT_ATTRIBUTES *attributes)
{
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;
    HANDLE handle = (HANDLE)(ULONG_PTR)0xdead;
    NTSTATUS status;

    memset(&iosb, 0, sizeof(iosb));
    timeout.QuadPart = -10000000;
    status = NtCreateNamedPipeFile(&handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                                   (POBJECT_ATTRIBUTES)(ULONG_PTR)attributes, &iosb,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, 0,
                                   FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                                   FILE_PIPE_QUEUE_OPERATION, 1, 0x1000, 0x1000, &timeout);
    ok(status == STATUS_ACCESS_VIOLATION, "NtCreateNamedPipeFile %s: %08lx", what,
       (unsigned long)status);
}

START_TEST(pipe_hostile_name)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    WCHAR pipeName[] = W("\\??\\pipe\\prstest_hostile");

    /* Depth 3: a well-formed descriptor around an unreadable Buffer. */
    name.Length = 8;
    name.MaximumLength = 8;
    name.Buffer = BAD_POINTER;
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = NULL;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;
    attributes.SecurityDescriptor = NULL;
    attributes.SecurityQualityOfService = NULL;
    create_pipe_with("bad name buffer", &attributes);

    /* Depth 2: the UNICODE_STRING itself. */
    attributes.ObjectName = BAD_POINTER;
    create_pipe_with("bad ObjectName", &attributes);

    /* Depth 1: the whole block. */
    create_pipe_with("bad attributes", BAD_POINTER);

    /* The control: a readable name reaches the create's own rules, so the
     * three refusals above are about the POINTER and not about everything.
     * A pipe with no direction shared is a malformed request. */
    name.Length = (USHORT)(sizeof(pipeName) - sizeof(WCHAR));
    name.MaximumLength = (USHORT)sizeof(pipeName);
    name.Buffer = pipeName;
    attributes.ObjectName = &name;
    {
        IO_STATUS_BLOCK iosb;
        HANDLE handle = NULL;
        NTSTATUS status;

        memset(&iosb, 0, sizeof(iosb));
        status = NtCreateNamedPipeFile(&handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                                       &attributes, &iosb, 0 /* no direction */, FILE_CREATE, 0,
                                       FILE_PIPE_TYPE_BYTE, FILE_PIPE_BYTE_STREAM_MODE,
                                       FILE_PIPE_QUEUE_OPERATION, 1, 0x1000, 0x1000, NULL);
        ok(status == STATUS_INVALID_PARAMETER,
           "control: a readable name reaches the create's own rules: %08lx", (unsigned long)status);
    }
}
