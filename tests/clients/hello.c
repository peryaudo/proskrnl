/* tests/clients/hello.c — the M7 Wine-bring-up acceptance client (docs/02
 * "Done when": a hello.exe linked only against ntdll starts and exits; an
 * SEH test — a deliberate access violation caught by __except — passes).
 *
 * This is a real MS-ABI PE built by mingw and linked ONLY against the pinned
 * Wine tree's PE ntdll import library. It is started by the unmodified Wine
 * ntdll.dll: the kernel enters LdrInitializeThunk, ntdll's loader_init runs
 * (heap, TLS, NLS, kernel32/kernelbase), and RtlUserThreadStart reaches
 * hello_start via kernel32's BaseThreadInitThunk. The SEH test raises an
 * access violation inside a .seh_handler-guarded region (the mechanism
 * __except compiles to — mingw-gcc has no __try, so the frame is set up in
 * hello_seh.S) and ntdll's KiUserExceptionDispatcher + RtlDispatchException
 * walk the real .pdata unwind path to our language handler, which resumes
 * via ExceptionContinueExecution.
 *
 * User clients follow the test-code conventions (Wine style, docs/15
 * exemption). Exit code 0 = PASS; a distinct nonzero code per failed step.
 */
#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntpsapi.h"
#include "abi/ntcontext.h"
#include "abi/ntpebteb.h"

/* From hello_seh.S: run the guarded store-through-null; returns 1 if the
 * language handler resumed us past it, 0 if the fault fell through. */
int hello_trigger_seh(void);

static volatile int seh_handler_ran;

static void say(const char *ascii)
{
    WCHAR wide[80];
    USHORT n = 0;
    while (ascii[n] != '\0' && n < 79)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    UNICODE_STRING string;
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

/* The x64 SEH language handler for hello_seh.S's guarded frame — what an
 * __except filter compiles into. Reached through ntdll's
 * KiUserExceptionDispatcher -> RtlDispatchException -> RtlVirtualUnwind over
 * the image's .pdata: exactly the machinery the SEH acceptance must prove.
 * Marking the fault handled by resuming at hello_seh_resume. */
ULONG hello_seh_handler(EXCEPTION_RECORD *record, void *frame, CONTEXT *context, void *dispatch)
{
    (void)frame;
    (void)dispatch;
    extern char hello_seh_resume[];
    if (record->ExceptionCode != (DWORD)STATUS_ACCESS_VIOLATION)
    {
        return 1; /* ExceptionContinueSearch */
    }
    seh_handler_ran = 1;
    context->Rip = (DWORD64)(ULONG_PTR)hello_seh_resume;
    return 0; /* ExceptionContinueExecution */
}

/* Entry: reached as RtlUserThreadStart's routine with the PEB as argument. */
void hello_start(void *peb_arg)
{
    int failures = 0;

    say("hello from Wine ntdll on proskrnl\n");

    /* The loader must have handed us the real PEB (the kernel-built one). */
    PEB *peb = (PEB *)peb_arg;
    if (!peb || peb->ImageBaseAddress == 0)
        failures |= 1;

    /* ntdll's loader_init built the in-process loader state. */
    if (!peb || !peb->LdrData || !peb->ProcessHeap)
        failures |= 2;

    /* The SEH test (docs/02): AV raised, dispatched by ntdll, caught, resumed. */
    if (!hello_trigger_seh() || !seh_handler_ran)
        failures |= 4;

    say(failures ? "hello: FAIL\n" : "hello: PASS\n");
    NtTerminateProcess((HANDLE) ~(ULONG_PTR)0 /* NtCurrentProcess() */, failures);
    for (;;)
    {
    }
}
