/*
 * ntapi.h — the ntapi test harness (docs/14-test-harness.md).
 *
 * ONE build, one binary per test: a Windows PE .exe built with mingw against
 * the system NT headers (winternl.h — the oracle's contract) and linked, with
 * no CRT, against the pinned Wine import libraries (ntdll + kernel32 +
 * kernelbase). The SAME .exe runs on both sides of the differential gate:
 *
 *   oracle    run under the pinned third_party/wine — the spec (Art. 5);
 *   proskrnl  baked under C:\ntapi and run by the kernel's ntapi runner
 *             (kernel/init/main.c) on the unmodified Wine PE userland.
 *
 * Which side the binary landed on is detected at runtime, not compiled in:
 * the proskrnl runner launches tests without a console, so no std output
 * handle == running on proskrnl (output falls back from NtWriteFile on
 * hStdOutput to NtDisplayString; todo_proskrnl keys off the same probe).
 * That probe is a runner contract, not an OS sniff — both runners are ours.
 */
#ifndef NTAPI_H
#define NTAPI_H

/* The system's own NT headers, never abi/ (the oracle defines truth; abi/ is
 * the KERNEL's generated contract and proving it against these headers at
 * run time is the point of the gate). WIN32_NO_STATUS + <ntstatus.h> is
 * Microsoft's documented dance for the full STATUS_* set (winnt.h alone
 * defines only a subset); Wine's own ntdll tests do the same. The #undef is
 * for mingw-w64, whose ntstatus.h is itself gated on WIN32_NO_STATUS being
 * unset. */
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

/* winternl.h omits the dispatcher-object enums (they live in the WDK's
 * ntdef.h, which cannot coexist with windows.h); declared here as Wine's
 * winternl.h and Microsoft's NtCreateEvent documentation define them. */
typedef enum _EVENT_TYPE
{
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

/* ---- harness state ------------------------------------------------------ */

struct ntapi_state
{
    const char *name;
    int failures;        /* hard assertion failures                */
    int todo_unexpected; /* todo_proskrnl block that unexpectedly passed */
    int skips;
    int todo_depth;  /* >0 while inside a todo_proskrnl block   */
    int on_proskrnl; /* runtime: no std output handle (see above) */
};

extern struct ntapi_state ntapi_ctx;

/* Implemented in ntapi.c. */
void ntapi_out(const char *text);        /* hStdOutput, else serial */
void ntapi_printf(const char *fmt, ...); /* formatted line to the same sink (tests/fuzz) */
void ntapi_okv(int cond, const char *file, int line, const char *fmt, ...);
void ntapi_skipv(const char *file, int line, const char *fmt, ...);
int ntapi_finish(void);    /* emit [KTEST] verdict, return exit code */
void ntapi_exit(int code); /* NtTerminateProcess — never returns */

/* ---- test entry point --------------------------------------------------- */

/* The .exe entry point is ntapi_start (ntapi.c) — the build is -nostdlib, so
 * no CRT ever wraps main. It probes the runner side, calls main, and exits
 * through ntapi_exit even if the test returns. */
#define START_TEST(name)                                                                           \
    struct ntapi_state ntapi_ctx = {#name, 0, 0, 0, 0, 0};                                         \
    static void ntapi_body(void);                                                                  \
    int main(void)                                                                                 \
    {                                                                                              \
        ntapi_body();                                                                              \
        ntapi_exit(ntapi_finish());                                                                \
        return 0;                                                                                  \
    }                                                                                              \
    static void ntapi_body(void)

/* ---- assertions --------------------------------------------------------- */

/* ok(cond, fmt, ...) — one assertion. Counts + logs [ASSERT] file:line on failure. */
#define ok(cond, ...) ntapi_okv((cond) != 0, __FILE__, __LINE__, __VA_ARGS__)

#define skip(...) ntapi_skipv(__FILE__, __LINE__, __VA_ARGS__)

/*
 * todo_proskrnl { ... } — assertions expected to fail on proskrnl (a known,
 * documented divergence — docs/03) but that MUST pass on the oracle. Mirrors
 * Wine's todo_wine, decided at RUN time by the harness's side probe:
 *   oracle:   transparent — the block must pass.
 *   proskrnl: an ok() failure inside is expected (not counted); an ok() that
 *             unexpectedly passes is flagged (delete the tag — hold the kernel
 *             to the behaviour now).
 */
#define todo_proskrnl for (ntapi_ctx.todo_depth++; ntapi_ctx.todo_depth; ntapi_ctx.todo_depth--)

#endif /* NTAPI_H */
