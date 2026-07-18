/*
 * ntapi.h — portable ntapi test harness.
 *
 * One source, two build modes (see docs/14-test-harness.md). The Makefile
 * defines exactly one of:
 *
 *   NTAPI_ORACLE    build as a Windows PE .exe; Nt* from the host ntdll;
 *                   contract headers = the oracle's (winternl.h); the truth.
 *   NTAPI_PROSKRNL  build as a freestanding flat binary for proskrnl (M4+);
 *                   Nt* from tests/ntapi/syscall/; contract headers = abi/.
 *
 * The header switch below is a conformance check: the same test compiling and
 * passing in both modes proves abi/ agrees with the oracle. Never include both
 * header sets in one build.
 */
#ifndef NTAPI_H
#define NTAPI_H

#if defined(NTAPI_ORACLE) == defined(NTAPI_PROSKRNL)
#  error "define exactly one of NTAPI_ORACLE / NTAPI_PROSKRNL"
#endif

#if defined(NTAPI_ORACLE)
/* The oracle defines truth: use the system's own NT headers, never abi/.
 * WIN32_NO_STATUS + <ntstatus.h> is Microsoft's documented dance for the
 * full STATUS_* set (winnt.h alone defines only a subset); Wine's own ntdll
 * tests do the same. The #undef is for mingw-w64, whose ntstatus.h is
 * itself gated on WIN32_NO_STATUS being unset. */
#  define WIN32_NO_STATUS
#  include <windows.h>
#  include <winternl.h>
#  undef WIN32_NO_STATUS
#  include <ntstatus.h>

/* winternl.h omits the dispatcher-object enums (they live in the WDK's
 * ntdef.h, which cannot coexist with windows.h); declared here as Wine's
 * winternl.h and Microsoft's NtCreateEvent documentation define them. */
typedef enum _EVENT_TYPE
{
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;
#elif defined(NTAPI_PROSKRNL)
/* proskrnl's generated contract (Article 4). Present from M4. */
#  include "abi/ntstatus.h"
#  include "abi/ntdef.h"
/* further abi/ headers are pulled in per-test as the surface grows */
#endif

/* ---- harness state ------------------------------------------------------ */

struct ntapi_state
{
    const char *name;
    int         failures;         /* hard assertion failures                */
    int         todo_unexpected;   /* todo_proskrnl block that unexpectedly passed */
    int         skips;
    int         todo_depth;        /* >0 while inside a todo_proskrnl block   */
};

extern struct ntapi_state ntapi_ctx;

/* Implemented per-mode in ntapi.c. */
void ntapi_out(const char *text);                 /* oracle: stdout; proskrnl: serial */
void ntapi_printf(const char *fmt, ...);          /* formatted line to the same sink (tests/fuzz) */
void ntapi_okv(int cond, const char *file, int line, const char *fmt, ...);
void ntapi_skipv(const char *file, int line, const char *fmt, ...);
int  ntapi_finish(void);                           /* emit [KTEST] verdict, return exit code */
void ntapi_exit(int code);                          /* oracle: exit(); proskrnl: isa-debug-exit */

/* ---- test entry point --------------------------------------------------- */

#define START_TEST(name)                                                      \
    struct ntapi_state ntapi_ctx = { #name, 0, 0, 0, 0 };                     \
    static void ntapi_body(void);                                             \
    int main(void)                                                            \
    {                                                                         \
        ntapi_body();                                                        \
        ntapi_exit(ntapi_finish());                                          \
        return 0;                                                            \
    }                                                                         \
    static void ntapi_body(void)

/* ---- assertions --------------------------------------------------------- */

/* ok(cond, fmt, ...) — one assertion. Counts + logs [ASSERT] file:line on failure. */
#define ok(cond, ...) ntapi_okv((cond) != 0, __FILE__, __LINE__, __VA_ARGS__)

#define skip(...)     ntapi_skipv(__FILE__, __LINE__, __VA_ARGS__)

/*
 * todo_proskrnl { ... } — assertions expected to fail on proskrnl (not yet
 * correct) but that MUST pass on the oracle. Mirrors Wine's todo_wine:
 *   oracle:   transparent — the block must pass.
 *   proskrnl: an ok() failure inside is expected (not counted); an ok() that
 *             unexpectedly passes is flagged (delete the tag — hold the kernel
 *             to the behaviour now).
 * Prefer this only for a test that is otherwise LIVE in the manifest. A wholly
 * unimplemented Nt* belongs out of the manifest, not wrapped in todo_proskrnl.
 */
#define todo_proskrnl                                                         \
    for (ntapi_ctx.todo_depth++; ntapi_ctx.todo_depth;                        \
         ntapi_ctx.todo_depth--)

#endif /* NTAPI_H */
