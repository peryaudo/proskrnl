/*
 * ntapi.c — per-mode implementation of the harness declared in ntapi.h.
 *
 * The oracle path is complete and buildable today (host libc). The proskrnl
 * path has one seam, marked "M4", that lights up when user mode + the syscall
 * boundary land; until then only the oracle target is built (tests/run/run.sh).
 */
#include "ntapi.h"
#include <stdarg.h>

/* Structured verdict prefixes — kept machine-greppable, separate from any
 * human free-text (docs/08). tests/run/ greps exactly these. */
#define PFX_ASSERT "[ASSERT] "
#define PFX_KTEST  "[KTEST] "

static void ntapi_vout(const char *Fmt, va_list Ap)
{
    char Buf[512];
#if defined(NTAPI_ORACLE)
    /* host vsnprintf is available and correct; the oracle is allowed libc. */
    extern int vsnprintf(char *, unsigned long, const char *, va_list);
    vsnprintf(Buf, sizeof Buf, Fmt, Ap);
#elif defined(NTAPI_PROSKRNL)
    /* M4: implement a tiny freestanding vsnprintf (or reuse the kernel's
     * mini-printf) here. Until the proskrnl target is built, this seam is
     * never reached. */
    Buf[0] = '\0';
    (void)Fmt; (void)Ap;
#endif
    ntapi_out(Buf);
}

static void ntapi_outf(const char *Fmt, ...)
{
    va_list Ap;
    va_start(Ap, Fmt);
    ntapi_vout(Fmt, Ap);
    va_end(Ap);
}

void ntapi_okv(int Cond, const char *File, int Line, const char *Fmt, ...)
{
    if (NtapiState.TodoDepth > 0)
    {
#if defined(NTAPI_PROSKRNL)
        /* Inside todo_proskrnl on the target: failure is expected (silent);
         * an unexpected pass means the tag is stale. */
        if (Cond)
        {
            NtapiState.TodoUnexpected++;
            ntapi_outf(PFX_ASSERT "%s:%d: todo_proskrnl succeeded (remove the tag): ",
                       File, Line);
            {
                va_list Ap; va_start(Ap, Fmt); ntapi_vout(Fmt, Ap); va_end(Ap);
            }
            ntapi_out("\n");
        }
        return;
#endif
        /* oracle: todo_proskrnl is transparent — fall through to normal check. */
    }

    if (!Cond)
    {
        NtapiState.Failures++;
        ntapi_outf(PFX_ASSERT "%s:%d: ", File, Line);
        {
            va_list Ap; va_start(Ap, Fmt); ntapi_vout(Fmt, Ap); va_end(Ap);
        }
        ntapi_out("\n");
    }
}

void ntapi_skipv(const char *File, int Line, const char *Fmt, ...)
{
    NtapiState.Skips++;
    ntapi_outf("[SKIP] %s:%d: ", File, Line);
    {
        va_list Ap; va_start(Ap, Fmt); ntapi_vout(Fmt, Ap); va_end(Ap);
    }
    ntapi_out("\n");
}

int ntapi_finish(void)
{
    if (NtapiState.Failures == 0 && NtapiState.TodoUnexpected == 0)
    {
        ntapi_outf(PFX_KTEST "%s PASS\n", NtapiState.Name);
        return 0;
    }
    ntapi_outf(PFX_KTEST "%s FAIL failures=%d todo_unexpected=%d\n",
               NtapiState.Name, NtapiState.Failures, NtapiState.TodoUnexpected);
    return 1;
}

/* ---- the per-mode I/O + exit seam --------------------------------------- */

#if defined(NTAPI_ORACLE)

void ntapi_out(const char *Text)
{
    extern int fputs(const char *, void *);
    extern void *stdout;
    fputs(Text, stdout);
}

void ntapi_exit(int Code)
{
    extern void exit(int);
    exit(Code);
}

#elif defined(NTAPI_PROSKRNL)

void ntapi_out(const char *Text)
{
    /* M4: write Text to the serial console (the same path the kernel's
     * [PANIC]/[KTEST] lines take). */
    (void)Text;
}

void ntapi_exit(int Code)
{
    /* M4: write the verdict to the isa-debug-exit port (iobase 0xf4) so QEMU
     * exits with a derived code; tests/run/run.sh reads it (docs/08). */
    (void)Code;
    for (;;) { /* halt */ }
}

#endif
