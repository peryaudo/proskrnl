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

static void ntapi_vout(const char *fmt, va_list ap)
{
    char buf[512];
#if defined(NTAPI_ORACLE)
    /* host vsnprintf is available and correct; the oracle is allowed libc. */
    extern int vsnprintf(char *, unsigned long, const char *, va_list);
    vsnprintf(buf, sizeof buf, fmt, ap);
#elif defined(NTAPI_PROSKRNL)
    /* M4: implement a tiny freestanding vsnprintf (or reuse the kernel's
     * mini-printf) here. Until the proskrnl target is built, this seam is
     * never reached. */
    buf[0] = '\0';
    (void)fmt; (void)ap;
#endif
    ntapi_out(buf);
}

static void ntapi_outf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ntapi_vout(fmt, ap);
    va_end(ap);
}

void ntapi_okv(int cond, const char *file, int line, const char *fmt, ...)
{
    if (ntapi_ctx.todo_depth > 0)
    {
#if defined(NTAPI_PROSKRNL)
        /* Inside todo_proskrnl on the target: failure is expected (silent);
         * an unexpected pass means the tag is stale. */
        if (cond)
        {
            ntapi_ctx.todo_unexpected++;
            ntapi_outf(PFX_ASSERT "%s:%d: todo_proskrnl succeeded (remove the tag): ",
                       file, line);
            {
                va_list ap; va_start(ap, fmt); ntapi_vout(fmt, ap); va_end(ap);
            }
            ntapi_out("\n");
        }
        return;
#endif
        /* oracle: todo_proskrnl is transparent — fall through to normal check. */
    }

    if (!cond)
    {
        ntapi_ctx.failures++;
        ntapi_outf(PFX_ASSERT "%s:%d: ", file, line);
        {
            va_list ap; va_start(ap, fmt); ntapi_vout(fmt, ap); va_end(ap);
        }
        ntapi_out("\n");
    }
}

void ntapi_skipv(const char *file, int line, const char *fmt, ...)
{
    ntapi_ctx.skips++;
    ntapi_outf("[SKIP] %s:%d: ", file, line);
    {
        va_list ap; va_start(ap, fmt); ntapi_vout(fmt, ap); va_end(ap);
    }
    ntapi_out("\n");
}

int ntapi_finish(void)
{
    if (ntapi_ctx.failures == 0 && ntapi_ctx.todo_unexpected == 0)
    {
        ntapi_outf(PFX_KTEST "%s PASS\n", ntapi_ctx.name);
        return 0;
    }
    ntapi_outf(PFX_KTEST "%s FAIL failures=%d todo_unexpected=%d\n",
               ntapi_ctx.name, ntapi_ctx.failures, ntapi_ctx.todo_unexpected);
    return 1;
}

/* ---- the per-mode I/O + exit seam --------------------------------------- */

#if defined(NTAPI_ORACLE)

void ntapi_out(const char *text)
{
    extern int fputs(const char *, void *);
    extern void *stdout;
    fputs(text, stdout);
}

void ntapi_exit(int code)
{
    extern void exit(int);
    exit(code);
}

#elif defined(NTAPI_PROSKRNL)

void ntapi_out(const char *text)
{
    /* M4: write text to the serial console (the same path the kernel's
     * [PANIC]/[KTEST] lines take). */
    (void)text;
}

void ntapi_exit(int code)
{
    /* M4: write the verdict to the isa-debug-exit port (iobase 0xf4) so QEMU
     * exits with a derived code; tests/run/run.sh reads it (docs/08). */
    (void)code;
    for (;;) { /* halt */ }
}

#endif
