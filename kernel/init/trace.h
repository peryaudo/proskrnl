/* kernel/init/trace.h — the recent-events ring the panic dump replays.
 *
 * Debug infrastructure, not an NT facility (Art. 9 / docs/12: "panic handler,
 * tracing, log formatting — build it thick first"): kernel-internal, Ki-named,
 * unobservable from user mode, so Art. 2 is untouched. A dump that says WHERE
 * the kernel died still leaves the LLM loop guessing WHAT led up to it; the
 * ring replays the last syscalls, context switches, and thread/process
 * lifecycle events with [TRACE]-prefixed lines (docs/08: machine-verdict
 * prefixes stay separate from free text; nothing greps [TRACE]).
 */
#ifndef PROSKRNL_KERNEL_INIT_TRACE_H
#define PROSKRNL_KERNEL_INIT_TRACE_H

#include <stdint.h>

typedef enum
{
    KiTraceNone = 0,     /* empty ring slot */
    KiTraceSyscall,      /* arg0=number, arg1/arg2=first two arguments */
    KiTraceSwap,         /* arg0=old thread, arg1=new thread */
    KiTraceThreadCreate, /* arg0=thread, arg1=startRoutine, arg2=process */
    KiTraceThreadExit,   /* arg0=thread */
    KiTraceUserFault,    /* arg0=vector, arg1=user RIP, arg2=CR2 (0 if not #PF) */
    KiTraceProcessExit,  /* arg0=process, arg1=exit NTSTATUS */
    KiTraceSyscallRet,   /* arg0=number, arg1=returned NTSTATUS, arg2=thread */
} KI_TRACE_TYPE;

/* Record one event. Takes the dispatcher lock itself (reentrant-safe: the
 * lock is a plain interrupt disable, Art. 3), so call sites that already
 * hold it — the context switch — need no special shape. */
void KiTraceEvent(KI_TRACE_TYPE type, uint64_t arg0, uint64_t arg1, uint64_t arg2);

/* Replay the ring oldest-first (skipping empty slots) with [TRACE] lines;
 * called from the panic path's system-state dump. No allocation. */
void KiDumpTraceRing(void);

#endif /* PROSKRNL_KERNEL_INIT_TRACE_H */
