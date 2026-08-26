/* kernel/init/profile.h — the boot profiler (debug instrumentation, Art. 9).
 *
 * "Boot is slow; where does the time go?" answered from inside the machine,
 * on the same serial channel every other verdict comes off. Three readings,
 * one arming knob:
 *
 *   - a per-syscall aggregate (count, wall time, on-CPU time) dumped by the
 *     panic path — so an operator NMI against a live boot (tests/gui/
 *     qmpctl.py nmi) prints where the kernel's time went, beside the
 *     all-threads dump that already says where everyone is parked;
 *   - a once-a-second delta line naming the top services of THAT second, so
 *     a phase can be blamed without stopping the machine;
 *   - a millisecond timestamp on every serial line (kernel/lib/dbgprint.c),
 *     which stamps ring-3 output too because NtDisplayString shares the
 *     transport (kernel/ps/display.c).
 *
 * NOTHING here is observable at the boundary: no Nt* service reports it, no
 * behavior changes with it armed (Art. 1/G2 — this is the KiTraceEvent ring's
 * category, a debug channel, not a kernel entity NT lacks). It is armed off
 * the QEMU command line (tools/qemu.sh GUEST_PROFILE=1 -> Hardware\qemu
 * "Profile") and is OFF by default, because the timestamp prefix changes what
 * every serial line looks like and the harness greps are anchored.
 *
 * WALL vs CPU. A syscall's wall time spans its parks, so the waits (a client
 * blocked on a server reply) show up in it; its on-CPU time excludes every
 * interval the thread was switched out, so the two together separate "this
 * service is expensive" from "this service waits for someone else". The
 * split is charged at KiSwapToNext, the kernel's ONE context-switch site.
 */
#ifndef PROSKRNL_KERNEL_INIT_PROFILE_H
#define PROSKRNL_KERNEL_INIT_PROFILE_H

#include "abi/ntdef.h"

#include <stdint.h>

/* PKTHREAD is Ke's (kernel/ke/ke.h); this header is included from the
 * dispatcher and the scheduler, both of which already have it. */
#include "kernel/ke/ke.h"

/* Armed by kernel/init/main.c from Hardware\qemu "Profile". Read on the
 * syscall path, so it is a plain BOOLEAN rather than a query. */
extern BOOLEAN KiProfileEnabled;

void KiEnableProfiling(void);

/* The syscall edges (kernel/syscall/table.c). Enter is called once the
 * service is known to exist; Exit once it has returned. Syscalls never nest
 * (the dispatcher asserts it), so one slot per thread is the whole state. */
void KiProfileSyscallEnter(PKTHREAD thread, uint64_t number);
void KiProfileSyscallExit(PKTHREAD thread);

/* The context-switch edges (kernel/ke/sched.c KiSwapToNext), called with the
 * dispatcher lock held: stop charging `old`, start charging `next`. */
void KiProfileSwitch(PKTHREAD old, PKTHREAD next);

/* The clock edge (kernel/ke/timer.c KiUpdateClock), dispatcher lock held:
 * emits the once-a-second delta line. */
void KiProfileTick(void);

/* The volume's side of the same question. A boot whose syscall time is all
 * in NtOpenFile/NtSetValueKey is a boot spending it on the disk, and the two
 * readings that separate "the work is large" from "the work is repeated" are
 * how many sectors the volume actually moved and how many times a file's
 * whole contents were pulled into the page cache (fs/fat32/file.c
 * FatEnsureCache, which loads a file WHOLE and drops it with the last
 * handle). Counted at the FAT layer's four device calls and at the cache
 * fill; no-ops unless armed. */
typedef enum
{
    KiProfileBlockRead,     /* one device read; amount = sectors */
    KiProfileBlockWrite,    /* one device write; amount = sectors */
    KiProfileFileCacheLoad, /* one whole-file cache fill; amount = bytes */
    KiProfileCounterCount
} KI_PROFILE_COUNTER;

void KiProfileCount(KI_PROFILE_COUNTER counter, uint64_t amount);

/* The panic path's section (kernel/init/panic.c KiDumpSystemState). */
void KiDumpSyscallProfile(void);

#endif /* PROSKRNL_KERNEL_INIT_PROFILE_H */
