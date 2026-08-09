/* tests/kmt/kmt.h — in-kernel unit test harness (M2+, docs/04).
 *
 * kmt tests are compiled into the kernel image and run from a kernel thread,
 * because dispatcher tests must be able to wait. Style follows tests/ (Wine
 * test snake_case, see tests/.clang-tidy), not the kernel casing: these are
 * tests, and their ok() reads like every other ok() in the tree.
 *
 * Verdicts use the fixed machine-greppable prefixes (docs/08):
 *   [ASSERT] file:line: ...        one failed assertion
 *   [KTEST] <name> PASS|FAIL       one test function's verdict
 */
#ifndef PROSKRNL_TESTS_KMT_KMT_H
#define PROSKRNL_TESTS_KMT_KMT_H

#include "kernel/lib/dbgprint.h"

extern int kmt_failures; /* total across the run */

#define ok(condition, ...)                                                                         \
    do                                                                                             \
    {                                                                                              \
        if (!(condition))                                                                          \
        {                                                                                          \
            kmt_failures++;                                                                        \
            DbgPrint("[ASSERT] %s:%d: ", __FILE__, __LINE__);                                      \
            DbgPrint(__VA_ARGS__);                                                                 \
            DbgPrint("\n");                                                                        \
        }                                                                                          \
    } while (0)

/* Run one test function, printing its own [KTEST] verdict line. */
#define KMT_RUN(test_fn)                                                                           \
    do                                                                                             \
    {                                                                                              \
        int kmt_before = kmt_failures;                                                             \
        test_fn();                                                                                 \
        DbgPrint("[KTEST] %s %s\n", #test_fn, kmt_failures == kmt_before ? "PASS" : "FAIL");       \
    } while (0)

/* The kernel/lib unit suite (tests/kmt/lib.c): LIST_ENTRY primitives, Rtl
 * counted strings, mem* intrinsics. Returns failures. */
int kmt_run_lib(void);

/* The M2 suite (tests/kmt/m2_dispatcher.c). Returns total failures. */
int kmt_run_m2(void);

/* The M3 suite (tests/kmt/m3_ob.c). Returns total failures. */
int kmt_run_m3(void);

/* The M4 suite (tests/kmt/m4_usermode.c): the mm/VAD engine exercised in
 * kernel mode, ahead of the ring-3 boot-module clients. Returns failures. */
int kmt_run_m4(void);

/* The M5 suite (tests/kmt/m5_section.c): section objects — anonymous view
 * sharing, RAM-disk file mapping + read consistency, PE image mapping with
 * relocation, guard-page bookkeeping — driven against a scratch address
 * space. Returns failures. */
int kmt_run_m5(void);

/* The M6 suite (tests/kmt/m6_io.c): virtio-blk sector I/O, the mounted
 * FAT32 volume through the Nt* file surface (create/read/write/enumerate/
 * delete round trips), and a SEC_IMAGE section created from an on-disk
 * file. Returns failures. */
int kmt_run_m6(void);

/* The virtio-blk driver units (tests/kmt/m6_blk.c): chunk-boundary
 * transfers, last-sector/past-capacity I/O, write+readback with neighbor
 * checks in the unpartitioned GPT slack. Called from kmt_run_m6. */
int kmt_run_m6_blk(void);

/* The CUI-8 machine verdicts (tests/kmt/cui8_async.c): progress while a
 * fill is parked, the docs/19 §8.4 depth floor, and in-flight
 * cancellation — deterministic via the await-spin knob. */
int kmt_run_cui8(void);

/* The CUI-9 shared-image-master machine verdicts (tests/kmt/cui9_cow.c):
 * the identity key, the sharing metric (second view costs only its
 * writable pages), refcount transitions with exact frame round-trips, and
 * the docs/17 §8 no-writable-master-PTE sweep. */
int kmt_run_cui9(void);

/* The FAT interop battery (tests/kmt/fat_interop.c): reads/checksums the
 * mtools-baked adversarial corpus and writes the battery the host extracts
 * and verifies. Runs only when C:\fatcorpus\manifest.txt exists (the
 * run.sh fatinterop image); silently absent everywhere else. */
int kmt_run_fat_interop(void);

/* The FS churn stress (tests/kmt/fat_churn.c): fixed-seed random ops vs an
 * in-memory shadow model; two-boot protocol (seed wet / replay dry + cold
 * verify). Runs only when C:\churn.cfg exists (the run.sh fatstress
 * images); silently absent everywhere else. */
int kmt_run_fat_churn(void);

/* The issue #96 preventive-mechanism guards (tests/kmt/preventive.c): the
 * non-blocking-region depth and the release-obligation ledger are balanced
 * across every representative gated FS verb, including its error paths.
 * Returns failures. */
int kmt_run_preventive(void);

/* The bounded-exhaustive interleaving search (tests/kmt/sched_explore.c,
 * issue #96 D): two-thread scenarios replayed under enumerated schedule
 * strings, each concurrent history checked for linearizability against the
 * oracle-pinned sequential semantics. Returns failures. */
int kmt_run_sched_explore(void);

/* The console terminate-unwind states (tests/kmt/condrv_unwind.c): a client
 * verb parked in condrv, aborted for termination while it is queued, while
 * conhost owns it, and after conhost has already completed it. Returns
 * failures. */
int kmt_run_condrv(void);

#endif /* PROSKRNL_TESTS_KMT_KMT_H */
