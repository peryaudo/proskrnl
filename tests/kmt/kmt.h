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

/* The M2 suite (tests/kmt/m2_dispatcher.c). Returns total failures. */
int kmt_run_m2(void);

/* The M3 suite (tests/kmt/m3_ob.c). Returns total failures. */
int kmt_run_m3(void);

#endif /* PROSKRNL_TESTS_KMT_KMT_H */
