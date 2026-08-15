/* arch/x86_64/lapic.c — Local APIC + the periodic clock interrupt, xAPIC mode.
 *
 * We drive the LAPIC through its xAPIC MMIO window rather than x2APIC MSRs.
 * x2APIC's advantages are 32-bit APIC IDs (>255 CPUs), no MMIO mapping, and a
 * single-write ICR; the first and third are worth nothing to a uniprocessor
 * kernel (Art. 3) and the second costs one page-table entry. What xAPIC buys
 * in exchange is that it is *unconditionally present*: every x86-64 CPU and
 * every QEMU has it, so there is no CPUID bit to test, no firmware "Local APIC
 * Mode = Compatibility" setting to lose to, and no second code path. x2APIC
 * comes back if and when the CPU count justifies it (docs/18 §13).
 *
 * M2 turns the M1 free-running timer into a real 1 ms clock: the LAPIC timer
 * frequency is CPU-dependent, so it is calibrated once against the PIT
 * (channel 2, gated one-shot — the classic dance), then programmed periodic.
 * The tick itself is handled in kernel/ke/timer.c (KiUpdateClock).
 *
 * Constants cross-check: Intel SDM Vol. 3A, "Advanced Programmable Interrupt
 * Controller (APIC)" (xAPIC register offsets, LVT/SVR/divide bit layouts,
 * IA32_APIC_BASE and its EN/EXTD bits, the 4 KiB register window and its
 * 32-bit-aligned access rule); Intel 8254 datasheet + IBM PC/AT port 0x61 for
 * the PIT side. The pinned QEMU we run on (third_party/qemu) decodes the same
 * values in hw/intc/apic.c (register index = offset >> 4: EOI 0x0B, SVR 0x0F,
 * LVT timer 0x32, initial/current count 0x38/0x39, divide 0x3E),
 * target/i386/cpu.h (MSR_IA32_APICBASE 0x1B, ENABLE bit 11, EXTD bit 10;
 * its MSR_IA32_APICBASE_BASE is the 32-bit-guest field, bits 31:12 — the
 * 51:12 mask below is the SDM's full-width one), include/hw/timer/i8254.h
 * (PIT_FREQ 1193182), and hw/audio/pcspk.c (port 0x61: bit 0 = channel-2
 * gate, bit 5 = channel-2 OUT).
 */
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/mmu.h"
#include "kernel/init/panic.h"
#include "kernel/lib/dbgprint.h"
#include "kernel/ke/ke.h"

#include <stdint.h>

#define IA32_APIC_BASE    0x1B
#define APIC_BASE_EN      (1ULL << 11) /* xAPIC global enable */
#define APIC_BASE_EXTD    (1ULL << 10) /* x2APIC enable       */
#define APIC_BASE_ADDRESS 0x000FFFFFFFFFF000ULL

/* xAPIC register offsets within the 4 KiB window. */
#define LAPIC_EOI      0x0B0
#define LAPIC_SVR      0x0F0
#define LAPIC_LVT_TMR  0x320
#define LAPIC_TMR_INIT 0x380
#define LAPIC_TMR_CUR  0x390
#define LAPIC_TMR_DIV  0x3E0

#define LAPIC_SVR_ENABLE   (1U << 8) /* APIC software enable */
#define LAPIC_TMR_PERIODIC (1U << 17)
#define LAPIC_TMR_MASKED   (1U << 16)

/* Kernel VA the register window is mapped at. Deliberately inside PML4 slot
 * 511 — the kernel image's slot, which MiInitializeVirtualMemory always
 * populates — because KiInitializeClock runs after MiFreezeKernelPml4
 * (kernel/init/main.c order) and claiming a *fresh* PML4 slot there would
 * panic. Lower-level tables under an existing slot are shared by every
 * process PML4 automatically, so growing them later is safe. The kernel image
 * itself sits in the top 2 GiB of the same slot (arch/x86_64/linker.ld),
 * 510 GiB above this. */
#define LAPIC_WINDOW_BASE 0xFFFFFF8000000000ULL

static volatile uint8_t *KiApicWindow;

/* The window is strongly uncacheable, so plain volatile 32-bit accesses are
 * the whole contract: no reordering into or out of a cacheable line, and the
 * SDM's "32-bit aligned accesses only" rule is satisfied by construction. */
static uint32_t KiApicRead(uint32_t offset)
{
    ASSERT(KiApicWindow != 0);
    return *(volatile uint32_t *)(KiApicWindow + offset);
}

static void KiApicWrite(uint32_t offset, uint32_t value)
{
    ASSERT(KiApicWindow != 0);
    *(volatile uint32_t *)(KiApicWindow + offset) = value;
}

/* PIT: channel 2 gated by port 0x61 bit 0; OUT2 readable at 0x61 bit 5. */
#define PIT_CHANNEL2 0x42
#define PIT_COMMAND  0x43
#define PIT_GATE     0x61
/* 1.193182 MHz PIT clock (QEMU include/hw/timer/i8254.h PIT_FREQ) in 10 ms:
 * 1193182 / 100 = 11931.82, rounded. */
#define PIT_10MS_COUNT 11932

extern uint64_t KiTrapThunkTable[]; /* trap.S */

void KiEndOfInterrupt(void)
{
    KiApicWrite(LAPIC_EOI, 0);
}

/* Put the LAPIC in xAPIC mode and map its register window. Firmware or a
 * bootloader may hand off with x2APIC already enabled, and in that mode every
 * access to the MMIO window faults — so force the mode rather than assuming
 * it. The SDM forbids clearing EXTD directly: the transition back to xAPIC
 * must pass through the disabled state (EN = 0, EXTD = 0). */
static void KiEnableXApic(void)
{
    uint64_t apicBase = KiReadMsr(IA32_APIC_BASE);
    if (apicBase & APIC_BASE_EXTD)
    {
        KiWriteMsr(IA32_APIC_BASE, apicBase & ~(APIC_BASE_EN | APIC_BASE_EXTD));
        apicBase &= ~APIC_BASE_EXTD;
    }
    KiWriteMsr(IA32_APIC_BASE, apicBase | APIC_BASE_EN);

    /* The window is relocatable (bits 51:12 of the MSR), so read it rather
     * than hardwiring the 0xFEE00000 power-on default. */
    MiMapDevicePage(LAPIC_WINDOW_BASE, apicBase & APIC_BASE_ADDRESS);
    KiApicWindow = (volatile uint8_t *)LAPIC_WINDOW_BASE;
}

uint64_t KiTscPerMillisecond;

/* The LAPIC timer's divide configuration, written to LAPIC_TMR_DIV as 0x3
 * (Intel SDM Vol. 3A, "Divide Configuration Register"). One name for it,
 * because the calibration and the arming below must not drift apart, and
 * because a bus frequency reported in kHz has to be divided by exactly this
 * to become a timer tick rate. */
#define KI_LAPIC_TIMER_DIVISOR 16
#define KI_LAPIC_TMR_DIV_BY_16 0x3

/* CPUID leaves that REPORT a frequency instead of making us measure one.
 *
 * 0x15 (TSC/core-crystal ratio: EAX = denominator, EBX = numerator, ECX =
 * crystal Hz) and 0x16 (EAX = processor base frequency in MHz) are Intel SDM
 * Vol. 2A, CPUID — the same table kernel/ps/query.c already reads 0x16 from.
 *
 * EVERY read below is gated on the maximum leaf the CPU advertises, and that
 * guard is load-bearing rather than tidy: CPUID with a leaf above the maximum
 * returns the HIGHEST supported leaf's registers, not zero (SDM Vol. 2A,
 * "INPUT EAX = Value Outside of Recognized Range"). Measured on the pinned
 * QEMU under TCG, which caps the basic maximum at 0x0D for every CPU model:
 * an ungated leaf-0x15 read on -cpu Skylake-Client-v4 answers
 * EAX=7 EBX=0x240 ECX=0x340, which the ratio below would turn into a
 * confident 68 kHz TSC. A guard that looks like defensive programming is the
 * only thing standing between this function and a clock two thousand times
 * too slow.
 *
 * 0x40000010 is NOT in the SDM: it is the hypervisor timing leaf, originally
 * VMware's and now answered by several hypervisors, EAX = TSC kHz and EBX =
 * APIC bus kHz. Verified against the pinned QEMU tree, target/i386/kvm/kvm.c
 * (`c->function = KVM_CPUID_SIGNATURE | 0x10; c->eax = env->tsc_khz;
 * c->ebx = env->apic_bus_freq / 1000;`), with the intent stated at
 * target/i386/cpu.h `vmware_cpuid_freq` — "the guest OS in CPUID page
 * 0x40000010, the same way that VMWare does". Re-check there, not from memory.
 * The hypervisor-present bit gating it is CPUID.1:ECX[31], SDM Vol. 2A. */
#define KI_CPUID_LEAF_TSC_RATIO   0x15U
#define KI_CPUID_LEAF_CPU_FREQ    0x16U
#define KI_CPUID_LEAF_HV_MAX      0x40000000U
#define KI_CPUID_LEAF_HV_TIMING   0x40000010U
#define KI_CPUID_1_ECX_HYPERVISOR (1U << 31)

/* What the platform says about its own clocks, as opposed to what a busy-wait
 * measures. Either field is 0 when the source cannot answer it — never a
 * plausible stand-in (G12): a zero here means "ask the next source", and if
 * none answers the PIT gate runs. */
typedef struct
{
    uint64_t tscPerMs;       /* TSC cycles in 1 ms */
    uint32_t apicTicksPerMs; /* LAPIC timer ticks in 1 ms, after the divisor */
    const char *source;      /* for the boot line; 0 when nothing answered */
} KI_REPORTED_RATES;

/* Ask the platform for the two rates, most trustworthy source first. This is
 * the order Linux uses and for its reason: a reported frequency is exact,
 * where a gate against an emulated PIT measures the emulation as much as the
 * clock. The gate remains as the last resort (KiInitializeClock). */
static KI_REPORTED_RATES KiQueryReportedRates(void)
{
    KI_REPORTED_RATES rates = {0, 0, 0};
    uint32_t regs[4];

    /* 1. The hypervisor, when there is one. It is the only source here that
     *    can also name the APIC bus, and it is the source that matters on the
     *    platform we actually run on. */
    KiCpuid(1, 0, regs);
    if ((regs[2] & KI_CPUID_1_ECX_HYPERVISOR) != 0)
    {
        KiCpuid(KI_CPUID_LEAF_HV_MAX, 0, regs);
        if (regs[0] >= KI_CPUID_LEAF_HV_TIMING)
        {
            KiCpuid(KI_CPUID_LEAF_HV_TIMING, 0, regs);
            /* kHz is cycles per millisecond, which is the unit we want, so
             * the "conversion" is the identity — stated because a stray
             * factor of 1000 here would be invisible. */
            if (regs[0] != 0)
            {
                rates.tscPerMs = regs[0];
                rates.source = "hypervisor leaf 0x40000010";
            }
            if (rates.tscPerMs != 0)
            {
                if (regs[1] != 0)
                {
                    rates.apicTicksPerMs = regs[1] / KI_LAPIC_TIMER_DIVISOR;
                }
                return rates;
            }
            /* EBX deliberately unread when EAX said nothing. The two numbers
             * are one source's testimony, and KiInitializeClock adopts them
             * together on one verdict; carrying the bus rate forward into a
             * fall-through to CPUID would mix two sources under a check that
             * only examined one of them. QEMU writes both or neither, so this
             * is unreachable there — which is exactly why it is worth closing
             * rather than relying on. */
        }
    }

    /* 2. CPUID 0x15, the architectural ratio. Only exact when the crystal
     *    frequency (ECX) is also reported; the SDM allows it to be 0, and
     *    guessing a crystal from a model number is the kind of table we have
     *    no way to verify (G8). */
    KiCpuid(0, 0, regs);
    uint32_t maxLeaf = regs[0];
    if (maxLeaf >= KI_CPUID_LEAF_TSC_RATIO)
    {
        KiCpuid(KI_CPUID_LEAF_TSC_RATIO, 0, regs);
        uint32_t denominator = regs[0], numerator = regs[1], crystalHz = regs[2];
        if (denominator != 0 && numerator != 0 && crystalHz != 0)
        {
            /* TSC Hz = crystal * numerator / denominator, then Hz -> per ms.
             * 64-bit throughout: crystal * numerator overflows 32 bits. */
            uint64_t tscHz = ((uint64_t)crystalHz * numerator) / denominator;
            rates.tscPerMs = tscHz / 1000;
            rates.source = "CPUID leaf 0x15";
            return rates;
        }
    }

    /* 3. CPUID 0x16's nominal base frequency. Coarser — it is the ADVERTISED
     *    frequency in whole MHz, not a measured one — but it is still the
     *    platform's own number rather than our busy-wait's. */
    if (maxLeaf >= KI_CPUID_LEAF_CPU_FREQ)
    {
        KiCpuid(KI_CPUID_LEAF_CPU_FREQ, 0, regs);
        if (regs[0] != 0)
        {
            rates.tscPerMs = (uint64_t)regs[0] * 1000; /* MHz -> cycles per ms */
            rates.source = "CPUID leaf 0x16";
            return rates;
        }
    }

    return rates;
}

/* Count LAPIC timer ticks (divide-by-16) across one 10 ms PIT gate, and count
 * TSC cycles across the same gate into *tscPerMs — one measurement, two
 * consumers, so the interpolation kernel/ke/timer.c does between ticks is
 * calibrated against the very gate that set the tick's length. */
static uint32_t KiCalibrateApicTimer(uint64_t *tscPerMs)
{
    /* Gate high, speaker off; channel 2, lobyte/hibyte, mode 0 (one-shot,
     * OUT rises at terminal count). */
    KiOutByte(PIT_GATE, (uint8_t)((KiInByte(PIT_GATE) & 0xFC) | 0x01));
    KiOutByte(PIT_COMMAND, 0xB0);

    /* Arm the LAPIC timer BEFORE the PIT starts counting, and start them as
     * close together as the two buses allow. In mode 0 with lobyte/hibyte
     * access the PIT loads and begins on the HIGH-byte write, so the low
     * byte goes out first, the LAPIC's initial-count store next, and the
     * high byte last -- one I/O write apart.
     *
     * The whole LAPIC setup used to sit after both count bytes, so the
     * LAPIC missed the head of the gate: the tick count came out low, the
     * derived ticks-per-ms came out low, and every timeout in the system
     * expired early. Small (<0.1%) but one-directional, which is what makes
     * it worth fixing rather than tolerating (docs/review-2026-07 §8). */
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT & 0xFF);
    KiApicWrite(LAPIC_TMR_DIV, KI_LAPIC_TMR_DIV_BY_16);
    KiApicWrite(LAPIC_LVT_TMR, LAPIC_TMR_MASKED | TIMER_VECTOR);
    KiApicWrite(LAPIC_TMR_INIT, 0xFFFFFFFFU);
    KiOutByte(PIT_CHANNEL2, PIT_10MS_COUNT >> 8);
    uint64_t tscStart = KiReadTimestampCounter();

    while ((KiInByte(PIT_GATE) & 0x20) == 0)
    {
    }

    uint64_t tscEnd = KiReadTimestampCounter();
    uint32_t remaining = KiApicRead(LAPIC_TMR_CUR);
    KiApicWrite(LAPIC_TMR_INIT, 0); /* stop */
    *tscPerMs = (tscEnd - tscStart) / 10;
    return (0xFFFFFFFFU - remaining) / 10; /* ticks per 1 ms */
}

/* Do two rates for the same clock describe the same machine? Within 1%, in
 * either direction, with no assumption about which of the two is larger. */
static BOOLEAN KiRatesAgree(uint64_t a, uint64_t b)
{
    uint64_t low = a < b ? a : b;
    uint64_t high = a < b ? b : a;
    return high - low <= low / 100;
}

void KiInitializeClock(void)
{
    /* Mask both halves of the legacy 8259 PIC so no stray IRQ arrives on a
     * vector that overlaps a CPU exception. */
    KiOutByte(0x21, 0xFF);
    KiOutByte(0xA1, 0xFF);

    KiEnableXApic();

    /* Enable the LAPIC; route spurious interrupts to vector 0xFF -- and give
     * that vector a gate. Without one, the architecturally-defined "ignore
     * this" event raised a #GP and panicked blaming an unrelated RIP
     * (docs/review-2026-07 §8). The handler returns WITHOUT an EOI, as the
     * SDM requires for a spurious interrupt (Vol. 3A §11.9 "Spurious
     * Interrupt"). */
    KiSetInterruptGate(KI_SPURIOUS_VECTOR, (uint64_t)(uintptr_t)KiSpuriousInterruptThunk);
    KiApicWrite(LAPIC_SVR, LAPIC_SVR_ENABLE | KI_SPURIOUS_VECTOR);

    KiSetInterruptGate(TIMER_VECTOR, KiTrapThunkTable[TIMER_VECTOR]);

    /* Measure ALWAYS, ask as well, and believe the answer when one comes back
     * (docs/22 §4b — this is Linux's order and its reason: a reported
     * frequency is exact, where a gate against an EMULATED PIT measures the
     * emulation as much as the clock).
     *
     * The gate runs unconditionally even so, for two reasons that outlive the
     * preference: it is the only thing that can name the LAPIC's own tick rate
     * when the platform will not, and running it every boot is what makes the
     * cross-check below exist on every boot. It costs 10 ms once.
     *
     * Believing a reported rate is only safe because of the maximum-leaf
     * guards in KiQueryReportedRates, and that dependency is worth naming
     * here: an UNGATED leaf-0x15 read answers a confident 68 kHz on a 2.8 GHz
     * machine (the measurement is in that function's comment), and this code
     * would now adopt it. The guards are the thing standing between the two.
     *
     * Verified on a KVM host, which is where the reported path first executed
     * at all — the pinned QEMU under TCG stops at basic leaf 0x0D and answers
     * nothing (issue #176). Every KVM run takes the reported path now:
     * tools/qemu.sh passes -cpu host,+invtsc, which is what makes QEMU publish
     * the leaf at all (target/i386/kvm/kvm.c gates it on
     * tsc_is_stable_and_known). On a Ryzen 5950X leaf 0x40000010 reported
     * tsc=3399997
     * cycles/ms and lapic=62500 ticks/ms where the gate measured 3400965 and
     * 62541 — 0.03% and 0.07% apart, with the reported LAPIC rate landing
     * exactly on QEMU's KVM_APIC_BUS_FREQUENCY / 16. The two sources agree,
     * and the exact one is the reported one. */
    uint64_t measuredTscPerMs = 0;
    uint32_t measuredTicksPerMs = KiCalibrateApicTimer(&measuredTscPerMs);
    KI_REPORTED_RATES reported = KiQueryReportedRates();

    uint64_t tscPerMs = measuredTscPerMs;
    uint32_t ticksPerMs = measuredTicksPerMs;
    const char *source = "measured against the PIT";

    if (reported.tscPerMs != 0)
    {
        tscPerMs = reported.tscPerMs;
        source = reported.source;
        /* The APIC bus rate rides along: the two numbers are one source's
         * testimony, adopted together (KiQueryReportedRates says so on the
         * other side of the seam).
         *
         * Only the hypervisor leaf names it, so the CPUID sources leave the
         * pair MIXED — a reported TSC rate against a measured LAPIC rate,
         * with nothing bounding their ratio, which is the ratio the sub-tick
         * interpolation in kernel/ke/timer.c runs on. That is intended and
         * costs little: an error in the ratio is bounded by the gate's own
         * error against the reported rate (a few hundred ppm of I/O timing
         * noise, and the cross-check below prints it either way), and it
         * shows up as a slightly-off sawtooth WITHIN a tick, never as
         * accumulating time — since §4a made the TSC, not the tick, decide
         * how far the clock moves. */
        if (reported.apicTicksPerMs != 0)
        {
            ticksPerMs = reported.apicTicksPerMs;
        }
    }

    DbgPrint("KiInitializeClock: tsc=%llu cycles/ms lapic=%lu ticks/ms (%s)\n",
             (unsigned long long)tscPerMs, (unsigned long)ticksPerMs, source);

    /* The cross-check, printed on every boot that has both numbers rather
     * than only when it fails: a preference for one source over another must
     * not be a SILENT preference (docs/22 §4b), and a regression here shows up
     * as a changed source or a changed verdict in the boot log rather than as
     * drift nobody notices (§6). This is the only cross-check available
     * without bringing up a second timer device that no other consumer wants.
     *
     * A disagreement is a log line and not a panic because neither source can
     * convict the other: 1% is a wide band for two descriptions of one clock —
     * the gate's own error is a few hundred ppm of I/O timing noise, and a
     * mis-derived frequency misses by a factor rather than by a percent — so
     * anything outside it means one of the two is describing a different
     * machine, and this code has no way to say which. Under Article 9 the
     * dump is the debugger, so it says so where a human will read it. */
    if (reported.tscPerMs != 0 && measuredTscPerMs != 0)
    {
        /* A rate the gate did not produce is NOT a disagreement — a dead
         * LAPIC timer under a live TSC would otherwise print "more than 1%
         * apart" when the truth is that one side said nothing. */
        BOOLEAN agrees = KiRatesAgree(reported.tscPerMs, measuredTscPerMs) &&
                         (reported.apicTicksPerMs == 0 || measuredTicksPerMs == 0 ||
                          KiRatesAgree(reported.apicTicksPerMs, measuredTicksPerMs));
        DbgPrint("KiInitializeClock: the PIT gate measured tsc=%llu cycles/ms lapic=%lu "
                 "ticks/ms -- %s\n",
                 (unsigned long long)measuredTscPerMs, (unsigned long)measuredTicksPerMs,
                 agrees ? "agrees with the reported rate within 1%"
                        : "MORE THAN 1% FROM THE REPORTED RATE, which is what the clock is "
                          "running on");
    }

    if (ticksPerMs == 0)
    {
        KiPanic("KiInitializeClock: LAPIC timer calibration failed");
    }
    if (tscPerMs == 0)
    {
        /* A stopped TSC would make every interpolated reading saturate at
         * one tick short of the next tick — still monotone, but a silently
         * useless clock. There is no such processor (the TSC has been
         * architectural since the Pentium, Intel SDM Vol. 3B §18.17) and no
         * such QEMU, so this refuses rather than degrading quietly (G12). */
        KiPanic("KiInitializeClock: TSC calibration failed");
    }
    KiTscPerMillisecond = tscPerMs;

    KiApicWrite(LAPIC_TMR_DIV, KI_LAPIC_TMR_DIV_BY_16);
    KiApicWrite(LAPIC_LVT_TMR, TIMER_VECTOR | LAPIC_TMR_PERIODIC);
    KiApicWrite(LAPIC_TMR_INIT, ticksPerMs); /* 1 ms period */

    /* Start the clock's interpolation base here, with interrupts still off:
     * the first tick measures how much time actually passed since the base
     * (kernel/ke/timer.c KiTicksElapsed), and the base KiInitializeTimerList
     * set predates the 10 ms gate above. */
    KiResetTickBase();

    __asm__ volatile("sti");
}
