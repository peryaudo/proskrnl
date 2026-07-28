/*
 * sem_ps/initial_fpu.c — the x87/SSE state a fresh process starts with.
 *
 * A new thread's MXCSR is 0x1f80 (all SIMD exceptions masked) and the x87
 * control word is 0x27f — what Wine's ntdll seeds new-thread CONTEXTs with
 * (third_party/wine dlls/ntdll/unix/signal_x86_64.c init_syscall_frame) and
 * what every CRT-less PE observes at entry. The inexact multiply below is
 * the everyday consumer: an unmasked precision exception turns the first
 * `x * .95` a GUI applet computes into a fatal #XM (notepad's
 * NOTEPAD_LoadSettingFromRegistry does exactly that multiply at startup).
 *
 * The state must survive the ntdll startup path (LdrInitializeThunk ->
 * NtContinue) — this probe reads the LIVE registers, not a CONTEXT.
 */
#include "util.h"

START_TEST(initial_fpu)
{
    unsigned int mxcsr = 0;
    unsigned short fcw = 0;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
    __asm__ volatile("fnstcw %0" : "=m"(fcw));

    ok(mxcsr == 0x1f80, "startup MXCSR %#x", mxcsr);
    ok(fcw == 0x27f, "startup x87 control word %#x", fcw);

    /* The observable consequence: an inexact SSE multiply must round, not
     * raise. (With PM unmasked this line dies with an unhandled #XM.) */
    volatile double base = 800.0;
    volatile double scaled = base * .95;
    ok(scaled > 759.9 && scaled < 760.1, "inexact multiply survived");

    /* The multiply left only status flags behind: the masks still hold. */
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
    ok((mxcsr & 0x1f80) == 0x1f80, "MXCSR masks intact after use (%#x)", mxcsr);
}
