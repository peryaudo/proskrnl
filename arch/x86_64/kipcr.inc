/* arch/x86_64/kipcr.inc — the KPCR fields and the ring-3 segment reload,
 * shared by the two paths that return to user mode: the syscall one
 * (kernel/syscall/entry.S) and the interrupt/exception one (trap.S).
 *
 * A .inc rather than a .h because it holds a `.macro`, and every .h under
 * kernel/ arch/ drivers/ fs/ is rewritten by `make format`'s clang-format,
 * which reads the directive as C and mangles it.
 *
 * The offsets describe arch/x86_64/gdt.h's KIPCR; gdt.c static_asserts them
 * against the struct, so a field that moves fails the build here.
 */

#define KIPCR_KERNEL_RSP 0
#define KIPCR_USER_RSP   8
#define KIPCR_USER_FS32  16

/* Load the ring-3 data selectors before an iretq to user mode. iretq
 * NULLIFIES any data segment whose descriptor DPL is below the new CPL, so
 * without this user mode runs with ds = es = fs = 0 — which is invisible to
 * 64-bit code (segments are ignored) and fatal to a WOW64 guest: wow64cpu
 * captures the live %ds and %fs with RtlCaptureContext and restores the
 * guest through them (dlls/wow64cpu/cpu.c BTCpuProcessInit), and compat mode
 * enforces the limits a null selector does not have. FS carries the thread's
 * TEB32 descriptor for a WOW64 thread and null for every other, which is
 * what the PCR field selects.
 *
 * EVERY return to ring 3 needs it, not just the syscall one: a timer tick or
 * a page fault taken in compat mode returns through trap.S, and a guest
 * resumed from one with a null FS dies on its next `mov %fs:0x18, %eax` —
 * NtCurrentTeb, i.e. the opening line of nearly every guest ntdll entry
 * point. The syscall path had this and the trap path did not, which made the
 * failure a question of WHERE the interrupt landed: the CUI WOW64 leg's
 * short-lived guest never noticed, and a windowed one died in under a
 * second.
 *
 * Clobbers %eax, so both callers run it while every GPR is still saved, and
 * both run it BEFORE swapgs, while GS is still the PCR.
 */
.macro KI_LOAD_USER_SEGMENTS
    movl %gs:KIPCR_USER_FS32, %eax
    movw %ax, %fs
    movl $(KI_GDT_USER_DS | 3), %eax
    movw %ax, %ds
    movw %ax, %es
.endm
