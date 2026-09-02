/* arch/x86_64/power.h — machine power-off (CUI: the ring-3 NtShutdownSystem
 * arms and the interactive session's end; eventually a bare-metal box).
 *
 * The one way the kernel turns the machine off. Through ACPI S5 when the
 * firmware tables arch/x86_64/acpi.c located carry a usable FADT PM1 control
 * block and \_S5 sleep type — the way the same image will end a session on
 * real hardware — and through QEMU's isa-debug-exit only as the fallback
 * where no usable S5 exists, said on serial. Machine control is `Ki`, not
 * `Hal` (docs/15: the HAL is absorbed into arch/). */
#ifndef PROSKRNL_ARCH_X86_64_POWER_H
#define PROSKRNL_ARCH_X86_64_POWER_H

/* Power the machine off. Never returns: after the S5 write the CPU halts
 * until the platform cuts power (QEMU: the main loop exits with status 0);
 * a platform that ignored the write hangs here with the [KTEST] line that
 * announced it on serial, which is the loud form of that failure. Every
 * mutation is already durable by Art. 3 (immediate writeback), so there is
 * nothing to flush first. Calls nothing that can park (G14). */
__attribute__((noreturn)) void KiPowerOff(void);

#endif /* PROSKRNL_ARCH_X86_64_POWER_H */
