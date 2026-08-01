/* arch/x86_64/rtc.h — MC146818 CMOS RTC, read once at boot (CUI-1). */
#ifndef PROSKRNL_ARCH_X86_64_RTC_H
#define PROSKRNL_ARCH_X86_64_RTC_H

#include <stdint.h>

/* Current wall-clock UTC as 100 ns units since 1601-01-01 (the NT FILETIME
 * epoch), or 0 if the CMOS content is implausible. */
uint64_t KiReadRtcTime(void);

/* CUI-7 (NtSetSystemTime): write wall-clock UTC (same units) back into the
 * CMOS so the set time survives a reboot. Encodes per the chip's own
 * register-B data/hour modes; a no-op for implausible input. */
void KiWriteRtcTime(uint64_t ntTime);

#endif /* PROSKRNL_ARCH_X86_64_RTC_H */
