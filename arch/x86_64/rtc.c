/* arch/x86_64/rtc.c — MC146818 CMOS RTC: read once at boot (CUI-1), written
 * back only by NtSetSystemTime (CUI-7).
 *
 * The one wall-clock read in the system: KiSystemTimeBase is seeded from it
 * and every later timestamp is base + interrupt time (kernel/ke/timer.c).
 * There is no periodic RTC interrupt and no alarm — QEMU's `-rtc base=utc`
 * default supplies host UTC and the clock only needs to be right once
 * (docs/03: the no-RTC deviation CUI-1 retired); the CUI-7 writeback exists
 * so a privileged SetSystemTime survives a reboot.
 *
 * Register map and flag bits: MC146818A datasheet (address map, registers
 * 0x00-0x0D) — the pinned QEMU tree mirrors it verbatim in
 * include/hw/rtc/mc146818rtc_regs.h, which also fixes the PC-CMOS century
 * byte at 0x32 (not part of the MC146818 itself; an IBM PC AT convention
 * QEMU implements in hw/rtc/mc146818rtc.c). Re-verify constants there.
 */
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/io.h"

/* Index/data port pair (IBM PC AT convention; pinned QEMU hw/rtc/
 * mc146818rtc.c RTC_ISA_BASE 0x70). Port 0x70 bit 7 doubles as the NMI
 * mask on real chipsets; writing it 0 leaves NMI enabled, which is the
 * state the kernel runs in anyway. */
#define RTC_INDEX_PORT 0x70
#define RTC_DATA_PORT  0x71

/* Time-of-day registers (MC146818A datasheet; QEMU mc146818rtc_regs.h). */
#define RTC_SECONDS      0x00
#define RTC_MINUTES      0x02
#define RTC_HOURS        0x04
#define RTC_DAY_OF_MONTH 0x07
#define RTC_MONTH        0x08
#define RTC_YEAR         0x09
#define RTC_REG_A        0x0a
#define RTC_REG_B        0x0b
#define RTC_CENTURY      0x32

#define RTC_REG_A_UIP  0x80 /* update in progress */
#define RTC_REG_B_SET  0x80 /* halt updates while the time is being written */
#define RTC_REG_B_DM   0x04 /* data mode: 1 = binary, 0 = BCD */
#define RTC_REG_B_2412 0x02 /* 1 = 24-hour, 0 = 12-hour with PM in hour bit 7 */

typedef struct RTC_SNAPSHOT
{
    uint8_t seconds;
    uint8_t minutes;
    uint8_t hours;
    uint8_t day;
    uint8_t month;
    uint8_t year;
    uint8_t century;
} RTC_SNAPSHOT;

static uint8_t RtcReadRegister(uint8_t index)
{
    KiOutByte(RTC_INDEX_PORT, index);
    return KiInByte(RTC_DATA_PORT);
}

static void RtcReadSnapshot(RTC_SNAPSHOT *snapshot)
{
    snapshot->seconds = RtcReadRegister(RTC_SECONDS);
    snapshot->minutes = RtcReadRegister(RTC_MINUTES);
    snapshot->hours = RtcReadRegister(RTC_HOURS);
    snapshot->day = RtcReadRegister(RTC_DAY_OF_MONTH);
    snapshot->month = RtcReadRegister(RTC_MONTH);
    snapshot->year = RtcReadRegister(RTC_YEAR);
    snapshot->century = RtcReadRegister(RTC_CENTURY);
}

static int RtcSnapshotsEqual(const RTC_SNAPSHOT *a, const RTC_SNAPSHOT *b)
{
    return a->seconds == b->seconds && a->minutes == b->minutes && a->hours == b->hours &&
           a->day == b->day && a->month == b->month && a->year == b->year &&
           a->century == b->century;
}

/* BCD unless register B's DM bit says binary (datasheet: DM selects the
 * format of ALL time/calendar registers, century included). */
static int RtcDecodeField(uint8_t value, uint8_t regB)
{
    if (regB & RTC_REG_B_DM)
    {
        return value;
    }
    if ((value & 0x0f) > 9 || (value >> 4) > 9)
    {
        return -1;
    }
    return (value >> 4) * 10 + (value & 0x0f);
}

static int RtcIsLeapYear(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

/* Days from 1601-01-01 (the NT epoch — MS FILETIME documentation) to
 * year-month-day by calendar arithmetic, no recalled constants (same
 * derivation as fs/fat32/fat.c FatDaysSinceNtEpoch). */
static uint64_t RtcDaysSinceNtEpoch(int year, int month, int day)
{
    static const int daysPerMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint64_t days = 0;
    for (int y = 1601; y < year; y++)
    {
        days += RtcIsLeapYear(y) ? 366 : 365;
    }
    for (int m = 1; m < month; m++)
    {
        days += (uint64_t)daysPerMonth[m - 1];
        if (m == 2 && RtcIsLeapYear(year))
        {
            days += 1;
        }
    }
    return days + (uint64_t)(day - 1);
}

uint64_t KiReadRtcTime(void)
{
    /* Wait out an in-progress update (register A UIP; the datasheet bounds
     * the update cycle well under a millisecond), then read until two
     * snapshots agree so no field rolled over mid-read. Bounded loops: a
     * hung RTC must not hang boot — fall through and let the plausibility
     * checks reject garbage. */
    for (int i = 0; i < 1000000 && (RtcReadRegister(RTC_REG_A) & RTC_REG_A_UIP); i++)
    {
    }
    RTC_SNAPSHOT snapshot, verify;
    RtcReadSnapshot(&snapshot);
    for (int i = 0; i < 16; i++)
    {
        RtcReadSnapshot(&verify);
        if (RtcSnapshotsEqual(&snapshot, &verify))
        {
            break;
        }
        snapshot = verify;
    }

    uint8_t regB = RtcReadRegister(RTC_REG_B);
    int seconds = RtcDecodeField(snapshot.seconds, regB);
    int minutes = RtcDecodeField(snapshot.minutes, regB);
    int day = RtcDecodeField(snapshot.day, regB);
    int month = RtcDecodeField(snapshot.month, regB);
    int year = RtcDecodeField(snapshot.year, regB);
    int century = RtcDecodeField(snapshot.century, regB);

    /* 12-hour mode keeps the PM flag in hour bit 7 (datasheet); decode the
     * low bits first, then fold 12 AM -> 0 and add 12 for PM. */
    int pm = (~regB & RTC_REG_B_2412) && (snapshot.hours & 0x80);
    int hours = RtcDecodeField(snapshot.hours & 0x7f, regB);
    if (hours >= 0 && (~regB & RTC_REG_B_2412))
    {
        hours = hours % 12 + (pm ? 12 : 0);
    }

    if (seconds < 0 || seconds > 59 || minutes < 0 || minutes > 59 || hours < 0 || hours > 23 ||
        day < 1 || day > 31 || month < 1 || month > 12 || year < 0 || year > 99 || century < 19 ||
        century > 99)
    {
        return 0;
    }

    uint64_t totalSeconds = RtcDaysSinceNtEpoch(century * 100 + year, month, day) * 86400ULL +
                            (uint64_t)hours * 3600 + (uint64_t)minutes * 60 + (uint64_t)seconds;
    return totalSeconds * 10000000ULL; /* 100 ns units */
}

/* --- the CUI-7 writeback ----------------------------------------------------- */

static void RtcWriteRegister(uint8_t index, uint8_t value)
{
    KiOutByte(RTC_INDEX_PORT, index);
    KiOutByte(RTC_DATA_PORT, value);
}

/* Encode per the chip's current data mode (the decode inverse). */
static uint8_t RtcEncodeField(int value, uint8_t regB)
{
    if (regB & RTC_REG_B_DM)
    {
        return (uint8_t)value;
    }
    return (uint8_t)(((value / 10) << 4) | (value % 10));
}

void KiWriteRtcTime(uint64_t ntTime)
{
    /* 100 ns units -> calendar fields, the KiReadRtcTime derivation run
     * backwards (calendar arithmetic, no recalled constants). */
    uint64_t totalSeconds = ntTime / 10000000ULL;
    int seconds = (int)(totalSeconds % 60);
    int minutes = (int)((totalSeconds / 60) % 60);
    int hours = (int)((totalSeconds / 3600) % 24);
    uint64_t days = totalSeconds / 86400ULL;

    static const int daysPerMonth[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int year = 1601;
    for (;;)
    {
        uint64_t inYear = RtcIsLeapYear(year) ? 366 : 365;
        if (days < inYear)
        {
            break;
        }
        days -= inYear;
        year++;
        if (year > 9999)
        {
            return; /* implausible input: leave the CMOS alone */
        }
    }
    int month = 1;
    for (;;)
    {
        uint64_t inMonth = (uint64_t)daysPerMonth[month - 1];
        if (month == 2 && RtcIsLeapYear(year))
        {
            inMonth += 1;
        }
        if (days < inMonth)
        {
            break;
        }
        days -= inMonth;
        month++;
    }
    int day = (int)days + 1;

    /* Halt the update cycle (register B SET — datasheet: the divider keeps
     * counting but the calendar bytes are safe to write), store per the
     * chip's own modes, then release. */
    uint8_t regB = RtcReadRegister(RTC_REG_B);
    RtcWriteRegister(RTC_REG_B, regB | RTC_REG_B_SET);
    RtcWriteRegister(RTC_SECONDS, RtcEncodeField(seconds, regB));
    RtcWriteRegister(RTC_MINUTES, RtcEncodeField(minutes, regB));
    if (regB & RTC_REG_B_2412)
    {
        RtcWriteRegister(RTC_HOURS, RtcEncodeField(hours, regB));
    }
    else
    {
        /* 12-hour mode: PM in hour bit 7, 12 AM stored as 12 (datasheet). */
        int pm = hours >= 12;
        int hour12 = hours % 12;
        if (hour12 == 0)
        {
            hour12 = 12;
        }
        RtcWriteRegister(RTC_HOURS, (uint8_t)(RtcEncodeField(hour12, regB) | (pm ? 0x80 : 0)));
    }
    RtcWriteRegister(RTC_DAY_OF_MONTH, RtcEncodeField(day, regB));
    RtcWriteRegister(RTC_MONTH, RtcEncodeField(month, regB));
    RtcWriteRegister(RTC_YEAR, RtcEncodeField(year % 100, regB));
    RtcWriteRegister(RTC_CENTURY, RtcEncodeField(year / 100, regB));
    RtcWriteRegister(RTC_REG_B, regB);
}
