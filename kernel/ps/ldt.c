/* kernel/ps/ldt.c — the per-process LDT (NtSetLdtEntries).
 *
 * A 32-bit process may give itself extra segment descriptors, and NT's
 * NtSetLdtEntries is the door: two selector/descriptor pairs per call, into
 * a table private to the calling process. `ntdll:wow64`'s test_selectors
 * sets two entries and reads them back through
 * NtQueryInformationThread(ThreadDescriptorTableEntry), which is what makes
 * this a boundary behavior (Art. 1) rather than a convenience.
 *
 * WHY THIS IS BUILT AT ALL, given the oracle refuses it. Wine's ntdll
 * answers STATUS_NOT_IMPLEMENTED for a 64-bit caller
 * (dlls/ntdll/unix/virtual.c: `if (is_win64 && !is_wow64()) return
 * STATUS_NOT_IMPLEMENTED`), and that status is never an answer proskrnl may
 * give: it means *unbuilt*, every ring-3 caller reaching one panics, and
 * G12 forbids pinning it. A gap in Wine is a gap in the ORACLE, not in NT
 * (docs/03 "Panic-on-STATUS_NOT_IMPLEMENTED boot"), so the case is built
 * against NT's own contract and pinned in a `beyond_oracle` block —
 * tests/ntapi/sem_ps/ldt.c. The alternative was a refusal the winetest
 * would have had to be exempted from, which is the re-exemption that same
 * doc forbids.
 *
 * The table is allocated on FIRST USE, so a process that never asks pays
 * nothing — which is every process in the tree today except a 32-bit one
 * that reaches for a custom selector. Uniprocessor, so one GDT slot holds
 * whichever process is current (arch/x86_64/gdt.c KiSetProcessLdt), exactly
 * as the compat-mode FS descriptor does.
 */
#include "kernel/ps/ps.h"

#include "abi/ntpsapi.h"
#include "arch/x86_64/gdt.h"
#include "kernel/init/panic.h"
#include "kernel/mm/pool.h"

#include "kernel/lib/string.h"

/* A selector's index is bits 15:3, so a full LDT is 8192 descriptors of 8
 * bytes (Intel SDM Vol. 3A §3.4.2 "Segment Selectors"). Allocated whole
 * rather than grown: one size, no reallocation, no partially-valid table
 * for the CPU to walk (Art. 3). */
#define PSP_LDT_ENTRIES 8192
#define PSP_LDT_BYTES   (PSP_LDT_ENTRIES * 8)

/* Descriptor bytes as the caller supplies them, so a set/read-back round
 * trip is byte-exact (the winetest memcmps what it wrote). */
typedef struct
{
    ULONG low;
    ULONG high;
} PSP_LDT_ENTRY;

_Static_assert(sizeof(PSP_LDT_ENTRY) == 8, "an LDT descriptor is 8 bytes");

/* The bits that make a descriptor SAFE to install for ring 3, checked
 * before anything is written. A descriptor the CPU will load is a
 * capability, so an arbitrary 8 bytes from user mode cannot become one:
 *
 *   S (bit 44) must be 1  — a system descriptor here would be a call gate,
 *                           an LDT, or a TSS, i.e. a ring transition;
 *   DPL (bits 46:45) == 3 — a ring-0 selector handed to ring 3;
 *   the descriptor must be PRESENT to be installed at all (a not-present
 *   one is the documented way to clear a slot and is always allowed).
 *
 * Intel SDM Vol. 3A §3.4.5 "Segment Descriptors", Table 3-1. NT sanitizes
 * the same way; refusing rather than silently masking keeps the caller's
 * read-back byte-exact. */
#define PSP_LDT_HIGH_S_BIT   (1u << 12) /* bit 44 of the descriptor */
#define PSP_LDT_HIGH_DPL     (3u << 13) /* bits 46:45 */
#define PSP_LDT_HIGH_PRESENT (1u << 15) /* bit 47 */

static BOOLEAN PspLdtEntryAcceptable(ULONG high)
{
    if ((high & PSP_LDT_HIGH_PRESENT) == 0)
    {
        return TRUE; /* clearing a slot */
    }
    return (high & PSP_LDT_HIGH_S_BIT) != 0 && (high & PSP_LDT_HIGH_DPL) == PSP_LDT_HIGH_DPL;
}

/* The table for `process`, allocated on first use. */
static PSP_LDT_ENTRY *PspGetLdt(PEPROCESS process)
{
    if (process->ldt == 0)
    {
        process->ldt = MiAllocatePool(PSP_LDT_BYTES); /* zeroed: all not-present */
    }
    return process->ldt;
}

void PspFreeLdt(PEPROCESS process)
{
    if (process->ldt != 0)
    {
        MiFreePool(process->ldt);
        process->ldt = 0;
    }
}

void PspLoadProcessLdt(PEPROCESS process)
{
    if (process == 0 || process->ldt == 0)
    {
        KiSetProcessLdt(0, 0);
        return;
    }
    KiSetProcessLdt((uint64_t)(uintptr_t)process->ldt, PSP_LDT_BYTES - 1);
}

/* Read one descriptor back for NtQueryInformationThread's
 * ThreadDescriptorTableEntry. Returns FALSE when the selector names no
 * present entry, which is the caller's cue to refuse — an absent slot must
 * NOT read back as a zeroed descriptor (Art. 12). */
BOOLEAN PspQueryLdtEntry(PEPROCESS process, ULONG selector, void *entryOut)
{
    if (process == 0 || process->ldt == 0)
    {
        return FALSE;
    }
    ULONG index = (selector >> 3) & 0x1fff;
    PSP_LDT_ENTRY *table = process->ldt;
    if ((table[index].high & PSP_LDT_HIGH_PRESENT) == 0)
    {
        return FALSE;
    }
    memcpy(entryOut, &table[index], sizeof(PSP_LDT_ENTRY));
    return TRUE;
}

/* One selector/descriptor pair. Index 0 is the null selector and is
 * silently ignored rather than refused — the winetest's first call passes
 * it deliberately and expects success (ldt_set_entry does the same). */
static NTSTATUS PspSetLdtEntry(PEPROCESS process, ULONG selector, ULONG low, ULONG high)
{
    if ((selector >> 16) != 0)
    {
        return STATUS_INVALID_LDT_DESCRIPTOR;
    }
    ULONG index = (selector >> 3) & 0x1fff;
    if (index == 0)
    {
        return STATUS_SUCCESS;
    }
    if (!PspLdtEntryAcceptable(high))
    {
        return STATUS_INVALID_LDT_DESCRIPTOR;
    }
    PSP_LDT_ENTRY *table = PspGetLdt(process);
    if (table == 0)
    {
        return STATUS_NO_MEMORY;
    }
    table[index].low = low;
    table[index].high = high;
    return STATUS_SUCCESS;
}

NTSTATUS NtSetLdtEntries(ULONG selector1, ULONG entry1Low, ULONG entry1High, ULONG selector2,
                         ULONG entry2Low, ULONG entry2High)
{
    PEPROCESS process = KeGetCurrentThread()->process;
    if (process == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* Both selectors are validated before either is written, so a call that
     * refuses leaves the table exactly as it was. */
    if ((selector1 >> 16) != 0 || (selector2 >> 16) != 0)
    {
        return STATUS_INVALID_LDT_DESCRIPTOR;
    }
    if (!PspLdtEntryAcceptable(entry1High) || !PspLdtEntryAcceptable(entry2High))
    {
        return STATUS_INVALID_LDT_DESCRIPTOR;
    }
    NTSTATUS status = PspSetLdtEntry(process, selector1, entry1Low, entry1High);
    if (NT_SUCCESS(status))
    {
        status = PspSetLdtEntry(process, selector2, entry2Low, entry2High);
    }
    if (NT_SUCCESS(status))
    {
        /* The table may have just come into existence; the descriptor the
         * CPU walks has to name it before this thread returns to ring 3. */
        PspLoadProcessLdt(process);
    }
    return status;
}
