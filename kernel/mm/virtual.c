/* kernel/mm/virtual.c — user virtual memory: VADs + NtAllocate/Free/Query
 * VirtualMemory (M4). See virtual.h for the Art. 3 shape.
 *
 * The boundary semantics here — rounding, status codes, the
 * MemoryBasicInformation runs — are pinned by tests/ntapi/sem_mm/
 * reserve_commit.c, which is green on the pinned Wine oracle; where this
 * file makes a choice, it is the choice Wine's implementation makes
 * (dlls/ntdll/unix/virtual.c is the reference for behaviour, not code).
 */
#include "kernel/mm/virtual.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/mm/section.h"
#include "kernel/ps/ps.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"
#include "arch/x86_64/mmu.h"

#include "abi/ntstatus.h"

/* One reservation: [base, base + size), page-granular, with one protection
 * word per page (0 = reserved-only, else the committed PAGE_* value —
 * possibly carrying PAGE_GUARD, in which case the frame is mapped
 * not-present until the guard fires). M5 adds mapped views: `type` is
 * MEM_PRIVATE for NtAllocateVirtualMemory memory, MEM_MAPPED/MEM_IMAGE for
 * section views; a view pins its Section object (one reference, owned by
 * the VAD, released when the VAD dies) and `ownsFrames` says whether
 * decommit returns the frames to the allocator (private memory and image
 * full copies) or leaves them alone (shared data-section frames). */
struct MI_VAD
{
    LIST_ENTRY listEntry; /* on MI_ADDRESS_SPACE.vadListHead, ascending */
    uint64_t base;
    uint64_t size;
    ULONG allocationProtect;
    PULONG pageProtect;
    ULONG type;        /* MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE */
    PVOID sectionBody; /* referenced Section body; 0 for private */
    BOOLEAN ownsFrames;
    /* CUI-7 write-watch (MEM_WRITE_WATCH at reserve): one dirty byte per
     * page, the AUTHORITATIVE record — the PTE's writable bit is only the
     * trap mechanism (docs/17 §6.B names why the bit alone is not a
     * record). A committed protection-writable page is mapped read-only
     * while clean; the write fault marks it and remaps (fault.c). Kernel
     * writes bypass PTEs, so every kernel path that writes user memory
     * marks through MiResolveWriteFault (uaccess probe retry,
     * MiCopyToUserRangeChecked). */
    BOOLEAN writeWatch;
    UCHAR *watchDirty; /* one byte per page; pool, zeroed */
    /* CUI-9 image masters (docs/17 §4, docs/03 "CUI-9 COW notes"): a bound
     * MEM_IMAGE view maps the shared already-relocated master's frames.
     * `pagePrivate` (allocated only when `master` is set) is the per-page
     * FRAME-OWNERSHIP record: 1 = this VAD owns a private copy (freed at
     * decommit), 0 = the PTE points at a master frame (left alone). It is
     * deliberately not the reported protection — the pinned oracle never
     * transitions Protect on a writecopy store (docs/03 hazard D), so the
     * shared/private state must live outside pageProtect. */
    PVOID master;       /* MI_IMAGE_MASTER (opaque here); one ref, VAD-owned */
    UCHAR *pagePrivate; /* one byte per page; pool, zeroed */
    /* CUI-7: the view's byte offset into its section (0 for private
     * memory), so NtFlushVirtualMemory can address the covered FILE range
     * (section.c used to compute and discard it). */
    uint64_t sectionOffset;
    /* Placeholders (docs/21 W5): MI_VAD_PLACEHOLDER / MI_VAD_FREE_PLACEHOLDER.
     * The oracle draws the same two-bit DISTINCTION in its view protection
     * (VPROT_PLACEHOLDER / VPROT_FREE_PLACEHOLDER, third_party/wine
     * dlls/ntdll/unix/virtual.c — different values, same meaning; these
     * never cross the ABI, so they are ours to number). The pair is not
     * redundant: FREE says
     * the range is an EMPTY placeholder right now, PLACEHOLDER alone says
     * it is a real allocation that CAME from one. Only the second can be
     * released back into a placeholder, which is the difference between
     * a MEM_PRESERVE_PLACEHOLDER free that works and one that answers
     * STATUS_CONFLICTING_ADDRESSES — and no other field can tell the two
     * apart, because a placeholder and a PAGE_NOACCESS reservation report
     * identically through MEMORY_BASIC_INFORMATION. */
    UCHAR placeholder;
};

/* This VAD participates in the placeholder protocol at all. */
#define MI_VAD_PLACEHOLDER 0x01
/* ...and is one right now: reserved, empty, waiting to be replaced. */
#define MI_VAD_FREE_PLACEHOLDER 0x02

static uint64_t MiRoundDown(uint64_t value, uint64_t align)
{
    return value & ~(align - 1);
}

static uint64_t MiRoundUp(uint64_t value, uint64_t align)
{
    return (value + align - 1) & ~(align - 1);
}

static ULONG MiVadPageCount(PMI_VAD vad)
{
    return (ULONG)(vad->size / PAGE_SIZE);
}

/* Valid anonymous-commit protections (Wine's get_vprot_flags): the WRITECOPY
 * flavours need a backing file and are rejected for private memory. */
static NTSTATUS MiCheckPageProtect(ULONG protect)
{
    switch (protect & ~(PAGE_GUARD | PAGE_NOCACHE))
    {
    case PAGE_NOACCESS:
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
}

/* --- the view-protection compatibility rule ------------------------------
 *
 * NT will not let a view be re-protected — or committed over — to an access
 * the VIEW was not mapped with. `VirtualProtect(view, PAGE_READWRITE)` on a
 * view mapped PAGE_READONLY is not a privilege check that happens to pass
 * for a lucky caller; it is refused, always, and the refusal is what stops a
 * read-only view from becoming a writable window onto shared frames.
 *
 * The rule is the oracle's set_protection (third_party/wine
 * dlls/ntdll/unix/virtual.c) and it is three lines:
 *
 *     if (is_view_valloc( view ))                 // private memory
 *         if (vprot & VPROT_WRITECOPY) return STATUS_INVALID_PAGE_PROTECTION;
 *     else {                                      // any section view
 *         BYTE access = vprot & (VPROT_READ | VPROT_WRITE | VPROT_EXEC);
 *         if ((view->protect & access) != access) return STATUS_INVALID_PAGE_PROTECTION;
 *     }
 *
 * Two things about it are easy to get wrong and both are load-bearing:
 *
 *  - the comparison is a SUBSET test on READ/WRITE/EXEC, not equality, so a
 *    view mapped PAGE_EXECUTE_READWRITE may be narrowed to anything;
 *  - VPROT_WRITECOPY is NOT one of the compared bits, so PAGE_WRITECOPY
 *    needs only READ. That is why a PAGE_READONLY view can be protected
 *    write-copy and a PAGE_READWRITE one can be too.
 *
 * kernel32:virtual sweeps this whole matrix — every section protection
 * crossed with every view protection crossed with every requested
 * protection — and ~2100 of its ~4100 failures were this rule missing
 * (virtual.c:4250/:4251).
 */

/* The READ/WRITE/EXEC access a Win32 page protection implies, as
 * get_vprot_flags computes it. `image` selects the arm where a plain
 * writable protection means WRITECOPY instead of WRITE — which, since
 * WRITECOPY is not an access bit, makes PAGE_READWRITE on an image view
 * demand only READ. Returns the bits; MiVprotFlags validates. */
/* Wine's VPROT_READ / VPROT_WRITE / VPROT_EXEC, same values (third_party/
 * wine dlls/ntdll/unix/virtual.c). They never cross this kernel's ABI —
 * MiCheckViewProtection's subset test is the only thing that reads them —
 * but keeping the oracle's numbering means that test can be read straight
 * against set_protection without a translation step. */
#define MI_ACCESS_READ  0x1u
#define MI_ACCESS_WRITE 0x2u
#define MI_ACCESS_EXEC  0x4u

static NTSTATUS MiVprotAccess(ULONG protect, BOOLEAN image, ULONG *accessOut)
{
    switch (protect & 0xff)
    {
    case PAGE_NOACCESS:
        *accessOut = 0;
        return STATUS_SUCCESS;
    case PAGE_READONLY:
        *accessOut = MI_ACCESS_READ;
        return STATUS_SUCCESS;
    case PAGE_WRITECOPY:
        *accessOut = MI_ACCESS_READ; /* WRITECOPY is not an access bit */
        return STATUS_SUCCESS;
    case PAGE_READWRITE:
        *accessOut = image ? MI_ACCESS_READ : (MI_ACCESS_READ | MI_ACCESS_WRITE);
        return STATUS_SUCCESS;
    case PAGE_EXECUTE:
        *accessOut = MI_ACCESS_EXEC; /* no READ — the oracle's own asymmetry */
        return STATUS_SUCCESS;
    case PAGE_EXECUTE_READ:
        *accessOut = MI_ACCESS_EXEC | MI_ACCESS_READ;
        return STATUS_SUCCESS;
    case PAGE_EXECUTE_WRITECOPY:
        *accessOut = MI_ACCESS_EXEC | MI_ACCESS_READ;
        return STATUS_SUCCESS;
    case PAGE_EXECUTE_READWRITE:
        *accessOut = image ? (MI_ACCESS_EXEC | MI_ACCESS_READ)
                           : (MI_ACCESS_EXEC | MI_ACCESS_READ | MI_ACCESS_WRITE);
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }
}

/* THE set_protection gate, for both of its callers: NtProtectVirtualMemory
 * and the MEM_COMMIT-over-an-existing-view path. One authority, because the
 * two used to disagree — protect enforced part of the rule and commit
 * enforced none of it. */
static NTSTATUS MiCheckViewProtection(PMI_VAD vad, ULONG protect)
{
    BOOLEAN image = vad->type == MEM_IMAGE;
    ULONG wanted;
    NTSTATUS status = MiVprotAccess(protect, image, &wanted);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (vad->type == MEM_PRIVATE)
    {
        /* 0xff: the oracle's own mask — get_vprot_flags switches on
         * `protect & 0xff`, so PAGE_GUARD and PAGE_NOCACHE (which live
         * above that byte) do not change which protection this is. */
        ULONG bits = protect & 0xff;
        if (bits == PAGE_WRITECOPY || bits == PAGE_EXECUTE_WRITECOPY)
        {
            return STATUS_INVALID_PAGE_PROTECTION;
        }
        return STATUS_SUCCESS;
    }
    ULONG granted;
    /* The view's OWN protection is the ceiling, not the section's: a
     * PAGE_READWRITE section mapped PAGE_READONLY yields a read-only
     * ceiling. vad->allocationProtect is that map protection. */
    status = MiVprotAccess(vad->allocationProtect, image, &granted);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if ((granted & wanted) != wanted)
    {
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    return STATUS_SUCCESS;
}

static void MiProtectToPteBits(ULONG protect, int *present, int *writable, int *executable)
{
    ULONG bits = protect & ~(PAGE_GUARD | PAGE_NOCACHE);
    /* A guard page is committed but mapped not-present so the first touch
     * traps (mm/fault.c clears the guard and remaps). */
    *present = bits != PAGE_NOACCESS && (protect & PAGE_GUARD) == 0;
    /* The WRITECOPY flavours appear on image views only (M5); every mapping
     * is already a private full copy (Art. 3: no COW), so they are plain
     * writable here — only the reported protection keeps the NT name. */
    *writable = bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE ||
                bits == PAGE_WRITECOPY || bits == PAGE_EXECUTE_WRITECOPY;
    *executable = bits == PAGE_EXECUTE || bits == PAGE_EXECUTE_READ ||
                  bits == PAGE_EXECUTE_READWRITE || bits == PAGE_EXECUTE_WRITECOPY;
}

/* The VAD containing `address`, or 0. */
static PMI_VAD MiFindVad(PMI_ADDRESS_SPACE space, uint64_t address)
{
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (address >= vad->base && address < vad->base + vad->size)
        {
            return vad;
        }
        if (vad->base > address)
        {
            break; /* ascending list */
        }
    }
    return 0;
}

static BOOLEAN MiRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size)
{
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (base < vad->base + vad->size && vad->base < base + size)
        {
            return FALSE;
        }
        if (vad->base >= base + size)
        {
            break;
        }
    }
    return TRUE;
}

/* The highest address a `zeroBits` allocation may occupy, INCLUSIVE — the
 * same "last byte fits under this" convention MiFindFreeRegion's limitHigh
 * uses, which is why it is spelled here and passed straight through. 0 =
 * unconstrained.
 *
 * zero_bits carries TWO meanings in one argument, and NT picks between them
 * by magnitude. Transcribed from the oracle's get_zero_bits_limit
 * (third_party/wine dlls/ntdll/unix/unix_private.h), which is the single
 * definition both NtAllocateVirtualMemory and NtMapViewOfSection call:
 *
 *   0            no constraint at all.
 *   1 .. 31      a COUNT of leading zero bits, measured in a 32-bit window:
 *                the limit is (~0ull >> (32 + zeroBits)), i.e. the address
 *                must be below 2^(32 - zeroBits). ntdll:virtual asserts
 *                exactly this shape — `(UINT_PTR)addr >> (32 - zero_bits)`
 *                must be 0 (virtual.c:170).
 *   >= 32        a MASK of the address bits the caller will accept: the
 *                limit is every bit up to and including its highest set one.
 *
 * The callers reject the gaps (`zeroBits > 21 && zeroBits < 32`, and
 * `> 32 && < granularity_mask`) before reaching here, so this function is
 * never asked about a value NT calls invalid. It still answers something
 * sane for one, because a placement ceiling that silently became 0 —
 * "unconstrained" — is the failure mode being fixed. */
uint64_t MiZeroBitsLimit(uint64_t zeroBits)
{
    if (zeroBits == 0)
    {
        return 0;
    }
    unsigned int shift;
    if (zeroBits < 32)
    {
        shift = 32 + (unsigned int)zeroBits;
    }
    else
    {
        /* Highest set bit, found the way the oracle finds it. */
        shift = 63;
        if (zeroBits >> 32)
        {
            shift -= 32;
            zeroBits >>= 32;
        }
        if (zeroBits >> 16)
        {
            shift -= 16;
            zeroBits >>= 16;
        }
        if (zeroBits >> 8)
        {
            shift -= 8;
            zeroBits >>= 8;
        }
        if (zeroBits >> 4)
        {
            shift -= 4;
            zeroBits >>= 4;
        }
        if (zeroBits >> 2)
        {
            shift -= 2;
            zeroBits >>= 2;
        }
        if (zeroBits >> 1)
        {
            shift -= 1;
        }
    }
    return (~(uint64_t)0) >> shift;
}

/* The CLASSIC allocation entry point's whole zero_bits contract, stated once:
 * the two bands NT calls invalid, and the placement ceiling everything else
 * names (virtual.h).
 *
 * It is a function rather than four lines at each caller because there is a
 * second caller and the oracle makes it the same way: its
 * NtSetInformationProcess(ProcessThreadStackAllocation) arm reserves the
 * stack by CALLING NtAllocateVirtualMemory (third_party/wine
 * dlls/ntdll/unix/process.c), so the class inherits these bands rather than
 * having bands of its own. Two transcriptions of one ladder would be a second
 * authority for the same rule (Art. 11) — and a silently divergent one, since
 * every status they disagree about is a status no test asks for twice. */
NTSTATUS MiZeroBitsPlacementLimit(uint64_t zeroBits, uint64_t *limitHighOut)
{
    /* Wine's zero_bits validation shape (dlls/ntdll/unix/virtual.c,
     * NtAllocateVirtualMemory). The x86-64 arm only: the `zero_bits >= 32`
     * refusal below it is inside `#ifndef _WIN64`. */
    if ((zeroBits > 21 && zeroBits < 32) ||
        (zeroBits > 32 && zeroBits < MI_ALLOCATION_GRANULARITY - 1))
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    *limitHighOut = MiZeroBitsLimit(zeroBits);
    return STATUS_SUCCESS;
}

/* Does a range the CALLER named fit inside the placement limits? The
 * free-range search below cannot ask this — it only ever returns addresses it
 * chose — so it is the other half of the same constraint, and both halves are
 * spelled once here (Art. 11).
 *
 * The one-byte asymmetry with MiFindFreeRegion is the oracle's and it is
 * measured, not inferred (tests/ntapi/sem_mm/map_zero_bits.c, the exact-extent
 * case): the search treats limitHigh as INCLUSIVE (`end = limit_high + 1`,
 * dlls/ntdll/unix/virtual.c map_view), while the named-base guard beside it
 * refuses at `base + size > limit_high` (the same file's is_beyond_limit), so
 * a named view whose LAST BYTE is exactly limitHigh is one byte too long.
 * Transcribed rather than tidied. 0 = unconstrained, either end. */
BOOLEAN MiRangeWithinLimits(uint64_t base, uint64_t size, uint64_t limitLow, uint64_t limitHigh)
{
    if (limitLow != 0 && base < limitLow)
    {
        return FALSE;
    }
    if (limitHigh != 0 && (base >= limitHigh || base + size > limitHigh))
    {
        return FALSE;
    }
    return TRUE;
}

/* Lowest aligned hole of `size` bytes, bottom-up like Wine. 0 = full. The
 * CUI-7 placement constraints (VirtualAlloc2's MEM_ADDRESS_REQUIREMENTS)
 * ride the same walk: limitLow/limitHigh bound the block INCLUSIVE of its
 * last byte, align raises the 64K step (0s = unconstrained; THE one
 * free-range authority — classic and Ex allocations both resolve here). */
static uint64_t MiFindFreeRegion(PMI_ADDRESS_SPACE space, uint64_t size, uint64_t limitLow,
                                 uint64_t limitHigh, uint64_t align)
{
    if (align < MI_ALLOCATION_GRANULARITY)
    {
        align = MI_ALLOCATION_GRANULARITY;
    }
    if (limitHigh == 0)
    {
        limitHigh = KI_USER_SPACE_LIMIT - 1;
    }
    uint64_t floor = MI_LOWEST_USER_ADDRESS;
    if (limitLow > floor)
    {
        floor = limitLow;
    }
    uint64_t candidate = MiRoundUp(floor, align);
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        if (candidate + size <= vad->base)
        {
            break;
        }
        if (vad->base + vad->size > candidate)
        {
            /* candidate only ever moves up: a VAD ending below the floor
             * never passes this test, so the floor holds. */
            candidate = MiRoundUp(vad->base + vad->size, align);
        }
    }
    if (candidate + size - 1 <= limitHigh && candidate + size <= KI_USER_SPACE_LIMIT)
    {
        return candidate;
    }
    return 0;
}

static void MiInsertVad(PMI_ADDRESS_SPACE space, PMI_VAD vad)
{
    PLIST_ENTRY entry = space->vadListHead.Flink;
    while (entry != &space->vadListHead &&
           CONTAINING_RECORD(entry, MI_VAD, listEntry)->base < vad->base)
    {
        entry = entry->Flink;
    }
    /* Insert before `entry`. */
    vad->listEntry.Flink = entry;
    vad->listEntry.Blink = entry->Blink;
    entry->Blink->Flink = &vad->listEntry;
    entry->Blink = &vad->listEntry;
}

/* Commit (or re-protect) the pages [base, base+size) inside `vad`. Frames
 * appear immediately, zeroed (Art. 3: no demand paging). */
/* The hardware writable bit for one page: the page's protection, minus the
 * write-watch trap — a watched CLEAN page maps read-only so ring-3's first
 * store faults into the mark (fault.c). ONE authority for the rule; commit,
 * re-protect and the watch re-arm all go through here. */
static int MipVadPageHwWritable(PMI_VAD vad, ULONG index, int protectionWritable)
{
    if (!protectionWritable)
    {
        return 0;
    }
    if (vad->writeWatch && vad->watchDirty != 0 && !vad->watchDirty[index])
    {
        return 0;
    }
    /* CUI-9: a still-shared master page maps read-only whatever the
     * protection says — the first store resolves through the COW arm
     * (MiResolveWriteFault), which copies, repoints and opens this gate by
     * flipping pagePrivate. Never satisfy writecopy by just setting the
     * writable bit: that is the shared master, for everyone (docs/17 §6B). */
    if (vad->master != 0 && vad->pagePrivate != 0 && !vad->pagePrivate[index])
    {
        return 0;
    }
    return 1;
}

static NTSTATUS MiCommitPages(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size,
                              ULONG protect)
{
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        int hwWritable = MipVadPageHwWritable(vad, index, writable);
        if (vad->pageProtect[index] == 0)
        {
            uint64_t frame = MiAllocatePage();
            if (frame == 0)
            {
                return STATUS_NO_MEMORY; /* earlier pages stay committed, as NT */
            }
            memset(MiPhysicalToVirtual(frame), 0, PAGE_SIZE);
            MiMapUserPage(space->pml4Physical, page, frame, present, hwWritable, executable);
        }
        else if (vad->pageProtect[index] != protect)
        {
            uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
            ASSERT(frame != 0); /* committed pages always keep their frame */
            MiUnmapUserPage(space->pml4Physical, page);
            MiMapUserPage(space->pml4Physical, page, frame, present, hwWritable, executable);
        }
        vad->pageProtect[index] = protect;
    }
    return STATUS_SUCCESS;
}

static void MiDecommitPages(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size)
{
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] != 0)
        {
            uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
            ASSERT(frame != 0);
            MiUnmapUserPage(space->pml4Physical, page);
            /* Frame ownership: per page for a master-bound view (private
             * copies are the VAD's, master frames are the master's — the
             * master deref in MiUnlinkAndFreeVad settles those), per VAD
             * for everything else. */
            if (vad->pagePrivate != 0 ? vad->pagePrivate[index] != 0 : vad->ownsFrames)
            {
                MiFreePage(frame);
            }
            vad->pageProtect[index] = 0;
        }
    }
}

static void MiUnlinkAndFreeVad(PMI_VAD vad)
{
    RemoveEntryList(&vad->listEntry);
    if (vad->master != 0)
    {
        MiDereferenceImageMaster(vad->master); /* the view's pin on the master */
    }
    if (vad->sectionBody != 0)
    {
        ObDereferenceObject(vad->sectionBody); /* the view's pin on the section */
    }
    if (vad->watchDirty != 0)
    {
        MiFreePool(vad->watchDirty);
    }
    if (vad->pagePrivate != 0)
    {
        MiFreePool(vad->pagePrivate);
    }
    MiFreePool(vad->pageProtect);
    MiFreePool(vad);
}

static PMI_VAD MiCreateVad(uint64_t base, uint64_t size, ULONG allocationProtect)
{
    PMI_VAD vad = MiAllocatePool(sizeof(MI_VAD));
    if (vad == 0)
    {
        return 0;
    }
    vad->base = base;
    vad->size = size;
    vad->allocationProtect = allocationProtect;
    vad->type = MEM_PRIVATE;
    vad->sectionBody = 0;
    vad->ownsFrames = TRUE;
    vad->writeWatch = FALSE;
    vad->watchDirty = 0;
    vad->master = 0;
    vad->pagePrivate = 0;
    vad->sectionOffset = 0;
    vad->placeholder = 0;
    vad->pageProtect = MiAllocatePool((size / PAGE_SIZE) * sizeof(ULONG));
    if (vad->pageProtect == 0)
    {
        MiFreePool(vad);
        return 0;
    }
    return vad;
}

/* A private VAD over [base, size) -- a strict sub-range of `vad` -- carrying
 * everything the original recorded about those pages: allocation
 * protection, placeholder state, per-page protection, and the write-watch
 * record if there is one. Nothing is committed and no frame moves; this is
 * bookkeeping for a split, and the caller decides what happens to the
 * pages. */
static PMI_VAD MiCloneVadRange(PMI_VAD vad, uint64_t base, uint64_t size)
{
    ASSERT(base >= vad->base && base + size <= vad->base + vad->size);
    PMI_VAD piece = MiCreateVad(base, size, vad->allocationProtect);
    if (piece == 0)
    {
        return 0;
    }
    ULONG firstPage = (ULONG)((base - vad->base) / PAGE_SIZE);
    ULONG pages = (ULONG)(size / PAGE_SIZE);
    piece->placeholder = vad->placeholder;
    memcpy(piece->pageProtect, vad->pageProtect + firstPage, pages * sizeof(ULONG));
    if (vad->watchDirty != 0)
    {
        piece->watchDirty = MiAllocatePool(pages);
        if (piece->watchDirty == 0)
        {
            MiFreePool(piece->pageProtect);
            MiFreePool(piece);
            return 0;
        }
        memcpy(piece->watchDirty, vad->watchDirty + firstPage, pages);
    }
    piece->writeWatch = vad->writeWatch;
    return piece;
}

/* Replace `vad` with whatever of it lies OUTSIDE [base, size), plus -- when
 * `carvedOut` is non-null -- a fresh VAD over the carved range itself, which
 * is the caller's to re-stamp. Every piece inherits the original's record
 * through MiCloneVadRange; `vad` is unlinked and freed either way, so a
 * carve of the whole VAD with no `carvedOut` is simply a release.
 *
 * Frames are the CALLER's business: no page table is touched and no frame
 * is freed here, so committed pages stay mapped across the carve and each
 * piece's copied per-page record keeps describing its own range. A caller
 * that wants a piece emptied decommits it, before or after — MEM_RELEASE
 * does it before (on the original VAD) and MEM_PRESERVE_PLACEHOLDER after
 * (on the carved one), and both are correct for that reason.
 *
 * Every allocation happens before anything is unlinked. The VAD list is the
 * only record of what a process owns, so a half-applied split is
 * unrecoverable — out of memory has to leave the address space exactly as
 * it was.
 *
 * ONE split for both consumers (Art. 11): MEM_RELEASE drops the carved range
 * and MEM_RELEASE|MEM_PRESERVE_PLACEHOLDER keeps it as the new placeholder.
 * They are the same operation, and the release path's own copy of it used to
 * lose the write-watch record — invisible until a watched range was split. */
static NTSTATUS MiCarveVad(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size,
                           PMI_VAD *carvedOut)
{
    ASSERT(vad->type == MEM_PRIVATE);
    ASSERT(base >= vad->base && base + size <= vad->base + vad->size);

    PMI_VAD head = 0;
    PMI_VAD tail = 0;
    PMI_VAD carved = 0;
    BOOLEAN wantHead = base > vad->base;
    BOOLEAN wantTail = base + size < vad->base + vad->size;

    if (wantHead)
    {
        head = MiCloneVadRange(vad, vad->base, base - vad->base);
    }
    if (wantTail && (!wantHead || head != 0))
    {
        tail = MiCloneVadRange(vad, base + size, vad->base + vad->size - (base + size));
    }
    if (carvedOut != 0 && (!wantHead || head != 0) && (!wantTail || tail != 0))
    {
        carved = MiCloneVadRange(vad, base, size);
    }
    if ((wantHead && head == 0) || (wantTail && tail == 0) || (carvedOut != 0 && carved == 0))
    {
        /* Not linked yet, so the pieces are freed by hand. */
        PMI_VAD pieces[3] = {head, tail, carved};
        for (int i = 0; i < 3; i++)
        {
            if (pieces[i] != 0)
            {
                if (pieces[i]->watchDirty != 0)
                {
                    MiFreePool(pieces[i]->watchDirty);
                }
                MiFreePool(pieces[i]->pageProtect);
                MiFreePool(pieces[i]);
            }
        }
        return STATUS_NO_MEMORY;
    }

    MiUnlinkAndFreeVad(vad);
    if (head != 0)
    {
        MiInsertVad(space, head);
    }
    if (tail != 0)
    {
        MiInsertVad(space, tail);
    }
    if (carved != 0)
    {
        MiInsertVad(space, carved);
        *carvedOut = carved;
    }
    return STATUS_SUCCESS;
}

/* --- the engines (virtual.h) ----------------------------------------------- */

NTSTATUS MiCreateAddressSpace(PMI_ADDRESS_SPACE space)
{
    space->pml4Physical = MiCreateUserPml4();
    if (space->pml4Physical == 0)
    {
        return STATUS_NO_MEMORY;
    }
    InitializeListHead(&space->vadListHead);
    return STATUS_SUCCESS;
}

void MiDeleteAddressSpace(PMI_ADDRESS_SPACE space)
{
    while (!IsListEmpty(&space->vadListHead))
    {
        PMI_VAD vad = CONTAINING_RECORD(space->vadListHead.Flink, MI_VAD, listEntry);
        MiDecommitPages(space, vad, vad->base, vad->size);
        MiUnlinkAndFreeVad(vad);
    }
    MiDeleteUserPml4(space->pml4Physical);
    space->pml4Physical = 0;
}

/* MEM_REPLACE_PLACEHOLDER: turn a placeholder into ordinary private memory
 * IN PLACE, keeping its VAD and therefore its address range. The range must
 * be a placeholder and the request must name all of it — a replacement that
 * covered part of one would have to split it, and splitting is
 * MEM_PRESERVE_PLACEHOLDER's job (which the caller must do first).
 *
 * The two refusals are different on purpose and the oracle keeps them apart
 * (its map_view placeholder arm): naming a range nobody reserved, or a
 * reserved range that never was a placeholder, is a bad ARGUMENT
 * (STATUS_INVALID_PARAMETER); naming a real placeholder but the wrong extent
 * of it is a range CONFLICT. */
static NTSTATUS MiReplacePlaceholder(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size,
                                     ULONG type, ULONG protect)
{
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (vad->base != base || vad->size != size)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    if ((vad->placeholder & MI_VAD_FREE_PLACEHOLDER) == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ASSERT(vad->type == MEM_PRIVATE);

    UCHAR *watchDirty = 0;
    if (type & MEM_WRITE_WATCH)
    {
        watchDirty = MiAllocatePool(size / PAGE_SIZE); /* pool zeroes */
        if (watchDirty == 0)
        {
            return STATUS_NO_MEMORY;
        }
    }

    ULONG wasProtect = vad->allocationProtect;
    UCHAR wasPlaceholder = vad->placeholder;
    /* The replacement's watch state is what THIS call asked for, not what
     * the placeholder happened to carry: MEM_WRITE_WATCH is legal on the
     * reserve that created the placeholder and means nothing there, because
     * a placeholder has no page to watch. The old record is released only
     * once the replacement is certain, so a failed commit can hand back the
     * range exactly as it was found. */
    UCHAR *wasWatchDirty = vad->watchDirty;
    BOOLEAN wasWriteWatch = vad->writeWatch;
    vad->watchDirty = watchDirty;
    vad->writeWatch = watchDirty != 0;
    vad->allocationProtect = protect;
    /* A replacement stays IN the protocol (MI_VAD_PLACEHOLDER) and stops
     * being an empty one — that is what lets the eventual
     * MEM_PRESERVE_PLACEHOLDER free give the range back rather than refuse.
     * A request that asks for both bits at once reserves a placeholder over
     * a placeholder and stays free, as the oracle's `vprot |
     * VPROT_PLACEHOLDER` leaves it. */
    vad->placeholder = MI_VAD_PLACEHOLDER;
    if (type & MEM_RESERVE_PLACEHOLDER)
    {
        vad->placeholder |= MI_VAD_FREE_PLACEHOLDER;
    }
    if (type & MEM_COMMIT)
    {
        NTSTATUS status = MiCommitPages(space, vad, base, size, protect);
        if (!NT_SUCCESS(status))
        {
            /* Put the placeholder back exactly as it was: the caller is
             * being told the request failed, and a half-replaced
             * placeholder is a range nobody can name again. */
            MiDecommitPages(space, vad, base, size);
            if (watchDirty != 0)
            {
                MiFreePool(watchDirty);
            }
            vad->watchDirty = wasWatchDirty;
            vad->writeWatch = wasWriteWatch;
            vad->allocationProtect = wasProtect;
            vad->placeholder = wasPlaceholder;
            return status;
        }
    }
    if (wasWatchDirty != 0)
    {
        MiFreePool(wasWatchDirty);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiAllocateVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                 ULONG type, ULONG protect)
{
    return MiAllocateVirtualMemoryEx(space, baseInOut, sizeInOut, type, protect, 0, 0, 0, 0);
}

NTSTATUS MiAllocateVirtualMemoryEx(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                                   ULONG type, ULONG protect, uint64_t limitLow, uint64_t limitHigh,
                                   uint64_t align, ULONG attributes)
{
    uint64_t requestedBase = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;

    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* The UNION of both entry points' masks. Which bits a CALLER may pass is
     * the entry point's question, not the engine's: NtAllocateVirtualMemoryEx
     * accepts the two placeholder bits and NtAllocateVirtualMemory does not,
     * and each states its own mask the way the oracle does (its
     * `static const ULONG type_mask` per Nt*, dlls/ntdll/unix/virtual.c). */
    if (type & ~(ULONG)(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET |
                        MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* Refuse an oversized request BEFORE the page rounding below, which
     * otherwise wraps: MiRoundUp(requestedBase + size, PAGE_SIZE) - base can
     * come out as 0 (or as a small value), and the size == 0 test above has
     * already been passed on the pre-rounding value. A rounded size of 0
     * reaches MiCreateVad and then MiAllocatePool(0), which panics.
     *
     * Position matters as much as the rule. The oracle splits these two
     * across a call boundary: NtAllocateVirtualMemory validates the type mask
     * (`if (type & ~type_mask) return STATUS_INVALID_PARAMETER;`) and only
     * then calls allocate_virtual_memory, which opens with
     * `if (is_beyond_limit( 0, size, working_set_limit )) return
     * STATUS_WORKING_SET_LIMIT_RANGE;` (third_party/wine
     * dlls/ntdll/unix/virtual.c). So a bad type outranks an oversized size,
     * and this test has to sit AFTER the mask check above -- both orders look
     * right until a caller gets both arguments wrong at once, which is why
     * sem_mm/reserve_commit pins it.
     *
     * working_set_limit starts at 0x7fffffff0000, i.e. KI_USER_SPACE_LIMIT.
     * With addr == 0 the macro reduces to a strict `size > limit`, so exactly
     * the limit falls through to the ordinary out-of-memory path. */
    if (size > KI_USER_SPACE_LIMIT)
    {
        return STATUS_WORKING_SET_LIMIT_RANGE;
    }
    /* Both placeholder bits are MODIFIERS on a reserve, never a request of
     * their own: MEM_REPLACE_PLACEHOLDER without MEM_RESERVE is a parameter
     * error even when the range it names is a perfectly good placeholder
     * (the oracle's `type & MEM_REPLACE_PLACEHOLDER && !(type & MEM_RESERVE)`
     * arm, folded into the same test). MEM_RESERVE_PLACEHOLDER falls out of
     * the mask below instead, because a placeholder carries no access and
     * PAGE_NOACCESS is the only protection it may be created with. */
    if ((type & (MEM_COMMIT | MEM_RESERVE | MEM_RESET)) == 0 ||
        ((type & MEM_REPLACE_PLACEHOLDER) != 0 && (type & MEM_RESERVE) == 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if ((type & MEM_RESERVE_PLACEHOLDER) != 0 && protect != PAGE_NOACCESS)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* MEM_EXTENDED_PARAMETER_EC_CODE asks for ARM64EC code memory, which only
     * an ARM64EC image has: the oracle's guard is `if (!arm64ec_view &&
     * (attributes & MEM_EXTENDED_PARAMETER_EC_CODE)) return
     * STATUS_INVALID_PARAMETER;` (third_party/wine dlls/ntdll/unix/virtual.c
     * allocate_virtual_memory), and proskrnl is x86_64-only
     * (docs/adr/0006-x64-only.md) so the left half is permanently true.
     *
     * The bit is a PROBE, not a preference. ntdll:unwind's
     * test_virtual_unwind_arm64 calls exactly this to ask whether it is on an
     * ARM64EC host, and on a "yes" runs ARM64 unwind opcodes over the x86_64
     * code buffer it just got — so accepting the bit and dropping it does not
     * return a wrong answer, it hands the caller a lie it then executes.
     *
     * Position is the oracle's: below the working-set and type-flag tests
     * above, so an oversized EC_CODE request still reports
     * STATUS_WORKING_SET_LIMIT_RANGE. It is in the ENGINE rather than in
     * MiCaptureExtendedParams because the mapping path takes the same word
     * and ignores it. Both halves pinned (sem_mm/alloc_ex, sem_mm/map_ex). */
    if ((attributes & MEM_EXTENDED_PARAMETER_EC_CODE) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    /* NO protection validation here. The oracle validates per BRANCH, not up
     * front (dlls/ntdll/unix/virtual.c allocate_virtual_memory): the reserve
     * branch calls get_vprot_flags, the commit branch calls set_protection —
     * and the commit branch's file-backed arm returns STATUS_ALREADY_COMMITTED
     * BEFORE either. Validating early inverts that: a PAGE_WRITECOPY commit
     * over a file view answered STATUS_INVALID_PAGE_PROTECTION (error 87)
     * where NT answers STATUS_ALREADY_COMMITTED (error 5), and kernel32:virtual
     * counted 464 of them at virtual.c:4291.
     *
     * A PURE MEM_RESET validates nothing at all, for the same reason: the
     * oracle's reset arm never asks. Note the qualifier — the oracle tests
     * MEM_RESERVE FIRST, so MEM_RESERVE|MEM_RESET routes to its RESERVE arm
     * and is validated there, while this function tests MEM_RESET first and
     * sends that combination to the reset arm unvalidated. The ordering
     * predates this change and nothing measures the combination; it is
     * written down here rather than "fixed" on a guess (Art. 6). */
    NTSTATUS status;

    uint64_t base;
    if (requestedBase != 0)
    {
        /* Explicit base: reserve rounds down to the 64K granularity,
         * commit-into-reservation to the page (Wine's exact rule). A
         * placeholder REPLACEMENT rounds to the page too, because the
         * placeholder it must match exactly may itself be a page-aligned
         * piece of a split — 64K rounding would walk the base off the front
         * of it and answer STATUS_CONFLICTING_ADDRESSES for a request that
         * named its range correctly. */
        base =
            MiRoundDown(requestedBase, (type & MEM_RESERVE) && (type & MEM_REPLACE_PLACEHOLDER) == 0
                                           ? MI_ALLOCATION_GRANULARITY
                                           : (uint64_t)PAGE_SIZE);
        size = MiRoundUp(requestedBase + size, PAGE_SIZE) - base;
        if (base < MI_LOWEST_USER_ADDRESS || base + size < base ||
            base + size > KI_USER_SPACE_LIMIT)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        base = 0;
        size = MiRoundUp(size, PAGE_SIZE);
    }

    /* Structural backstop for the rounding above. The size > limit test at the
     * top of this function is what a caller observes, but nothing downstream
     * is prepared for a zero-sized VAD: MiCreateVad would call
     * MiAllocatePool(0) (a panic), and a zero-length VAD could never be found
     * by MiFindVad afterwards, so it would be unfreeable and unqueryable. */
    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (type & MEM_RESET)
    {
        /* MEM_RESET: contents may be discarded. Nothing is ever paged out
         * (Art. 3), so keeping them is a correct implementation. */
        PMI_VAD vad = MiFindVad(space, base);
        if (vad == 0 || base + size > vad->base + vad->size)
        {
            return STATUS_NOT_MAPPED_VIEW;
        }
        *baseInOut = (PVOID)(uintptr_t)base;
        *sizeInOut = size;
        return STATUS_SUCCESS;
    }

    if ((type & MEM_RESERVE) || requestedBase == 0)
    {
        /* The reserve branch's own validation, where the oracle's
         * get_vprot_flags call sits. */
        status = MiCheckPageProtect(protect);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (type & MEM_REPLACE_PLACEHOLDER)
        {
            status = MiReplacePlaceholder(space, base, size, type, protect);
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            *baseInOut = (PVOID)(uintptr_t)base;
            *sizeInOut = size;
            return STATUS_SUCCESS;
        }
        if (requestedBase == 0)
        {
            base = MiFindFreeRegion(space, size, limitLow, limitHigh, align);
            if (base == 0)
            {
                return STATUS_NO_MEMORY;
            }
        }
        else if (!MiRangeIsFree(space, base, size))
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        PMI_VAD vad = MiCreateVad(base, size, protect);
        if (vad == 0)
        {
            return STATUS_NO_MEMORY;
        }
        if (type & MEM_WRITE_WATCH)
        {
            /* Not yet linked: free by hand on failure. */
            vad->watchDirty = MiAllocatePool(size / PAGE_SIZE); /* pool zeroes */
            if (vad->watchDirty == 0)
            {
                MiFreePool(vad->pageProtect);
                MiFreePool(vad);
                return STATUS_NO_MEMORY;
            }
            vad->writeWatch = TRUE;
        }
        if (type & MEM_RESERVE_PLACEHOLDER)
        {
            vad->placeholder = MI_VAD_PLACEHOLDER | MI_VAD_FREE_PLACEHOLDER;
        }
        MiInsertVad(space, vad);
        if (type & MEM_COMMIT)
        {
            status = MiCommitPages(space, vad, base, size, protect);
            if (!NT_SUCCESS(status))
            {
                MiDecommitPages(space, vad, base, size);
                MiUnlinkAndFreeVad(vad);
                return status;
            }
        }
    }
    else
    {
        /* Commit into an existing reservation; the whole range must sit in
         * one VAD (Wine: find_view(base, size) else NOT_MAPPED_VIEW). */
        PMI_VAD vad = MiFindVad(space, base);
        if (vad == 0 || base + size > vad->base + vad->size)
        {
            return STATUS_NOT_MAPPED_VIEW;
        }
        /* The oracle's commit branch, in its order:
         *
         *   else if (view->protect & SEC_FILE) status = STATUS_ALREADY_COMMITTED;
         *   else ... set_protection( view, base, size, protect );
         *
         * A FILE-backed view — data or image — is already committed by its
         * file, and the refusal comes before any look at the protection.
         * kernelbase turns STATUS_ALREADY_COMMITTED into ERROR_ACCESS_DENIED,
         * which is what kernel32:virtual asserts (virtual.c:4291).
         *
         * An ANONYMOUS section view (pagefile-backed, no SEC_FILE) is a
         * different answer entirely: the commit is allowed, gated only by
         * the same view-protection rule NtProtectVirtualMemory uses, and it
         * really does re-protect the pages. That is virtual.c:4264/:4273,
         * which wanted success for a compatible protection and
         * ERROR_INVALID_PARAMETER for an incompatible one — and got
         * ERROR_ACCESS_DENIED for both, because every non-private view took
         * the file-backed answer. */
        if (vad->type != MEM_PRIVATE)
        {
            PMI_SECTION section = vad->sectionBody;
            if (section == 0 || (section->attributes & SEC_FILE) != 0)
            {
                return STATUS_ALREADY_COMMITTED;
            }
        }
        /* A placeholder IS reserved, so a commit that does not know about
         * them lands here and quietly succeeds — turning the hole somebody
         * is holding open into ordinary committed memory. NT refuses: the
         * only way into a placeholder is to replace it. Same position as the
         * oracle's own test, one line under the SEC_FILE arm above. */
        if (vad->placeholder & MI_VAD_FREE_PLACEHOLDER)
        {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        status = MiCheckViewProtection(vad, protect);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (vad->type != MEM_PRIVATE)
        {
            /* Already committed by the map; what is left is the protection
             * change, applied through the one engine that owns it. The
             * base/size it reports back are its own rounding of the same
             * range, which this caller has already computed — so they go to
             * scratch and the caller's values below stand. */
            uint64_t protectBase = base;
            uint64_t protectSize = size;
            ULONG previous = 0;
            status = MiProtectVirtualMemory(space, &protectBase, &protectSize, protect, &previous);
        }
        else
        {
            status = MiCommitPages(space, vad, base, size, protect);
        }
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    *baseInOut = (PVOID)(uintptr_t)base;
    *sizeInOut = size;
    return STATUS_SUCCESS;
}

/* MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER: give the range back AS a
 * placeholder rather than to the free pool. Two different callers reach
 * this with the same three arguments:
 *
 *   - all of a replacement, undoing MEM_REPLACE_PLACEHOLDER. The memory
 *     goes away and the placeholder that was there before comes back.
 *   - PART of a placeholder, which is how a placeholder is SPLIT — the
 *     named piece becomes a placeholder of its own and the remainder stays
 *     one, so the caller can then replace them independently.
 *
 * All of a placeholder is neither, and NT refuses it rather than succeeding
 * vacuously. That refusal is what makes the FREE bit worth keeping
 * separately from the PLACEHOLDER bit. */
static NTSTATUS MiPreservePlaceholder(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base,
                                      uint64_t size)
{
    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if ((vad->placeholder & MI_VAD_PLACEHOLDER) == 0)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    if ((vad->placeholder & MI_VAD_FREE_PLACEHOLDER) != 0 && size == vad->size)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    ASSERT(vad->type == MEM_PRIVATE);

    if (size < vad->size)
    {
        /* Carve first, then empty only the carved piece: the head and tail
         * of a partially-preserved REPLACEMENT keep their committed pages,
         * so decommitting the whole VAD up front would take memory the
         * caller never asked to give back. */
        PMI_VAD carved = 0;
        NTSTATUS status = MiCarveVad(space, vad, base, size, &carved);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        vad = carved;
    }
    MiDecommitPages(space, vad, vad->base, vad->size);
    vad->allocationProtect = PAGE_NOACCESS;
    vad->placeholder = MI_VAD_PLACEHOLDER | MI_VAD_FREE_PLACEHOLDER;
    if (vad->watchDirty != 0)
    {
        /* A placeholder has no pages, so it has nothing to watch. The state
         * belonged to the allocation that just went away, and carrying it
         * into the placeholder would hand the NEXT replacement a watch it
         * never asked for. */
        MiFreePool(vad->watchDirty);
        vad->watchDirty = 0;
    }
    vad->writeWatch = FALSE;
    return STATUS_SUCCESS;
}

/* MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS: merge a run of adjacent
 * placeholders back into one. The range must start at a placeholder's base,
 * end at a placeholder's end, and cover more than one of them — anything
 * else is STATUS_CONFLICTING_ADDRESSES rather than a partial merge, because
 * a caller that got the extent wrong is describing a layout it does not
 * have. */
static NTSTATUS MiCoalescePlaceholders(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base,
                                       uint64_t size)
{
    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER_3;
    }
    if (base != vad->base)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    /* Walk forward over free placeholders that TOUCH: a gap in the middle
     * of the run, or a replacement, or an ordinary allocation, all stop the
     * walk and leave `covered` short of the request. */
    uint64_t covered = 0;
    ULONG count = 0;
    for (PMI_VAD curr = vad; (curr->placeholder & MI_VAD_FREE_PLACEHOLDER) != 0;)
    {
        ASSERT(curr->type == MEM_PRIVATE);
        count++;
        covered += curr->size;
        if (covered >= size)
        {
            break;
        }
        PLIST_ENTRY next = curr->listEntry.Flink;
        if (next == &space->vadListHead)
        {
            break;
        }
        PMI_VAD nextVad = CONTAINING_RECORD(next, MI_VAD, listEntry);
        if (curr->base + curr->size != nextVad->base)
        {
            break;
        }
        curr = nextVad;
    }
    if (count < 2 || covered != size)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    /* A merge CARRIES the pages, it does not empty them. That is easy to
     * get wrong here and impossible to get wrong in the oracle, because the
     * oracle's per-page protection is one global array indexed by address —
     * merging its views moves no records at all — while ours lives in the
     * VAD and has to be rebuilt at the new length. A free placeholder is
     * normally uncommitted and this is all zeros, but it is not GUARANTEED
     * to be: MEM_COMMIT is legal on the reserve that creates a placeholder
     * (PAGE_NOACCESS commits present-less pages), and the pinned oracle
     * leaves those pages committed across both the split and the merge.
     * Dropping the records instead would leak every frame in the run, with
     * a live user PTE still pointing at each one.
     *
     * Write-watch is a per-VAD attribute here, so the merged range takes
     * the FIRST piece's — which is also what the oracle does, its merged
     * view keeping the first view's `protect` word. */
    ULONG pages = (ULONG)(size / PAGE_SIZE);
    PULONG mergedProtect = MiAllocatePool(pages * sizeof(ULONG));
    UCHAR *mergedWatch = 0;
    if (mergedProtect == 0)
    {
        return STATUS_NO_MEMORY;
    }
    if (vad->writeWatch)
    {
        mergedWatch = MiAllocatePool(pages); /* pool zeroes */
        if (mergedWatch == 0)
        {
            MiFreePool(mergedProtect);
            return STATUS_NO_MEMORY;
        }
    }

    ULONG filled = MiVadPageCount(vad);
    memcpy(mergedProtect, vad->pageProtect, filled * sizeof(ULONG));
    if (mergedWatch != 0)
    {
        memcpy(mergedWatch, vad->watchDirty, filled);
    }
    for (ULONG i = 1; i < count; i++)
    {
        PMI_VAD victim = CONTAINING_RECORD(vad->listEntry.Flink, MI_VAD, listEntry);
        ULONG victimPages = MiVadPageCount(victim);
        memcpy(mergedProtect + filled, victim->pageProtect, victimPages * sizeof(ULONG));
        if (mergedWatch != 0 && victim->watchDirty != 0)
        {
            memcpy(mergedWatch + filled, victim->watchDirty, victimPages);
        }
        filled += victimPages;
        MiUnlinkAndFreeVad(victim);
    }
    ASSERT(filled == pages);

    MiFreePool(vad->pageProtect);
    vad->pageProtect = mergedProtect;
    if (vad->watchDirty != 0)
    {
        MiFreePool(vad->watchDirty);
    }
    vad->watchDirty = mergedWatch;
    vad->size = size;
    return STATUS_SUCCESS;
}

NTSTATUS MiFreeVirtualMemory(PMI_ADDRESS_SPACE space, PVOID *baseInOut, SIZE_T *sizeInOut,
                             ULONG type)
{
    uint64_t address = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;

    uint64_t base = MiRoundDown(address, PAGE_SIZE);
    if (size != 0)
    {
        size = MiRoundUp(address + size, PAGE_SIZE) - base;
    }
    if (base == 0)
    {
        return STATUS_INVALID_PARAMETER; /* Wine: never free the first page */
    }
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0)
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    if (vad->type != MEM_PRIVATE)
    {
        /* A section view is unmapped, never freed (Wine: !is_view_valloc ->
         * STATUS_INVALID_PARAMETER; pinned by sem_mm/anonymous_section). */
        return STATUS_INVALID_PARAMETER;
    }
    if (size == 0 && base != vad->base)
    {
        return STATUS_FREE_VM_NOT_AT_BASE;
    }
    /* A coalesce is the one verb whose range is MEANT to run past the VAD it
     * starts in — merging one placeholder with itself is not a merge. It
     * does its own extent check against the run of placeholders it finds
     * (the oracle carries the same exemption on this test). */
    if (vad->base + vad->size - base < size && (type & MEM_COALESCE_PLACEHOLDERS) == 0)
    {
        return STATUS_UNABLE_TO_FREE_VM;
    }

    NTSTATUS status;
    switch (type)
    {
    case MEM_DECOMMIT:
        /* size 0 = the whole VAD, and the reported size stays 0 (the shape
         * Wine's own test pins for modern Windows). */
        MiDecommitPages(space, vad, base, size != 0 ? size : vad->base + vad->size - base);
        break;

    case MEM_RELEASE:
        if (size == 0)
        {
            size = vad->size;
        }
        MiDecommitPages(space, vad, base, size);
        status = MiCarveVad(space, vad, base, size, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        break;

    case MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER:
        status = MiPreservePlaceholder(space, vad, base, size);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        break;

    case MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS:
        status = MiCoalescePlaceholders(space, vad, base, size);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        break;

    case MEM_COALESCE_PLACEHOLDERS:
        /* Both placeholder verbs are modifiers on MEM_RELEASE, and the
         * oracle names WHICH argument was wrong rather than answering a
         * bare STATUS_INVALID_PARAMETER for this one. MEM_PRESERVE_
         * PLACEHOLDER alone is not singled out and falls to the default. */
        return STATUS_INVALID_PARAMETER_4;

    default:
        return STATUS_INVALID_PARAMETER;
    }

    *baseInOut = (PVOID)(uintptr_t)base;
    *sizeInOut = size;
    return STATUS_SUCCESS;
}

NTSTATUS MiQueryVirtualMemoryBasic(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_BASIC_INFORMATION info)
{
    uint64_t base = MiRoundDown((uint64_t)(uintptr_t)address, PAGE_SIZE);
    if (base >= KI_USER_SPACE_LIMIT)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PMI_VAD vad = MiFindVad(space, base);
    info->BaseAddress = (PVOID)(uintptr_t)base;
    if (vad == 0)
    {
        /* Free: the run extends to the next reservation (or the limit). */
        uint64_t end = KI_USER_SPACE_LIMIT;
        for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
             entry = entry->Flink)
        {
            PMI_VAD next = CONTAINING_RECORD(entry, MI_VAD, listEntry);
            if (next->base > base)
            {
                end = next->base;
                break;
            }
        }
        info->AllocationBase = 0;
        info->AllocationProtect = 0;
        info->RegionSize = end - base;
        info->State = MEM_FREE;
        info->Protect = PAGE_NOACCESS;
        info->Type = 0;
        return STATUS_SUCCESS;
    }

    ULONG first = (ULONG)((base - vad->base) / PAGE_SIZE);
    ULONG protect = vad->pageProtect[first];
    ULONG last = first;
    while (last + 1 < MiVadPageCount(vad) && (vad->pageProtect[last + 1] == 0) == (protect == 0) &&
           vad->pageProtect[last + 1] == vad->pageProtect[first])
    {
        last++;
    }
    info->AllocationBase = (PVOID)(uintptr_t)vad->base;
    info->AllocationProtect = vad->allocationProtect;
    info->RegionSize = (uint64_t)(last - first + 1) * PAGE_SIZE;
    info->State = protect != 0 ? MEM_COMMIT : MEM_RESERVE;
    info->Protect = protect;
    info->Type = vad->type;
    return STATUS_SUCCESS;
}

/* MemoryRegionInformation: the whole reservation, not the like-protected run
 * inside it that MemoryBasicInformation describes. Same VAD walk as
 * MiQueryVirtualMemoryBasic — the difference is entirely in the question, so
 * it extends that engine rather than adding a second one (Art. 11).
 *
 * Three things here are the oracle's, not invented (third_party/wine
 * dlls/ntdll/unix/virtual.c get_memory_region_info; pinned
 * sem_mm/region_info.c):
 *
 *   - a FREE address is STATUS_INVALID_ADDRESS. MemoryBasicInformation
 *     describes the hole; this class refuses it. The caller's buffer is left
 *     untouched on that refusal, which is why nothing is written until the
 *     VAD is known.
 *   - RegionType is reported as ZERO, every bit of it. The oracle sets it to
 *     0 with a FIXME and does not classify the region, and the winetest
 *     asserts each of Private/MappedDataFile/MappedImage/MappedPageFile/
 *     MappedPhysical/DirectMapped is clear even for a mapped view. It is a
 *     measured answer, not an unfilled field.
 *   - CommitSize counts a MAPPED view's pages only when they are WRITE-COPY,
 *     while a private allocation's every committed page counts. That is the
 *     oracle's `vprot_mask |= PAGE_WRITECOPY for a non-valloc view`, and it
 *     is measured on both sides: the same section mapped PAGE_READONLY
 *     reports commit 0 and mapped PAGE_WRITECOPY reports the whole view.
 */
NTSTATUS MiQueryVirtualMemoryRegion(PMI_ADDRESS_SPACE space, const void *address,
                                    PMEMORY_REGION_INFORMATION info)
{
    uint64_t base = MiRoundDown((uint64_t)(uintptr_t)address, PAGE_SIZE);
    if (base >= KI_USER_SPACE_LIMIT)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }

    ULONG pages = MiVadPageCount(vad);
    BOOLEAN mapped = vad->type != MEM_PRIVATE;
    uint64_t committed = 0;
    for (ULONG i = 0; i < pages; i++)
    {
        ULONG protect = vad->pageProtect[i];
        if (protect == 0)
        {
            continue;
        }
        /* Mask the modifier bits before comparing, as everything else in this
         * file does (MiProtectVirtualMemory and friends): a guarded or
         * uncached write-copy page is still write-copy. The oracle tests a
         * BIT (`vprot & vprot_mask`), which VPROT_GUARD does not disturb, so
         * a strict equality here would silently drop those pages. */
        ULONG bare = protect & ~(ULONG)(PAGE_GUARD | PAGE_NOCACHE);
        if (mapped && bare != PAGE_WRITECOPY && bare != PAGE_EXECUTE_WRITECOPY)
        {
            continue;
        }
        committed += PAGE_SIZE;
    }

    info->AllocationBase = (PVOID)(uintptr_t)vad->base;
    info->AllocationProtect = vad->allocationProtect;
    info->RegionType = 0;
    info->RegionSize = (uint64_t)pages * PAGE_SIZE;
    info->CommitSize = committed;
    /* PartitionId and NodePreference are deliberately NOT set. The oracle
     * never writes them (get_memory_region_info assigns five fields and
     * returns), so the caller's own bytes must survive there — see
     * MiRegionInfoWriteBytes, which is what stops them being copied out. A
     * zero here would be a fabricated answer for a field nobody computed. */
    return STATUS_SUCCESS;
}

/* MemoryImageInformation: "is this address inside an image view, and which
 * one". The same VAD walk again, asked a third question (Art. 11) — the only
 * state it reads is the VAD's type, base and size.
 *
 * Four things here are the oracle's, not invented (third_party/wine
 * dlls/ntdll/unix/virtual.c get_memory_image_info and the server handler it
 * calls, server/mapping.c DECL_HANDLER(get_image_view_info); pinned
 * sem_mm/image_info.c):
 *
 *   - a MAPPED-but-not-image address is a SUCCESS with an ALL-ZERO struct,
 *     not a refusal. find_mapped_addr finds the view, the `view->flags &
 *     SEC_IMAGE` arm does not run, and the zeroed reply IS the answer. A
 *     private allocation, a data view and a pagefile view all land here.
 *   - the struct is zeroed BEFORE the lookup, so the caller sees zeroes even
 *     on the STATUS_INVALID_ADDRESS refusal below. That is the opposite of
 *     MemoryRegionInformation, which leaves every byte of the buffer intact
 *     on its refusal, and the pin measures both.
 *   - an address above the user range is STATUS_INVALID_ADDRESS, NOT the
 *     STATUS_INVALID_PARAMETER MiQueryVirtualMemoryRegion answers for the
 *     same address: the oracle's fall-back folds every error the basic query
 *     can raise into one status (`if (status || basic_info.State ==
 *     MEM_FREE) status = STATUS_INVALID_ADDRESS;`).
 *   - SizeOfImage is the VIEW's size (reply->size), which on proskrnl is
 *     always the image's whole SizeOfImage: MipMapImageView maps
 *     image->sizeOfImage whatever view size was asked for. That is also why
 *     ImagePartialMap stays clear — there is no partial image view to report,
 *     rather than a bit nobody computed. ImageSigningLevel stays 0 for the
 *     same kind of reason and the opposite conclusion: the oracle reports 12
 *     unconditionally, nothing here validates a signature, and the winetest
 *     accepts either (docs/03 "`MemoryImageInformation` reports signing level
 *     ZERO"). */
NTSTATUS MiQueryVirtualMemoryImage(PMI_ADDRESS_SPACE space, const void *address,
                                   PMEMORY_IMAGE_INFORMATION info)
{
    memset(info, 0, sizeof(*info));

    uint64_t base = MiRoundDown((uint64_t)(uintptr_t)address, PAGE_SIZE);
    if (base >= KI_USER_SPACE_LIMIT)
    {
        return STATUS_INVALID_ADDRESS;
    }

    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (vad->type != MEM_IMAGE)
    {
        return STATUS_SUCCESS;
    }

    info->ImageBase = (PVOID)(uintptr_t)vad->base;
    info->SizeOfImage = vad->size;
    return STATUS_SUCCESS;
}

/* How many bytes of MEMORY_REGION_INFORMATION a request of `length` actually
 * gets. Not min(length, sizeof) — the oracle fills each tail field only when
 * the buffer reaches the offset of the NEXT one, and never fills the last
 * two at all (third_party/wine dlls/ntdll/unix/virtual.c
 * get_memory_region_info: RegionSize under `len >= FIELD_OFFSET(CommitSize)`,
 * CommitSize under `len >= FIELD_OFFSET(PartitionId)`). So a 28-byte buffer
 * gets RegionSize and NOT four bytes of a half-written CommitSize. */
static SIZE_T MiRegionInfoWriteBytes(SIZE_T length)
{
    if (length >= offsetof(MEMORY_REGION_INFORMATION, PartitionId))
    {
        return offsetof(MEMORY_REGION_INFORMATION, PartitionId);
    }
    return offsetof(MEMORY_REGION_INFORMATION, CommitSize);
}

/* --- section-view plumbing (virtual.h; used by mm/section.c) ---------------- */

uint64_t MiFindFreeViewBaseEx(PMI_ADDRESS_SPACE space, uint64_t size, uint64_t limitLow,
                              uint64_t limitHigh, uint64_t align)
{
    return MiFindFreeRegion(space, MiRoundUp(size, PAGE_SIZE), limitLow, limitHigh, align);
}

BOOLEAN MiViewRangeIsFree(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size)
{
    if (base < MI_LOWEST_USER_ADDRESS || base + size < base || base + size > KI_USER_SPACE_LIMIT)
    {
        return FALSE;
    }
    return MiRangeIsFree(space, base, MiRoundUp(size, PAGE_SIZE));
}

PMI_VAD MiCreateMappedVad(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size,
                          ULONG allocationProtect, ULONG vadType, PVOID sectionBody,
                          BOOLEAN ownsFrames, uint64_t sectionOffset)
{
    ASSERT(vadType == MEM_MAPPED || vadType == MEM_IMAGE);
    /* A section-backed view pins its section body; a body-less mapped VAD is
     * only valid when it does not own its frames (M7: the shared
     * KUSER_SHARED_DATA page maps one kernel-owned frame with no section). */
    ASSERT(sectionBody != 0 || !ownsFrames);
    PMI_VAD vad = MiCreateVad(base, MiRoundUp(size, PAGE_SIZE), allocationProtect);
    if (vad == 0)
    {
        return 0;
    }
    vad->type = vadType;
    vad->sectionBody = sectionBody;
    vad->ownsFrames = ownsFrames;
    vad->sectionOffset = sectionOffset;
    MiInsertVad(space, vad);
    return vad;
}

void MiCommitFrameInVad(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t virtualAddress,
                        uint64_t frame, ULONG protect, BOOLEAN ownedFrame)
{
    ULONG index = (ULONG)((virtualAddress - vad->base) / PAGE_SIZE);
    ASSERT(virtualAddress >= vad->base && index < MiVadPageCount(vad));
    ASSERT(vad->pageProtect[index] == 0); /* views commit each page exactly once */
    if (vad->pagePrivate != 0)
    {
        vad->pagePrivate[index] = ownedFrame ? 1 : 0;
    }
    else
    {
        /* Without a per-page record, ownership is the VAD-wide flag; the
         * caller's claim must agree with it. */
        ASSERT(ownedFrame == vad->ownsFrames);
    }
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    vad->pageProtect[index] = protect;
    /* Through the one hardware-writability rule: a shared master page maps
     * read-only however writable its recorded protection is (CUI-9). */
    MiMapUserPage(space->pml4Physical, virtualAddress, frame, present,
                  MipVadPageHwWritable(vad, index, writable), executable);
}

/* CUI-9: bind an image view's VAD to its (identity, base) master. On
 * success the VAD owns the caller's master reference (released by
 * MiUnlinkAndFreeVad); on failure the caller keeps it. */
NTSTATUS MiBindVadImageMaster(PMI_VAD vad, PVOID master)
{
    ASSERT(vad->type == MEM_IMAGE && vad->master == 0);
    ASSERT(!vad->writeWatch); /* watch exists only on MEM_PRIVATE VADs */
    vad->pagePrivate = MiAllocatePool(MiVadPageCount(vad)); /* pool zeroes */
    if (vad->pagePrivate == 0)
    {
        return STATUS_NO_MEMORY;
    }
    vad->master = master;
    return STATUS_SUCCESS;
}

/* docs/17 §8, "the highest-value single check": no writable PTE anywhere may
 * point at a frame a shared master owns — it catches a kernel write that
 * skipped the resolver (hazard A), a writecopy satisfied by flipping the
 * bit (B), a base-keying mistake (F), and a flush-eliding path (H).
 * ASSERT is always compiled in, so the hot paths run the check SCOPED to
 * the pages they touched: the map path sweeps its one new VAD, the
 * reprotect path only its protected range — the loader protects each DLL
 * many times, and the full every-image-VAD sweep there was quadratic in
 * module count. The whole-space form remains for the kmt suite. */
void MiAssertVadNoWritableMasterPteRange(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base,
                                         uint64_t size)
{
    if (vad->master == 0)
    {
        return;
    }
    ASSERT(base >= vad->base && base + size <= vad->base + vad->size);
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] == 0)
        {
            continue;
        }
        int writable = 0;
        int present = 0;
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, &writable, &present);
        ASSERT(frame != 0);
        if (vad->pagePrivate[index])
        {
            ASSERT(frame != MiImageMasterFrame(vad->master, index));
        }
        else
        {
            ASSERT(frame == MiImageMasterFrame(vad->master, index));
            ASSERT(!writable);
        }
    }
}

void MiAssertNoWritableMasterPte(PMI_ADDRESS_SPACE space)
{
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        MiAssertVadNoWritableMasterPteRange(space, vad, vad->base, vad->size);
    }
}

void MiDeleteMappedVad(PMI_ADDRESS_SPACE space, PMI_VAD vad)
{
    MiDecommitPages(space, vad, vad->base, vad->size);
    MiUnlinkAndFreeVad(vad);
}

NTSTATUS MiUnmapView(PMI_ADDRESS_SPACE space, uint64_t address)
{
    PMI_VAD vad = MiFindVad(space, MiRoundDown(address, PAGE_SIZE));
    if (vad == 0 || vad->type == MEM_PRIVATE)
    {
        return STATUS_NOT_MAPPED_VIEW;
    }
    MiDeleteMappedVad(space, vad);
    return STATUS_SUCCESS;
}

void MiCopyToUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                       uint64_t length)
{
    const char *from = source;
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t va = userBase + copied;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, 0);
        ASSERT(frame != 0);
        memcpy((char *)MiPhysicalToVirtual(frame) + pageOffset, from + copied, chunk);
        copied += chunk;
    }
}

void MiZeroUserRange(PMI_ADDRESS_SPACE space, uint64_t userBase, uint64_t length)
{
    uint64_t zeroed = 0;
    while (zeroed < length)
    {
        uint64_t va = userBase + zeroed;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - zeroed)
        {
            chunk = length - zeroed;
        }
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, 0);
        ASSERT(frame != 0);
        memset((char *)MiPhysicalToVirtual(frame) + pageOffset, 0, chunk);
        zeroed += chunk;
    }
}

/* CUI-4: NtReadVirtualMemory's engine — copy from a (possibly non-current)
 * address space's user range into a kernel/current-space buffer, stopping at
 * the first page that is not present. Returns the bytes copied (< length ==
 * a fault). Unlike MiCopyToUserRange it never asserts: a probe of another
 * process's memory can legitimately hit an unmapped page. */
uint64_t MiCopyFromUserRange(PMI_ADDRESS_SPACE space, void *dest, uint64_t userBase,
                             uint64_t length)
{
    char *to = dest;
    uint64_t copied = 0;
    while (copied < length)
    {
        uint64_t va = userBase + copied;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - copied)
        {
            chunk = length - copied;
        }
        int present = 0;
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, va - pageOffset, 0, &present);
        if (frame == 0 || !present)
        {
            break;
        }
        memcpy(to + copied, (const char *)MiPhysicalToVirtual(frame) + pageOffset, chunk);
        copied += chunk;
    }
    return copied;
}

/* NtWriteVirtualMemory's engine — the present-and-writable-checked mirror of
 * MiCopyToUserRange. Stops at the first page that is not present-and-writable;
 * returns the bytes written. */
uint64_t MiCopyToUserRangeChecked(PMI_ADDRESS_SPACE space, uint64_t userBase, const void *source,
                                  uint64_t length)
{
    const char *from = source;
    uint64_t written = 0;
    while (written < length)
    {
        uint64_t va = userBase + written;
        uint64_t pageOffset = va & (PAGE_SIZE - 1);
        uint64_t chunk = PAGE_SIZE - pageOffset;
        if (chunk > length - written)
        {
            chunk = length - written;
        }
        int present = 0;
        int writable = 0;
        uint64_t frame =
            MiTranslateUserPage(space->pml4Physical, va - pageOffset, &writable, &present);
        if (frame != 0 && present && !writable)
        {
            /* A clean watched page marks, a shared master page copies —
             * the kernel-side write resolves exactly as a ring-3 store
             * would (CUI-7/CUI-9, the one authority). A claimed-but-failed
             * copy stops the loop: a short write, never a master write. */
            NTSTATUS resolve;
            if (MiResolveWriteFault(space, va - pageOffset, &resolve) && NT_SUCCESS(resolve))
            {
                frame =
                    MiTranslateUserPage(space->pml4Physical, va - pageOffset, &writable, &present);
            }
        }
        if (frame == 0 || !present || !writable)
        {
            break;
        }
        memcpy((char *)MiPhysicalToVirtual(frame) + pageOffset, from + written, chunk);
        written += chunk;
    }
    return written;
}

/* --- write-watch (CUI-7) ----------------------------------------------------- */

/* Remap one committed page's PTE to the current rule (dirty state changed).
 * MiMapUserPage refuses a live PTE, so re-protect is unmap-then-map
 * (the MiCommitPages precedent). */
static void MipRemapWatchPage(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t page, ULONG index)
{
    ULONG protect = vad->pageProtect[index];
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    if (!present)
    {
        return; /* PAGE_NOACCESS / guard: nothing mapped to change */
    }
    uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
    ASSERT(frame != 0);
    MiUnmapUserPage(space->pml4Physical, page);
    MiMapUserPage(space->pml4Physical, page, frame, present,
                  MipVadPageHwWritable(vad, index, writable), executable);
}

/* CUI-9 fault-injection knob (hazard E): fail the NEXT COW frame
 * allocation, so the never-leaves-half-state guarantee is an executed
 * path, not an assertion nobody reached (docs/17 §8 "which tests gate
 * which commit"). kmt-set; always FALSE on a real fault. */
BOOLEAN MiCowFailNextAllocation;
static ULONG MipCowCopies; /* lazy copies resolved (the sharing metric's pair) */

ULONG MiGetCowCopyCount(void)
{
    return MipCowCopies;
}

/* A write hit a present, non-hardware-writable page whose RECORDED
 * protection allows writing — the two lies the kernel tells the MMU: a
 * CLEAN WATCHED page (mark it, open the gate) or a STILL-SHARED MASTER
 * page (copy it, repoint, open the gate). Returns TRUE when the fault was
 * claimed, with *statusOut the resolution: STATUS_SUCCESS = retry the
 * access, STATUS_IN_PAGE_ERROR = the copy could not get a frame and NO
 * state changed (hazard E — the master was never made writable). FALSE =
 * not ours: a real protection violation, uncommitted, or a guard page
 * (the guard arm consumes those first and the NEXT write copies —
 * hazard G's ordering).
 *
 * Space-parameterized so the kernel's own user-memory writers (probe
 * retry, the cross-process checked copy, KiMaterializeUserRange via
 * MiHandleUserFault) resolve through the SAME arms the ring-3 fault takes
 * (Art. 11 — hazard A is closed here, once, for every caller). */
BOOLEAN MiResolveWriteFault(PMI_ADDRESS_SPACE space, uint64_t pageAddress, NTSTATUS *statusOut)
{
    ASSERT((pageAddress & (PAGE_SIZE - 1)) == 0);
    *statusOut = STATUS_SUCCESS;
    PMI_VAD vad = MiFindVad(space, pageAddress);
    if (vad == 0)
    {
        return FALSE;
    }
    ULONG index = (ULONG)((pageAddress - vad->base) / PAGE_SIZE);
    ULONG protect = vad->pageProtect[index];
    if (protect == 0 || (protect & PAGE_GUARD) != 0)
    {
        return FALSE; /* uncommitted or guard: not ours */
    }
    int present, writable, executable;
    MiProtectToPteBits(protect, &present, &writable, &executable);
    if (!writable)
    {
        return FALSE; /* a real protection violation (hazard B's boundary case) */
    }

    /* The write-watch arm (CUI-7): mark and open. A watched VAD is never
     * master-bound (MEM_WRITE_WATCH is MEM_PRIVATE-only; asserted at bind). */
    if (vad->writeWatch)
    {
        if (vad->watchDirty[index])
        {
            return FALSE; /* already open: not ours */
        }
        vad->watchDirty[index] = 1;
        MipRemapWatchPage(space, vad, pageAddress, index);
        return TRUE;
    }

    /* The COW arm (CUI-9): copy the shared master page and repoint. The
     * recorded protection is deliberately NOT touched — the pinned oracle
     * never transitions Protect on a writecopy store (docs/03 hazard D);
     * the private/shared state lives in pagePrivate alone. */
    if (vad->master != 0 && !vad->pagePrivate[index])
    {
        uint64_t copy = 0;
        if (MiCowFailNextAllocation)
        {
            MiCowFailNextAllocation = FALSE;
        }
        else
        {
            copy = MiAllocatePage();
        }
        if (copy == 0)
        {
            /* Hazard E, atomically: nothing was touched — the PTE still
             * points read-only at the master. NT's status for a paging
             * failure on an access is STATUS_IN_PAGE_ERROR. */
            *statusOut = STATUS_IN_PAGE_ERROR;
            return TRUE;
        }
        uint64_t masterFrame = MiTranslateUserPage(space->pml4Physical, pageAddress, 0, 0);
        ASSERT(masterFrame != 0 && masterFrame == MiImageMasterFrame(vad->master, index));
        memcpy(MiPhysicalToVirtual(copy), MiPhysicalToVirtual(masterFrame), PAGE_SIZE);
        vad->pagePrivate[index] = 1; /* opens MipVadPageHwWritable's gate */
        MiUnmapUserPage(space->pml4Physical, pageAddress);
        /* NX/X from the SAME recorded protection (hazard C): the remap
         * changes the frame and the writable bit, nothing else. Both map
         * calls invlpg (hazard H — counted, kmt-asserted). */
        MiMapUserPage(space->pml4Physical, pageAddress, copy, present,
                      MipVadPageHwWritable(vad, index, writable), executable);
        MipCowCopies++;
        return TRUE;
    }

    return FALSE; /* stale hardware state; nothing for the resolver */
}

/* The get/reset engines (wine dlls/ntdll/unix/virtual.c NtGetWriteWatch /
 * NtResetWriteWatch; pinned by sem_mm/write_watch). The range must sit
 * inside ONE write-watch VAD. */
static PMI_VAD MipFindWatchRange(PMI_ADDRESS_SPACE space, uint64_t base, uint64_t size)
{
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0 || !vad->writeWatch || base + size > vad->base + vad->size)
    {
        return 0;
    }
    return vad;
}

/* Re-arm [base, base+size): clear dirty and close the hardware gate. */
static void MipRearmWatchRange(PMI_ADDRESS_SPACE space, PMI_VAD vad, uint64_t base, uint64_t size)
{
    for (uint64_t page = base; page < base + size; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->watchDirty[index])
        {
            vad->watchDirty[index] = 0;
            MipRemapWatchPage(space, vad, page, index);
        }
    }
}

NTSTATUS NtGetWriteWatch(HANDLE process, ULONG flags, PVOID baseAddress, SIZE_T size,
                         PVOID *addresses, ULONG_PTR *count, ULONG *granularity)
{
    /* The oracle operates on the CALLER's address space whatever the handle
     * says (its implementation never consults `process`); reproduced. The
     * ladder order is the oracle's own (pinned). */
    (void)process;
    uint64_t start = (uint64_t)(uintptr_t)baseAddress;
    uint64_t base = start & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t length = (size + (start - base) + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);

    if (count == 0 || granularity == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(count, sizeof(*count), sizeof(*count));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(granularity, sizeof(*granularity), sizeof(*granularity));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG_PTR capacity = *count;
    if (capacity == 0 || size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (flags & ~(ULONG)WRITE_WATCH_FLAG_RESET)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (addresses == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    uint64_t maxEntries = length / PAGE_SIZE;
    if (capacity < maxEntries)
    {
        maxEntries = capacity;
    }
    status = KiProbeForWrite(addresses, maxEntries * sizeof(PVOID), sizeof(PVOID));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    PMI_VAD vad = MipFindWatchRange(space, base, length);
    if (vad == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ULONG_PTR pos = 0;
    uint64_t page = base;
    uint64_t end = base + length;
    while (pos < capacity && page < end)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->watchDirty[index])
        {
            addresses[pos++] = (PVOID)(uintptr_t)page;
        }
        page += PAGE_SIZE;
    }
    if (flags & WRITE_WATCH_FLAG_RESET)
    {
        /* Only the SCANNED subrange re-arms (the oracle's `size = addr -
         * base` before its reset; pinned): dirty pages past a filled count
         * stay dirty. */
        MipRearmWatchRange(space, vad, base, page - base);
    }
    *count = pos;
    *granularity = PAGE_SIZE;
    return STATUS_SUCCESS;
}

NTSTATUS NtResetWriteWatch(HANDLE process, PVOID baseAddress, SIZE_T size)
{
    (void)process; /* as the get side: the caller's space */
    uint64_t start = (uint64_t)(uintptr_t)baseAddress;
    uint64_t base = start & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t length = (size + (start - base) + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    if (size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    PMI_VAD vad = MipFindWatchRange(space, base, length);
    if (vad == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    MipRearmWatchRange(space, vad, base, length);
    return STATUS_SUCCESS;
}

/* --- flush/lock/prefetch (CUI-7) --------------------------------------------- */

/* Implemented by the Io manager (kernel/io/rw.c) — the same seam direction
 * as IopBuildSectionBacking (mm/section.c): write the file's cached byte
 * range through to the device. */
NTSTATUS IoWritebackSectionRange(PVOID fileObjectBody, uint64_t offset, uint64_t length);

NTSTATUS NtFlushVirtualMemory(HANDLE process, LPCVOID *addressInOut, SIZE_T *sizeInOut,
                              IO_STATUS_BLOCK *ioStatusBlock)
{
    /* The oracle operates on the caller's space (foreign handles go through
     * an APC the CUI stack never issues) and accepts-but-never-writes the
     * IOSB (its own FIXME; pinned by sem_mm/flush_lock). */
    (void)process;
    (void)ioStatusBlock;
    NTSTATUS status =
        KiProbeForWrite((void *)addressInOut, sizeof(*addressInOut), sizeof(*addressInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t addr = (uint64_t)(uintptr_t)*addressInOut & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t size = *sizeInOut;
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    PMI_VAD vad = MiFindVad(space, addr);
    if (vad == 0 || (size != 0 && addr + size > vad->base + vad->size))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (size == 0)
    {
        size = vad->size; /* the WHOLE region, as the oracle answers */
    }
    *addressInOut = (LPCVOID)(uintptr_t)addr;
    *sizeInOut = size;

    /* A shared file-backed view's stores live in the file's page cache;
     * route the covered bytes to the FS writeback (the IopFlushBuffers
     * seam). With write-through FAT this is belt — and it retires the
     * flush half of the docs/03 mapped-view deferred-writeback note for
     * this path. Private/image/anonymous views have no file to flush. */
    if (vad->type == MEM_MAPPED && !vad->ownsFrames && vad->sectionBody != 0)
    {
        PMI_SECTION section = vad->sectionBody;
        if (section->fileObject != 0 && section->cache != 0)
        {
            uint64_t span = size;
            if (addr + span > vad->base + vad->size)
            {
                span = vad->base + vad->size - addr;
            }
            status = IoWritebackSectionRange(section->fileObject,
                                             vad->sectionOffset + (addr - vad->base), span);
            if (!NT_SUCCESS(status))
            {
                return STATUS_NOT_MAPPED_DATA; /* the oracle's msync-failure arm */
            }
        }
    }
    return STATUS_SUCCESS;
}

/* Lock and unlock share one walk: round + echo, then every page must be
 * committed and accessible — the oracle's mlock/munlock cannot populate
 * PROT_NONE (reserved-only, NOACCESS, guard), everything else is resident
 * already so locking is a validating no-op (docs/03 "CUI-7"). */
static NTSTATUS MipLockWalk(PVOID *addressInOut, SIZE_T *sizeInOut)
{
    NTSTATUS status =
        KiProbeForWrite((void *)addressInOut, sizeof(*addressInOut), sizeof(*addressInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    uint64_t start = (uint64_t)(uintptr_t)*addressInOut;
    uint64_t base = start & ~(uint64_t)(PAGE_SIZE - 1);
    uint64_t length = (*sizeInOut + (start - base) + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
    *addressInOut = (PVOID)(uintptr_t)base;
    *sizeInOut = length;
    if (length == 0 || base + length < base)
    {
        return STATUS_ACCESS_DENIED;
    }
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    for (uint64_t page = base; page < base + length; page += PAGE_SIZE)
    {
        PMI_VAD vad = MiFindVad(space, page);
        if (vad == 0)
        {
            return STATUS_ACCESS_DENIED;
        }
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        ULONG protect = vad->pageProtect[index];
        int present, writable, executable;
        MiProtectToPteBits(protect, &present, &writable, &executable);
        if (protect == 0 || !present)
        {
            return STATUS_ACCESS_DENIED;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtLockVirtualMemory(HANDLE process, PVOID *addressInOut, SIZE_T *sizeInOut, ULONG flags)
{
    (void)process; /* the caller's space, as the oracle's local arm */
    (void)flags;   /* the oracle ignores it entirely */
    return MipLockWalk(addressInOut, sizeInOut);
}

NTSTATUS NtUnlockVirtualMemory(HANDLE process, PVOID *addressInOut, SIZE_T *sizeInOut, ULONG flags)
{
    (void)process;
    (void)flags;
    return MipLockWalk(addressInOut, sizeInOut);
}

NTSTATUS NtSetInformationVirtualMemory(HANDLE process, VIRTUAL_MEMORY_INFORMATION_CLASS infoClass,
                                       ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses, PVOID ptr,
                                       ULONG size)
{
    /* The oracle's exact ladder (wine dlls/ntdll/unix/virtual.c
     * NtSetInformationVirtualMemory + prefetch_memory; pinned by
     * sem_mm/flush_lock). Prefetch validates and succeeds without work:
     * everything is resident under Art. 3 (docs/03 "CUI-7"); the addresses
     * themselves are deliberately NOT validated, as the oracle's madvise
     * ignores unmapped ranges. */
    (void)process;
    switch (infoClass)
    {
    case VmPrefetchInformation:
    {
        if (ptr == 0)
        {
            return STATUS_INVALID_PARAMETER_5;
        }
        if (size != sizeof(ULONG))
        {
            return STATUS_INVALID_PARAMETER_6;
        }
        if (count == 0)
        {
            return STATUS_INVALID_PARAMETER_3;
        }
        NTSTATUS status = KiProbeForRead(ptr, sizeof(ULONG), 1);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        ULONGLONG entryBytes = (ULONGLONG)count * sizeof(MEMORY_RANGE_ENTRY);
        if (entryBytes > (64u << 20))
        {
            return STATUS_INVALID_PARAMETER_3;
        }
        status = KiProbeForRead(addresses, (SIZE_T)entryBytes, sizeof(uint64_t));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        for (ULONG_PTR i = 0; i < count; i++)
        {
            if (addresses[i].NumberOfBytes == 0)
            {
                return STATUS_INVALID_PARAMETER_4;
            }
        }
        return STATUS_SUCCESS;
    }
    case VmPageDirtyStateInformation:
        return STATUS_NOT_SUPPORTED; /* the oracle's default-config answer */
    default:
        return STATUS_INVALID_PARAMETER_2;
    }
}

/* --- guard pages (virtual.h; used by mm/fault.c) ---------------------------- */

BOOLEAN MiClearGuardPage(PMI_ADDRESS_SPACE space, uint64_t pageAddress)
{
    ASSERT((pageAddress & (PAGE_SIZE - 1)) == 0);
    PMI_VAD vad = MiFindVad(space, pageAddress);
    if (vad == 0)
    {
        return FALSE;
    }
    ULONG index = (ULONG)((pageAddress - vad->base) / PAGE_SIZE);
    ULONG protect = vad->pageProtect[index];
    if (protect == 0 || (protect & PAGE_GUARD) == 0)
    {
        return FALSE;
    }
    /* One-shot: drop the guard bit and make the (already committed) frame
     * an ordinary present page — through the one hardware-writability rule,
     * like every other PTE-writing site. The raw protection bit here made a
     * guarded writecopy page's SHARED MASTER frame hardware-writable (the
     * docs/17 §6B violation: writable, for everyone), and a guarded clean
     * WATCHED page writable without a dirty mark (a page silently lost from
     * NtGetWriteWatch). The clear itself consumes nothing: the retried
     * store faults again and resolves through MiResolveWriteFault — copy or
     * mark, the same arm every write takes (hazard G's ordering). */
    uint64_t frame = MiTranslateUserPage(space->pml4Physical, pageAddress, 0, 0);
    ASSERT(frame != 0);
    ULONG newProtect = protect & ~(ULONG)PAGE_GUARD;
    int present, writable, executable;
    MiProtectToPteBits(newProtect, &present, &writable, &executable);
    MiUnmapUserPage(space->pml4Physical, pageAddress);
    MiMapUserPage(space->pml4Physical, pageAddress, frame, present,
                  MipVadPageHwWritable(vad, index, writable), executable);
    vad->pageProtect[index] = newProtect;
    return TRUE;
}

/* --- the Nt* surface -------------------------------------------------------- */

/* Resolve a process-handle argument (virtual.h): the pseudo-handle or a real
 * handle to a Process object; *referenced tells the caller to dereference.
 * Shared with the section Nt* in mm/section.c (M5). */
NTSTATUS MiReferenceProcessByHandle(HANDLE processHandle, ACCESS_MASK desiredAccess,
                                    PEPROCESS *process, BOOLEAN *referenced)
{
    if (processHandle == NtCurrentProcess())
    {
        *process = KeGetCurrentThread()->process;
        *referenced = FALSE;
        return STATUS_SUCCESS;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(processHandle, desiredAccess, &PspProcessType,
                                                ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *process = body;
    *referenced = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS NtAllocateVirtualMemory(HANDLE process, PVOID *baseInOut, ULONG_PTR zeroBits,
                                 SIZE_T *sizeInOut, ULONG type, ULONG protect)
{
    uint64_t zeroBitsLimit = 0;
    NTSTATUS zeroBitsStatus = MiZeroBitsPlacementLimit(zeroBits, &zeroBitsLimit);
    if (!NT_SUCCESS(zeroBitsStatus))
    {
        return zeroBitsStatus;
    }
    /* This entry point's own type mask, narrower than the engine's by
     * exactly the two placeholder bits. VirtualAlloc2 (NtAllocateVirtualMemoryEx)
     * is the only documented way into a placeholder, so a caller reaching for
     * the classic form is passing a flag that does not exist here — a bad
     * ARGUMENT, not a range that is busy or a service that is missing. */
    if (type & (MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    /* zero_bits is a PLACEMENT CONSTRAINT and it is honoured, through the
     * same limitHigh the MEM_ADDRESS_REQUIREMENTS path already uses — one
     * bounded-placement mechanism, not two (Art. 11).
     *
     * It applies only when the caller named no base, exactly as the oracle
     * applies it (`if (!*ret) limit = get_zero_bits_limit( zero_bits ); else
     * limit = 0;`). A caller that supplies BOTH an address and zero_bits is
     * telling the allocator where to put it, and the constraint is dropped
     * rather than checked.
     *
     * This used to be dropped on the floor, with a comment claiming the
     * bottom-up allocator satisfied it anyway. It does not, and could not:
     * ntdll:virtual sweeps zero_bits 2..20 and requires the result under
     * 2^(32-zero_bits) — at zero_bits 20 that is a 4 KiB ceiling, which no
     * general allocator hits by luck. Twelve of its thirteen failures were
     * this one line (virtual.c:170). */
    status = MiAllocateVirtualMemoryEx(&target->addressSpace, &base, &size, type, protect, 0,
                                       base == 0 ? zeroBitsLimit : 0, 0, 0);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* --- the VirtualAlloc2 extended-parameter contract (CUI-7) ------------------ */

/* Capture + validate a user MEM_EXTENDED_PARAMETER array, mirroring the
 * oracle's ladder exactly (wine dlls/ntdll/unix/virtual.c
 * get_extended_params; pinned by sem_mm/alloc_ex): unknown or duplicated
 * types refuse; AddressRequirements validates alignment (power of two,
 * >= the 64K granularity), a 64K-aligned Lowest below the user-space
 * limit, and a page-end Highest above Lowest within the limit;
 * NumaNode/PartitionHandle/UserPhysicalHandle are accepted and ignored. */
NTSTATUS MiCaptureExtendedParams(const MEM_EXTENDED_PARAMETER *parameters, ULONG count,
                                 MI_EXTENDED_PARAMS *out)
{
    memset(out, 0, sizeof(*out));
    if (count == 0)
    {
        return STATUS_SUCCESS;
    }
    if (parameters == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = KiProbeForRead(parameters, (SIZE_T)count * sizeof(*parameters),
                                     _Alignof(MEM_EXTENDED_PARAMETER));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    ULONG present = 0;
    for (ULONG i = 0; i < count; i++)
    {
        ULONG parameterType = (ULONG)parameters[i].Type;
        if (parameterType >= 32 || (present & (1u << parameterType)) != 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        present |= 1u << parameterType;
        switch (parameterType)
        {
        case MemExtendedParameterAddressRequirements:
        {
            const MEM_ADDRESS_REQUIREMENTS *requirements = parameters[i].Pointer;
            status = KiProbeForRead(requirements, sizeof(*requirements), sizeof(uint64_t));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            uint64_t alignment = requirements->Alignment;
            uint64_t low = (uint64_t)(uintptr_t)requirements->LowestStartingAddress;
            uint64_t high = (uint64_t)(uintptr_t)requirements->HighestEndingAddress;
            if (alignment != 0)
            {
                if ((alignment & (alignment - 1)) != 0 ||
                    alignment - 1 < MI_ALLOCATION_GRANULARITY - 1)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->align = alignment;
            }
            if (low != 0)
            {
                if (low >= KI_USER_SPACE_LIMIT || (low & (MI_ALLOCATION_GRANULARITY - 1)) != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->limitLow = low;
            }
            if (high != 0)
            {
                /* The (high + 1) & (page_mask - 1) test is the oracle's own
                 * arithmetic, reproduced bit for bit (wine
                 * dlls/ntdll/unix/virtual.c get_extended_params). */
                if (high > KI_USER_SPACE_LIMIT || high <= out->limitLow ||
                    ((high + 1) & ((uint64_t)PAGE_SIZE - 1 - 1)) != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                out->limitHigh = high;
            }
            break;
        }
        case MemExtendedParameterAttributeFlags:
            out->attributes = parameters[i].ULong;
            break;
        case MemExtendedParameterImageMachine:
            out->machine = (USHORT)parameters[i].ULong;
            break;
        case MemExtendedParameterNumaNode:
        case MemExtendedParameterPartitionHandle:
        case MemExtendedParameterUserPhysicalHandle:
            break; /* accepted and ignored, as the oracle */
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtAllocateVirtualMemoryEx(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut, ULONG type,
                                   ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* The oracle's own order (pinned by sem_mm/alloc_ex): parameters first,
     * then the Ex type mask, then base-vs-requirements, then the size. */
    MI_EXTENDED_PARAMS extended;
    status = MiCaptureExtendedParams(parameters, count, &extended);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (type & ~(ULONG)(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN | MEM_WRITE_WATCH | MEM_RESET |
                        MEM_RESERVE_PLACEHOLDER | MEM_REPLACE_PLACEHOLDER))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (*baseInOut != 0 &&
        (extended.align != 0 || extended.limitLow != 0 || extended.limitHigh != 0))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (*sizeInOut == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    status = MiAllocateVirtualMemoryEx(&target->addressSpace, &base, &size, type, protect,
                                       extended.limitLow, extended.limitHigh, extended.align,
                                       extended.attributes);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

NTSTATUS NtFreeVirtualMemory(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut, ULONG type)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PVOID base = *baseInOut;
    SIZE_T size = *sizeInOut;
    status = MiFreeVirtualMemory(&target->addressSpace, &base, &size, type);
    if (NT_SUCCESS(status))
    {
        *baseInOut = base;
        *sizeInOut = size;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

NTSTATUS NtQueryVirtualMemory(HANDLE process, LPCVOID address,
                              MEMORY_INFORMATION_CLASS informationClass, PVOID buffer,
                              SIZE_T length, SIZE_T *returnLength)
{
    /* Each class states its own minimum, and MemoryRegionInformation's is
     * NOT its own size: the oracle accepts any buffer reaching CommitSize's
     * offset and fills what fits (third_party/wine dlls/ntdll/unix/virtual.c
     * get_memory_region_info; pinned sem_mm/region_info.c, which measures
     * offsetof(RegionSize) refused and offsetof(CommitSize) accepted). */
    SIZE_T needed;
    SIZE_T writeBytes;
    switch (informationClass)
    {
    case MemoryBasicInformation:
        needed = sizeof(MEMORY_BASIC_INFORMATION);
        writeBytes = sizeof(MEMORY_BASIC_INFORMATION);
        break;
    case MemoryRegionInformation:
        needed = offsetof(MEMORY_REGION_INFORMATION, CommitSize);
        writeBytes = MiRegionInfoWriteBytes(length);
        break;
    case MemoryImageInformation:
        /* This class's minimum IS its own size — there is no partial fill
         * (get_memory_image_info's `if (len < sizeof(*info))`). */
        needed = sizeof(MEMORY_IMAGE_INFORMATION);
        writeBytes = sizeof(MEMORY_IMAGE_INFORMATION);
        break;
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
    if (length < needed)
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    /* Probe exactly what will be WRITTEN, never the caller's stated `length`.
     * KiProbeForWrite demands every page of the range be present and
     * writable, so probing a length larger than the bytes we touch would
     * refuse a caller the oracle serves — and this probe is also the
     * write-watch dirty-marking site (kernel/syscall/uaccess.c), so a wider
     * range would mark pages nothing wrote. MemoryBasicInformation's probe is
     * therefore unchanged by the arrival of a second class. */
    NTSTATUS status = KiProbeForWrite(buffer, writeBytes, sizeof(uint64_t));
    if (NT_SUCCESS(status) && returnLength != 0)
    {
        status = KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(*returnLength));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_QUERY_INFORMATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (informationClass == MemoryRegionInformation)
    {
        MEMORY_REGION_INFORMATION region;
        status = MiQueryVirtualMemoryRegion(&target->addressSpace, address, &region);
        if (NT_SUCCESS(status))
        {
            /* Only the fields the oracle would have filled — but ReturnLength
             * is the WHOLE struct either way, which is what the oracle
             * reports and what the winetest asserts against sizeof(). */
            memcpy(buffer, &region, writeBytes);
            if (returnLength != 0)
            {
                *returnLength = sizeof(region);
            }
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return status;
    }

    if (informationClass == MemoryImageInformation)
    {
        MEMORY_IMAGE_INFORMATION image;
        status = MiQueryVirtualMemoryImage(&target->addressSpace, address, &image);
        /* Copied UNCONDITIONALLY: the oracle zeroes the caller's struct
         * before it decides, so a STATUS_INVALID_ADDRESS still lands zeroes
         * in the buffer. ReturnLength is the field that survives a refusal,
         * because it is written on success alone. */
        memcpy(buffer, &image, writeBytes);
        if (NT_SUCCESS(status) && returnLength != 0)
        {
            *returnLength = sizeof(image);
        }
        if (referenced)
        {
            ObDereferenceObject(target);
        }
        return status;
    }

    MEMORY_BASIC_INFORMATION info;
    status = MiQueryVirtualMemoryBasic(&target->addressSpace, address, &info);
    if (NT_SUCCESS(status))
    {
        memcpy(buffer, &info, sizeof(info));
        if (returnLength != 0)
        {
            *returnLength = sizeof(info);
        }
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* Change the protection of a committed run and report the previous protection
 * (M7: ntdll's loader flips .text/.data protection during import fixups). The
 * range must lie inside one VAD and be fully committed — the reprotect reuses
 * the same frames (no COW, Art. 3), only rewriting the PTE bits. */
NTSTATUS MiProtectVirtualMemory(PMI_ADDRESS_SPACE space, uint64_t *baseInOut, uint64_t *sizeInOut,
                                ULONG newProtect, ULONG *oldProtectOut)
{
    /* The WRITECOPY flavours are valid protections on MAPPED views only —
     * the oracle's set_protection rule (wine dlls/ntdll/unix/virtual.c:
     * is_view_valloc -> STATUS_INVALID_PAGE_PROTECTION; pinned by
     * sem_mm/writecopy_query). Everything else goes through the ordinary
     * anonymous-protection switch.
     *
     * THE PROTECTION IS VALIDATED LAST, not first, and the position is the
     * pinned part. The oracle asks its three questions in the order
     * view -> committed -> protection: `if ((view = find_view( base, size )))`
     * / `get_committed_size(...)` / `set_protection( view, base, size,
     * new_prot )`, which is where get_vprot_flags refuses. So an
     * unserviceable protection over a FREE address reports the address
     * (STATUS_INVALID_PARAMETER) and over a RESERVED range reports the
     * commit (STATUS_NOT_COMMITTED) — never STATUS_INVALID_PAGE_PROTECTION,
     * which this function used to answer for both because it validated on
     * the way in. Pinned by sem_mm/protect_old_prot.c.
     *
     * A ZERO-SIZE request is an ordinary trip down that ladder, not a fourth
     * rung above it. The oracle has no size guard at all: `ROUND_SIZE(addr,
     * 0, mask)` is 0 for an aligned address, find_view still answers the
     * containing view, and set_protection walks no pages — so it succeeds and
     * reports the named page's protection, while the same call on a reserved
     * range is STATUS_NOT_COMMITTED and on a free address
     * STATUS_INVALID_PARAMETER. All four measured (sem_mm/protect_old_prot.c
     * pins them); this function used to refuse every one of them with
     * STATUS_INVALID_PARAMETER. What remains refused here is the OVERFLOW the
     * oracle's find_view refuses in the same words (`addr + size < addr`). */
    ULONG bits = newProtect & ~(PAGE_GUARD | PAGE_NOCACHE);
    BOOLEAN writeCopyFlavour = bits == PAGE_WRITECOPY || bits == PAGE_EXECUTE_WRITECOPY;
    uint64_t base = MiRoundDown(*baseInOut, PAGE_SIZE);
    uint64_t end = MiRoundUp(*baseInOut + *sizeInOut, PAGE_SIZE);
    if (end < base)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PMI_VAD vad = MiFindVad(space, base);
    if (vad == 0 || end > vad->base + vad->size)
    {
        /* No single view covers the range — a free address, or a range that
         * runs off the end of one. Both are the oracle's find_view returning
         * NULL (dlls/ntdll/unix/virtual.c: `if (view->base + view->size <
         * addr + size) break;` and the miss below it), whose one caller
         * answers STATUS_INVALID_PARAMETER for either.
         *
         * This used to be STATUS_INVALID_ADDRESS, which is not merely a
         * different shade of refusal at the boundary: Wine's PE-side
         * RtlNtStatusToDosError maps c0000141 to ERROR_UNEXP_NET_ERR (59),
         * so VirtualProtect over a free address reported an "unexpected
         * network error" (dlls/ntdll/error.h:686, against :389 where
         * Windows' own STATUS_CONFLICTING_ADDRESSES maps to
         * ERROR_INVALID_ADDRESS). NT and the oracle disagree here — upstream
         * says so itself at dlls/ntdll/tests/virtual.c:2677 — and the
         * pinned oracle is this project's arbiter when they do (Art. 6).
         * Pinned by sem_mm/protect_old_prot.c; docs/03 has the three-way
         * table. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Check the WHOLE range before touching any of it. NT requires every
     * page in the range to be committed, and discovering an uncommitted one
     * halfway through used to leave the range half-reprotected while
     * reporting failure -- ntdll's loader flips section protections through
     * this path, so a partly-applied change is a process that runs with the
     * wrong page permissions (docs/review-2026-07 §7).
     *
     * The NAMED page is checked outside the loop because a zero-size request
     * has an empty range and still asks about it — the oracle's
     * get_committed_size reads the base page's vprot whatever the size is,
     * and answers STATUS_NOT_COMMITTED for a zero-size protect over a
     * reserved range (measured). It is also where the reported previous
     * protection comes from, for the same reason. */
    ULONG baseIndex = (ULONG)((base - vad->base) / PAGE_SIZE);
    if (vad->pageProtect[baseIndex] == 0)
    {
        return STATUS_NOT_COMMITTED;
    }
    for (uint64_t page = base + PAGE_SIZE; page < end; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        if (vad->pageProtect[index] == 0)
        {
            return STATUS_NOT_COMMITTED;
        }
    }

    /* Only now the protection itself (the head comment has the ordering and
     * its citation). */
    if (!writeCopyFlavour)
    {
        NTSTATUS valid = MiCheckPageProtect(newProtect);
        if (!NT_SUCCESS(valid))
        {
            return valid;
        }
    }
    if (writeCopyFlavour && vad->type == MEM_PRIVATE)
    {
        return STATUS_INVALID_PAGE_PROTECTION;
    }
    /* THE view-protection gate (MiCheckViewProtection's comment has the rule
     * and its citation). It subsumes the private-writecopy refusal just
     * above — kept because sem_mm/writecopy_query pins it by name and a
     * redundant check that agrees is not a second authority. */
    NTSTATUS compatible = MiCheckViewProtection(vad, newProtect);
    if (!NT_SUCCESS(compatible))
    {
        return compatible;
    }
    /* A SHARED view's PTEs point straight at the section's (or the file
     * cache's) frames, so a PLAIN-WRITABLE protection here writes every
     * other view and — with immediate writeback (Art. 3) — the file. The
     * backing handle's write access gates that, at protect time exactly as
     * MiMapViewOfSectionEx gates it at map time: without it, mapping
     * PAGE_READONLY over a read-only handle and then protecting
     * PAGE_READWRITE writes a file the caller could not open for writing
     * (docs/review-2026-07 §11's protect-time half).
     *
     * The status and the SCOPE are the pinned oracle's, not a guess:
     * sem_mm/protect_shared_view runs exactly this ladder on Wine and
     * answers STATUS_INVALID_PAGE_PROTECTION for the plain-writable case —
     * and SUCCESS for the WRITECOPY flavours on every shared view,
     * including this same read-only-handle one. So writecopy is deliberately
     * NOT refused here: the oracle grants it and realizes it as a writable
     * shared mapping (the store reaches the file and the other views), which
     * is what this kernel already does. Refusing it would be a divergence
     * from the spec dressed up as a fix (docs/03 "CUI-9 COW notes"). */
    if (vad->type == MEM_MAPPED && !vad->ownsFrames &&
        (bits == PAGE_READWRITE || bits == PAGE_EXECUTE_READWRITE))
    {
        PMI_SECTION section = vad->sectionBody;
        /* A body-less shared VAD is the kernel-owned KUSER_SHARED_DATA
         * frame (MiCreateMappedVad's one sectionBody == 0 case): ring 3
         * never gets it writable. */
        if (section == 0 || !section->backingWritable)
        {
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }
    /* On an image view the plain-writable protections canonicalize to
     * writecopy (the oracle's get_vprot_flags with image=TRUE: READWRITE ->
     * VPROT_READ|VPROT_WRITECOPY), which is also what a later query
     * reports — pinned by sem_mm/writecopy_query. */
    if (vad->type == MEM_IMAGE)
    {
        if (bits == PAGE_READWRITE)
        {
            newProtect = (newProtect & (PAGE_GUARD | PAGE_NOCACHE)) | PAGE_WRITECOPY;
        }
        else if (bits == PAGE_EXECUTE_READWRITE)
        {
            newProtect = (newProtect & (PAGE_GUARD | PAGE_NOCACHE)) | PAGE_EXECUTE_WRITECOPY;
        }
    }

    int present, writable, executable;
    MiProtectToPteBits(newProtect, &present, &writable, &executable);

    /* Read before the loop, not in it: a zero-size request changes no page
     * and still reports the named one (see the commit check above). */
    ULONG oldProtect = vad->pageProtect[baseIndex];
    for (uint64_t page = base; page < end; page += PAGE_SIZE)
    {
        ULONG index = (ULONG)((page - vad->base) / PAGE_SIZE);
        uint64_t frame = MiTranslateUserPage(space->pml4Physical, page, 0, 0);
        ASSERT(frame != 0);
        MiUnmapUserPage(space->pml4Physical, page);
        /* The watch trap survives a protection change (pinned by
         * sem_mm/write_watch): a clean watched page stays hardware
         * read-only whatever the protection says. */
        MiMapUserPage(space->pml4Physical, page, frame, present,
                      MipVadPageHwWritable(vad, index, writable), executable);
        vad->pageProtect[index] = newProtect;
    }
    if (vad->master != 0)
    {
        MiAssertVadNoWritableMasterPteRange(space, vad, base, end - base); /* docs/17 §8 */
    }
    *baseInOut = base;
    *sizeInOut = end - base;
    *oldProtectOut = oldProtect;
    return STATUS_SUCCESS;
}

void MiQueryVmCounters(PMI_ADDRESS_SPACE space, uint64_t *reservedBytesOut,
                       uint64_t *committedBytesOut)
{
    uint64_t reserved = 0;
    uint64_t committed = 0;
    for (PLIST_ENTRY entry = space->vadListHead.Flink; entry != &space->vadListHead;
         entry = entry->Flink)
    {
        PMI_VAD vad = CONTAINING_RECORD(entry, MI_VAD, listEntry);
        reserved += vad->size;
        uint64_t pages = vad->size / PAGE_SIZE;
        for (uint64_t i = 0; i < pages; i++)
        {
            if (vad->pageProtect[i] != 0)
            {
                committed += PAGE_SIZE;
            }
        }
    }
    *reservedBytesOut = reserved;
    *committedBytesOut = committed;
}

NTSTATUS NtProtectVirtualMemory(HANDLE process, PVOID *baseInOut, SIZE_T *sizeInOut,
                                ULONG newProtect, ULONG *oldProtect)
{
    NTSTATUS status = KiProbeForWrite(baseInOut, sizeof(*baseInOut), sizeof(*baseInOut));
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(sizeInOut, sizeof(*sizeInOut), sizeof(*sizeInOut));
    }
    if (NT_SUCCESS(status))
    {
        status = KiProbeForWrite(oldProtect, sizeof(*oldProtect), sizeof(*oldProtect));
    }
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PEPROCESS target;
    BOOLEAN referenced;
    status = MiReferenceProcessByHandle(process, PROCESS_VM_OPERATION, &target, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t base = (uint64_t)(uintptr_t)*baseInOut;
    uint64_t size = *sizeInOut;
    ULONG old = 0;
    status = MiProtectVirtualMemory(&target->addressSpace, &base, &size, newProtect, &old);
    if (NT_SUCCESS(status))
    {
        *baseInOut = (PVOID)(uintptr_t)base;
        *sizeInOut = size;
        *oldProtect = old;
    }
    else
    {
        /* A FAILED protect still answers the old-protection slot, and it
         * answers PAGE_NOACCESS — the oracle's own closing `else *old_prot =
         * PAGE_NOACCESS;` (dlls/ntdll/unix/virtual.c NtProtectVirtualMemory,
         * mirrored in its remote-APC arm). The slot's contract is therefore
         * "always written once the operation ran", not "written when there
         * was a previous protection to report": an unserviceable protection,
         * an uncommitted range and a free address all land here, and none of
         * them has one.
         *
         * The base/size slots are deliberately NOT written with it. They
         * carry this call's rounding of the range, which only a success has
         * applied; the oracle rounds into locals for exactly that reason.
         *
         * The two returns ABOVE this point stay silent, and that is the
         * distinction rather than an omission: a probe failure has no
         * writable slot, and an unresolvable process handle means the
         * operation never ran — the oracle's server_queue_process_apc
         * failure returns above the `else` too. Pinned both ways by
         * sem_mm/protect_old_prot.c. */
        *oldProtect = PAGE_NOACCESS;
    }
    if (referenced)
    {
        ObDereferenceObject(target);
    }
    return status;
}

/* kernel/io/file.c: the Mm<->Io seam for file identity (the
 * IopBuildSectionBacking pattern, mm/section.c). */
BOOLEAN IoIsSameUnderlyingFile(PVOID fileBody1, PVOID fileBody2);

NTSTATUS NtAreMappedFilesTheSame(PVOID address1, PVOID address2)
{
    /* The loader's find_existing_module probe (dlls/ntdll/loader.c): is the
     * image at address2 the same on-disk file as the module at address1?
     * Statuses and their ORDER as the oracle's dlls/ntdll/unix/virtual.c
     * NtAreMappedFilesTheSame + server/mapping.c is_same_mapping, pinned by
     * sem_mm/mapped_same: both addresses must land in views; private
     * (NtAllocateVirtualMemory) memory refuses CONFLICTING_ADDRESSES; one
     * view is trivially the same; two views are the same only when the
     * FIRST is an image view and both name the same on-disk file. */
    PMI_ADDRESS_SPACE space = &KeGetCurrentThread()->process->addressSpace;
    PMI_VAD vad1 = MiFindVad(space, (uint64_t)(uintptr_t)address1);
    PMI_VAD vad2 = MiFindVad(space, (uint64_t)(uintptr_t)address2);
    if (vad1 == 0 || vad2 == 0)
    {
        return STATUS_INVALID_ADDRESS;
    }
    if (vad1->type == MEM_PRIVATE || vad2->type == MEM_PRIVATE)
    {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    if (vad1 == vad2)
    {
        return STATUS_SUCCESS;
    }
    PMI_SECTION section1 = vad1->sectionBody;
    PMI_SECTION section2 = vad2->sectionBody;
    if (section1 == 0 || section2 == 0 || section1->fileObject == 0 || section2->fileObject == 0 ||
        (section1->attributes & SEC_IMAGE) == 0 ||
        !IoIsSameUnderlyingFile(section1->fileObject, section2->fileObject))
    {
        return STATUS_NOT_SAME_DEVICE;
    }
    return STATUS_SUCCESS;
}

/* CUI-4: cross-process memory access (toolhelp/debug readers). Contract from
 * ntdll's unix side (dlls/ntdll/unix/virtual.c): a read validates the OUT
 * buffer (ACCESS_VIOLATION on failure, bytes 0), then moves from the target
 * address space, reporting STATUS_PARTIAL_COPY with bytes 0 on any fault; a
 * write validates the source buffer (PARTIAL_COPY on failure) then moves into
 * the target. The buffer is always in the CALLER's address space (direct
 * access under the current CR3); only the far side rides MiTranslateUserPage +
 * the HHDM. Pinned by sem_ps/virtual_memory. */
NTSTATUS NtReadVirtualMemory(HANDLE processHandle, const void *baseAddress, void *buffer,
                             SIZE_T size, SIZE_T *bytesRead)
{
    if (bytesRead != 0)
    {
        NTSTATUS probe = KiProbeForWrite(bytesRead, sizeof(*bytesRead), sizeof(*bytesRead));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        *bytesRead = 0;
    }
    if (size == 0)
    {
        return STATUS_SUCCESS;
    }
    /* The OUT buffer must be writable in the caller (Wine's
     * virtual_check_buffer_for_write); failure is ACCESS_VIOLATION, not a
     * partial copy. */
    if (!NT_SUCCESS(KiProbeForWrite(buffer, size, 1)))
    {
        return STATUS_ACCESS_VIOLATION;
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    NTSTATUS status =
        MiReferenceProcessByHandle(processHandle, PROCESS_VM_READ, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t copied =
        MiCopyFromUserRange(&process->addressSpace, buffer, (uint64_t)(uintptr_t)baseAddress, size);
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    if (copied != size)
    {
        return STATUS_PARTIAL_COPY; /* bytesRead already 0 (Wine's fault shape) */
    }
    if (bytesRead != 0)
    {
        *bytesRead = size;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtWriteVirtualMemory(HANDLE processHandle, void *baseAddress, const void *buffer,
                              SIZE_T size, SIZE_T *bytesWritten)
{
    if (bytesWritten != 0)
    {
        NTSTATUS probe =
            KiProbeForWrite(bytesWritten, sizeof(*bytesWritten), sizeof(*bytesWritten));
        if (!NT_SUCCESS(probe))
        {
            return probe;
        }
        *bytesWritten = 0;
    }
    if (size == 0)
    {
        return STATUS_SUCCESS;
    }
    /* The source must be readable in the caller (Wine's
     * virtual_check_buffer_for_read); failure is STATUS_PARTIAL_COPY. */
    if (!NT_SUCCESS(KiProbeForRead(buffer, size, 1)))
    {
        return STATUS_PARTIAL_COPY;
    }

    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    NTSTATUS status =
        MiReferenceProcessByHandle(processHandle, PROCESS_VM_WRITE, &process, &referenced);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    uint64_t written = MiCopyToUserRangeChecked(&process->addressSpace,
                                                (uint64_t)(uintptr_t)baseAddress, buffer, size);
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    if (written != size)
    {
        return STATUS_PARTIAL_COPY;
    }
    if (bytesWritten != 0)
    {
        *bytesWritten = size;
    }
    return STATUS_SUCCESS;
}
