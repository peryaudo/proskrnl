/*
 * sem_mm/zero_bits.c — NtAllocateVirtualMemory's `zero_bits` is a real
 * placement constraint, not a validated-then-ignored argument.
 *
 * The argument carries two meanings and NT picks between them by magnitude
 * (third_party/wine dlls/ntdll/unix/unix_private.h, get_zero_bits_limit —
 * the one definition both NtAllocateVirtualMemory and NtMapViewOfSection
 * call):
 *
 *   0        unconstrained.
 *   1..31    a COUNT of leading zero bits in a 32-bit window: the returned
 *            address must be below 2^(32 - zero_bits).
 *   >= 32    a MASK of acceptable address bits.
 *
 * and the validation around it has two gaps that are INVALID rather than
 * merely unusual (dlls/ntdll/unix/virtual.c, NtAllocateVirtualMemory):
 * 22..31 is STATUS_INVALID_PARAMETER_3, and so is 33..0xfffe.
 *
 * proskrnl had the validation and not the constraint: the argument was
 * range-checked and then dropped, under a comment asserting that a
 * bottom-up allocator satisfies it anyway. It does not. ntdll:virtual
 * sweeps zero_bits 2..20 and checks the result against
 * `(UINT_PTR)addr >> (32 - zero_bits)` — at 20 bits that is a 4 KiB
 * ceiling, and twelve of the pair's thirteen failures were that one line
 * (virtual.c:170).
 *
 * What makes it worth a pin of its own rather than leaving it to the
 * winetest pair: the failure was INVISIBLE to every existing test, because
 * an ignored constraint still returns a perfectly good address. Only an
 * assertion about WHERE the address landed can see it.
 *
 * Oracle-first (G5).
 */
#include "util.h"

START_TEST(zero_bits)
{
    NTSTATUS status;
    void *addr;
    SIZE_T size;
    ULONG_PTR bits;

    /* --- the count form: 1 .. 21 ---------------------------------------
     * 21 is included deliberately. It is the largest value the validation
     * accepts, and it is also the one that can never be satisfied: a 4 KiB
     * page under a 2^11 = 2048-byte ceiling does not fit, and NT's answer
     * is an ordinary out-of-memory, NOT a parameter error. The two are
     * easy to collapse into one check and the boundary keeps them apart. */
    for (bits = 1; bits <= 21; bits++)
    {
        addr = NULL;
        size = 0x1000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, bits, &size,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (bits == 21)
        {
            ok(status == STATUS_NO_MEMORY, "zero_bits 21 -> %08lx", (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                size = 0;
                NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
            }
            continue;
        }

        ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY, "zero_bits %u -> %08lx",
           (unsigned)bits, (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            continue;
        }
        /* The whole point of the test. */
        ok(((ULONG_PTR)addr >> (32 - bits)) == 0,
           "zero_bits %u put the allocation at %p, above the 2^%u ceiling", (unsigned)bits, addr,
           (unsigned)(32 - bits));
        size = 0;
        status = NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
        ok(status == STATUS_SUCCESS, "release the zero_bits %u allocation -> %08lx", (unsigned)bits,
           (unsigned long)status);
    }

    /* --- the invalid band: 22 .. 31 ------------------------------------
     * Not "cannot be satisfied" — malformed. STATUS_INVALID_PARAMETER_3
     * names the argument, and it must not decay into the generic
     * STATUS_INVALID_PARAMETER. */
    addr = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 22, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_3, "zero_bits 22 -> %08lx", (unsigned long)status);

    addr = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 31, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_3, "zero_bits 31 -> %08lx", (unsigned long)status);

    /* 33 is inside the second invalid band (> 32 and below the allocation
     * granularity mask), and it is what keeps the mask reading from
     * swallowing every large value. */
    addr = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 33, &size, MEM_RESERVE | MEM_COMMIT,
                                     PAGE_READWRITE);
    ok(status == STATUS_INVALID_PARAMETER_3, "zero_bits 33 -> %08lx", (unsigned long)status);

    /* --- the mask form -------------------------------------------------
     * 0xffffff is a legal mask (>= the granularity mask): every address bit
     * up to and including its highest set one is allowed, so the ceiling is
     * 0xffffff and the allocation must land under it. */
    addr = NULL;
    size = 0x1000;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0xffffff, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(status == STATUS_SUCCESS || status == STATUS_NO_MEMORY, "zero_bits mask 0xffffff -> %08lx",
       (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        ok((ULONG_PTR)addr <= 0xffffff, "the 0xffffff mask put the allocation at %p", addr);
        size = 0;
        NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
    }

    /* --- and a NAMED base drops the constraint entirely -----------------
     * `if (!*ret) limit = get_zero_bits_limit( zero_bits ); else limit = 0;`
     * — a caller who supplies an address is telling the allocator where to
     * put it, and zero_bits is not then re-checked against it. A kernel
     * that enforced the ceiling anyway would refuse this, and nothing in
     * the winetest pair would notice. */
    {
        void *scratch = NULL;
        size = 0x10000;
        status = NtAllocateVirtualMemory(NtCurrentProcess(), &scratch, 0, &size, MEM_RESERVE,
                                         PAGE_READWRITE);
        ok(status == STATUS_SUCCESS, "reserve a scratch range -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            /* Deliberately above the 2^12 ceiling zero_bits 20 would set. */
            addr = scratch;
            size = 0x1000;
            status = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 20, &size, MEM_COMMIT,
                                             PAGE_READWRITE);
            ok(status == STATUS_SUCCESS, "commit at a named base with zero_bits 20 -> %08lx",
               (unsigned long)status);
            ok(addr == scratch, "the named base moved: %p vs %p", addr, scratch);

            size = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &scratch, &size, MEM_RELEASE);
        }
    }
}
