# 15 — Code style

proskrnl's kernel C follows the **modern Win32/NT naming convention** so the code reads as a
teaching artifact against *Windows Internals* and the `Nt*` boundary — **not** Linux-kernel
`snake_case`. This is a gate (`docs/CONTRIBUTING.md`), not a preference.

**Provenance first (Article 8, `docs/11`).** We adopt the *convention* — a publicly known set
of naming rules also visible in the Windows SDK/WDK headers and *Windows Internals*. We do
**not** read or translate WRK or ReactOS **source** into this kernel; kernel-code reference
material is limited to **Wine headers and official Microsoft documentation**. "Looks like
WRK" is about the naming shape, never about where a line came from.

## The hard rule: never redefine an NT function with a different signature

If an identifier is a real NT name, it carries a real NT contract. Silently giving it a
different signature is exactly the boundary erosion the constitution exists to stop.

> **Before naming a function with an `Nt`/`Ke`/`Mm`/`Ob`/`Ps`/`Io`/`Cm`/`Hal`/`Rtl`/`Zw`
> name, grep the Wine tree for it.** If it exists, match its signature exactly. If it does
> not, the name is free — but prefer an internal `Ki`/`Mi`/`Hal p`-style name for things NT
> does not export.

```sh
grep -rn "KeBugCheck" third_party/wine/   # -> void WINAPI KeBugCheck(ULONG code)
```

So a fatal-error helper that takes a *string* may **not** be called `KeBugCheck` (whose real
signature is `KeBugCheck(ULONG)`) — it is `KiPanic(const char *)` (`KiPanic` is absent from
Wine, hence free). Want a different argument list? Use a different name. Period.

## Naming

| Kind | Convention | Examples |
|---|---|---|
| **Functions** | `PascalCase`, 2–3 letter subsystem prefix; a lowercase `i`/`p` marks *internal/private* | `KeInitializeIdt`, `MmAllocatePage`, `KiDispatchTrap`, `HalpQemuExit` |
| **Types** (typedefs) | `UPPER_SNAKE`, with a `_Name` struct tag and a `PName` pointer typedef | `typedef struct _KTRAP_FRAME { … } KTRAP_FRAME, *PKTRAP_FRAME;` |
| **Locals / parameters** | `PascalCase` (see note), no strict systems Hungarian | `Status`, `TrapFrame`, `PageFrame`, `Length` |
| **Globals** | `PascalCase` with subsystem prefix | `KeTickCount`, `KiLastSystemCall` |
| **Macros / constants / hardware regs** | `UPPER_SNAKE` | `PAGE_SIZE`, `TIMER_VECTOR`, `IA32_APIC_BASE` |
| **Files** | lowercase, terse (as in NT) | `idt.c`, `lapic.c`, `phys.c` |

**Subsystem prefixes** (the department names of `docs/04`): `Ke` kernel, `Mm` memory, `Ob`
objects, `Ps` process, `Io` I/O, `Cm` config/registry, `Se` security, `Hal` hardware layer
(absorbed into `arch/`), `Rtl` runtime library, `Kd` kernel debug, `Nt`/`Zw` the syscall
boundary. Internal helpers add `i`/`p`: `Ki*`, `Mi*`, `Iop*`, `Halp*`.

- **No strict systems Hungarian.** `PLIST_ENTRY Head`, not `lpHead`; `ULONG Length`, not
  `cbLength`. The pointer typedef prefixes NT already bakes into type names (`P…`) suffice.
- **No Linux idioms.** No `snake_case` identifiers, no `foo_t`, no `struct foo *foo`.

> **Note on local variables.** This follows the classic NT *kernel* convention:
> `PascalCase` (capital first) locals — `NTSTATUS Status; ULONG Index;` — so locals, params,
> functions, and members share one casing. (App/C++/C# code more often uses `camelCase`
> locals; that is a different tradition. If the team prefers `camelCase` locals, change this
> row and re-run — it is the one soft call here.)

- Numeric ABI constants are **generated**, never named by hand (Article 4, `docs/09`).

## Formatting

Enforced by `.clang-format` (LLVM base, tuned to the NT layout): **Allman braces** (opening
brace on its own line, for functions *and* control flow), 4-space indent, 100 columns,
right-aligned pointers, no include reordering. Run it:

```sh
make format          # clang-format -i over all kernel C (uses the llvm keg)
```

clang-format governs layout only — it cannot enforce the naming above, so the naming rules
are on you (and on review). A `PostToolUse` hook formats edited files automatically.

## The M1 rename (reference)

The M1 bring-up was first written in Linux style and converted to this guide:

| Linux-style (was) | NT-style (now) |
|---|---|
| `kmain` | `KiSystemStartup` |
| `serial_init` / `serial_putc` / `serial_puts` | `HalInitializeSerial` / `HalPutChar` / `HalPutString` |
| `outb` / `inb` / `rdmsr` / `wrmsr` | `__outbyte` / `__inbyte` / `__readmsr` / `__writemsr` |
| `kprintf` / `kvprintf` | `DbgPrint` / `DbgPrintV` |
| `panic(const char *)` | `KiPanic(const char *)` — *not* `KeBugCheck`, whose real signature is `KeBugCheck(ULONG)` |
| `trap_handler` / `struct trap_frame` | `KiDispatchTrap` / `KTRAP_FRAME` |
| `idt_init` / `idt_set_gate` | `KiInitializeIdt` / `KiSetInterruptGate` |
| `timer_init` / `lapic_eoi` / `timer_tick(s)` | `HalInitializeTimer` / `HalEndOfInterrupt` / `KeUpdateTickCount` / `KeTickCount` |
| `phys_init` / `phys_alloc` / `phys_free` | `MmInitializePhysicalMemory` / `MmAllocatePage` / `MmFreePage` |
