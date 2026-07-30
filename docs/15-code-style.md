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

> **Before naming a function with an `Nt`/`Ke`/`Mm`/`Ob`/`Ps`/`Io`/`Cm`/`Rtl`/`Zw`
> name, grep the Wine tree for it.** If it exists, match its signature exactly. If it does
> not, the name is free — but prefer an internal `Ki`/`Mi`-style name for things NT does not
> export.

```sh
grep -rn "KeBugCheck" third_party/wine/   # -> void WINAPI KeBugCheck(ULONG code)
```

So a fatal-error helper that takes a *string* may **not** be called `KeBugCheck` (whose real
signature is `KeBugCheck(ULONG)`) — it is `KiPanic(const char *)` (`KiPanic` is absent from
Wine, hence free). Want a different argument list? Use a different name. Period.

The same logic governs the prefix: the page-frame primitives are `Mi*` (`MiAllocatePage`,
`MiFreePage`), **not** `Mm*` — Wine has no `MmAllocatePage`, so a public-looking `Mm` name
would falsely imply an exported contract. Non-exported internals take the `i`/`p` prefix.
A name that *is* a real export keeps it and matches the signature: `DbgPrint` stays
`DbgPrint` but returns `NTSTATUS`, not `void`; `KeTickCount` stays a global.

## Naming

| Kind | Convention | Examples |
|---|---|---|
| **Functions** | `PascalCase`, 2–3 letter subsystem prefix; a lowercase `i`/`p` marks *internal/private* | `KeInitializeIdt`, `MiAllocatePage`, `KiDispatchTrap`, `KiQemuExit` |
| **Types** (typedefs) | `UPPER_SNAKE` typedef + a `PName` pointer typedef; anonymous struct tag (a `_Name` tag is a reserved identifier) | `typedef struct { … } KTRAP_FRAME, *PKTRAP_FRAME;` |
| **Locals / parameters** | `camelCase`, no strict systems Hungarian | `status`, `trapFrame`, `pageFrame`, `length` |
| **Struct members** | `camelCase` | `frame->errorCode`, `entry->offsetLow` |
| **Globals** (incl. file-scope `static`) | `PascalCase` with subsystem prefix | `KeTickCount`, `KiLastSystemCall`, `MiFreeListHead` |
| **Macros / constants / hardware regs** | `UPPER_SNAKE` | `PAGE_SIZE`, `TIMER_VECTOR`, `IA32_APIC_BASE` |
| **Files** | lowercase, terse (as in NT) | `idt.c`, `lapic.c`, `phys.c` |

**Subsystem prefixes** (the department names of `docs/04`): `Ke` kernel, `Mm` memory, `Ob`
objects, `Ps` process, `Io` I/O, `Cm` config/registry, `Se` security, `Rtl` runtime library,
`Kd` kernel debug, `Nt`/`Zw` the syscall boundary. Internal helpers add `i`/`p`: `Ki*`,
`Mi*`, `Iop*`.

**There is no `Hal` prefix.** The HAL is deliberately absorbed into `arch/` (`docs/04`,
`docs/00` scope), so hardware-facing boot primitives — serial, LAPIC timer, port I/O,
machine control — are **`Ki`** (kernel-internal), not `Hal`/`Halp`. **Default to `Ki`;** use
a department prefix only when the code *clearly* belongs to that department. The page-frame
allocator is `Mi` because it lives in `kernel/mm/phys.c` — the earliest-built floor of the
Mm department (M4–M5), and `Mi` = Mm-internal. (If a real `Kd` kernel-debug subsystem is
later built, the serial/`DbgPrint` transport can migrate from `Ki` to `Kd`.)

- **No strict systems Hungarian.** `PLIST_ENTRY Head`, not `lpHead`; `ULONG Length`, not
  `cbLength`. The pointer typedef prefixes NT already bakes into type names (`P…`) suffice.
- **No Linux idioms.** No `snake_case` identifiers, no `foo_t`, no `struct foo *foo`.

> **The casing rule in one line:** anything that holds a runtime *value* — locals,
> parameters, struct members — is `camelCase`; *names of code and types* — functions,
> typedefs, macros — are `PascalCase`/`UPPER_SNAKE`; module **globals** (including file-scope
> `static`) keep a `PascalCase` subsystem prefix so they stand out from locals
> (`KeTickCount`, `MiFreeListHead`). This departs from classic NT, which PascalCases locals
> and members too — a deliberate project choice for readability.

- Numeric ABI constants are **generated**, never named by hand (Article 4, `docs/09`).

## Formatting

Enforced by `.clang-format` (LLVM base, tuned to the NT layout): **Allman braces** (opening
brace on its own line, for functions *and* control flow), 4-space indent, 100 columns,
right-aligned pointers, no include reordering. Run it:

```sh
make format          # clang-format -i over all kernel C (uses the llvm keg)
```

clang-format governs *layout*; the *naming* rules above are enforced by **`make tidy`**
(clang-tidy's `readability-identifier-naming`, configured in `.clang-tidy`) — the kernel is
warning-clean, and CI/review should keep it so. A `PostToolUse` hook formats edited files
automatically.

**Tests are exempt.** `tests/` follows **Wine test style** (snake_case functions like `ok`,
`START_TEST`, `ntapi_out`; distilled from `dlls/*/tests`), and forward-declares Windows API
names that must keep their PascalCase — so `tests/.clang-tidy` turns the naming check off
there. Don't apply the kernel casing to test code.

**`user/wine/` is the other exemption — and the only one under `user/`.** That glue sits
directly against the pinned tree's sources (unixlib seams, per-program PE entry points) and
mirrors Wine style, so `user/wine/.clang-format` disables formatting and
`user/wine/.clang-tidy` turns the naming check off. **`user/smss/` is not exempt:** the
session manager is our own code, so it follows this guide exactly like `kernel/`, `drivers/`
and `fs/` — `make format` formats it and `make tidy` checks it (under the mingw target it is
built for, since it is a PE). Its names are unprefixed-by-department but subsystem-prefixed
all the same: `Smss*` for the process's own surface, `Session*` for the acceptance flows,
`Firstboot*` for the wineboot hand-off.

## The M1 rename (reference)

The M1 bring-up was first written in Linux style and converted to this guide:

| Linux-style (was) | NT-style (now) |
|---|---|
| `kmain` | `KiSystemStartup` |
| `serial_init` / `serial_putc` / `serial_puts` | `KiInitializeSerial` / `KiSerialPutChar` / `KiSerialPutString` (no HAL → `Ki`) |
| `outb` / `inb` / `rdmsr` / `wrmsr` | `KiOutByte` / `KiInByte` / `KiReadMsr` / `KiWriteMsr` (we hand-roll them; `__`-names are reserved) |
| `kprintf` / `kvprintf` | `DbgPrint` (real export → `NTSTATUS` return) / private `DbgpPrintV` |
| `panic(const char *)` | `KiPanic(const char *)` — *not* `KeBugCheck`, whose real signature is `KeBugCheck(ULONG)` |
| `trap_handler` / `struct trap_frame` | `KiDispatchTrap` / `KTRAP_FRAME` |
| `idt_init` / `idt_set_gate` | `KiInitializeIdt` / `KiSetInterruptGate` |
| `timer_init` / `lapic_eoi` / `timer_tick(s)` | `KiInitializeTimer` / `KiEndOfInterrupt` / `KiUpdateTickCount` / `KeTickCount` (real export) |
| `phys_init` / `phys_alloc` / `phys_free` | `MiInitializePhysicalMemory` / `MiAllocatePage` / `MiFreePage` (internal → `Mi`) |
