# Provenance

Per-component record of where code and constants come from (docs/11,
CONTRIBUTING "Provenance rules"). Kernel-code reference material is limited to
**Wine headers and official Microsoft documentation** — never ReactOS, never
leaked Windows source, never model memory.

| Component | Provenance |
|---|---|
| `abi/ntstatus.h`, `abi/ntdef.h` | **Generated** by `tools/gen_abi.py` from `third_party/wine/include/{ntstatus.h,ntdef.h,winnt.h}` (Art. 4). Never hand-edited; regenerate with `make gen-abi`. |
| `kernel/ke/` dispatcher types (`DISPATCHER_HEADER`, `KEVENT`, `KSEMAPHORE`, `KMUTANT`, `KTIMER`, `KWAIT_BLOCK`, `KWAIT_REASON`) | Struct shapes and `Ke*` function signatures taken from `third_party/wine/include/ddk/wdm.h` and `dlls/ntoskrnl.exe/sync.c` (headers/signatures only — Wine's implementation is a user-space emulation and was not translated). Member casing per docs/15. Internal layouts (`KTHREAD`, scheduler, wait algorithm) are original (docs/03: internals ours). |
| `kernel/lib/list.h` | NT list API names/signatures as declared in Wine's `wdm.h`; implementation original (the semantics are fully specified by the declarations). |
| `kernel/mm/` (phys, pool), `kernel/ke/` scheduler/wait internals | Original, written to Art. 3 (one lock, one pool, no preemption). |
| `arch/x86_64/` (IDT, LAPIC/x2APIC, PIT calibration, paging, context switch) | Original, from public hardware documentation (Intel SDM, OSDev-common PIT/LAPIC facts) and the Limine boot protocol (`third_party/limine/limine.h`, BSD-licensed header). |
| `tests/` | Original; harness style modelled on Wine's test conventions (`ok()`, snake_case), no Wine test code copied yet. |
