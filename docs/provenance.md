# Provenance

Per-component record of where code and constants come from (docs/11,
CONTRIBUTING "Provenance rules"). Kernel-code reference material is limited to
**Wine headers and official Microsoft documentation** — never ReactOS, never
leaked Windows source, never model memory.

| Component | Provenance |
|---|---|
| `abi/ntstatus.h`, `abi/ntdef.h`, `abi/ntobapi.h`, `abi/ntmmapi.h`, `abi/ntimage.h`, `abi/ntpsapi.h` | **Generated** by `tools/gen_abi.py` from `third_party/wine/include/{ntstatus.h,ntdef.h,winnt.h,winternl.h,ddk/wdm.h}` (Art. 4) — including the M3–M5 `Nt*` prototypes, the section enums/structs, and the PE/COFF on-disk structures, extracted verbatim. Never hand-edited; regenerate with `make gen-abi`. |
| `kernel/mm/section.c`, `kernel/mm/fault.c` | `Nt*` signatures via the generated `abi/ntmmapi.h`; boundary behaviour (creation/mapping statuses, guard-page semantics) pinned by `tests/ntapi/sem_mm/` against the Wine oracle, with Wine's `server/mapping.c` + `dlls/ntdll/unix/virtual.c` as the behaviour reference (behaviour, not code). Internals (section body, page-cache seed, VAD view plumbing) original. |
| `kernel/mm/pecoff.c` | PE/COFF structures from the generated `abi/ntimage.h` (Wine's `winnt.h` — the layout Microsoft's public PE/COFF specification documents); relocation-block walk per the documented `IMAGE_REL_BASED_*` semantics (Wine's `LdrProcessRelocationBlock` reimplementation as behaviour reference). Parser/mapper implementation original. |
| `kernel/init/initrd.c` | Original (the M5 seed RAM-disk; internal shape free per Art. 1 — nothing here is user-observable). |
| `kernel/ob/` | `Ob*` export signatures and `OBJECT_HANDLE_INFORMATION`/`MODE` from `third_party/wine/include/ddk/wdm.h`; `Nt*` signatures via the generated `abi/ntobapi.h`; NTSTATUS conventions pinned by `tests/ntapi/sem_ob/` against the Wine oracle. Internals (object header, handle table, namespace walk) original (docs/03: internals ours). |
| `kernel/lib/rtl.c` | `Rtl*` signatures from `third_party/wine/include/winternl.h`; implementations original (ASCII-only upcase recorded in docs/03). |
| `kernel/mm/kasan.c` | Original; implements the public ASan compiler ABI (`__asan_*` outline hooks, 1/8 shadow encoding) as documented by LLVM/the sanitizer interface headers. Not derived from the Linux kernel's KASAN sources. |
| `kernel/ke/` dispatcher types (`DISPATCHER_HEADER`, `KEVENT`, `KSEMAPHORE`, `KMUTANT`, `KTIMER`, `KWAIT_BLOCK`, `KWAIT_REASON`) | Struct shapes and `Ke*` function signatures taken from `third_party/wine/include/ddk/wdm.h` and `dlls/ntoskrnl.exe/sync.c` (headers/signatures only — Wine's implementation is a user-space emulation and was not translated). Member casing per docs/15. Internal layouts (`KTHREAD`, scheduler, wait algorithm) are original (docs/03: internals ours). |
| `kernel/lib/list.h` | NT list API names/signatures as declared in Wine's `wdm.h`; implementation original (the semantics are fully specified by the declarations). |
| `kernel/mm/` (phys, pool), `kernel/ke/` scheduler/wait internals | Original, written to Art. 3 (one lock, one pool, no preemption). |
| `arch/x86_64/` (IDT, LAPIC/x2APIC, PIT calibration, paging, context switch) | Original, from public hardware documentation (Intel SDM, OSDev-common PIT/LAPIC facts) and the Limine boot protocol (`third_party/limine-protocol/include/limine.h`, pinned submodule, 0BSD). |
| `third_party/limine`, `third_party/limine-protocol`, `third_party/qemu` | Pinned submodules of the official upstreams (limine-bootloader on GitHub; QEMU's official GitHub mirror). Build/run tooling only — none of their code enters the kernel image; Limine's BIOS stages live on the boot disk under their own BSD license. |
| `tests/` | Original; harness style modelled on Wine's test conventions (`ok()`, snake_case), no Wine test code copied yet. |
| `LICENSE` | Verbatim GPL-2.0 license text fetched from the canonical FSF source (`https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt`), not model-recalled. |
