# Architecture Decision Records

Load-bearing decisions, each in the form: context → decision → consequences. These are the
choices that, if reversed, make proskrnl a different (and mostly harder) project. They are
the durable record behind `docs/01-tradeoffs.md`.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-drop-driver-abi.md) | Drop Windows driver binary compatibility | Accepted |
| [0002](0002-nt-native-api-boundary.md) | Compatibility target is the NT native-API boundary | Accepted |
| [0003](0003-cui-first.md) | CUI is the final supported target; GUI is opt-in | Accepted |
| [0004](0004-reuse-wine-pe.md) | Reuse Wine's PE user-land; swap only ntdll's unix backend | Accepted |
| [0005](0005-stupidly-correct.md) | "Stupidly correct" internals (no COW/eviction/SMP initially) | Accepted |
| [0006](0006-x64-only.md) | x86-64 only; 32-bit via WOW64, added last | Accepted |
| [0007](0007-gui-route-a.md) | GUI via route (a): user-mode wineserver-lite desktop server | Accepted |
| [0008](0008-wine-desktop-first.md) | Wine's desktop before the ReactOS shell | Accepted |
| [0009](0009-make-federated-build.md) | Plain Make; foreign builds stay native (federated superbuild) | Accepted |
| [0010](0010-limine-boot.md) | Boot with Limine, not Multiboot2/GRUB | Accepted |

Each ADR is deliberately short. The reasoning is expanded in the numbered `docs/` files;
the ADR fixes the decision and its main consequences so they are not silently reopened.
