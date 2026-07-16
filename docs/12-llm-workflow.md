# 12 — Driving proskrnl with an LLM

This project is intended to be implemented largely by an LLM coding agent. That is viable,
but the failure modes are specific and the leverage is uneven. An LLM's competence here
tracks the same axis used throughout these docs: **oracle presence + failure visibility.**

## Where the LLM is strong (spec exists, failure is loud)

- **`io/query.c`** — info-class struct-filling. Wine headers are the answer key; the best
  LLM task in the tree.
- **`drivers/virtio/*`, `fs/fat32/{fat,dir,file}.c`** — public specs, abundant reference
  implementations in training data.
- **`abi/` headers** — declarations, and *verifiable* via `static_assert` offsets.
- **`tests/ntapi/`** — the highest-value use. The model has broad knowledge of Windows
  behaviour, and the project's life depends on this test asset.
- **Panic handler, tracing, log formatting** — under LLM-driven dev this is the debugger;
  build it thick first.
- **Differential fuzzer generator** — mechanical oracle, explicit failure, boring: ideal.

## Where the LLM is weak (no oracle, silent failure)

- **`mm/{section,fault,pagecache}.c`** — the top danger zone. Plausible code, unit tests
  pass, then it corrupts silently under Wine's real load. *This is where Article 3 saves
  the project*: with no COW/eviction/locking, the hard bugs cannot form.
- **`ke/{wait,apc}.c`** — subtly wrong yet still runs; surfaces as "calc occasionally
  hangs" months later, with a multi-month latency.
- **`ps/usermode.c`** — assembly + stack-layout exactness; the model lies in the details.
- **`arch/x86_64/*.S`** — assembly generally (small, which is the mercy).
- **Wine build extraction** — not a knowledge problem but a "try 40 combinations" problem;
  the loop turns, but it devours time.

## Where it breaks: the M7 phase transition

Failure changes character at M7:

- **M1–M6:** failure = "my test failed"; the cause is inside my own code; the loop is clean.
- **M7+:** failure = "a million lines of someone else's code did something and stopped";
  the bug lives in the invisible gap between my semantics and Wine's expectations. The model
  holds only local information, so its effectiveness drops sharply here.

M7 is both the biggest mountain and the point where LLM leverage collapses. Mitigation is
front-loaded: **make M2–M6 semantic tests green before M7** (Article 5), so that an M7 bug
was already catchable at M3.

## The two LLM-specific bugs, and their defences

1. **Plausible constants from memory** → Article 4: generate all of `abi/` from Wine
   headers; forbid hand-typed and model-recalled values. Approximately-right constants
   hide; that is worse than wrong.
2. **"Growing" NT-absent things** → Article 2 + the `hacks.md` ledger + `abi/` isolation.
   The model, trained on Linux, adds IRQL/Cc/POSIX idioms out of helpfulness. The human
   guards this fence; it cannot be delegated to the model.

## The provenance recursion (see docs/11)

The same GPL-contamination risk discussed for Linux-driver translation recurs *inside the
kernel*: "implement `NtQueryInformationFile`" may surface ReactOS-derived (GPLv2) code from
training data. Fix the license first; restrict kernel-code reference material to Wine
headers + MS docs if a permissive license is wanted.

## Effort/leverage reality

- The code the LLM is good at is ~90% of the **lines** but ~50% of the **effort**. The hard
  ~7k lines (`mm/{section,fault,pagecache}` + `ke/{wait,apc}` + `ps/usermode`) are ~10% of
  lines and ~50% of effort.
- Realistic speedup: **~1.9×**, not 10×. The LLM melts the boring 90%; it barely touches
  the 10% that makes this project hard — and that 10% breeds bugs that never terminate
  unless *you* understand them.

## Division of labour

1. **Maximum budget to `tests/`** — the LLM's best use and the project's lifeline.
2. **Generate `abi/`** — no hand-typing, no recall.
3. **Thick debugging infra first** — logs and panic dumps are the model's eyes.
4. **You design the 3 hard files; the LLM writes them.** The reverse kills the project.
5. **M2–M6 tests must be green before M7.**

## If you insist on "no M0, LLM does everything, now"

Legitimate under time pressure — motivation is non-fungible, and "start now" can be the
correct expected-value move even if M0 is cheap in the abstract. But then two levers matter
more than anything, and both are decided *today*, not learned over months:

- **Make Article 3 a constitution, not a choice.** It deletes the difficulty of the code
  you cannot review. This *replaces* M0a — you needn't learn to write COW because you don't
  write COW.
- **Pull calc.exe off the npfs critical path** (wineserver-lite over shared-section+events;
  npfs/cmd after the calculator). Faster pixels ⇒ sustained motivation ⇒ lower attrition,
  which is the real killer.

Honest odds to "calc.exe on screen": **~7%**, dominated by attrition and world-first
novelty, *not* by having made a wrong decision. Raising it to ~12–15% comes from
**constitution + differential fuzzing + asserts**, of which the **constitution is half**.
And note: **M7 (Wine ntdll runs hello.exe), at ~30%, is itself a world-first and a complete
result.** Detection does not compensate for inexperience; **design makes inexperience
irrelevant.**
