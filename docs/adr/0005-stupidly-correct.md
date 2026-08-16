# ADR 0005 — "Stupidly correct" internals

**Status:** Accepted; the no-COW clause was amended at CUI-9 for `SEC_IMAGE` sections
(measured functional ceiling — `docs/17-cow-strategy.md`, `docs/03` "CUI-9 COW notes")

## Context
Every genuinely hard bug in Mm and Ke is a **concurrency or optimization** bug — COW,
eviction, writeback windows, fine-grained locking, SMP, kernel preemption — and every one of
those is **unobservable from user mode**, i.e. not part of the boundary contract. The NT
Mm/Cc/Io "triangle" that ReactOS is still rewriting after 30 years is made of exactly these.
An implementer who cannot fully review concurrent kernel code needs the hardest bugs to be
*impossible*, not merely detectable.

## Decision
The initial implementation mandates: **no copy-on-write; no eviction; immediate writeback;
one dispatcher lock; uniprocessor; no kernel preemption; one pool.** The page cache is
unified (standing in for Cc). Optimizations are added later, behind the same tests, only if
genuinely needed.

## Consequences
- Mapped-view/`ReadFile` consistency — NT's real hard problem — becomes *structurally
  trivial* (same page-cache page). ~90% of Mm/Ke difficulty disappears.
- `mm/{section,fault,pagecache}` drops from ~3500 to ~1200 lines and changes difficulty
  class. `ke/wait.c` becomes a plain state machine.
- Costs RAM (duplicated read-only pages) and performance and SMP. Accepted: CUI-in-a-VM does
  not care, and the project sells semantics, not speed.
- This is the most powerful verification tool in the repo: a bug that cannot exist needs no
  review. Enforced as Constitution Article 3.
