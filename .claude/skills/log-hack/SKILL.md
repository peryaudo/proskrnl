---
name: log-hack
description: Append the next HACK-NNN entry to docs/10-hacks-ledger.md for a deliberate NT-absent addition (a new device or new process at the outside of the boundary). Use when introducing something NT does not have, per Constitution Article 2.
disable-model-invocation: true
---

# log-hack

Record a deliberate NT-absent addition in `docs/10-hacks-ledger.md`. Per Article 2, such a thing may exist **only as a new device or new process at the outside of the boundary** — never inside existing `Nt*` or Wine PE code. The ledger's length is a tracked metric, so add an entry only for a genuine hack.

`$ARGUMENTS` may describe the hack (name / what it is). If details are missing, ask.

## Steps

1. Read `docs/10-hacks-ledger.md`. Note the format block and the highest existing `HACK-NNN`. The new number is that + 1 (zero-padded to 3 digits).
2. First confirm it actually *is* a hack, not a mislabeled one. It is **not** a hack (do not add an entry) if it is a real NT mechanism (WOW64, conhost/condrv, smss-equivalent, section objects/APCs/handles, shared-section transport) or an Article-3 simplification (no COW, one lock, etc.) — those go in `docs/03-nt-deviations.md`, not here. If it's one of these, say so and stop.
3. Verify it lives only in **new files at the outside of the boundary**. If it mutates existing `Nt*`/kernel/Wine code, it violates Article 2 — flag that and stop.
4. Append an entry in the exact ledger format:

   ```
   ## HACK-NNN: <name>
   Status:     proposed
   Introduced: <milestone, e.g. GUI-1>
   Not in NT:  <what NT does instead>
   Reason:     <why we add it anyway>
   Scope:      <new files touched — must be at the boundary's outside>
   Retirement: <concrete condition under which this entry is deleted>
   ```

   Every field is required. `Retirement` must be a concrete world-state (e.g. "if an NtGdi-side display-driver abstraction is ever built"), not "someday".
5. Show the appended entry and remind the user the scope files must be subtractable without touching the core (Article 7).
