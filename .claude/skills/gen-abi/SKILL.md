---
name: gen-abi
description: Regenerate the abi/ numeric constants (NTSTATUS, info-class numbers, struct offsets, flags) from Wine headers via tools/gen_abi.py, per Constitution Article 4. Use when abi/ values need (re)generating, or when a static_assert offset check fails.
disable-model-invocation: true
---

# gen-abi

Regenerate `abi/` from Wine headers. Article 4: **no hand-typed or model-recalled constants** — every numeric value in `abi/` comes from this generator, and struct layouts carry `static_assert(offsetof(...) == ...)`.

`$ARGUMENTS` may name a specific header/target to regenerate; otherwise regenerate all.

## Steps

1. Check the generator exists: `ls tools/gen_abi.py`.
   - **If it does not exist yet** (pre-M1 / not built): do **not** hand-write constants as a workaround — that violates G4. Tell the user the generator is missing and offer to help design/implement `tools/gen_abi.py` (it should read the Wine submodule headers and emit `abi/*.h` with generated values + offset `static_assert`s). Stop.
2. Confirm the Wine submodule is present and checked out (headers are the source of truth): `git submodule status`.
3. Run the generator, e.g. `python3 tools/gen_abi.py` (pass `$ARGUMENTS` through if given). Show its output.
4. Review the diff to `abi/` (`git diff abi/`): values should change only where Wine headers changed. Flag any suspicious hand-looking edits.
5. Build to let the `static_assert(offsetof(...) == ...)` checks run; a mismatch is a real ABI drift, not something to silence. Report pass/fail.

Never substitute values from memory or from ReactOS/leaked source if the tool fails — fix the tool or the Wine headers instead.
