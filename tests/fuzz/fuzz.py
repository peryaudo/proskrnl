#!/usr/bin/env python3
"""fuzz.py - the proskrnl differential fuzzer driver (docs/08; tests/fuzz/).

Generate random Nt* call-sequence programs from the generated op model
(tests/fuzz/gen/fuzz_model.py), build the one interpreter (tests/fuzz/interp.c)
as ONE CRT-less PE .exe (the single-binary ntapi shape, docs/14), run the SAME
binary on each side, and diff the normalized [FUZZ] traces:

    generate programs (seed) -> blob -> fuzz_interp.exe
      +- oracle  : run under the pinned third_party/wine     -> [FUZZ] trace
      +- proskrnl: baked at C:\ntapi\interp.exe, swept by the
                   kernel's ntapi runner under QEMU           -> [FUZZ] trace
    difference (minus the known-divergence baseline) == bug

On a divergence the offending program is minimized by greedy call removal and a
re-runnable repro is written under build/tests/fuzz/repro/ (docs/09 Art. 6: the
permanent tests/ntapi/ regression a human then curates from it is the
conviction; this tool names the suspect and hands over a shrunk reproducer).

Usage:
    tests/run/run.sh fuzz [options]      (preferred entry point)
    tests/fuzz/fuzz.py   [options]

Options:
    --seed N          base seed (default 1)
    --programs N      programs per batch (default 64)
    --calls N         max calls per program (default 32)
    --allow-avoid     include choices normally skipped as known docs/03
                      deviations (used to self-test the detection path)
    --self-check      run the SAME blob through the oracle twice and diff; a
                      difference means the trace still leaks a non-canonical
                      value (e.g. a raw handle). No proskrnl build.
    --oracle-only     build+run the oracle side only (spec smoke; no QEMU)
    --replay FILE     re-run a saved repro blob (build both sides, diff)
    --no-minimize     report the first divergence without shrinking it
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FUZZ = os.path.join(ROOT, "tests", "fuzz")
NTAPI = os.path.join(ROOT, "tests", "ntapi")
BUILD = os.path.join(ROOT, "build", "tests", "fuzz")

sys.path.insert(0, os.path.join(FUZZ, "gen"))
import fuzz_model as M  # noqa: E402  (generated; regenerate with `make gen-abi`)

import random  # noqa: E402


# --- model helpers -------------------------------------------------------

NAME_COUNT = len(M.NAME_TAGS)

# Object-name generation policy, by level. proskrnl and Wine agree on the
# dispatcher-object + handle-table + wait/query core, but proskrnl still maps
# malformed / nested / colliding namespace paths to different *error statuses*
# than Wine (OBJECT_NAME_INVALID vs INVALID_PARAMETER vs PATH_SYNTAX_BAD vs
# PATH_NOT_FOUND vs ACCESS_DENIED). Wine is the operative oracle (docs/09
# Art. 6), so each of those is a proskrnl bug to fix — the backlog is just
# larger than one change. The DEFAULT policy is anonymous objects only: a
# clean, converging green gate today. --names named adds valid names;
# --names malformed adds the deliberately-bad ones. Both wider levels
# enumerate the bugs still to fix (see README "Scope").
_NAME_WEIGHTS_BY_LEVEL = {
    "anon": {"none": 1},  # everything else 0
    "named": {"none": 3, "valid": 8, "subdir": 3, "subitem": 4},
    "malformed": {"none": 3, "valid": 8, "subdir": 3, "subitem": 4,
                  "bad": 2, "root": 1, "basedir": 1},
}

NAME_WEIGHTS = [_NAME_WEIGHTS_BY_LEVEL["anon"].get(tag, 0) for _i, tag in M.NAME_TAGS]


def set_name_policy(level):
    global NAME_WEIGHTS
    w = _NAME_WEIGHTS_BY_LEVEL[level]
    NAME_WEIGHTS = [w.get(tag, 0) for _i, tag in M.NAME_TAGS]

# op name -> kinds, keyed for slot-liveness bookkeeping during generation.
OP_BY_INDEX = {opcode: (name, nt, kinds) for name, opcode, nt, kinds in M.OPS}


def _pick_choice(rng, table, allow_avoid):
    count, avoid = M.CHOICES[table]
    while True:
        j = rng.randrange(count)
        if allow_avoid or j not in avoid:
            return j


def gen_operand(rng, kind, live, allow_avoid):
    """Return one operand byte (== the logical index; interp mods by count)."""
    if kind in ("slot_in", "slot_out"):
        if kind == "slot_in" and live and rng.random() < 0.8:
            return rng.choice(sorted(live))
        return rng.randrange(M.SLOT_COUNT)
    if kind == "name":
        return rng.choices(range(NAME_COUNT), weights=NAME_WEIGHTS, k=1)[0]
    if kind == "fname":
        return rng.randrange(len(M.FNAME_TAGS))
    if kind == "kname":
        return rng.randrange(len(M.KNAME_TAGS))
    assert kind.startswith("ch_"), kind
    return _pick_choice(rng, kind[3:], allow_avoid)


def gen_call(rng, live, allow_avoid):
    name, opcode, nt, kinds = rng.choice(M.OPS)
    operands = []
    out_slots = []
    for k in kinds:
        b = gen_operand(rng, k, live, allow_avoid)
        operands.append(b)
        if k == "slot_out":
            out_slots.append(b)
    for s in out_slots:
        live.add(s)  # approximate: assume the create/open populated the slot
    return (opcode, operands)


def gen_program(rng, max_calls, allow_avoid):
    live = set()
    n = rng.randint(1, max_calls)
    return [gen_call(rng, live, allow_avoid) for _ in range(n)]


def gen_batch(seed, programs, max_calls, allow_avoid):
    """Return a list of (id, calls). id doubles as the per-program sub-seed."""
    batch = []
    for i in range(programs):
        pid = seed * 100000 + i
        rng = random.Random(pid)
        batch.append((pid, gen_program(rng, max_calls, allow_avoid)))
    return batch


# --- blob encode ---------------------------------------------------------

def _u16(v):
    return bytes((v & 0xFF, (v >> 8) & 0xFF))


def _u32(v):
    return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF))


def encode(batch):
    out = bytearray(b"PFZ1")
    out += _u32(len(batch))
    for pid, calls in batch:
        out += _u32(pid & 0xFFFFFFFF)
        out += _u16(len(calls))
        for opcode, operands in calls:
            out.append(opcode & 0xFF)
            out += bytes(b & 0xFF for b in operands)
    return bytes(out)


def write_blob_c(blob, path):
    body = ", ".join(str(b) for b in blob)
    text = (
        "/* GENERATED by tests/fuzz/fuzz.py - the differential-fuzzer program blob. */\n"
        "const unsigned char fuzz_programs[] = { " + body + " };\n"
        "const unsigned int fuzz_programs_len = " + str(len(blob)) + ";\n"
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


# --- build + run both sides ----------------------------------------------

CFLAGS_COMMON = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-I" + ROOT, "-I" + NTAPI]


def find_wine():
    for w in (os.path.join(ROOT, "third_party", "wine", "wine64"),
              os.path.join(ROOT, "third_party", "wine", "wine")):
        if os.access(w, os.X_OK):
            return w
    return os.environ.get("WINE", "wine")


WINE_PE = os.path.join(ROOT, "third_party", "wine", "dlls")
WINE_LIBS = [os.path.join(WINE_PE, "kernel32", "x86_64-windows", "libkernel32.a"),
             os.path.join(WINE_PE, "kernelbase", "x86_64-windows", "libkernelbase.a"),
             os.path.join(WINE_PE, "ntdll", "x86_64-windows", "libntdll.a")]


def build_interp(blob_c):
    """One .exe for BOTH sides: the single-binary ntapi build (docs/14) —
    CRT-less, entry ntapi_start, linked against the pinned Wine import
    libs."""
    cc = os.environ.get("CC_ORACLE", "x86_64-w64-mingw32-gcc")
    exe = os.path.join(BUILD, "fuzz_interp.exe")
    cmd = ([cc] + CFLAGS_COMMON +
           ["-ffreestanding", "-fno-builtin", "-nostdlib", "-nostartfiles",
            "-Wl,--entry=ntapi_start",
            os.path.join(FUZZ, "interp.c"), os.path.join(NTAPI, "ntapi.c"), blob_c]
           + WINE_LIBS + ["-lgcc", "-o", exe])
    subprocess.run(cmd, check=True)
    return exe


def run_oracle(exe):
    wine = find_wine()
    env = dict(os.environ, WINEDEBUG="-all")
    out = subprocess.run([wine, exe], capture_output=True, text=True, env=env).stdout
    return out.replace("\r", "")


def build_proskrnl(exe):
    """Bake the SAME interp .exe under C:\\ntapi beside the Wine PE userland;
    the kernel's ntapi runner (kernel/init/main.c) sweeps and runs it."""
    kernel = os.path.join(ROOT, "build", "proskrnl")
    img = os.path.join(BUILD, "fuzz.hdd")
    os.makedirs(BUILD, exist_ok=True)

    if not os.path.exists(kernel):
        subprocess.run(["make", "-C", ROOT], check=True, stdout=subprocess.DEVNULL)

    # Seed the RAM disk with the same files the kernel's own kmt M5 suite reads,
    # so the kernel reaches C:\ntapi instead of failing before it.
    specs = []
    for seed in (os.path.join(ROOT, "build", "modules", "pe_smoke.exe"),
                 os.path.join(ROOT, "build", "modules", "sample.dat")):
        if os.path.exists(seed):
            specs.append(seed + "=initrd")
    # The Wine PE userland the interp runs on, plus the NLS data files (the
    # NtInitializeNlsFiles/NtGetNlsSectionPtr ops see the same pinned-Wine
    # tables on both sides).
    for dll in ("ntdll", "kernel32", "kernelbase"):
        specs.append("win:" + os.path.join(WINE_PE, dll, "x86_64-windows", dll + ".dll")
                     + "=windows/system32/" + dll + ".dll")
    for nls in ("locale", "l_intl", "c_1252", "c_437", "sortdefault",
                "normnfc", "normnfd", "normnfkc", "normnfkd", "normidna"):
        path = os.path.join(ROOT, "third_party", "wine", "nls", nls + ".nls")
        if os.path.exists(path):
            specs.append("win:" + path + "=windows/system32/" + nls + ".nls")
    # The session manager: it sweeps C:\ntapi and is what spawns the interp
    # (user/smss/session.c — the kernel itself launches only smss.exe).
    specs.append("win:" + os.path.join(ROOT, "build", "modules", "smss.exe")
                 + "=windows/system32/smss.exe")
    specs.append("win:" + exe + "=ntapi/interp.exe")
    subprocess.run([os.path.join(ROOT, "tools", "mkimage.sh"), kernel, img] + specs,
                   check=True, stdout=subprocess.DEVNULL)
    return img


def run_proskrnl(img):
    log = os.path.join(BUILD, "fuzz-serial.log")
    # The M8 registry ops make mutating calls genuinely slow on proskrnl (every
    # NtSetValueKey/NtCreateKey rewrites the whole hive file — immediate
    # writeback, Art. 3), so the default batch needs minutes, not seconds. A
    # truncated serial log reads as en-masse "proskrnl=none" divergences.
    # GUEST_LEG=ntapi is what makes the session manager SWEEP C:\ntapi at all:
    # which leg a boot runs is a QEMU command-line flag (tools/qemu.sh,
    # HACK-006), not the presence of a directory. Without it this boot runs the
    # plain suite, the interp never starts, and every op reads "proskrnl=none"
    # — a whole batch of fabricated divergences. GUEST_GUI=0 keeps the console
    # on the serial transport this log is read off.
    env = dict(os.environ, LOG=log, PASS_RE=r"\[FUZZ\] batch end",
               GUEST_GUI="0", GUEST_LEG="ntapi",
               TIMEOUT=os.environ.get("TIMEOUT", "420"))
    subprocess.run([os.path.join(ROOT, "tools", "qemu.sh"), img], env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(log) as f:
        return f.read().replace("\r", "")


def _which(prog):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(d, prog)
        if os.access(cand, os.X_OK):
            return cand
    raise FileNotFoundError(prog)


# --- trace extraction, baseline, diff ------------------------------------

def extract(text):
    return [ln for ln in text.splitlines() if ln.startswith("[FUZZ] ")]


def _status_of(line):
    if line is None:
        return "none"
    m = re.search(r"st=(\w+)", line)
    return m.group(1) if m else "?"


def load_baseline():
    """Known-divergence baseline (tests/fuzz/known_divergences.txt): the set of
    root-divergence signatures (NtName, oracle_status, proskrnl_status) that are
    already documented as bugs still to fix (Wine is the operative oracle,
    docs/09 Art. 6 — a divergence from Wine is a proskrnl bug by definition).
    The fuzzer ignores these and fails only on a NEW signature — so it is a
    green regression gate whose baseline is a visible, cited backlog, not a
    silence. File format, one per line:
        <NtName> oracle=<hexstatus> proskrnl=<hexstatus>   # citation
    """
    path = os.path.join(FUZZ, "known_divergences.txt")
    sigs = set()
    if not os.path.exists(path):
        return sigs
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"(\w+)\s+oracle=(\w+)\s+proskrnl=(\w+)", line)
            if m:
                sigs.add((m.group(1), m.group(2), m.group(3)))
    return sigs


def root_divergences(oracle, prosk):
    """Per program, the FIRST differing call line (the root; everything after it
    in that program is cascade from divergent state). Returns a list of dicts
    with prog id, signature, both lines, and oracle-side context."""
    def parse(lines):
        by_pc, ctx = {}, {}
        for ln in lines:
            m = re.match(r"\[FUZZ\] p(\d+) c(\d+) (\w+)", ln)
            if m:
                by_pc[(int(m.group(1)), int(m.group(2)))] = (m.group(3), ln)
        return by_pc

    od, pd = parse(oracle), parse(prosk)
    progs = {}
    for (p, c) in set(od) | set(pd):
        progs.setdefault(p, set()).add(c)

    found = []
    for p in sorted(progs):
        for c in sorted(progs[p]):
            oline = od.get((p, c), (None, None))[1]
            pline = pd.get((p, c), (None, None))[1]
            if oline != pline:
                nt = (od.get((p, c)) or pd.get((p, c)))[0]
                found.append({
                    "prog": p, "call": c,
                    "sig": (nt, _status_of(oline), _status_of(pline)),
                    "oracle": oline, "proskrnl": pline,
                })
                break
    return found


# --- top-level actions ---------------------------------------------------

def build_and_trace(batch, oracle_only=False):
    blob_c = os.path.join(BUILD, "fuzz_programs.c")
    write_blob_c(encode(batch), blob_c)
    exe = build_interp(blob_c)
    oracle = extract(run_oracle(exe))
    if oracle_only:
        return oracle, None
    prosk = extract(run_proskrnl(build_proskrnl(exe)))
    return oracle, prosk


def report(oracle, prosk, baseline):
    """Print a divergence summary and return the list of NEW (non-baseline)
    root divergences. Empty list == the gate is green."""
    divs = root_divergences(oracle, prosk)
    known = [d for d in divs if d["sig"] in baseline]
    new = [d for d in divs if d["sig"] not in baseline]

    if known:
        counts = {}
        for d in known:
            counts[d["sig"]] = counts.get(d["sig"], 0) + 1
        print("\n-- known divergences hit (baselined; see known_divergences.txt) --")
        for sig, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print("   %-28s oracle=%s proskrnl=%s   x%d" % (sig[0], sig[1], sig[2], n))

    for d in new:
        print("\n!! NEW DIVERGENCE  program p%d call c%d:" % (d["prog"], d["call"]))
        print("   signature: %s oracle=%s proskrnl=%s" % d["sig"])
        print("   oracle  : " + (d["oracle"] or "(no line — proskrnl produced one)"))
        print("   proskrnl: " + (d["proskrnl"] or "(no line — oracle produced one)"))
    return new


def single_program_sig(pid, calls):
    """Root-divergence signature of one program (None if it agrees)."""
    o, p = build_and_trace([(pid, calls)])
    divs = root_divergences(o, p)
    return divs[0]["sig"] if divs else None


def minimize(pid, calls, target_sig):
    """Greedy call-removal shrink that preserves the NEW divergence signature."""
    print("\n== minimizing p%d (id=%d, %d calls) to signature %s ==" %
          (pid, pid, len(calls), target_sig))
    i, probes = 0, 0
    while i < len(calls):
        trial = calls[:i] + calls[i + 1:]
        if not trial:
            break
        probes += 1
        if single_program_sig(pid, trial) == target_sig:
            calls = trial
            print("   dropped call %d, %d remain" % (i, len(calls)))
        else:
            i += 1
    print("== minimized to %d calls after %d probes ==" % (len(calls), probes))
    return calls


def emit_repro(pid, calls, sig):
    repro_dir = os.path.join(BUILD, "repro")
    os.makedirs(repro_dir, exist_ok=True)
    blob = encode([(pid, calls)])
    blob_path = os.path.join(repro_dir, "fuzz_%d.blob" % pid)
    with open(blob_path, "wb") as f:
        f.write(blob)
    listing = os.path.join(repro_dir, "fuzz_%d.txt" % pid)
    with open(listing, "w") as f:
        f.write("# minimized NEW divergent program id=%d (%d calls)\n" % (pid, len(calls)))
        f.write("# signature: %s oracle=%s proskrnl=%s\n" % sig)
        f.write("# re-run: tests/run/run.sh fuzz --replay %s\n\n" % blob_path)
        for ci, (opcode, operands) in enumerate(calls):
            _name, nt, kinds = OP_BY_INDEX[opcode]
            f.write("c%d %-26s %s\n" % (ci, nt, list(zip(kinds, operands))))
    print("\nRepro written:\n  %s\n  %s" % (blob_path, listing))
    print("Disposition (docs/09 Art. 6, Wine is the operative oracle — this is a\n"
          "proskrnl bug): pin the Wine behaviour with a tests/ntapi/ case, fix the\n"
          "kernel; only if it cannot be fixed now, add the signature to\n"
          "known_divergences.txt with a note so it stays a visible debt.")


def decode_blob(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"PFZ1", "bad magic"
    n = int.from_bytes(data[4:8], "little")
    pos = 8
    batch = []
    for _ in range(n):
        pid = int.from_bytes(data[pos:pos + 4], "little")
        cc = int.from_bytes(data[pos + 4:pos + 6], "little")
        pos += 6
        calls = []
        for _c in range(cc):
            opcode = data[pos]
            pos += 1
            _name, _nt, kinds = OP_BY_INDEX[opcode]
            operands = list(data[pos:pos + len(kinds)])
            pos += len(kinds)
            calls.append((opcode, operands))
        batch.append((pid, calls))
    return batch


def main():
    ap = argparse.ArgumentParser(description="proskrnl differential fuzzer")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--programs", type=int, default=64)
    ap.add_argument("--calls", type=int, default=32)
    ap.add_argument("--allow-avoid", action="store_true")
    ap.add_argument("--names", choices=("anon", "named", "malformed"), default="anon",
                    help="object-name space: anon (default, the clean green gate); named "
                         "(valid names); malformed (adds bad names). named/malformed enumerate "
                         "the error-status bugs still to fix (see README)")
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--oracle-only", action="store_true")
    ap.add_argument("--replay")
    ap.add_argument("--no-minimize", action="store_true")
    args = ap.parse_args()
    os.makedirs(BUILD, exist_ok=True)
    set_name_policy(args.names)
    baseline = load_baseline()

    if args.replay:
        batch = decode_blob(args.replay)
        oracle, prosk = build_and_trace(batch)
        new = report(oracle, prosk, baseline)
        return 1 if new else 0

    batch = gen_batch(args.seed, args.programs, args.calls, args.allow_avoid)

    if args.self_check:
        # Same blob, oracle twice: any difference is a non-canonical trace leak.
        blob_c = os.path.join(BUILD, "fuzz_programs.c")
        write_blob_c(encode(batch), blob_c)
        exe = build_interp(blob_c)
        a = extract(run_oracle(exe))
        b = extract(run_oracle(exe))
        divs = root_divergences(a, b)
        if not divs:
            print("== self-check: oracle trace is deterministic and canonical (%d lines) ==" % len(a))
            return 0
        print("!! self-check FAILED (trace leaks a non-canonical value):")
        for d in divs[:5]:
            print("   p%d c%d: %s  vs  %s" % (d["prog"], d["call"], d["oracle"], d["proskrnl"]))
        return 1

    oracle, prosk = build_and_trace(batch, oracle_only=args.oracle_only)
    if args.oracle_only:
        print("== oracle-only: %d [FUZZ] lines, no divergence check ==" % len(oracle))
        return 0

    new = report(oracle, prosk, baseline)
    print("\n== fuzz: %d programs, names=%s, %d oracle / %d proskrnl lines, %d NEW divergence(s) ==" %
          (args.programs, args.names, len(oracle), len(prosk), len(new)))
    if not new:
        return 0

    if not args.no_minimize:
        d = new[0]
        pid = batch[d["prog"]][0]
        calls = minimize(pid, batch[d["prog"]][1], d["sig"])
        emit_repro(pid, calls, d["sig"])
    return 1


if __name__ == "__main__":
    sys.exit(main())
