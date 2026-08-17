#!/usr/bin/env python3
"""tools/blocking_frontier.py - compute the kernel's blocking frontier.

Issue #96 A, the static half. "Which code can park?" is a call-graph
reachability query, not a judgement call: docs/20 sec.10.1 records that CUI-8's
census drew the frontier at fs/ and never asked Ob, so nobody noticed that
IopCloseFileObject -> FatVfsCleanup -> FatAcquireVolumeGate makes NtClose a
blocking point. This prints that path.

The runtime half is KI_MAY_BLOCK() (kernel/ke/ke.h): this catches design
drift at review time, that catches it under any test that hits the path.

Method. A C parser is not needed and not wanted here - what is wanted is an
OVER-approximation, because a missed edge is a missed hazard. So:

  * comments and string literals are stripped, then top-level function
    definitions are found by brace matching;
  * every identifier followed by '(' inside a body is a call edge (keywords
    and the function's own declarations excluded);
  * indirect calls are resolved by MEMBER NAME: '.Cleanup = FatVfsCleanup' in
    any initializer registers FatVfsCleanup under 'Cleanup', and any
    '->Cleanup(' / '.Cleanup(' call gets an edge to every function so
    registered. That is what reaches through IO_VFS_OPS and Ob's
    closeProcedure/deleteProcedure, which is exactly where the frontier
    actually was.

Over-approximation costs false positives, never false negatives, and the
baseline file below makes them a one-time acknowledgement rather than noise.

Usage:
    tools/blocking_frontier.py --report          human-readable frontier
    tools/blocking_frontier.py --path NtClose    shortest path to a park
    tools/blocking_frontier.py --check           baseline drift + the
                                                 must-not-block list (CI)
"""

import argparse
import collections
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that make up the kernel proper. tests/ and user/ are outside the
# question: a test that blocks is doing its job.
SOURCE_DIRS = ("kernel", "fs", "drivers", "arch")

# The seeds: a call that reaches one of these can park the caller. KiCommitWait
# is THE park (kernel/ke/wait.c) and KiSwapToNext THE context switch
# (kernel/ke/sched.c); everything else here is a leaf the parser cannot see
# through (asm) or an intentional restatement for readable paths.
BLOCKING_SEEDS = (
    "KiCommitWait",
    "KiSwapToNext",
    "KiSwapContext",
)

# Functions that must NEVER be able to park, with the reason. The runtime
# mirror is KiEnterNoBlockRegion()/KI_MAY_BLOCK() (docs/20 R2 generalized):
# these are the regions that raise noBlockDepth, so a violation is both a
# build-time error here and a fatal assert there.
MUST_NOT_BLOCK = {
    "IoDrainDeviceCompletions": "docs/20 R2: the drain harvests and wakes, nothing else",
    "VioBlkDrain": "docs/20 R2: drain context, reachable from the timer tick",
    "VioSndDrain": "docs/20 R2: drain context, reachable from the timer tick",
    "VioNetDrain": "docs/20 R2: drain context, reachable from the timer tick (Net-1)",
    "KiUpdateClock": "interrupt context: the tick readies threads, never switches",
    "KiDispatchInterrupt": "interrupt context",
    "KiVerifyKernelStateIdle": "the idle consistency sweep runs with the lock held",
    "KiPanic": "the panic path is the debugger (Art. 9); it must not depend on scheduling",
    "KiAssertFail": "same as KiPanic",
}

# Entry points whose ability to park is acknowledged. Generated with
# --write-baseline; a diff that adds a row must add it deliberately, which is
# the whole point (the CUI-8 census would have had to write NtClose down).
BASELINE = os.path.join(ROOT, "tools", "blocking_frontier.txt")

# An "entry point" for the report: something reached from ring 3 or from
# another department, as opposed to an internal helper. Prefix-based, which is
# exactly what the NT department naming (docs/15) is for.
ENTRY_PREFIXES = ("Nt", "Zw")

C_KEYWORDS = {
    "if", "while", "for", "switch", "return", "sizeof", "do", "else", "case",
    "defined", "typedef", "struct", "union", "enum", "static", "const",
    "volatile", "unsigned", "signed", "void", "char", "int", "long", "short",
    "float", "double", "inline", "extern", "goto", "break", "continue",
    "_Static_assert", "static_assert", "offsetof", "__asm__", "asm",
    "__attribute__", "__builtin_offsetof", "alignas", "_Alignof",
}


def strip_comments(text):
    """Replace comments and string/char literal bodies with blanks, keeping
    offsets (and newlines) intact so brace matching stays honest."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in "\"'":
            quote = c
            j = i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


DEFINITION = re.compile(
    r"(?<![\w.>])([A-Za-z_]\w*)\s*\([^;{}()]*(?:\([^()]*\)[^;{}()]*)*\)\s*"
    r"(?:__attribute__\s*\(\(.*?\)\)\s*)*\{",
    re.DOTALL,
)
CALL = re.compile(r"(?<![\w.>])([A-Za-z_]\w*)\s*\(")
INDIRECT_CALL = re.compile(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*\(")
MEMBER_INIT = re.compile(r"\.\s*([A-Za-z_]\w*)\s*=\s*&?\s*([A-Za-z_]\w*)\s*[,;}]")
MEMBER_STORE = re.compile(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*=\s*&?\s*([A-Za-z_]\w*)\s*;")


def match_brace(text, open_index):
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def source_files():
    for directory in SOURCE_DIRS:
        for base, _dirs, names in os.walk(os.path.join(ROOT, directory)):
            for name in sorted(names):
                if name.endswith((".c", ".h")):
                    yield os.path.join(base, name)


class Graph:
    def __init__(self):
        self.calls = collections.defaultdict(set)   # caller -> callees
        self.callers = collections.defaultdict(set)  # callee -> callers
        self.where = {}                              # function -> file:line
        self.members = collections.defaultdict(set)  # member name -> functions
        self.member_calls = collections.defaultdict(set)  # caller -> members

    def add(self, caller, callee):
        self.calls[caller].add(callee)
        self.callers[callee].add(caller)


def build_graph():
    graph = Graph()
    bodies = []
    for path in source_files():
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = strip_comments(handle.read())
        relative = os.path.relpath(path, ROOT)

        # Function-pointer members, file-wide: designated initializers
        # (IO_VFS_OPS tables, OBJECT_TYPE_INITIALIZER) and plain stores.
        for pattern in (MEMBER_INIT, MEMBER_STORE):
            for member, target in pattern.findall(text):
                if target not in C_KEYWORDS:
                    graph.members[member].add(target)

        index = 0
        while True:
            match = DEFINITION.search(text, index)
            if match is None:
                break
            open_index = match.end() - 1
            close_index = match_brace(text, open_index)
            name = match.group(1)
            if name not in C_KEYWORDS:
                line = text.count("\n", 0, match.start(1)) + 1
                graph.where.setdefault(name, "%s:%d" % (relative, line))
                bodies.append((name, text[open_index + 1:close_index]))
            index = close_index + 1

    for name, body in bodies:
        for callee in CALL.findall(body):
            if callee != name and callee not in C_KEYWORDS:
                graph.add(name, callee)
        for member in INDIRECT_CALL.findall(body):
            graph.member_calls[name].add(member)

    # Resolve indirect calls by member name (see the module docstring).
    for caller, members in graph.member_calls.items():
        for member in members:
            for target in graph.members.get(member, ()):
                graph.add(caller, target)
    return graph


def blocking_set(graph):
    """Every function that can transitively reach a park, with the parent that
    put it there (so a path can be printed)."""
    parent = {}
    queue = collections.deque()
    for seed in BLOCKING_SEEDS:
        if seed not in parent:
            parent[seed] = None
            queue.append(seed)
    while queue:
        callee = queue.popleft()
        for caller in graph.callers.get(callee, ()):
            if caller not in parent:
                parent[caller] = callee
                queue.append(caller)
    return parent


def path_to_park(parent, name):
    if name not in parent:
        return None
    path = [name]
    while parent[path[-1]] is not None:
        path.append(parent[path[-1]])
    return path


def format_path(graph, path):
    return " -> ".join("%s [%s]" % (f, graph.where.get(f, "?")) for f in path)


def entry_frontier(parent):
    return sorted(f for f in parent if f.startswith(ENTRY_PREFIXES))


def read_baseline():
    if not os.path.exists(BASELINE):
        return None
    with open(BASELINE, "r", encoding="utf-8") as handle:
        return [
            line.strip()
            for line in handle
            if line.strip() and not line.startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="print the frontier")
    parser.add_argument("--path", metavar="FUNCTION", help="shortest path to a park")
    parser.add_argument("--check", action="store_true", help="baseline + must-not-block")
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()
    if not (args.report or args.path or args.check or args.write_baseline):
        args.report = True

    graph = build_graph()
    parent = blocking_set(graph)

    if args.path:
        path = path_to_park(parent, args.path)
        if path is None:
            print("%s cannot park" % args.path)
            return 0
        print(format_path(graph, path))
        return 0

    if args.write_baseline:
        with open(BASELINE, "w", encoding="utf-8") as handle:
            handle.write(
                "# Generated by tools/blocking_frontier.py --write-baseline.\n"
                "# Every ring-3 entry point that can park the calling thread\n"
                "# (issue #96 A). A diff that adds a row here is widening the\n"
                "# blocking frontier: say so, and re-check docs/20's tables\n"
                "# (sec.8.4 - a new blocking point re-opens every STILL-TRUE row).\n"
            )
            for name in entry_frontier(parent):
                handle.write("%s\n" % name)
        print("wrote %s (%d entry points)" % (BASELINE, len(entry_frontier(parent))))
        return 0

    failures = 0

    if args.report:
        frontier = entry_frontier(parent)
        print("== blocking frontier: %d of %d ring-3 entry points can park ==" %
              (len(frontier), sum(1 for f in graph.where if f.startswith(ENTRY_PREFIXES))))
        # Grouped by the first hop out of the entry point, because that is the
        # finding: it is not that 164 services each block for their own
        # reason, it is that a handful of shared verbs (dropping an object
        # reference, closing a handle) reach the volume gate.
        groups = collections.defaultdict(list)
        for name in frontier:
            groups[path_to_park(parent, name)[1]].append(name)
        for hop in sorted(groups, key=lambda h: (-len(groups[h]), h)):
            path = path_to_park(parent, hop)
            print("\n  via %s [%s]  (%d entry points)" %
                  (hop, graph.where.get(hop, "?"), len(groups[hop])))
            print("      %s" % " -> ".join(path))
            for chunk in range(0, len(groups[hop]), 3):
                print("      %s" % "  ".join("%-32s" % n for n in groups[hop][chunk:chunk + 3]))
        print("\n== reachable-to-park functions: %d ==" % len(parent))

    if args.check:
        for name, reason in sorted(MUST_NOT_BLOCK.items()):
            if name in parent and name not in BLOCKING_SEEDS:
                path = path_to_park(parent, name)
                print("FAIL: %s must not block (%s)" % (name, reason))
                print("      %s" % format_path(graph, path))
                failures += 1
        baseline = read_baseline()
        if baseline is None:
            print("FAIL: %s missing (run --write-baseline)" % BASELINE)
            failures += 1
        else:
            frontier = entry_frontier(parent)
            for name in sorted(set(frontier) - set(baseline)):
                path = path_to_park(parent, name)
                print("FAIL: %s can now park and is not in the baseline" % name)
                print("      %s" % format_path(graph, path))
                failures += 1
            for name in sorted(set(baseline) - set(frontier)):
                print("FAIL: %s no longer parks; drop it from the baseline" % name)
                failures += 1
        print("== blocking-frontier check: %d failing ==" % failures)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
