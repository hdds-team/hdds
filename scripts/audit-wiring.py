#!/usr/bin/env python3
"""Is every source file in the build graph, and is every test registered?

Two reachability questions the rest of the audit cannot answer, because both
are about what the COMPILER was given rather than about what the code says.

  1. ORPHANS.  A `.rs` file no `mod` statement names is compiled in no
     configuration.  `cargo build`, `cargo test` and clippy are all silent
     about it: it is not dead code, it is absent code that looks present.
     The oracle is cargo's own dep-info (`target/**/*.d`), the list of files
     rustc actually opened - not a parse of `mod` statements, which would have
     to re-implement `#[path]`, `#[cfg]`, `include!` and macro-declared
     modules, and would eventually lie.

  2. GHOST TESTS.  A `#[test]` the harness never registers.  Usually a
     consequence of (1); when it is not, it is a test behind a cfg no gate
     compiles - which is its own finding, because a gate that runs one feature
     set never runs the tests written for the other.

THE ALLOWLIST POLICES ITSELF.  An exemption must name the cfg that would put
the file in the build graph.  If that cfg later appears in dep-info, the
exemption is stale and this fails: the entry cannot rot into a blanket
suppression.  Entries are printed on every run, so the list is visible rather
than forgotten, and a file that is neither compiled nor explained is a GAP,
counted and shown, never silently passed.

HOW THE ORACLE IS BUILT, AND WHY
--------------------------------
The check has to be cheap enough for a pre-commit hook, so it avoids three
expensive habits:

  * `glob("target/**/*.d", recursive=True)` descends into `incremental/` and
    `.fingerprint/`, which hold the overwhelming majority of the directory
    entries under `target/` and no `.d` file. Every dep-info file lives under
    `<profile>/deps`, `<profile>/examples`, `<profile>/build/<pkg>` or
    `<profile>/` itself, so pruning the two barren trees is exhaustive, not
    approximate.
  * `os.path.realpath()` on every `.rs` token of every dep-info file is an
    `lstat` per path component, and most tokens name crates under
    `~/.cargo/registry` that this check can never care about. Tokens are
    filtered against the source root by string compare (no syscall) and only
    survivors are resolved.
  * READING the dep-info files is what actually costs, and concurrency does not
    rescue it (many small opens, slow on network filesystems). The answer is
    to open FEWER files, not to open them faster.

Only a small fraction of the dep-info files carry a path under
`crates/hdds/src` at all - the library, and every example and integration
test. Their names are the names of the examples (`shape_main`, `tsn_rtt`,
`basic_pubsub`, ...), so a filter keyed on the name would be a list that goes
stale the day somebody adds an example.

So the name is used as an ORDER, never as a filter.  `dep_info_paths()` yields
the units most likely to name our sources first and every other file after
them, and `find_in_dep_info()` stops as soon as every path it was asked about
has been found.  The search stays exhaustive - a file that is genuinely in no
build graph still costs a full sweep, which is right, because that answer
blocks a commit and must be certain - but the ordinary case, where the file IS
compiled, stops after a handful of opens.

`HDDS_AUDIT_CACHE` then lets a commit pay the directory walk once instead of
once per staged file, and remembers paths already PROVEN to be in the graph.
It can only ever turn into a faster YES: a path absent from it is searched for
exactly as if the cache were empty, so no answer can be manufactured by it.

The cache deliberately has no invalidation: its lifetime is one run of the
hook, during which the tree does not change.  It is a way of not asking the
same question twice in one second, never a way of remembering an answer.
"""
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# cargo's target directory: CARGO_TARGET_DIR when set (extrem-audit-scan.sh
# exports the resolved one), else target/ under ROOT. Reading a hard-coded
# target/ under an overridden CARGO_TARGET_DIR found no dep-info at all.
TARGET = os.path.abspath(os.environ.get("CARGO_TARGET_DIR") or os.path.join(ROOT, "target"))
SRC = os.path.join(ROOT, "crates", "hdds", "src")
ALLOW = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wiring-allowlist.json")

# Directories under target/ that cargo never writes a .d into: every dep-info
# file sits in deps/, examples/, build/<pkg>/ or the profile root. Pruning
# these is what turns a walk of every incremental fragment into a walk of a
# few hundred directories.
PRUNE_DIRS = {"incremental", ".fingerprint"}

# Where the hook parks the oracle so a commit pays for it once, not once per
# staged file. Unset outside the hook, in which case nothing is cached.
CACHE_DIR = os.environ.get("HDDS_AUDIT_CACHE") or ""


def dep_info_paths():
    """Every dep-info file under target/, likeliest first.

    "Likeliest" means a unit whose name starts with the crate's own - the
    library, its test binaries, its C shim. The examples and integration tests
    are searched right after, along with everything else. The order is a
    hint about where to look first and NEVER a restriction on where to look:
    the list returned is complete, so a wrong guess costs time and cannot cost
    correctness.
    """
    cached = _read_cache("dep-paths.txt")
    if cached is not None:
        likely, rest = [], []
        for path in cached:
            (likely if _likely(path) else rest).append(path)
        return sorted(likely) + sorted(rest)

    likely, rest = [], []
    for dirpath, dirnames, filenames in os.walk(TARGET):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        for name in filenames:
            if name.endswith(".d"):
                full = os.path.join(dirpath, name)
                (likely if _likely(full) else rest).append(full)
    out = sorted(likely) + sorted(rest)
    _write_cache("dep-paths.txt", out)
    return out


def _likely(path):
    """Does this dep-info file's name suggest a unit built from our sources?"""
    return os.path.basename(path).lstrip("l").startswith("hdds")


def _tokens_under_src(text, src_prefix):
    """The paths under the source root that this dep-info file names."""
    found = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue
        body = line.split(": ", 1)[1] if ": " in line else line
        for token in body.split():
            if not token.endswith(".rs"):
                continue
            # String test first: no syscall, and it discards every registry
            # crate before anything touches the disk.
            candidate = token if os.path.isabs(token) else os.path.join(ROOT, token)
            candidate = os.path.normpath(candidate)
            if candidate.startswith(src_prefix):
                found.add(os.path.realpath(candidate))
    return found


def find_in_dep_info(wanted):
    """Which of `wanted` does some dep-info file name? Stops when all are found.

    Returns the subset that is in the build graph. Reading every dep-info file
    costs minutes on this tree; reading until the question is answered usually
    costs a handful of opens.
    """
    src_prefix = os.path.realpath(SRC) + os.sep
    outstanding = set(wanted)

    # A sweep that ran to the end already built the whole oracle, so it answers
    # both ways. Caching a NEGATIVE is only sound because the cache lives for
    # one run of the hook, during which nothing recompiles: within that run,
    # "no dep-info names this path" cannot become false. Outside the hook there
    # is no cache and every call re-reads.
    full = _read_cache("dep-info-src.txt")
    if full is not None:
        return outstanding & full

    proven = _read_cache("dep-info-proven.txt") or set()
    found = outstanding & proven
    outstanding -= found
    if not outstanding:
        return found

    # A file that is NOT in the build graph costs a full sweep to establish it,
    # and a commit that adds files - the common case - would otherwise pay that
    # sweep once per added file. Reading to the end yields the complete oracle
    # for free, so keep it.
    everything = set()
    exhaustive = True
    for dep in dep_info_paths():
        try:
            with open(dep, errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        tokens = _tokens_under_src(text, src_prefix)
        everything |= tokens
        hit = tokens & outstanding
        if hit:
            found |= hit
            outstanding -= hit
            if not outstanding:
                exhaustive = False  # stopped early: `everything` is partial
                break
    if exhaustive:
        _write_cache("dep-info-src.txt", everything)
    elif found:
        _write_cache("dep-info-proven.txt", proven | found)
    return found


def _read_cache(name):
    if not CACHE_DIR:
        return None
    path = os.path.join(CACHE_DIR, name)
    try:
        with open(path) as fh:
            return set(line.rstrip("\n") for line in fh if line.strip())
    except OSError:
        return None


def _write_cache(name, values):
    if not CACHE_DIR:
        return
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(os.path.join(CACHE_DIR, name), "w") as fh:
            fh.write("\n".join(sorted(values)))
    except OSError:
        pass  # A cache that cannot be written is a cache that is not used.


def dep_info_files():
    """Every source path under SRC that rustc recorded, across every build.

    Only paths under the source root are kept. A dep-info file names every
    crate rustc opened, registry dependencies included; resolving those was
    the bulk of the work and none of the answer.
    """
    cached = _read_cache("dep-info-src.txt")
    if cached is not None:
        return cached

    src_prefix = os.path.realpath(SRC) + os.sep
    seen = set()
    for dep in dep_info_paths():
        try:
            with open(dep, errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        seen |= _tokens_under_src(text, src_prefix)
    _write_cache("dep-info-src.txt", seen)
    return seen


def _why_no_dep_info():
    """Say which input is missing, so a skip names its cause."""
    target = TARGET
    if os.path.islink(target) and not os.path.exists(target):
        return ("target/ points to %s, which does not exist (a tmpfs build "
                "dir is emptied at reboot) - build first"
                % os.readlink(target))
    return "no dep-info under target/ - build first"


def load_allowlist():
    if not os.path.exists(ALLOW):
        return {}
    with open(ALLOW) as fh:
        return {e["file"]: e for e in json.load(fh)["allow"]}


def main_one_file(targets):
    """Are THESE files in the build graph? The pre-commit scope.

    A tool with two modes has two scopes. Asking the whole-tree question from
    a per-file hook would fail every commit on orphans the author did not
    touch, and the first thing anybody does with a gate like that is bypass
    it. Per file, the question is worth asking at exactly the moment it is
    cheapest to answer: you just wrote a file, does any `mod` name it?

    Several paths are accepted in one call because the oracle is whole-tree
    whatever is asked of it: answering for one file and answering for thirteen
    cost the same, and the hook used to pay the difference thirteen times.
    """
    src_prefix = os.path.realpath(SRC) + os.sep
    inside = []
    for target in targets:
        real = os.path.realpath(target)
        if not real.startswith(src_prefix):
            print("  wiring: %s is outside crates/hdds/src, not checked"
                  % os.path.relpath(real, ROOT))
        elif not os.path.isfile(real):
            # Asking about a path that is not there would otherwise cost a full
            # sweep of every dep-info file to establish an answer nobody wants:
            # of course no `mod` names a file that does not exist. The hook
            # already skips deleted files; this is for every other caller.
            print("  wiring: %s does not exist, not checked"
                  % os.path.relpath(real, ROOT))
        else:
            inside.append(real)

    if not inside:
        return 0

    if not dep_info_paths():
        # Return 2, never 0. The caller turns 0 into "every source file is in
        # the build graph", so a skip that exits 0 prints a clearance for a
        # check that did not run. That used to need a missing target/; with
        # target/ a symlink into tmpfs it happens after every reboot.
        print("  wiring: SKIPPED - %s" % _why_no_dep_info())
        return 2
    compiled = find_in_dep_info(inside)

    allow = load_allowlist()
    failures = 0
    for real in inside:
        rel = os.path.relpath(real, ROOT)
        if real in compiled:
            print("  [OK] wiring: %s is in the build graph" % rel)
        elif rel in allow:
            print("  [OK] wiring: %s is allowlisted" % rel)
        else:
            print("  [X] NOT IN THE BUILD GRAPH: %s - no `mod` statement names "
                  "it, so no configuration compiles it and no other check can "
                  "see it" % rel)
            failures += 1
    return 1 if failures else 0


def main():
    compiled = dep_info_files()
    if not compiled:
        print("  [X] %s (cargo test --lib --no-run, both feature sets)"
              % _why_no_dep_info())
        return 2

    on_disk = {os.path.realpath(p)
               for p in glob.glob(os.path.join(SRC, "**", "*.rs"), recursive=True)}
    orphans = sorted(on_disk - compiled)
    allow = load_allowlist()

    unexplained, stale, explained = [], [], []
    for path in orphans:
        rel = os.path.relpath(path, ROOT)
        entry = allow.get(rel)
        if entry is None:
            unexplained.append(rel)
        else:
            explained.append((rel, entry["reason"], entry["cfg"]))

    # Self-policing: an exemption whose cfg now reaches the build graph is
    # stale. The file is compiled, so the reason it was exempt is gone.
    for rel, entry in allow.items():
        if os.path.realpath(os.path.join(ROOT, rel)) in compiled:
            stale.append((rel, entry["cfg"]))

    print("  files on disk: %d   in the build graph: %d   orphans: %d"
          % (len(on_disk), len(on_disk & compiled), len(orphans)))

    if explained:
        print("  allowed, each naming the cfg that would compile it:")
        for rel, reason, cfg in explained:
            print("      %s  [%s] %s" % (rel, cfg, reason))

    failures = 0
    for rel, cfg in stale:
        print("  [X] STALE EXEMPTION: %s is compiled now (cfg %s reached the "
              "build graph); remove its allowlist entry" % (rel, cfg))
        failures += 1

    for rel in unexplained:
        try:
            lines = sum(1 for _ in open(os.path.join(ROOT, rel), errors="ignore"))
        except OSError:
            lines = 0
        print("  [X] NOT IN THE BUILD GRAPH: %s (%d lines) - no `mod` names it, "
              "so no configuration compiles it" % (rel, lines))
        failures += 1

    # Ghost tests: written but never registered by the harness.
    ghosts = ghost_tests()
    if ghosts is None:
        print("  [!] ghost-test count SKIPPED (cargo test --list unavailable)")
    else:
        written, registered = ghosts
        gap = written - registered
        print("  tests written: %d   registered by the harness: %d   never run: %d"
              % (written, registered, gap))
        if gap > 0 and not unexplained:
            print("      (every orphan is explained, so these sit behind a cfg "
                  "no gate compiles - check that a lane runs that feature set)")

    if failures:
        print("  [X] WIRING: %d file(s) the compiler never sees" % failures)
        return 1
    print("  [OK] every source file is in the build graph")
    return 0


def ghost_tests():
    """(#[test] written in src, tests the harness registers) or None."""
    try:
        out = subprocess.run(
            ["cargo", "test", "-p", "hdds", "--lib", "--all-features", "--", "--list"],
            cwd=ROOT, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    registered = sum(1 for line in out.stdout.splitlines() if line.endswith(": test"))
    written = 0
    for path in glob.glob(os.path.join(SRC, "**", "*.rs"), recursive=True):
        try:
            with open(path, errors="ignore") as fh:
                written += sum(1 for line in fh if line.strip() == "#[test]")
        except OSError:
            continue
    return written, registered


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--file":
        sys.exit(main_one_file(sys.argv[2:]))
    sys.exit(main())
