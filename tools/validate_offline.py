#!/usr/bin/env python3
"""Validates every strategy with the real `nfqws --dry-run` WITHOUT building the Rust project.

    python3 tools/validate_offline.py /path/to/nfqws /path/to/lists /path/to/bin
(the lists dir must contain list-*.txt / ipset-*.txt, the bin dir the *.bin fakes; Linux only).
Expands the placeholders the same way as src/capture.rs, drops the Windows-only --wf-* options and
reports duplicates (two names must never expand to the same arguments) and rejected arguments.
"""
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gen_strategies as g  # noqa: E402


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    nfqws, lists, binp = sys.argv[1], sys.argv[2].rstrip("/") + "/", sys.argv[3].rstrip("/") + "/"
    subst = (("{BIN}", binp), ("{LISTS}", lists), ("{WFRAW}", "x"), ("{GF_TCP}", "12"), ("{GF_UDP}", "12"))
    bad, seen = 0, {}
    for name, _desc, classic, lean in g.STRATEGIES:
        for kind, tpl in (("lean", lean), ("classic", classic)):
            if tpl is None:
                continue
            args = []
            for t in tpl:
                for k, v in subst:
                    t = t.replace(k, v)
                if not t.startswith("--wf-"):
                    args.append(t)
            if tuple(args) in seen:
                print(f"DUPLICATE {name}/{kind} == {seen[tuple(args)]}")
                bad += 1
            seen[tuple(args)] = f"{name}/{kind}"
            r = subprocess.run([nfqws, "--dry-run", "--qnum=200", *args], capture_output=True, text=True)
            if r.returncode != 0:
                bad += 1
                print(f"FAIL {name}/{kind}: {(r.stderr or r.stdout).strip()[:200]}")
    print(f"strategies: {len(g.STRATEGIES)}, problems: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
