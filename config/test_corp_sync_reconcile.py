#!/usr/bin/env python3
"""Tests for corp-sync-reconcile.py (superset / minimal-reload CIDR reconcile).

Run: python3 config/test_corp_sync_reconcile.py
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import subprocess
import sys
import tempfile

_here = os.path.dirname(os.path.abspath(__file__))
_script = f"{_here}/corp-sync-reconcile.py"

# import to keep a module ref (ensures it stays importable / py_compile-clean)
_spec = importlib.util.spec_from_file_location("reconcile", _script)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

FAILS: list[str] = []


def run(active, handadded, block, private=(), opts=(), seen=()):
    """Invoke the reconcile CLI; return (status, [block cidrs]).

    Since 2026-09-27 the output also carries REFUSED and SEEN sections; `run`
    returns only the block, and `run_full` the rest.
    """
    status, body, _refused, _seen = run_full(
        active, handadded, block, private, opts, seen
    )
    return status, body


def run_full(active, handadded, block, private=(), opts=(), seen=()):
    """(status, block, refused, seen) — the whole stdout contract."""
    files = []

    def mk(lines):
        f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        f.write("\n".join(lines) + ("\n" if lines else ""))
        f.close()
        files.append(f.name)
        return f.name

    args = [
        sys.executable,
        _script,
        "--active",
        mk(active),
        "--handadded",
        mk(handadded),
        "--block",
        mk(block),
        "--private",
        mk(list(private)),
    ]
    if seen:
        args += ["--seen", mk(list(seen))]
    args += list(opts)
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    for fn in files:
        os.unlink(fn)
    lines = out.strip().splitlines()
    status = lines[0] if lines else ""
    rest = lines[1:]
    ri = rest.index("REFUSED") if "REFUSED" in rest else len(rest)
    si = rest.index("SEEN") if "SEEN" in rest else len(rest)
    return status, rest[:ri], rest[ri + 1 : si], rest[si + 1 :]


def check(name, got, want):
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


PRIV = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
]


def main() -> int:
    # 1. active covered by a broad hand-added CIDR -> no reload.
    s, _ = run(["11.122.0.0/15"], ["11.0.0.0/8"], [])
    check("broad-cover", s, "NOCHANGE")

    # 2. reconnect whose routes are already persisted in the block -> no reload.
    s, _ = run(["30.100.0.0/16"], [], ["30.100.0.0/16", "6.0.0.0/12"])
    check("persisted", s, "NOCHANGE")

    # 3. a new uncovered live route -> add it, keep disjoint stale. The route
    # must be enterprise-internal: since rule 1 a globally-routable one is
    # refused instead (see the rule-1 cases below).
    s, body = run(["26.9.0.0/16"], [], ["6.0.0.0/12"])
    check("add-new", (s, body), ("CHANGE", ["6.0.0.0/12", "26.9.0.0/16"]))

    # 4. collision: stale 30.0.0.0/9 overlaps a live route -> dropped WHOLE.
    s, body = run(["30.100.0.0/16", "30.200.0.0/16"], [], ["30.0.0.0/9", "6.0.0.0/12"])
    check(
        "collision-whole-drop",
        (s, body),
        ("CHANGE", ["6.0.0.0/12", "30.100.0.0/16", "30.200.0.0/16"]),
    )

    # 5. all tunnels down (no active) -> persist, no reload.
    s, _ = run([], [], ["30.0.0.0/8", "6.0.0.0/12"])
    check("all-down-persist", s, "NOCHANGE")

    # 6. private-range live routes are never mirrored; private cruft pruned.
    s, body = run(
        ["10.5.0.0/16", "26.9.0.0/16", "100.64.75.0/24"],
        [],
        ["192.168.9.0/24", "30.1.0.0/16"],
        PRIV,
    )
    check("private-filter", (s, body), ("CHANGE", ["26.9.0.0/16", "30.1.0.0/16"]))

    # 7. only private live routes, no public -> nothing to mirror.
    s, _ = run(["10.5.0.0/16", "192.168.1.0/24"], [], [], PRIV)
    check("all-private", s, "NOCHANGE")

    # --- rule 1: never AUTO-mirror a globally-routable range (2026-09-27) -----
    # A corp VPN really does advertise its cloud tenancy, and those same ranges
    # host everyone else. Refuse, report, and leave the choice to the person.
    s, body, refused, _ = run_full(["43.0.0.0/9", "26.9.0.0/16"], [], [], PRIV)
    check(
        "rule1-refuses-public",
        (s, body, refused),
        ("CHANGE", ["26.9.0.0/16"], ["43.0.0.0/9"]),
    )

    # …including one that reached the block before the rule existed.
    s, body, refused, _ = run_full(["26.9.0.0/16"], [], ["43.0.0.0/9"], PRIV)
    check("rule1-evicts-public", (s, body), ("CHANGE", ["26.9.0.0/16"]))

    # Nothing but public live routes: nothing to mirror, and it is not silent.
    s, body, refused, _ = run_full(["47.96.0.0/11", "8.128.0.0/10"], [], [], PRIV)
    check(
        "rule1-all-public",
        (s, body, refused),
        ("NOCHANGE", [], ["8.128.0.0/10", "47.96.0.0/11"]),
    )

    # --- rule 2: prune only while the tunnel is UP ---------------------------
    BLK = ["11.160.0.0/13", "30.27.64.0/18", "26.9.0.0/16"]
    s, body = run(["11.160.0.0/13"], [], BLK, PRIV, opts=["--tunnel-up"])
    check("rule2-prunes-when-up", (s, body), ("CHANGE", ["11.160.0.0/13"]))
    s, _ = run(["11.160.0.0/13"], [], BLK, PRIV)
    check("rule2-frozen-when-down", s, "NOCHANGE")

    # --- rule 3: expire by age ----------------------------------------------
    NOW, OLD = 1800000000, 1800000000 - 40 * 86400
    s, body = run(
        ["11.160.0.0/13"],
        [],
        ["11.160.0.0/13", "26.9.0.0/16"],
        PRIV,
        opts=["--now", str(NOW), "--max-age-days", "30"],
        seen=[f"26.9.0.0/16\t{OLD}"],
    )
    check("rule3-expires-unseen", (s, body), ("CHANGE", ["11.160.0.0/13"]))
    s, _ = run(
        ["11.160.0.0/13"],
        [],
        ["11.160.0.0/13", "26.9.0.0/16"],
        PRIV,
        opts=["--now", str(NOW), "--max-age-days", "0"],
        seen=[f"26.9.0.0/16\t{OLD}"],
    )
    check("rule3-disabled-by-zero", s, "NOCHANGE")

    # --- the two real route tables, anonymised by structure ------------------
    # 2026-09-27: one protocol switch took the tunnel from 50 routes to 90 and
    # put 22.8M addresses of third-party cloud into the corp lane. Whatever the
    # tunnel advertises, the block must never contain a globally-routable range.
    for tag in ("before", "after"):
        path = os.path.join(_here, "fixtures", f"corp-routes-{tag}.txt")
        with open(path, encoding="utf-8") as fh:
            live = [x.strip() for x in fh if x.strip() and not x.startswith("#")]
        s, body, refused, _ = run_full(live, [], [], PRIV)
        leaked = [c for c in body if not _mod._mirrorable(ipaddress.ip_network(c))]
        check(f"table-{tag}-no-public-in-block", leaked, [])
        if not refused:
            FAILS.append(f"table-{tag}: expected some refused public ranges, got none")

    if FAILS:
        print("FAIL")
        for f in FAILS:
            print("  " + f)
        return 1
    print("ok — corp-sync-reconcile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
