#!/usr/bin/env python3
"""Generate reconcile cases: hand-picked edges first, then randomized ones.

The reconcile is CIDR arithmetic — containment, overlap, collapsing — which is
exactly where a reimplementation goes subtly wrong on inputs nobody thought to
write down. So the differential gate feeds both implementations the same
generated cases rather than only the scenarios in the docstring.

Deterministic: seeded, so a failure is reproducible and the corpus doesn't
churn between runs.

Usage: gen-reconcile-cases.py OUTDIR [count]
"""

from __future__ import annotations

import ipaddress
import os
import random
import sys

# Ranges the corp lane actually deals with: RFC1918, CGNAT, the DoD-assigned
# /8s enterprises use internally — and, since 2026-09-27, genuinely PUBLIC
# space, because a corp VPN really does advertise it and rule 1 has to refuse.
_BASES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "11.0.0.0/8",
    "30.0.0.0/8",
    "47.96.0.0/11",
    "8.128.0.0/10",
    "43.0.0.0/9",
]
_PRIVATE = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n100.64.0.0/10\n169.254.0.0/16\n"

# The scenarios the docstring names, written out so a regression in any of them
# is legible rather than hiding among the random cases.
HANDPICKED = [
    # (active, handadded, block)
    ("11.122.0.0/15", "11.0.0.0/8", ""),  # covered by a broad hand entry
    ("30.1.0.0/16", "", "12.0.0.0/8"),  # uncovered -> rewrite
    (
        "30.1.0.0/16\n40.0.0.0/16",
        "",
        "30.0.0.0/8",
    ),  # colliding block entry dropped whole
    ("10.1.0.0/16\n30.1.0.0/16", "", "10.9.0.0/16"),  # private skipped and pruned
    ("10.0.0.0/8", "10.0.0.0/9\n10.128.0.0/9", ""),  # halves collapse to cover
    ("", "", ""),  # nothing at all
    ("", "", "30.0.0.0/8"),  # stale block, no live routes
    ("30.0.0.0/8", "30.0.0.0/8", "30.0.0.0/8"),  # identical everywhere
    ("30.1.2.3/16", "", ""),  # host bits set
    ("not-a-cidr\n30.1.0.0/16", "# comment\n", "\n"),  # junk tolerated
    # Rule 1 (2026-09-27): a globally-routable route is refused, never mirrored,
    # and one already in the block is evicted. The DoD /8s still mirror.
    ("43.0.0.0/9\n30.27.64.0/18", "", ""),  # public refused, internal kept
    ("47.96.0.0/11", "", ""),  # public only -> nothing to add
    ("30.1.0.0/16", "", "43.0.0.0/9"),  # public already in the block: evicted
    ("", "", "8.128.0.0/10\n11.0.0.0/8"),  # evicted with no live routes at all
    (
        "11.160.0.0/13\n47.96.0.0/11",
        "11.0.0.0/8",
        "",
    ),  # covered internal + refused public
]

# Rule 2 (--tunnel-up) and rule 3 (--seen/--now/--max-age-days) change the argv,
# so a case may carry extra flags. `_OPTS` lines up with HANDPICKED_OPTS below;
# every other case runs with the four original flags, which is what the gate did
# before these rules existed.
HANDPICKED_OPTS = [
    # (active, handadded, block, opts, seen)
    (
        "11.160.0.0/13",
        "",
        "11.160.0.0/13\n30.27.64.0/18\n26.9.0.0/16",
        "--tunnel-up",
        "",
    ),  # prune to what the tunnel routes
    (
        "11.160.0.0/13",
        "",
        "11.160.0.0/13\n30.27.64.0/18",
        "",
        "",
    ),  # tunnel down: frozen
    (
        "11.160.0.0/13",
        "",
        "11.160.0.0/13\n26.9.0.0/16",
        "--seen SEEN --now 1800000000 --max-age-days 30",
        "26.9.0.0/16\t1796544000\n",
    ),  # 26.9 unseen 40d -> expired
    (
        "11.160.0.0/13",
        "",
        "11.160.0.0/13\n26.9.0.0/16",
        "--seen SEEN --now 1800000000 --max-age-days 0",
        "26.9.0.0/16\t1796544000\n",
    ),  # expiry disabled
    (
        "30.1.0.0/16",
        "",
        "",
        "--seen SEEN --now 1800000000",
        "",
    ),  # first sight starts the clock
]


def rnd_net(rng: random.Random) -> str:
    base = ipaddress.ip_network(rng.choice(_BASES))
    prefix = rng.randint(base.prefixlen, min(base.prefixlen + 10, 30))
    span = int(base.broadcast_address) - int(base.network_address)
    addr = int(base.network_address) + (rng.randint(0, span) if span else 0)
    return str(ipaddress.ip_network((addr, prefix), strict=False))


def rnd_list(rng: random.Random, lo: int, hi: int) -> str:
    return "".join(f"{rnd_net(rng)}\n" for _ in range(rng.randint(lo, hi)))


def main() -> int:
    outdir = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    rng = random.Random(20260809)
    os.makedirs(outdir, exist_ok=True)

    cases = [(a, h, b, "", "") for a, h, b in HANDPICKED]
    cases += HANDPICKED_OPTS
    for _ in range(count):
        # A third of the random cases carry rule 2/3 flags, so the new paths see
        # arbitrary input too rather than only the five written-down shapes.
        roll = rng.random()
        opts, seen = "", ""
        if roll < 0.17:
            opts = "--tunnel-up"
        elif roll < 0.34:
            opts = "--seen SEEN --now 1800000000 --max-age-days 30"
            seen = "".join(
                f"{rnd_net(rng)}\t{rng.choice([1796544000, 1799990000])}\n"
                for _ in range(rng.randint(0, 3))
            )
        cases.append(
            (rnd_list(rng, 0, 5), rnd_list(rng, 0, 3), rnd_list(rng, 0, 5), opts, seen)
        )

    for i, (a, h, b, opts, seen) in enumerate(cases):
        d = os.path.join(outdir, f"case{i:04d}")
        os.makedirs(d, exist_ok=True)
        for name, body in (
            ("active", a),
            ("handadded", h),
            ("block", b),
            ("private", _PRIVATE),
            ("seen", seen),
        ):
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        # `SEEN` in the opts line stands for this case's own seen file, so the
        # generator does not have to know the gate's directory layout.
        with open(os.path.join(d, "opts"), "w", encoding="utf-8") as fh:
            fh.write(opts.replace("SEEN", os.path.join(d, "seen")))
    print(len(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
