#!/usr/bin/env python3
"""Reconcile the corp lane's auto-synced CIDR block toward a *superset* of the
live tunnel routes, with the fewest possible rewrites (each rewrite costs a
sing-box reload).

Three inputs, one CIDR per line (IPv4; blanks/comments ignored):

  --active      A: CIDRs routed by the currently-UP tunnels (netstat, now)
  --handadded   H: CIDRs the user typed into corp-domains.txt by hand
  --block       B: CIDRs currently in the auto-managed sync block

The corp lane only has to CONTAIN every live route (a superset is fine — an
over-broad hand-added 11.0.0.0/8 already covers a live 11.122.0.0/15). So:

  * If every a in A is covered by H ∪ B (CIDR containment) -> print NOCHANGE.
    Nothing is rewritten, nothing reloads. Stale CIDRs kept from a now-down
    tunnel stay put (still needed in-office), even if they overlap nothing.

  * Otherwise a live route is uncovered, so rewrite to the minimal new block:
        B' = { c in B : c is disjoint from A }        # keep non-colliding stale
             ∪ { a in A : a not covered by H }         # add what H doesn't cover
    A block CIDR that COLLIDES with (overlaps) any live route is dropped WHOLE
    (never shrunk). Hand-added CIDRs (H) are never touched — they live outside
    the managed block. Live routes already covered by H aren't re-added (minimal).

THREE RULES bound what that block can grow into. On 2026-09-27 a corp VPN
briefly advertised 246 routes including broad PUBLIC aggregates (8.128.0.0/10,
43.0.0.0/9, 47.96.0.0/11). 69 CIDRs — 22.8 million addresses of third-party
cloud — entered the corp lane and stayed, because NOCHANGE keeps the block
verbatim and `keep` only ever drops a CIDR that OVERLAPS a live route.

  1. NEVER auto-mirror a globally-routable range. Third-party sites live there,
     and sending them through an employer's VPN is never what the user meant.
     Enterprise-internal space still mirrors: anything Python calls non-global
     (RFC1918, loopback, link-local, reserved, documentation) plus the
     DoD-assigned /8s that enterprises use internally and that host nobody else.
     A refused route is REPORTED, not silently dropped, so the caller can print
     the `corp add` that would allow it. Hand-added CIDRs are never touched —
     the user's explicit choice always wins.
  2. PRUNE while the tunnel is UP (--tunnel-up). The block then means "what this
     tunnel routes beyond H", so a CIDR no live route needs goes. With the
     tunnel DOWN the block is frozen, which is the in-office case the
     stale-keep rule was written for.
  3. EXPIRE by age (--seen FILE --now EPOCH --max-age-days N): the backstop for
     a machine whose tunnel is never up. A block CIDR unseen that long is
     dropped even then. `--seen` holds `<cidr>\t<epoch>` lines; this program
     only READS it and prints the refreshed map, never writes.

stdout: first line CHANGE or NOCHANGE; on CHANGE, the sorted B' CIDRs follow.
Then, always, a `REFUSED` line followed by the globally-routable live routes
rule 1 declined, and a `SEEN` line followed by `<cidr>\t<epoch>` for the caller
to persist. Both sections may be empty.
Stdlib only; nothing is written to disk here.
"""

from __future__ import annotations

import argparse
import ipaddress


def _load(path: str | None) -> list[ipaddress.IPv4Network]:
    if not path:
        return []
    out: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                continue
            key = str(net)
            if key not in seen:
                seen.add(key)
                out.append(net)
    return out


def _covered_by(a: ipaddress.IPv4Network, pool) -> bool:
    """True if a is entirely contained in the union of `pool` (collapsed)."""
    return any(a.subnet_of(n) for n in pool)


# IANA-assigned to the US DoD and, by long convention, used as private space
# inside large enterprises — they carry no third-party sites, so mirroring one
# cannot route someone's shopping through the corp VPN. Python calls them
# global (they are technically routable), which is why they need naming here.
ENTERPRISE_INTERNAL = [
    ipaddress.ip_network(c)
    for c in (
        "6.0.0.0/8",
        "7.0.0.0/8",
        "11.0.0.0/8",
        "21.0.0.0/8",
        "22.0.0.0/8",
        "26.0.0.0/8",
        "28.0.0.0/7",
        "30.0.0.0/8",
        "33.0.0.0/8",
        "55.0.0.0/8",
        "214.0.0.0/7",
    )
]


def _mirrorable(n: ipaddress.IPv4Network) -> bool:
    """Rule 1: may this range be mirrored into the corp lane AUTOMATICALLY?

    Only if nothing that is not the employer can be on it. A globally-routable
    range fails, however plausible it looks: 47.96.0.0/11 is the employer's
    cloud provider, not the employer.
    """
    return not n.is_global or any(n.subnet_of(r) for r in ENTERPRISE_INTERNAL)


def _seen_map(path: str | None) -> dict[str, int]:
    """`<cidr>\t<epoch>` lines. A malformed line is skipped, not fatal: this
    file is a cache, and losing it must never break a sync."""
    out: dict[str, int] = {}
    if not path:
        return out
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with fh:
        for raw in fh:
            parts = raw.split()
            if len(parts) != 2:
                continue
            try:
                out[str(ipaddress.ip_network(parts[0], strict=False))] = int(parts[1])
            except ValueError:
                continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="corp-lane superset reconcile")
    ap.add_argument("--active", help="live tunnel routes (A)")
    ap.add_argument("--handadded", help="hand-typed corp CIDRs (H)")
    ap.add_argument("--block", help="current auto-managed block CIDRs (B)")
    ap.add_argument(
        "--private",
        help="private/overlay ranges the router already defaults to unbound (P): "
        "routes inside them are never mirrored, and are pruned from the block",
    )
    ap.add_argument(
        "--tunnel-up",
        action="store_true",
        help="rule 2: the corp tunnel is UP, so the block may be pruned to what "
        "it actually routes. With it down the block is frozen (in-office).",
    )
    ap.add_argument("--seen", help="rule 3: <cidr><TAB><epoch> last-seen cache")
    ap.add_argument("--now", type=int, default=0, help="epoch seconds for rule 3")
    ap.add_argument(
        "--max-age-days",
        type=int,
        default=30,
        help="rule 3: drop a block CIDR unseen this long (0 disables)",
    )
    args = ap.parse_args()

    A = _load(args.active)
    H = _load(args.handadded)
    B = _load(args.block)
    P = list(ipaddress.collapse_addresses(_load(args.private)))

    # What is on disk right now. Every filter below decides what the block
    # SHOULD hold; NOCHANGE is only honest when that equals what it does hold —
    # the original code filtered and then printed NOCHANGE anyway, so a dropped
    # CIDR silently stayed in the file. That is how the 2026-09-27 block kept 69
    # ranges nothing needed.
    on_disk = {str(c) for c in B}

    # Ranges the router already sends unbound by default (RFC1918/CGNAT/…) don't
    # belong in the sync block: skip such live routes, and drop them from B below.
    A = [a for a in A if not _covered_by(a, P)]
    B = [c for c in B if not _covered_by(c, P)]

    # Rule 1, before anything else looks at A: a globally-routable route is not
    # a candidate at all. Reported so the caller can offer the `corp add`.
    refused = [a for a in A if not _mirrorable(a)]
    A = [a for a in A if _mirrorable(a)]
    # …and a block CIDR that rule 1 would refuse today does not get to stay
    # because it arrived before the rule existed.
    B = [c for c in B if _mirrorable(c)]

    # Rule 3: forget what no tunnel has advertised in a long time. Anything live
    # right now is seen now; a CIDR with no record at all is being met for the
    # first time, so it starts its clock rather than expiring immediately.
    seen = _seen_map(args.seen)
    now = args.now
    live_keys = {str(a) for a in A}
    fresh = dict(seen)
    for k in live_keys:
        fresh[k] = now
    if now and args.max_age_days > 0:
        cutoff = now - args.max_age_days * 86400
        B = [c for c in B if fresh.get(str(c), now) >= cutoff]

    cover = list(ipaddress.collapse_addresses(H + B))
    # Rule 2 can shrink the block with every live route already covered, so an
    # unchanged-coverage check is no longer enough to skip the rewrite.
    prunable = args.tunnel_up and any(not any(c.overlaps(a) for a in A) for c in B)
    # …and rules 1 and 3 may have dropped something that is still in the file.
    dropped = on_disk - {str(c) for c in B}
    if all(_covered_by(a, cover) for a in A) and not prunable and not dropped:
        print("NOCHANGE")
        _report(refused, fresh, args)
        return 0

    hcover = list(ipaddress.collapse_addresses(H)) if H else []
    # Rule 2: with the tunnel UP the block means "what this tunnel routes beyond
    # H", so a CIDR no live route needs goes. With it DOWN, keep the old rule —
    # stale ranges are still needed in the office.
    if args.tunnel_up:
        keep = [c for c in B if any(c.overlaps(a) for a in A)]
    else:
        keep = [c for c in B if not any(c.overlaps(a) for a in A)]
    add = [a for a in A if not _covered_by(a, hcover)]

    merged: dict[str, ipaddress.IPv4Network] = {}
    for net in keep + add:
        merged[str(net)] = net
    result = sorted(
        merged.values(), key=lambda n: (int(n.network_address), n.prefixlen)
    )

    print("CHANGE")
    for net in result:
        print(str(net))
    _report(refused, fresh, args)
    return 0


def _report(refused, fresh: dict[str, int], args) -> None:
    """The two trailing sections. Always printed, so a reader never has to guess
    whether an empty one means 'nothing' or 'this version does not say'."""
    print("REFUSED")
    for net in sorted(
        set(refused), key=lambda n: (int(n.network_address), n.prefixlen)
    ):
        print(str(net))
    print("SEEN")
    if args.seen and args.now:
        for cidr, ts in sorted(fresh.items()):
            print(f"{cidr}\t{ts}")


if __name__ == "__main__":
    raise SystemExit(main())
