#!/usr/bin/env python3
"""Discover the internal/corporate DNS domains the current network advertises.

Parses `scutil --dns` (macOS) and reports the search / match domains and the
private-range nameservers that a corp LAN or a connected corp VPN registers —
the raw material for suggesting corp-lane domain suffixes. This is a SUGGESTION
aid, not an auto-apply: a machine can legitimately see many internal domains and
only the human knows which belong in the corp lane.

Only observable when the signal is live — on the corp LAN, or with the corp VPN
up. At home with the VPN down there's nothing to see (that's what a persisted
per-corp store is for).

  --input FILE   read `scutil --dns` output from FILE instead of running it
                 (for tests). Default: run `scutil --dns`.

Emits JSON on stdout:
  {
    "internal_domains":  ["corp.example.com", "hq.corp.example", ...],  # de-duped
    "physical_search":   ["hq.corp.example"],   # search domains on the primary NIC
    "corp_nameservers":  ["30.1.2.3"],          # nameservers in private/corp space
    "overlay_domains":   ["ts.net"]              # zones ONLY an overlay resolver answers
  }
Stdlib only; reads nothing but the DNS config; writes nothing.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys

# Nameserver IPs that indicate an internal resolver: RFC1918 + CGNAT + link-local,
# plus the public-looking /8s that some corporate clouds route privately (11/30/6).
_INTERNAL_NS = [
    ipaddress.ip_network(c)
    for c in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "11.0.0.0/8",
        "30.0.0.0/8",
        "6.0.0.0/12",
    )
]


# An OVERLAY resolver: a nameserver inside the CGNAT range that overlay VPNs
# hand out (Tailscale's MagicDNS at 100.100.100.100; Headscale's equivalent).
# A zone served only by one of these resolves NOWHERE else — not at a public
# resolver, and not through /etc/resolv.conf, which on macOS carries the PRIMARY
# resolver only and never the scoped ones. That is what makes such a zone safe
# to act on automatically, unlike the rest of `internal_domains`: there is no
# lane in which the alternative works.
_OVERLAY_NS = ipaddress.ip_network("100.64.0.0/10")
# The company such a zone's resolvers may keep. Anything else — a public
# resolver, or the 11/30/6 space a corporate cloud routes privately — means the
# zone is somebody's intranet, which stays a suggestion for the human.
_OVERLAY_OK_NS = [
    ipaddress.ip_network(c)
    for c in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
    )
]


def _ns_v4(ip: str) -> ipaddress.IPv4Address | None:
    """The address if it is IPv4, else None.

    IPv6 nameservers are ignored throughout this file (Tailscale advertises
    `fd7a:115c:a1e0::53` alongside its v4 one, and the v4 one carries the same
    signal), which keeps one address parser rather than two in each language.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return addr if addr.version == 4 else None


def _is_internal_ns(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in n for n in _INTERNAL_NS)


def _skip_domain(d: str) -> bool:
    d = d.lower()
    if not d or d == "local":
        return True
    if d.endswith(".arpa"):  # reverse-DNS zones
        return True
    if d.endswith(".ts.net") or "tailscale" in d:  # Tailscale MagicDNS
        return True
    return False


def _skip_zone(d: str) -> bool:
    """Noise for the overlay question — but NOT the Tailscale skip.

    `_skip_domain` drops `*.ts.net` because corp-routing a tailnet zone is
    wrong; here those zones are exactly what is being looked for, and only
    `local` and the reverse-DNS zones are noise.
    """
    d = d.lower()
    return not d or d == "local" or d.endswith(".arpa")


def _overlay_block(ns: list[str]) -> bool:
    """Is this resolver block an overlay resolver, served by nothing else?

    At least one CGNAT nameserver, and no v4 nameserver outside overlay/private
    space. The first half is the signal; the second is what keeps a corp VPN's
    own zone (`dns.corp.example` -> `30.9.8.7`) out of it.
    """
    v4 = [a for a in (_ns_v4(x) for x in ns) if a is not None]
    if not any(a in _OVERLAY_NS for a in v4):
        return False
    return all(any(a in n for n in _OVERLAY_OK_NS) for a in v4)


def _collapse(doms: list[str]) -> list[str]:
    """Drop a zone a broader one already covers.

    The consumer matches by suffix, so `ts.net` covers `tail1234.ts.net` — one
    entry instead of one per tailnet this machine has ever joined.
    """
    return [d for d in doms if not any(o != d and d.endswith("." + o) for o in doms)]


def _scutil_output(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    try:
        return subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse(text: str) -> dict:
    internal: list[str] = []
    seen: set[str] = set()
    phys_search: list[str] = []
    ns: list[str] = []
    ns_seen: set[str] = set()
    overlay: list[str] = []
    overlay_seen: set[str] = set()

    # `scutil --dns` lists a resolver's `search domain` BEFORE its `if_index`, so
    # buffer each resolver block and resolve which NIC it's scoped to at flush.
    cur_search: list[str] = []  # search-domain entries in the current block
    cur_phys = False  # current block is scoped to a physical NIC (enN)
    cur_match: list[str] = []  # match-domain entries (`domain :`) in the block
    cur_ns: list[str] = []  # every nameserver in the block, internal or not

    def flush():
        if cur_phys:
            for d in cur_search:
                if d not in phys_search:
                    phys_search.append(d)
        # A zone is only claimed as overlay-served on the evidence of its OWN
        # resolver block, which is why this waits for the flush: the nameservers
        # may be printed after the domain they serve.
        if _overlay_block(cur_ns):
            for d in cur_match:
                if d not in overlay_seen:
                    overlay_seen.add(d)
                    overlay.append(d)

    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("resolver #"):
            flush()
            cur_search = []
            cur_phys = False
            cur_match = []
            cur_ns = []
            continue
        m = re.match(r"if_index\s*:\s*\d+\s*\(([^)]+)\)", line)
        if m:
            cur_phys = bool(re.match(r"en\d+$", m.group(1)))
            continue
        m = re.match(r"(search )?domain(?:\[\d+\])?\s*:\s*(\S+)", line)
        if m:
            is_search = bool(m.group(1))
            dom = m.group(2).lower()
            # The overlay question asks about MATCH domains only: a search
            # domain is a suffix the OS appends to short names, not a zone a
            # resolver claims.
            if not is_search and not _skip_zone(dom):
                cur_match.append(dom)
            if not _skip_domain(dom):
                if dom not in seen:
                    seen.add(dom)
                    internal.append(dom)
                if is_search:
                    cur_search.append(dom)
            continue
        m = re.match(r"nameserver(?:\[\d+\])?\s*:\s*(\S+)", line)
        if m:
            cur_ns.append(m.group(1))
            if _is_internal_ns(m.group(1)) and m.group(1) not in ns_seen:
                ns_seen.add(m.group(1))
                ns.append(m.group(1))
    flush()

    return {
        "internal_domains": internal,
        "physical_search": phys_search,
        "corp_nameservers": ns,
        "overlay_domains": _collapse(overlay),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="detect internal/corp DNS domains")
    ap.add_argument("--input", help="read scutil --dns output from FILE (for tests)")
    args = ap.parse_args()
    result = parse(_scutil_output(args.input))
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
