#!/usr/bin/env python3
"""Tests for net-detect.py (scutil --dns -> internal/corp domain suggestions).

Synthetic fixtures only — no real employer data. Run: python3 config/test_netdetect.py
"""

from __future__ import annotations

import sys

import importlib.util
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("netdetect", f"{_here}/net-detect.py")
nd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nd)

# A resolver block puts `search domain` BEFORE `if_index` — the parser must still
# tag it as the physical NIC's search domain (the ordering bug this guards).
FIXTURE = """DNS configuration

resolver #1
  search domain[0] : hz.corp.example
  nameserver[0] : 30.1.2.3
  nameserver[1] : fd00:1::1
  if_index : 14 (en0)
  flags    : Request A records, Request AAAA records

resolver #2
  domain   : local
  flags    : Request A records

resolver #3
  domain   : 254.169.in-addr.arpa
  flags    : Request A records

resolver #8
  domain   : corp.example
  nameserver[0] : 223.5.5.5
  flags    : Request A records

resolver #9
  domain   : vpn.corp.example
  nameserver[0] : 10.0.0.53
  flags    : Request A records

resolver #11
  domain   : search.tailscale
  search domain[0] : tail1234.ts.net
  search domain[1] : hz.corp.example
  flags    : Request A records

resolver #12
  domain   : ts.net
  nameserver[0] : 100.100.100.100
  nameserver[1] : fd7a:115c:a1e0::53
  flags    : Request A records

resolver #13
  domain   : tail1234.ts.net
  nameserver[0] : 100.100.100.100
  flags    : Request A records

resolver #14
  domain   : vpn-dns.corp.example
  nameserver[0] : 30.9.8.7
  nameserver[1] : 100.100.100.100
  flags    : Request A records
"""

FAILS: list[str] = []


def check(name: str, got, want) -> None:
    if got != want:
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


def main() -> int:
    r = nd.parse(FIXTURE)

    # local, *.arpa, *.ts.net and search.tailscale are dropped; corp domains kept,
    # de-duped, first-seen order.
    check(
        "internal_domains",
        r["internal_domains"],
        [
            "hz.corp.example",
            "corp.example",
            "vpn.corp.example",
            "ts.net",
            "vpn-dns.corp.example",
        ],
    )
    # physical search domain resolved despite appearing before if_index.
    check("physical_search", r["physical_search"], ["hz.corp.example"])
    # 30.1.2.3 (30/8 corp-cloud) and 10.0.0.53 (RFC1918) are internal; 223.5.5.5
    # (public) and the IPv6 are not.
    check(
        "corp_nameservers",
        r["corp_nameservers"],
        ["30.1.2.3", "10.0.0.53", "100.100.100.100", "30.9.8.7"],
    )

    # A zone only an overlay resolver answers. resolver #13's tail1234.ts.net is
    # covered by #12's ts.net and the consumer matches by suffix, so only the
    # broader zone is reported; #14 has a CGNAT nameserver AND 30.9.8.7, and
    # one overlay address does not make a zone overlay-only — that is somebody's
    # intranet, whose lane stays the human's call.
    check("overlay_domains", r["overlay_domains"], ["ts.net"])
    check(
        "overlay: corp ns disqualifies",
        nd._overlay_block(["30.9.8.7", "100.100.100.100"]),
        False,
    )
    check(
        "overlay: v6 companion is ignored",
        nd._overlay_block(["100.100.100.100", "fd7a:115c:a1e0::53"]),
        True,
    )
    # A private resolver with no overlay address is a corp VPN, not an overlay —
    # and a block with no nameserver at all (scutil prints those) is neither.
    check("overlay: rfc1918 alone", nd._overlay_block(["10.0.0.53"]), False)
    check("overlay: no nameserver", nd._overlay_block([]), False)

    # A SEARCH domain is a suffix the OS appends to short names, not a zone the
    # resolver claims, so it is never reported as overlay-served.
    searchonly = nd.parse(
        "resolver #1\n  search domain[0] : tail1234.ts.net\n  nameserver[0] : 100.100.100.100\n"
    )
    check("overlay: search domain only", searchonly["overlay_domains"], [])

    # Empty / no-signal input yields empty lists, no crash.
    empty = nd.parse("")
    check("empty", empty["internal_domains"], [])
    check("empty overlay", empty["overlay_domains"], [])

    if FAILS:
        print("FAIL")
        for f in FAILS:
            print("  " + f)
        return 1
    print("ok — net-detect")
    return 0


if __name__ == "__main__":
    sys.exit(main())
