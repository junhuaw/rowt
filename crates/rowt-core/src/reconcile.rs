//! Corp-lane superset reconcile — the port of `config/corp-sync-reconcile.py`.
//!
//! The corp lane only has to *contain* every live tunnel route; a superset is
//! fine, since an over-broad hand-added `11.0.0.0/8` already covers a live
//! `11.122.0.0/15`. Each rewrite costs a sing-box reload, so the rule is: change
//! nothing unless some live route is actually uncovered.

pub use ipnet::Ipv4Net;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every live route is already covered — nothing is rewritten, nothing reloads.
    NoChange,
    /// A live route was uncovered; this is the new managed block, sorted.
    Change(Vec<Ipv4Net>),
}

/// IANA-assigned to the US DoD and, by long convention, private space inside
/// large enterprises — they carry no third-party sites, so mirroring one cannot
/// route somebody's shopping through the corp VPN. `is_global` calls them
/// routable, which is why they are named here.
const ENTERPRISE_INTERNAL: [&str; 11] = [
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8", "26.0.0.0/8",
    "28.0.0.0/7", "30.0.0.0/8", "33.0.0.0/8", "55.0.0.0/8", "214.0.0.0/7",
];

/// `is_global` for an IPv4 network, matching Python's `ip_network.is_global`
/// closely enough for this decision: anything special-purpose is NOT global.
fn is_global(n: &Ipv4Net) -> bool {
    let o = n.network().octets();
    let private = matches!(o[0], 10)
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..128).contains(&o[1]))   // CGNAT
        || matches!(o[0], 127)                           // loopback
        || (o[0] == 169 && o[1] == 254)                  // link-local
        || o[0] == 0
        || o[0] >= 224                                   // multicast + reserved
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)       // IETF protocol
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)       // TEST-NET-1
        || (o[0] == 198 && (18..20).contains(&o[1]))     // benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)    // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)     // TEST-NET-3
        || (o[0] == 192 && o[1] == 88 && o[2] == 99);    // 6to4 relay
    !private
}

/// Rule 1: may this range be mirrored into the corp lane AUTOMATICALLY?
///
/// Only if nothing that is not the employer can be on it. A globally-routable
/// range fails however plausible it looks: `47.96.0.0/11` is the employer's
/// cloud provider, not the employer. `_mirrorable` in the Python.
pub fn mirrorable(n: &Ipv4Net) -> bool {
    if !is_global(n) {
        return true;
    }
    ENTERPRISE_INTERNAL
        .iter()
        .any(|r| r.parse::<Ipv4Net>().is_ok_and(|r| r.contains(n)))
}

/// Everything the caller needs beyond the block itself: what rule 1 declined
/// (so it can print the `corp add` that would allow it) and the refreshed
/// last-seen map (so it can persist it). Mirrors the Python's REFUSED/SEEN.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    pub refused: Vec<Ipv4Net>,
    pub seen: BTreeMap<String, i64>,
}

/// The knobs rules 2 and 3 add. `now == 0` or `max_age_days == 0` disables
/// expiry, which is what a caller with no cache passes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Opts {
    pub tunnel_up: bool,
    pub now: i64,
    pub max_age_days: i64,
}

/// Parse one CIDR per line, ignoring blanks, comments, non-IPv4 and junk, and
/// de-duplicating by normalized form — `_load` in the Python.
pub fn load(body: &str) -> Vec<Ipv4Net> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `ip_network(..., strict=False)` — host bits are allowed and cleared.
        let Ok(net) = line.parse::<Ipv4Net>() else { continue };
        let net = net.trunc();
        if seen.insert(net.to_string()) {
            out.push(net);
        }
    }
    out
}

fn covered_by(a: &Ipv4Net, pool: &[Ipv4Net]) -> bool {
    pool.iter().any(|n| n.contains(a))
}

fn collapse(nets: &[Ipv4Net]) -> Vec<Ipv4Net> {
    Ipv4Net::aggregate(&nets.to_vec())
}

/// A: live tunnel routes. H: hand-typed corp CIDRs. B: the managed block.
/// P: ranges the router already sends unbound, which never belong in the block.
pub fn reconcile(active: &[Ipv4Net], hand: &[Ipv4Net], block: &[Ipv4Net], private: &[Ipv4Net]) -> Outcome {
    reconcile_with(active, hand, block, private, &Opts::default(), &BTreeMap::new()).0
}

/// The full form: rules 1–3 and the report. `reconcile` is this with no opts,
/// which is the pre-2026-09-27 behaviour plus rule 1 (never optional).
pub fn reconcile_with(
    active: &[Ipv4Net],
    hand: &[Ipv4Net],
    block: &[Ipv4Net],
    private: &[Ipv4Net],
    opts: &Opts,
    seen: &BTreeMap<String, i64>,
) -> (Outcome, Report) {
    let p = collapse(private);
    // What the file holds right now. Every filter below decides what it SHOULD
    // hold, and NoChange is only honest when the two agree — filtering and then
    // returning NoChange is how a dropped CIDR silently stayed on disk, and how
    // the 2026-09-27 block kept 69 ranges nothing needed.
    let on_disk: std::collections::HashSet<String> = block.iter().map(|n| n.to_string()).collect();

    let a: Vec<Ipv4Net> = active.iter().filter(|n| !covered_by(n, &p)).copied().collect();
    let b: Vec<Ipv4Net> = block.iter().filter(|n| !covered_by(n, &p)).copied().collect();

    // Rule 1, before anything else looks at them: a globally-routable range is
    // not a candidate, and one already in the block does not get to stay
    // because it arrived before the rule existed.
    let refused: Vec<Ipv4Net> = a.iter().filter(|n| !mirrorable(n)).copied().collect();
    let a: Vec<Ipv4Net> = a.into_iter().filter(mirrorable).collect();
    let b: Vec<Ipv4Net> = b.into_iter().filter(mirrorable).collect();

    // Rule 3: forget what no tunnel has advertised in a long time. Anything live
    // is seen now; one with no record at all is being met for the first time, so
    // it starts its clock rather than expiring immediately.
    let mut fresh = seen.clone();
    for x in &a {
        fresh.insert(x.to_string(), opts.now);
    }
    let b: Vec<Ipv4Net> = if opts.now != 0 && opts.max_age_days > 0 {
        let cutoff = opts.now - opts.max_age_days * 86_400;
        b.into_iter()
            .filter(|c| *fresh.get(&c.to_string()).unwrap_or(&opts.now) >= cutoff)
            .collect()
    } else {
        b
    };

    let report = Report { refused, seen: fresh };

    let mut cover_src = hand.to_vec();
    cover_src.extend_from_slice(&b);
    let cover = collapse(&cover_src);
    let overlaps = |c: &Ipv4Net| a.iter().any(|x| c.contains(&x.network()) || x.contains(&c.network()));
    // Rule 2 can shrink the block even when every live route is covered, and
    // rules 1/3 may have dropped something still in the file — so coverage
    // alone is no longer enough to skip the rewrite.
    let prunable = opts.tunnel_up && b.iter().any(|c| !overlaps(c));
    let dropped = on_disk.len() != b.len() || b.iter().any(|c| !on_disk.contains(&c.to_string()));
    if a.iter().all(|x| covered_by(x, &cover)) && !prunable && !dropped {
        return (Outcome::NoChange, report);
    }

    let hcover = if hand.is_empty() { Vec::new() } else { collapse(hand) };
    // Rule 2: with the tunnel UP the block means "what this tunnel routes beyond
    // the hand entries", so a CIDR no live route needs goes. With it DOWN the
    // old rule stands — stale ranges are still needed in the office. Either way
    // a block CIDR is dropped WHOLE, never shrunk.
    let keep: Vec<&Ipv4Net> = if opts.tunnel_up {
        b.iter().filter(|c| overlaps(c)).collect()
    } else {
        b.iter().filter(|c| !overlaps(c)).collect()
    };
    // Live routes already covered by hand entries are not re-added (minimal).
    let add = a.iter().filter(|x| !covered_by(x, &hcover));

    let mut merged: BTreeMap<(u32, u8), Ipv4Net> = BTreeMap::new();
    for net in keep.into_iter().chain(add) {
        merged.insert((net.network().into(), net.prefix_len()), *net);
    }
    (Outcome::Change(merged.into_values().collect()), report)
}

/// The stdout contract the shell reads: `CHANGE` + the block, or `NOCHANGE`.
pub fn render_outcome(o: &Outcome) -> String {
    match o {
        Outcome::NoChange => "NOCHANGE".to_string(),
        Outcome::Change(nets) => {
            let mut s = String::from("CHANGE");
            for n in nets {
                s.push('\n');
                s.push_str(&n.to_string());
            }
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(v: &[&str]) -> Vec<Ipv4Net> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn a_broader_hand_entry_already_covers_a_live_route() {
        let o = reconcile(&nets(&["11.122.0.0/15"]), &nets(&["11.0.0.0/8"]), &[], &[]);
        assert_eq!(o, Outcome::NoChange);
    }

    #[test]
    fn an_uncovered_route_forces_a_rewrite() {
        // The stale entry has to be enterprise-internal: since rule 1 a
        // globally-routable one (12.0.0.0/8 here, once) is evicted instead.
        let o = reconcile(&nets(&["30.1.0.0/16"]), &[], &nets(&["6.0.0.0/12"]), &[]);
        assert_eq!(o, Outcome::Change(nets(&["6.0.0.0/12", "30.1.0.0/16"])));
    }

    #[test]
    fn a_colliding_block_entry_is_dropped_whole_not_shrunk() {
        // 30.0.0.0/8 overlaps the live 30.1.0.0/16 and a second route is
        // uncovered, so the block is rewritten and the overlapping entry goes.
        let o = reconcile(
            &nets(&["30.1.0.0/16", "26.9.0.0/16"]),
            &[],
            &nets(&["30.0.0.0/8"]),
            &[],
        );
        assert_eq!(o, Outcome::Change(nets(&["26.9.0.0/16", "30.1.0.0/16"])));
    }

    #[test]
    fn private_ranges_are_never_mirrored_and_are_pruned() {
        let o = reconcile(
            &nets(&["10.1.0.0/16", "30.1.0.0/16"]),
            &[],
            &nets(&["10.9.0.0/16"]),
            &nets(&["10.0.0.0/8"]),
        );
        // the 10/8 route is skipped, the 10/8 block entry pruned, 30/16 added
        assert_eq!(o, Outcome::Change(nets(&["30.1.0.0/16"])));
    }

    #[test]
    fn collapsing_lets_two_halves_cover_their_supernet() {
        // Neither half contains 10.0.0.0/8 alone; collapsed they do.
        let o = reconcile(&nets(&["10.0.0.0/8"]), &nets(&["10.0.0.0/9", "10.128.0.0/9"]), &[], &[]);
        assert_eq!(o, Outcome::NoChange);
    }

    #[test]
    fn junk_and_duplicates_are_ignored_on_load() {
        let l = load("# c\n\n10.0.0.0/8\nnot-a-cidr\n10.0.0.0/8\n::1/128\n");
        assert_eq!(l, nets(&["10.0.0.0/8"]));
    }

    #[test]
    fn host_bits_are_tolerated() {
        assert_eq!(load("10.1.2.3/8\n"), nets(&["10.0.0.0/8"]));
    }

    /// Rule 1 (2026-09-27): a corp VPN advertising its cloud tenancy must not
    /// drag every other tenant's site through the employer's VPN.
    #[test]
    fn a_globally_routable_range_is_never_auto_mirrored() {
        let (o, r) = reconcile_with(
            &nets(&["43.0.0.0/9", "26.9.0.0/16"]), &[], &[], &[],
            &Opts::default(), &BTreeMap::new(),
        );
        assert_eq!(o, Outcome::Change(nets(&["26.9.0.0/16"])));
        assert_eq!(r.refused, nets(&["43.0.0.0/9"]));
        // …and one already in the block is evicted, not grandfathered.
        let (o, _) = reconcile_with(
            &nets(&["26.9.0.0/16"]), &[], &nets(&["43.0.0.0/9"]), &[],
            &Opts::default(), &BTreeMap::new(),
        );
        assert_eq!(o, Outcome::Change(nets(&["26.9.0.0/16"])));
        // The DoD /8s enterprises use internally still mirror, though
        // `is_global` calls them routable.
        for c in ["6.0.0.0/12", "11.160.0.0/13", "26.9.0.0/16", "30.27.64.0/18", "214.1.0.0/16"] {
            assert!(mirrorable(&c.parse().unwrap()), "{c} should mirror");
        }
        for c in ["43.0.0.0/9", "8.128.0.0/10", "47.96.0.0/11", "1.1.1.0/24"] {
            assert!(!mirrorable(&c.parse().unwrap()), "{c} should be refused");
        }
    }

    /// Rule 2: the block means "what this tunnel routes" only while it is up.
    #[test]
    fn the_block_is_pruned_only_while_the_tunnel_is_up() {
        let blk = nets(&["11.160.0.0/13", "30.27.64.0/18", "26.9.0.0/16"]);
        let up = Opts { tunnel_up: true, ..Opts::default() };
        let (o, _) = reconcile_with(&nets(&["11.160.0.0/13"]), &[], &blk, &[], &up, &BTreeMap::new());
        assert_eq!(o, Outcome::Change(nets(&["11.160.0.0/13"])));
        // Tunnel down: frozen, because those ranges are still needed in-office.
        let (o, _) = reconcile_with(
            &nets(&["11.160.0.0/13"]), &[], &blk, &[], &Opts::default(), &BTreeMap::new(),
        );
        assert_eq!(o, Outcome::NoChange);
    }

    /// Rule 3: the backstop for a machine whose tunnel never comes up.
    #[test]
    fn a_block_cidr_unseen_for_too_long_expires() {
        const NOW: i64 = 1_800_000_000;
        let blk = nets(&["11.160.0.0/13", "26.9.0.0/16"]);
        let mut seen = BTreeMap::new();
        seen.insert("26.9.0.0/16".to_string(), NOW - 40 * 86_400);
        let o = |days| {
            reconcile_with(&nets(&["11.160.0.0/13"]), &[], &blk, &[],
                           &Opts { now: NOW, max_age_days: days, ..Opts::default() }, &seen).0
        };
        assert_eq!(o(30), Outcome::Change(nets(&["11.160.0.0/13"])));
        assert_eq!(o(0), Outcome::NoChange, "0 disables expiry");
        // A CIDR nobody has a record for starts its clock rather than expiring.
        let (o2, r) = reconcile_with(&nets(&["30.1.0.0/16"]), &[], &[], &[],
            &Opts { now: NOW, max_age_days: 30, ..Opts::default() }, &BTreeMap::new());
        assert_eq!(o2, Outcome::Change(nets(&["30.1.0.0/16"])));
        assert_eq!(r.seen.get("30.1.0.0/16"), Some(&NOW));
    }

    /// The trap that made the 2026-09-27 block permanent: filtering and then
    /// reporting NoChange leaves what was filtered sitting on disk.
    #[test]
    fn nochange_is_only_honest_when_nothing_was_dropped() {
        let (o, _) = reconcile_with(
            &nets(&["26.9.0.0/16"]), &[], &nets(&["26.9.0.0/16", "43.0.0.0/9"]), &[],
            &Opts::default(), &BTreeMap::new(),
        );
        assert_eq!(o, Outcome::Change(nets(&["26.9.0.0/16"])), "the public entry must go");
    }
}
