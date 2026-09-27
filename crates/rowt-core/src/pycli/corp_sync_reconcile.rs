//! `rowt-reconcile` — the corp-lane superset reconcile, drop-in for
//! `config/corp-sync-reconcile.py`. Same flags, same stdout contract.

use crate::reconcile::{load, reconcile_with, render_outcome, Opts};
use std::collections::BTreeMap;
use std::process::ExitCode;

fn read(p: Option<&String>) -> String {
    p.and_then(|x| std::fs::read_to_string(x).ok()).unwrap_or_default()
}

/// `<cidr>\t<epoch>` lines. A malformed line is skipped, never fatal: the file
/// is a cache, and losing it must not break a sync. `_seen_map` in the Python.
fn seen_map(body: &str) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    for raw in body.lines() {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() != 2 {
            continue;
        }
        let (Ok(net), Ok(ts)) = (parts[0].parse::<ipnet::Ipv4Net>(), parts[1].parse::<i64>()) else {
            continue;
        };
        out.insert(net.trunc().to_string(), ts);
    }
    out
}

pub fn main(argv: &[String]) -> ExitCode {
    let args: Vec<String> = argv.to_vec();
    let get = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
    };
    let num = |flag: &str, dflt: i64| -> i64 {
        get(flag).and_then(|v| v.parse::<i64>().ok()).unwrap_or(dflt)
    };
    let (a, h, b, p) = (get("--active"), get("--handadded"), get("--block"), get("--private"));
    let seen_path = get("--seen");
    let opts = Opts {
        tunnel_up: args.iter().any(|x| x == "--tunnel-up"),
        now: num("--now", 0),
        // argparse's default; `0` disables expiry.
        max_age_days: num("--max-age-days", 30),
    };
    let seen = seen_map(&read(seen_path.as_ref()));
    let (out, report) = reconcile_with(
        &load(&read(a.as_ref())),
        &load(&read(h.as_ref())),
        &load(&read(b.as_ref())),
        &load(&read(p.as_ref())),
        &opts,
        &seen,
    );
    println!("{}", render_outcome(&out));
    // Both sections are always printed, so a reader never has to guess whether
    // an empty one means "nothing" or "this version does not say".
    println!("REFUSED");
    let mut refused: Vec<String> = report.refused.iter().map(|n| n.to_string()).collect();
    refused.sort_by_key(|s| {
        let n: ipnet::Ipv4Net = s.parse().unwrap();
        (u32::from(n.network()), n.prefix_len())
    });
    refused.dedup();
    for r in refused {
        println!("{r}");
    }
    println!("SEEN");
    if seen_path.is_some() && opts.now != 0 {
        for (cidr, ts) in &report.seen {
            println!("{cidr}\t{ts}");
        }
    }
    ExitCode::SUCCESS
}
