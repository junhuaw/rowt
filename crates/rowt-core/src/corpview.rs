//! The `corp lane:` line in `rowt status` and `rowt doctor` — what rowt's corp
//! lane sees, and whose call the corp VPN's health is.
//!
//! The line used to read `corp VPN: none`, which was rowt's list of recognised
//! VPN client APPS, not a statement about the tunnel. On 2026-10-11 an agent read
//! it as "the corp VPN is down" while the VPN was fine. rowt cannot judge that
//! either way: the tunnel it would route corp traffic into (the busiest
//! non-overlay utun with three or more routes) exists throughout exactly the
//! outages that matter. A dedicated checker can — corp-route publishes one line,
//! `<epoch> <ok|fail|down|untested> <corp id>`, every 30 s — so rowt shows that
//! verdict when there is one, labelled as the checker's, and otherwise says the
//! health is not its call.
//!
//! A verdict older than the stale limit is "no opinion": the checker may have
//! stopped, and an old `ok` must not pin anyone's view. The corp id is never
//! printed — it can name the employer, and the line does not need it.

/// The text after `corp lane:` (status) or `corp` (doctor).
///
/// `tunnel` is rowt's corp tunnel (`_vpn_iface`), "" when none. `verdict` is
/// the checker file's contents, `None` when it does not exist. `now` and
/// `stale` are seconds.
pub fn line(tunnel: &str, verdict: Option<&str>, now: i64, stale: i64) -> String {
    let view = if tunnel.is_empty() {
        "no corp tunnel seen, so corp traffic follows the OS routing table (not a VPN health check)".to_string()
    } else {
        format!("routes into {tunnel} (the tunnel rowt sends corp traffic to; not a VPN health check)")
    };
    format!("{view} · VPN health: {}", health(verdict, now, stale))
}

fn health(verdict: Option<&str>, now: i64, stale: i64) -> String {
    let Some(body) = verdict else {
        return "not judged by rowt (no corp-route verdict) — ask your VPN client".into();
    };
    let first = body.lines().next().unwrap_or("");
    let mut f = first.split(' ');
    let (ep, word) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
    let ep_ok = !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit());
    let word_ok = !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_' || b == b'-');
    let Some(at) = ep.parse::<i64>().ok().filter(|_| ep_ok && word_ok) else {
        return "corp-route's verdict is unreadable".into();
    };
    let age = (now - at).max(0);
    if age > stale {
        format!("unknown — corp-route's last verdict ({word}) is {} old", span(age))
    } else {
        format!("{word}, per corp-route {} ago", span(age))
    }
}

/// `12 s`, `7 min`, `3 h`, `9 d` — whole units, rounded down.
fn span(s: i64) -> String {
    if s < 60 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} d", s / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 2_000_000_000;

    #[test]
    fn a_fresh_verdict_is_shown_as_the_checkers_and_the_corp_id_is_not() {
        let l = line("utun11", Some("1999999988 ok example-corp\n"), NOW, 300);
        assert_eq!(l, "routes into utun11 (the tunnel rowt sends corp traffic to; not a VPN health check) · VPN health: ok, per corp-route 12 s ago");
        assert!(!l.contains("example-corp"));
        assert!(line("utun11", Some("1999999820 fail x"), NOW, 300).ends_with("VPN health: fail, per corp-route 3 min ago"));
    }

    #[test]
    fn a_stale_verdict_is_no_opinion() {
        // The checker may have stopped; its last `ok` must not pin anyone's view.
        assert!(line("", Some("1999999000 ok x"), NOW, 300)
            .ends_with("VPN health: unknown — corp-route's last verdict (ok) is 16 min old"));
        assert!(line("", Some("1000000000 ok x"), NOW, 300).ends_with("is 11574 d old"));
    }

    #[test]
    fn no_verdict_file_means_rowt_does_not_judge() {
        assert_eq!(line("", None, NOW, 300),
                   "no corp tunnel seen, so corp traffic follows the OS routing table (not a VPN health check) · VPN health: not judged by rowt (no corp-route verdict) — ask your VPN client");
    }

    #[test]
    fn a_garbled_verdict_is_unreadable_not_a_verdict() {
        for bad in ["", "\n", "ok", "12x ok id", "1999999988", "1999999988 o!k id", " 1999999988 ok"] {
            assert!(line("u", Some(bad), NOW, 300).ends_with("VPN health: corp-route's verdict is unreadable"), "{bad:?}");
        }
    }

    #[test]
    fn a_verdict_from_the_future_reads_as_just_written() {
        assert!(line("u", Some("2999999999 ok x"), NOW, 300).ends_with("ok, per corp-route 0 s ago"));
    }

    #[test]
    fn spans_round_down_into_whole_units() {
        assert_eq!(span(59), "59 s");
        assert_eq!(span(60), "1 min");
        assert_eq!(span(7199), "119 min");
        assert_eq!(span(7200), "2 h");
        assert_eq!(span(172_800), "2 d");
    }
}
