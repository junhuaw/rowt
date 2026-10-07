# rowt-monitor

A terminal UI for observing a running `rowt` proxy — live connections and
throughput, a rolling-window view of errors and blocked domains, and
outbound-server health. The companion to the `rowt` CLI (`htop`/`btop`). Beyond
observing, it offers a few **confirmed, reversible controls** — switch the active
server, route a domain to a lane, toggle the system proxy — each a front-end to
the same `rowt` command; everything else stays observe-only.

Invoked as `rowt monitor`; also runs standalone as `rowt-monitor`.

## Run

```sh
rowt-monitor              # live TUI (falls back to a demo fixture when the
                          # proxy / clash API isn't reachable)
rowt-monitor --servers list   # start with a two-row paged server list
rowt-monitor --fixtures   # force the offline demo data
rowt-monitor --render 150x38   # print one frame as plain text (dev/testing)
```

## Keys

**Navigate:** `↑↓`/`jk` move (first press locks a row by domain; leaving a pane
forgets it) · `←→`/`hl` switch pane / pick a server chip · `Tab` cycle focus
(conns → errors → health) · `g` toggle servers: scroll / list · `v` flip the connections pane (live / ↑ upload /
↓ download history) · `s` span (metrics timescale band) · `f` lane filter
(`1`/`2`/`3` jump, `0` clear) · `/` search hosts (regex, filters both panes;
`↵` commit, `esc` clear) · `w` or `[`/`]` errors window · `y` yank selected
domain · `p` pause · `?` help · `q` quit. (`v`/`s`/`f`/`/`/`w` are all global.)

**Controls** (confirmed, reversible; each runs the matching `rowt` command):
`e`/`c`/`b`/`d` route the locked domain → escape/corp/block/direct (arm, then
re-press or `↵` to commit; batched into one reload ~7s later) · `t` put it on
the **hotspot** lane — macOS's proxy *bypass* list, so a venue's captive-portal
page loads with the proxy on (`t` is the one letter of "hotspot" not already
bound) · `u` use the selected server · `a` auto server selection on/off · `o`
toggle the system proxy.

**Auto server selection** (`a`, from any pane; or click `auto` above the strip)
switches the escape server group between a pinned server and rowt's urltest
`auto`, which rides the fastest live server and re-probes the pool every
`ROWT_AUTO_INTERVAL` (default 20m). While it is on, the server auto is actually
using comes first and is marked `▶` (with `—` for latency until its first probe).
Turning it off pins *that* server, so traffic stays
where it is — and with no resolved pick yet it refuses rather than guess.
Selecting a server with `u` also turns auto off: in auto mode `u` pins any chip,
auto's own pick included. Each change restarts the router, and rowt does not
serialize restarts — two overlapping ones can kill each other's routers — so
while one is still running (a server change, or the batched lane reload) further
server changes are refused with a toast and a due lane reload waits its turn.

A hotspot edit is not a routing edit: nothing in that lane is rendered, and the
CLI refreshes the bypass list on the spot instead of bouncing the router. The
batched reload still fires, because `t` on a host that sits in a routing lane
pulls it out of there (single-lane rule), and the router keeps routing it until
something reloads. `d` clears a hotspot entry too. Refreshing the bypass list is
a `sudo networksetup` call with no terminal to prompt on — like `o`, it works
silently with the passwordless rule `rowt watch install` adds and is otherwise
skipped, in which case the entry is written and lands on the next `rowt proxy on`.

Shifted — `E`/`C`/`B`/`D`/`T` — make the same five edits on the host's **parent
suffix** instead of the host: `x.y.z.com` → `z.com`, so one keystroke covers a
whole service rather than the one hostname that happened to surface in the pane.
Registry second levels stay whole (`x.y.z.co.uk` → `z.co.uk`, never `co.uk`).
For a portal that is usually what you want: `www.unitedwifi.com` → `T` →
`unitedwifi.com`, which the bypass list holds as both the apex and `*.` form.

The entry is bare, not dot-led — measured against the router's own matcher
(`sing-box rule-set match`, 1.13.14):

| entry | `z.com` | `a.z.com` | `xz.com` |
|---|---|---|---|
| `domain_suffix: ["z.com"]` | ✓ | ✓ | ✗ |
| `domain_suffix: [".z.com"]` | ✗ | ✓ | ✗ |

sing-box matches on a **label boundary either way**, so a leading dot would only
*lose* the apex — not what "cover the whole service" means. `rowt explain` uses
the same boundary rule, so what it reports is what the router does.

Where there is nothing broader to add — an IP, or a host that already *is* its
registrable domain (`x.com`) — the shifted key stays **inert** and says so in the
footer, rather than silently writing what the lowercase key would.

Undo an `E`/`C`/`B`/`T` with `D`, not `d`: lane removal is an exact-line match, so
`d` on `x.y.z.com` removes only that entry and reports success without touching
a `z.com` written by `E`.

**The confirm bar sits at the right of the footer and has two phases.** For the
first **½ second** it is a plain confirmation, in the normal foreground colour
with no cursor: press the same key again to apply, or another arm key to
re-target. After that it turns **amber and grows a block cursor** — the entry is
now a live field, and the arm keys type instead of committing.

Each phase names only the key that works in it — `→ press e again to apply`,
then `→ escape · ↵ apply · esc cancel`. The shorter hint is **padded** to the
width of the longer, so the phase change swaps text in place and the entry does
not move; typing likewise extends the entry *leftward*, leaving the cursor and
everything after it where they were.

(Phase 1 shows the key rather than the lane name. The key *is* the lane —
`press c again` means corp — and the lane is spelled out the moment the bar
becomes editable.)

In the editable phase the cursor starts at the **left**, because a proposed
entry is nearly always too specific rather than too short and the first thing
you do is trim from the front. `Ctrl-W` does that in one keystroke — it drops
the **leading** label (`i.ytimg.com` → `ytimg.com` → `com`), the manual version
of what `E` computes for you. Otherwise: type to insert, `←→`/`Home`/`End` move
the cursor, `Backspace`/`Delete` cut, `↵` applies whatever is in the field.
There is no kill-line: an empty field is a cancel, and `Esc` says that directly.
An entry containing a space is refused rather than silently closed up
(`edit_list` would strip it and write something the bar never showed).

**Over-broad entries are refused.** A lane entry is a `domain_suffix`, so `com`
is not a host — it is every `.com`, and a few `^W`s is all it takes to get there
(`i.ytimg.com` → `ytimg.com` → `com`). The bar turns the entry **red** as you type one, and `↵`
declines with a reason instead of writing it. Two shapes are caught: a single
label (`com`, `cn`, `localhost`, `.com` — any bare TLD) and a bare registry
suffix (`co.uk`, `com.cn`, `ne.jp`). `bbc.co.uk` and `google.com` are fine —
it is the *shape* that identifies the mistake, not a list of TLDs. The rule is
`rowt_core::lanes::entry_risk`, shared with the CLI so the colour here and the
refusal there can never disagree; `rowt <lane> add` takes a `--force` to step
past it, the TUI deliberately does not.

Two consequences worth knowing. Once editable, printable keys go to the field —
so `q` types `q` rather than quitting, and `?`/`y` likewise; press `Esc` first.
And an armed edit **auto-cancels after 10s idle** — measured from the last
keypress, so typing keeps it alive and a pause to think doesn't discard it. The
cancel is exactly what `Esc` does, and just as silent.

**Mouse:** wheel scrolls (and focuses) the list under the pointer; click a row /
lane / window-tab to activate, a server chip to select it in place, or `sys proxy`
/ `auto` to toggle it (hover-highlights).

## Layout

- One **outer frame** (the only rounded corners); everything inside connects to
  it with `├ ┤` rules — no inset boxes.
- **Identity band** (neofetch-style logo + session facts) on top. Its `watch`
  cell reports the watchdog agent as *alive*, not merely loaded: `on · 1m` is
  the time since the last tick **completed** (rowt stamps `watch.tick` on its
  way out), `stalled · 14m` (orange) means launchd holds the job but no tick
  has finished in twice its interval, `off` means installed but not loaded,
  `—` not installed. Plain `on` with no age means an older rowt that writes no
  heartbeat. And a monitor left open across a `brew upgrade` announces it on
  the top rule — `┤ monitor 3.5.2 ≠ installed 3.5.5 · restart ├` — rather than
  presenting a days-old binary as current.
- **`live connections`** and **`errors & blocked`** panes — side by side,
  split by a center rule (tab labels shorten on narrow terminals).
- Full-width **`server health`**, merged onto the closing `┴` rule. The row
  above it leads with the **`auto` on/off toggle**, then pool counts.
  **Scroll is the default:** the original single-row marquee, with the active
  `▶` server pinned when there is room and the connection/error pane heights
  unchanged. Selecting a chip freezes the strip; `Esc` resumes it, and `↑`
  returns to the connections pane.
  Press **`g`** to toggle between scroll and list,
  or start with **`--servers scroll|list`**. Switching modes keeps the selected
  server. The mode key is also shown in `?` help and the footer.
  **List mode** wraps entries across at most **two rows**, without automatic
  scrolling. The active server comes first, followed by a `│` separator when
  space allows, even if its probe fails; remaining
  entries sort by latency ascending (unknown after known, ties by name), with
  failed servers marked `down` at the end. Focus with `Tab`; `←→` selects, while
  `↑↓`/`jk`, `PgUp`/`PgDn`, or the wheel over the list changes pages. The page
  counter appears beside the pool counts. Selecting across a page boundary
  reveals that server. Names too wide for a row are clipped at the right edge,
  without a middle ellipsis; latency remains visible.
  In both modes, all pool members are available immediately, even before
  probing or while the router is down. Pending readings show `—` and do not
  count as up or down. Down servers can be selected but cannot be used with `u`.
  Selection follows the name across refreshes; switching servers uses the full name.
  Each probe round measures every node three times, with at most 10 nodes
  being tested concurrently. Each finished node publishes its result immediately
  and frees a slot for the next node, without waiting for other nodes.
  Results appear on the next UI data tick. Latency is the median of successful samples
  (the mean for two); all three failing yields `down`. The section caption shows
  the age of the last completed round, such as `probe 2m ago`, or `probe —`
  before a round completes. The 10-minute interval and 5-second timeout stay the same.
  Pressing `r` during a round reports `previous probe still running…` and is
  ignored: it neither restarts nor queues another round, and does not reset the age.

The interactive layout supports **40 columns × 12 rows** (including the footer).
Small windows use a compact header and fewer table columns, keeping the two
panes side by side. Scroll mode always uses one server row. In list mode,
below 21 rows the server list uses one row with paging;
taller windows show up to two rows as needed. Below 40×12, a resize hint
replaces the layout; expanding the terminal restores the display and server page.

## Data sources

Everything is derived on a 2-second tick from: the clash API
(`127.0.0.1:9090` — `/traffic`, `/connections`, `/proxies`),
`~/.config/rowt/host.json`, `~/.config/rowt/state/servers.json`,
`~/.config/rowt/log/lane-*.log`, and host system facts. Respects
`ROWT_CLASH_PORT` (default 9090) and `ROWT_PORT` (default 7890).

## Design

- **[DESIGN.md](DESIGN.md)** — the full design doc: architecture, the data
  pipeline (clash API, incremental log tailing, block-lane bucketing, the
  server-health prober), rendering, interactions, resource characteristics, and
  the testing strategy.
- **[`renders/`](renders/)** — the reference frames: `.txt` glyph baselines and
  per-theme `.ansi` renders, updated when the layout changes (DESIGN.md §4.2).
  Filenames retain the original sizes; tests use 96×41, 150×30 and 212×30.
- **[`../archive/ux-design/rowt_monitor/`](../archive/ux-design/rowt_monitor/)**
  — the original UX handoff (spec + HTML prototype), archived. The monitor has
  moved past it; DESIGN.md §10 lists the deliberate deviations.

The layout and 130-column reflow reproduce the `.txt` captures byte-for-byte in
width. `tests/golden.rs` renders each geometry via ratatui's `TestBackend` and
diffs against them, masking the deliberate deviations; `--render WxH` is the
same path exposed on the CLI. The original scrolling goldens are unchanged.
List mode has separate `renders/rowt-monitor-list-*` captures and checks in
`tests/server_modes.rs`; generate them with `--servers list --render WxH` or
`--servers list --theme dark|light --render-ansi WxH`. The legacy filename sizes
map to actual render sizes 96×41, 150×30, and 212×30.

## Themes

Two palettes — dark and light — with the same layout, glyphs, and keys; only the
colors change. **[COLORS.md](COLORS.md)** is the full palette: every token in both
columns, its contrast, and where it renders (a test keeps it matching `theme.rs`).

```
rowt monitor                       # auto-detect (default)
rowt monitor --theme light         # pin it; also ROWT_MONITOR_THEME=light
```

`--theme auto` reads the terminal's *actual* background — `COLORFGBG` first, then
an OSC 11 query with a 100 ms budget — and picks light only for a near-paper
background (relative luminance ≥ 0.75); anything dimmer, or no answer at all,
stays dark. `$TERM` is never consulted. Pin the theme if your terminal reports its
background wrongly, or if you switch light/dark mid-session.
