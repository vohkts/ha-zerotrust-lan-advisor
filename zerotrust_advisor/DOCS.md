# Zero-Trust LAN Advisor — Documentation

## What this is

A Home Assistant add-on that passively watches your router's firewall and
flow logs, builds a picture of your network from that traffic alone, and
uses an LLM to suggest narrow, evidence-backed zero-trust firewall rules.
Everything happens through this add-on's own screens — no YAML editing, no
command line, no manual subnet/VLAN configuration required to get useful
output.

It never writes to your router. It listens, learns, and recommends; you
decide what to do with each suggestion.

## Router-side setup

You need to point two things at this add-on: your router's **firewall
syslog** and, optionally but recommended, its **NetFlow/IPFIX export**.

1. Open this add-on's **Setup** screen. It shows the exact IP and ports to
   use, live service status, and a coverage check for what's actually
   arriving vs. what's expected — including a specific warning if you're
   only seeing WAN-crossing traffic but no LAN-to-LAN traffic yet, which
   usually means firewall logging isn't enabled on your internal rules.
2. On the router (UniFi UDM Pro is the tested target; the parser is
   tolerant of firmware drift, not hard-coded to one exact log line
   format): enable per-rule firewall logging on the rules you want
   visibility into — especially inter-VLAN rules — and point syslog at the
   add-on's UDP port. Separately enable NetFlow/IPFIX export to the
   NetFlow port.
3. **Read the coverage warnings.** On UDM-class hardware, inter-VLAN
   routing is typically hardware-offloaded, which means NetFlow
   structurally cannot see traffic between your own VLANs — only
   WAN-crossing traffic. Per-rule firewall logging is the only reliable
   east-west evidence source on that class of hardware. The Setup screen
   detects and explains this specific gap when it applies to you.

Router menu paths drift between firmware versions — the Setup screen's
copy is a living starting point, not gospel. Nothing in the parsing logic
depends on that exact path being right.

## How network discovery works

No manual subnet/VLAN entry is required. Firewall logs carry `IN=`/`OUT=`
— the actual bridge/VLAN interface a packet crossed — which is used to
group devices onto the same network far more reliably than guessing from
an IP alone. Devices never seen with interface info (flow-only data, since
NetFlow doesn't carry this) fall back to a /24-prefix grouping instead.

The **Traffic** screen shows what's been discovered: each network's
guessed IP range (always marked as a guess — there's no router API in this
stage to confirm the real subnet mask, just good inference from address
density), which grouping method found it (interface-confirmed vs.
address-based), host counts, top flows, and the last 100 recent distinct
flow examples. You can give any discovered network a friendly name right
there; it's a pure display convenience; nothing depends on it.

The same screen also answers the most basic coverage question directly:
is this add-on actually seeing traffic *between* devices on your own
networks, or only traffic crossing to/from the internet? If it's only
ever seeing WAN-crossing traffic, that's flagged plainly.

## Recommendations

Split into two tabs:

- **Zero-Trust Rules** — real segmentation decisions. When the same
  traffic pattern (source class, destination class, network, protocol,
  port) recurs across enough distinct days, the LLM is asked to explain
  what it's likely for and suggest the narrowest rule that would cover it.
  Every recommendation states its confidence and caveats; the model is
  explicitly instructed to say "I don't recognize this" rather than invent
  a plausible-sounding purpose when it doesn't know.
- **Setup & Tuning** — deterministic, LLM-free findings about the
  observability setup itself, not your firewall. Currently: recognizing
  known-noisy router logging categories (AP client roaming events,
  `syslog-ng`/`logread` status messages, UniFi's `mcad` WAN diagnostics)
  once they cross a volume threshold, and suggesting you turn that logging
  category down. These never touch a firewall rule.

Traffic destined for this add-on's own syslog/NetFlow receiver — e.g. the
router logging its own log-forwarding traffic — is excluded from
recommendations by default (**Settings → "Ignore traffic to this add-on's
own receiver"**). That's expected, intentional traffic, not a segmentation
decision.

## Settings reference

All settings are edited from this add-on's own Settings screen (which also
appears identically in Home Assistant's normal Add-on Configuration tab —
they're the same underlying store). **Every change needs an add-on restart
to actually take effect** — Supervisor updates the stored config
immediately, but the already-running process doesn't pick it up live.

| Setting | What it does |
|---|---|
| Syslog / NetFlow ports | UDP ports the receivers listen on. |
| Allowed source IPs | Only these IPs' messages are accepted; others are counted as rejected (visible on Setup) rather than silently dropped. Leave empty until you know your router's IP. |
| Manual network overrides | Optional `CIDR=Label` entries that override auto-discovery for a specific range. Most people won't need this. |
| Retention (days) | How long parsed events are kept before pruning. |
| Minimum recurring days | How many distinct days a pattern must recur across before it becomes a Zero-Trust recommendation. Lower this temporarily if you want to see recommendations sooner on a fresh install — with only one day of history, nothing can meet a 3-day default. |
| Ignore own-receiver traffic | See above. On by default. |
| Enable mDNS listening | Passive mDNS for better device classification (real hostnames instead of vendor/IP fallback). Requires host networking, which is the *only* reason this add-on would ever need it — left off by default since it's a real network-isolation trade-off, not because it doesn't work. |
| LLM mode | Local (bundled `llama-server`, runs on your own hardware) or Remote (any OpenAI-compatible endpoint). One code path handles both — just a different base URL and key. |
| Remote base URL / API key | Only used in Remote mode. The key is written to `/data/secrets/`, never to the options store, never logged. |

## Privacy, if you use a remote LLM endpoint

Local mode never sends anything off the device. If you switch to a remote
OpenAI-compatible endpoint, only pseudonymized data is sent: device
*classes* like "iPhone" or "Apple HomePod / smart speaker" and network
labels, never real IPs, MACs, or hostnames. Tokens are derived with
HMAC-SHA256 from a per-install random salt, so the token alone (without
the salt file) can't be reversed back to a real address.

## Known limitations (Stage 1)

- Network discovery only sees what firewall/flow logs show it — it has no
  authoritative view of your router's actual configuration. That's Stage
  2's job (a future, optional, read-only connection to your router's own
  API), not built yet.
- No write access exists anywhere in this add-on. Applying an approved
  recommendation is a manual step you do on your router; a future,
  entirely optional Stage 3 might change that, but only with explicit,
  narrowly-scoped approval per change — never built without it.
- The recommendation engine currently reads firewall events only, not
  NetFlow-derived flows, for pattern-grouping (NetFlow still feeds the
  Traffic screen and coverage checks).
- Local CPU inference speed varies a lot by hardware — plan for tens of
  seconds per recommendation on modest hardware, not an instant response.

## Design notes, for anyone extending this

- **Stdlib-first.** The whole add-on has two third-party Python
  dependencies (Flask, waitress). Everything else — UDP sockets, NetFlow
  decoding, SQLite, pseudonymization, the LLM HTTP client — is stdlib.
  Keep it that way unless there's a strong reason not to.
- **Reject, don't guess.** Every parser here (firewall log lines, NetFlow
  template/data sets, mDNS records) drops malformed input rather than
  storing a partial or inferred record. Weak evidence poisons everything
  downstream of it.
- **Never store raw log text.** Only structured, parsed fields are
  persisted. Where categorization of *unparsed* content is useful (see the
  noise-category classifier), it's counted by category, never stored as
  raw text.
- **One LLM code path.** `app/llm/client.py` is the only place that talks
  to an LLM, local or remote. Don't add a second one.
- **Ingress-relative URLs only.** Every link, form action, and redirect in
  this app is a plain relative path with no leading slash — Ingress serves
  this add-on under a per-install path prefix the app is never told, and
  an absolute path would silently break under it. Client-side tab toggles
  are used instead of a second route at a different URL depth for exactly
  this reason (see `routes_recommendations.py`).
- **Commit immediately, never batch.** Several services share one SQLite
  file; holding a write transaction open between events starved every
  other writer in production once, badly enough to be worth a standing
  rule: commit right after every write.
