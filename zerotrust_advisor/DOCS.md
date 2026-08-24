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

## Stage 2: UniFi UDM integration (optional, read-only)

Off by default, and only relevant if your router is a UniFi UDM. When
enabled, this add-on reads your UDM's own view of its network — devices,
connected clients, firewall zones, firewall policies — over the official,
key-based **Network Integration API**
(`https://<console>/proxy/network/integration/v1`). It deliberately does
**not** use the older cookie-session "classic" API that UniFi's own web UI
uses, even though that one exposes more (full VLAN CRUD, legacy firewall
rules, port forwards): the integration API is narrower but stays within a
clean, official, credential-light model — an API key, not your UniFi
account's username and password. Nothing in this add-on writes to UniFi,
regardless of any setting below.

**Setup**, all from the Settings screen:

1. In UniFi's own UI, create a Network Integration API key (Network
   Application → Settings → Control Plane → Integrations, or similar —
   this menu path moves between versions).
2. Enter your console's IP or hostname and the key in this add-on's
   Settings screen, under "UniFi integration". Leave "Verify TLS
   certificate" off unless your console has a certificate your system
   already trusts — a local UDM's default certificate is self-signed.
3. Click **Test connection**. This checks the key live, right there,
   against a fixed set of read-only calls — reach the console, authenticate,
   list sites, read devices, read clients, read firewall zones, read
   firewall policies — and shows exactly which succeeded. Firewall
   zones/policies need a newer Network Application version (roughly
   10.0.162+); everything else works on far older ones. A key missing
   firewall access can still be useful for device/client visibility, so
   each capability is reported independently, not as one pass/fail answer.
4. Save. Enabling the checkbox is what turns on the background sync — a
   handful of cheap GETs on the same schedule as the LLM analysis pass
   (plus a manual "Refresh now" on the new **Network** screen).

Once at least one capability has worked, a **Network** screen appears in
the sidebar showing the cached zones, policies, devices, and clients. It
only appears at all under that condition — every other screen in this
add-on is unchanged whether or not you use this.

**What it adds to Recommendations**: an enabled UniFi firewall policy with
logging turned off gets flagged under **Setup & Tuning**. If that policy is
matching real traffic, this add-on (and anything else watching your
syslog feed) never sees it happen — silently. This is an audit finding
about the policy's configuration, not proof it has actually matched
anything; the API doesn't expose per-policy match evidence, only the
policy's own settings.

**Firewall rule apply mode** — reserved, not yet functional. A future
stage may let this add-on write accepted zero-trust rules back to UniFi
automatically instead of you doing it by hand; the setting exists now so
it's visible where the rest of the UniFi settings live, but selecting
"automatic" changes nothing today. There is no code path anywhere in this
add-on that writes to UniFi.

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
| Enable UniFi integration | Off by default. See "Stage 2: UniFi UDM integration" above. |
| UniFi console IP / API key | The key is written to `/data/secrets/`, same as the remote LLM key. |
| Verify UniFi console TLS certificate | Off by default, for a local UDM's self-signed certificate. |
| Firewall rule apply mode | Reserved for a future stage — not yet functional either way. |

## Privacy, if you use a remote LLM endpoint

Local mode never sends anything off the device. If you switch to a remote
OpenAI-compatible endpoint, only pseudonymized data is sent: device
*classes* like "iPhone" or "Apple HomePod / smart speaker" and network
labels, never real IPs, MACs, or hostnames. Tokens are derived with
HMAC-SHA256 from a per-install random salt, so the token alone (without
the salt file) can't be reversed back to a real address.

## Known limitations

- Network discovery from traffic alone has no authoritative view of your
  router's actual configuration (VLAN names, real subnet masks, which
  zone a network belongs to) — the UniFi integration above adds that, but
  only for UniFi UDM consoles, and only what the console's Integration API
  actually exposes.
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
