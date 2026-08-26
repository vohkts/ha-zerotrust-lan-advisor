# Changelog

## 0.4.0

### Added

- **Stage 3: applying a recommendation to UniFi.** Off by default, gated
  behind three independent conditions (manual apply mode, a new explicit
  "I understand this can write to my firewall" acknowledgment, and a
  working API key) before it's reachable at all. Creates exactly one
  narrow rule per confirmation, always previewed from the literal payload
  first — never modifies, disables, reorders, or deletes anything. See
  `STAGE3_APPLY_GOVERNANCE.md` for the full contract. **Currently in a
  live-testing mode**: every created rule is forced disabled
  (`app.unifi.apply.CREATE_RULES_ENABLED`), so a mistake during validation
  has zero effect on real traffic.
- **Live View** tab (new landing page): a polling, real-time table of
  firewall events (source, destination, port, allow/block), off until
  Start is clicked.
- Expandable Hosts and Firewall-policy rows with full behavior/config
  detail, including an on-demand LLM "guess" for unclassified devices.
- Recommendations now check the existing UniFi ruleset before suggesting
  anything new (never counting a broad "allow everything" rule as
  coverage), show whether an accepted rule has actually been implemented
  yet, and default to showing only open (pending) items — accepted/
  dismissed ones move to their own tab with a Reopen action.
- `llm_send_real_identifiers` setting (off by default): sends real
  hostnames/IPs instead of device classes, for anyone whose configured
  LLM endpoint never actually leaves their own network.
- A local-LLM host capacity check on Settings: detected CPU/RAM against a
  comfortable range, plus a reference performance table.
- Real UniFi network names now resolve via VLAN-tagged bridge interfaces
  (`br<vlanId>`) as well as by subnet — some UniFi Network Application
  versions don't expose a subnet on the network object at all, which had
  made real names silently never appear before this.

### Fixed

- Settings save could 502 through real Ingress: the automatic restart
  this add-on triggers after a save was racing the still-in-flight HTTP
  response, killing the container before "Saved" ever reached the
  browser. The restart now waits until the response has had a chance to
  finish sending.
- Host-detail and Traffic page performance (compound DB indexes, an
  async-loaded Traffic page instead of one big synchronous render).

## 0.3.0

### Added

- **Stage 2: optional, read-only UniFi UDM integration.** Off by default,
  scoped to UniFi UDM consoles only, and built against the official
  key-based Network Integration API (`/proxy/network/integration/v1`) —
  never the older cookie-session "classic" API. Everything here is a GET;
  nothing in this add-on writes to UniFi.
  - Configured entirely from the **Settings** screen: console IP/hostname,
    API key (stored the same way as the remote LLM key — `/data/secrets/`,
    never the options store, never logged), and whether to verify the
    console's TLS certificate (off by default, for a local UDM's
    self-signed cert).
  - **Test connection** button probes the key's actual capabilities live —
    can it reach the console, authenticate, list sites, read devices,
    clients, firewall zones, firewall policies — and shows exactly which
    of those work and which don't, independently (an older Network
    Application without zone-based firewalling can still be useful for
    device/client visibility).
  - A background sync (same schedule as the LLM analysis pass, plus a
    manual "Refresh now") caches devices, clients, firewall zones and
    policies locally, refreshed wholesale on each run.
  - New **Network** screen: zones, firewall policies (with state/action/
    logging), devices, and connected clients, straight from the cache
    above. Only appears in the sidebar at all once the integration is
    enabled and at least one capability has actually worked — every other
    screen is unchanged if you don't use this.
  - A new deterministic **Setup & Tuning** finding: an *enabled* UniFi
    firewall policy with logging turned off. If it's matching real traffic,
    that traffic never reaches this add-on's logs (or anywhere else
    watching them) — silently. This is a configuration audit finding, not
    proof the policy has matched anything.
  - Reserved (not yet functional) setting for a future stage: whether
    accepted zero-trust rules should eventually be written to UniFi
    manually by you or automatically by the add-on. Selecting "automatic"
    changes nothing today — there is no write path to UniFi anywhere in
    this codebase yet.
- A genuine visual redesign: sidebar navigation, card-based layout, and a
  UniFi-dashboard-inspired dark theme (with a matching light palette) —
  replacing the previous plain, unstyled look. No new dependencies; still
  server-rendered Jinja2 + one small `app.js`, no build step.

## 0.2.0

### Added

- Automatic network discovery from traffic — networks are grouped from the
  firewall log's interface field (`IN=`/`OUT=`) where available, falling
  back to a /24-prefix guess otherwise. No manual subnet/VLAN entry
  required. Discovered networks show a human-recognizable guessed IP
  range by default (not a raw bridge name), clearly marked as a guess
  until named, plus an optional rename control.
- **Traffic** screen: identified networks, top hosts, top flows by volume,
  and the last 100 deduplicated recent flow examples — real local
  IPs/hostnames, since this page never leaves the box.
- A first-pass coverage check: is any observed traffic actually
  internal-to-internal, or only ever WAN-crossing? Surfaced on both the
  Setup and Traffic screens.
- Recommendations split into two tabs: **Zero-Trust Rules** (LLM-derived
  real segmentation decisions) and **Setup & Tuning** (deterministic,
  LLM-free — currently, recognizing known-noisy router logging categories
  worth turning down).
- `ignore_own_receiver_traffic` setting (on by default): traffic destined
  for this add-on's own syslog/NetFlow ports is excluded from
  recommendations.
- The Setup screen now shows the exact host IP to point your router at,
  read from the Supervisor's own network info.
- Health counters (accepted/rejected/parsed/decoded flows) now persist
  across add-on restarts instead of resetting to zero.

### Fixed

- NetFlow receiver crashed on a malformed/truncated template set
  (`UndecodableRecord` wasn't caught for template sets, only data records).
- Several SQLite correctness issues: connections shared across waitress's
  thread pool (not safe), and long-held write transactions (batched
  commits, or one commit per whole analysis pass) starving other writers
  sharing the database file — now commits immediately after every write.
- Firewall log action (allow/drop) parsing: real UniFi/EdgeOS logs encode
  the verdict in the auto-generated rule name itself
  (`RULESET-A-priority`/`-D-`/`-R-`), not a separate `ACTION=` field —
  every event ingested before this fix had a silently-wrong "always
  blocked" status.
- A hand-written AppArmor profile blocked the base image's own `/init`
  from executing under Supervisor's actual confinement (a plain
  `docker run` never applies it, so this was invisible until real
  deployment) — disabled rather than hand-crafting a correct profile blind.
- `llama-server` was built dynamically linked against build-tree-only
  libraries with none of them copied into the final image — statically
  linked instead.
- `GET /network/info` returned 403 Forbidden: `hassio_api`/`hassio_role`
  were never declared in `config.yaml`.
- A database migration adding the `recommendations.category` column could
  crash every service on an existing (non-fresh) database: the schema
  script's `CREATE INDEX` on that column ran before the column-migration
  step that adds it.

## 0.1.0

Initial Stage 1 scaffold: syslog and NetFlow/IPFIX receivers, the
sanitize/classify/pseudonymize pipeline, the LLM-based recommendation
engine (bundled local `llama-server` or an optional remote
OpenAI-compatible endpoint), and the Setup/Recommendations/Settings
Ingress screens.
