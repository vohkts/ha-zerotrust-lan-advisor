# Zero-Trust LAN Advisor

A Home Assistant add-on that watches your router's firewall and flow logs
and suggests narrow, evidence-backed allow rules for a zero-trust network —
no spreadsheets, no CLI, no YAML editing.

It does **not** touch your firewall. It listens, learns, and recommends.
You review every suggestion in the add-on's own screen inside Home
Assistant and decide what to do with it.

## What it does

- Runs its own small syslog and NetFlow/IPFIX receivers so your router can
  point its logs at Home Assistant.
- **Maps your network by watching it** — no manual subnet/VLAN entry. Real
  firewall logs carry the interface a packet crossed, which is a far
  stronger signal than guessing from an IP; devices get grouped by that,
  and shown under the /24 range a human actually recognizes (clearly
  marked as a guess until you name it yourself).
- Sanitizes what it collects: real IPs, MACs and hostnames never leave the
  add-on. Traffic is bucketed by *device class* (e.g. "phone", "smart
  speaker") instead.
- Uses a small local LLM (bundled, runs on your own hardware) to explain
  *why* a recurring flow is probably showing up — with an optional switch
  to a remote OpenAI-compatible endpoint if you want faster or higher
  quality output. Pseudonymized data is all that's ever sent remotely, and
  only if you turn that on.
- Splits its recommendations into two kinds: **Zero-Trust Rules** (a real
  segmentation decision to consider) and **Setup & Tuning** (deterministic,
  LLM-free findings about the observability setup itself — noisy router
  logging categories worth turning down, gaps worth closing). Mixing the
  two made the real firewall decisions harder to act on.
- Tells you plainly what it *can't* see yet. Most home routers hardware-
  offload inter-VLAN routing, which means flow export tools like NetFlow
  never see that traffic at all — the add-on watches for that gap and
  tells you specifically what to turn on to close it.
- **Optional, read-only UniFi UDM integration.** If your router is a UniFi
  UDM, point this add-on at your console's official Integration API key
  and it'll cross-reference your router's own firewall zones/policies
  against what it observes — e.g. flagging an active policy with logging
  disabled, which silently hides whatever traffic it matches. Off by
  default; the add-on works fully without it.

## Status

Stage 1 and Stage 2 are built and running. Proof-of-concept target is a
UniFi UDM Pro, though the passive log parsing is intentionally tolerant
rather than hard-coded to one router; the Stage 2 API integration is UniFi
UDM-only by design. See [`zerotrust_advisor/DOCS.md`](zerotrust_advisor/DOCS.md)
for setup and [`zerotrust_advisor/CHANGELOG.md`](zerotrust_advisor/CHANGELOG.md)
for what's landed so far.

## Installation

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add this repository's URL.
3. Install **Zero-Trust LAN Advisor**, start it, and open its panel — the
   setup screen walks you through the rest.

## Roadmap

Three stages. Stage one (passive log analysis) and stage two (optional,
read-only UniFi UDM integration) are both built. Stage three, entirely
optional and off by default even once it exists, would let the add-on
apply an approved rule for you instead of you doing it by hand — not built
yet; a setting for it already exists in Settings, clearly labeled as not
yet functional, but nothing in this codebase writes to your router.

## Contributing

Issues and PRs welcome. Keep it small — this project deliberately avoids
scope creep; see the design notes in `zerotrust_advisor/DOCS.md` before
proposing new data sources or dependencies.
