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
- Sanitizes what it collects: real IPs, MACs and hostnames never leave the
  add-on. Traffic is bucketed by *device class* (e.g. "phone", "smart
  speaker") instead.
- Uses a small local LLM (bundled, runs on your own hardware) to explain
  *why* a recurring flow is probably showing up — with an optional switch
  to a remote OpenAI-compatible endpoint if you want faster or higher
  quality output. Pseudonymized data is all that's ever sent remotely, and
  only if you turn that on.
- Tells you plainly what it *can't* see yet. Most home routers hardware-
  offload inter-VLAN routing, which means flow export tools like NetFlow
  never see that traffic at all — the add-on watches for that gap and
  tells you specifically what to turn on to close it.

## Status

Early build, proof-of-concept target is a UniFi UDM Pro. See
[`zerotrust_advisor/DOCS.md`](zerotrust_advisor/DOCS.md) for setup and
[`CHANGELOG.md`](zerotrust_advisor/CHANGELOG.md) for what's landed so far.

## Installation

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add this repository's URL.
3. Install **Zero-Trust LAN Advisor**, start it, and open its panel — the
   setup screen walks you through the rest.

## Roadmap

This is stage one of three. Stage two adds optional read-only access to
your router's own API for richer device/network context. Stage three,
entirely optional, lets the add-on apply an approved rule for you instead
of you doing it by hand. Neither exists yet, and stage one is fully useful
without them.

## Contributing

Issues and PRs welcome. Keep it small — this project deliberately avoids
scope creep; see the design notes in `zerotrust_advisor/DOCS.md` before
proposing new data sources or dependencies.
