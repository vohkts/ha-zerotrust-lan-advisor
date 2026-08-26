# Stage 3: Applying Recommendations to UniFi — Governance

This document is the contract for the one feature in this project capable
of changing the user's actual firewall, before any of it is built. It
exists to be agreed on first and implemented against second — if an
implementation detail and this document ever disagree, the document wins
until it's deliberately updated.

Everything before this stage — syslog/NetFlow collection, classification,
the LLM recommendation engine, the UniFi read-only integration — has one
property in common: **nothing in this add-on has ever been able to change
another system.** `UnifiClientAPI` (`app/unifi/client.py`) has a private
`_get()` and nothing else. `recommendations.status` only ever means
"what the user thinks of this suggestion," never "what happened to the
router." That property is the whole reason this add-on has been safe to
run continuously against a real production network throughout its
development. Stage 3 is the first thing that gives it up, for one narrow
capability, and this document is what keeps the loss narrow.

## 0. Current status: live-testing mode (temporary)

Implemented and deployed, but not yet exercised against a real write —
the user asked to validate the real write path first with zero risk to
real traffic, rather than trust the first live apply to also be a fully
active one. Every rule this add-on creates right now is forced to
`enabled: false` regardless of what the recommendation said
(`app.unifi.apply.CREATE_RULES_ENABLED`, currently `False`) — a UniFi
policy that's disabled has no effect on any traffic no matter how it's
scoped, so a mistake in the write path during this testing phase is
inert, not a real segmentation change. Everything else in this document
already applies in full during this phase: create-only, one at a time,
previewed and confirmed, gated behind the same three conditions.

This is a single, clearly-marked flag, not a separate code path — flip it
back once a handful of applies have been confirmed to land correctly
(name, scope, protocol/port all match what was previewed, on the actual
UniFi console). Until then, expect every applied rule to show up
disabled in UniFi; that's expected, not a bug to chase.

## 1. What this stage is

A **human-gated** ability to create exactly the firewall policy a
recommendation already described, on the user's own UniFi console,
without them re-typing it by hand.

That's the entire feature. It is not automation, not a background job,
and not a second opinion on whether the recommendation was good — that
judgment already happened when the user clicked **Accept**. Apply is a
second, separate, and later decision: *do it now, on the real router.*

## 2. What this stage is not (hard boundary, not a roadmap item)

- **It never modifies an existing policy.** Not to fix a typo, not to
  merge two similar rules, not to "clean up" anything. If an existing
  rule needs to change, that's a human editing it in UniFi's own UI.
- **It never disables, reorders, or deletes a policy.** Including ones
  this add-on itself created. Deleting is exactly as consequential as
  creating and does not get a shortcut just because the add-on made the
  thing being deleted.
- **It never touches zones, networks, VLANs, port forwards, WAN rules,
  or anything outside a single firewall policy object.** The Integration
  API's write surface may be broader than this; this add-on's use of it
  is not.
- **It never applies more than one rule per confirmation.** No "apply
  all accepted recommendations." Every write is its own explicit,
  reviewed action, no matter how many recommendations are sitting there
  accepted.
- **It never runs unattended.** `unifi_apply_mode: automatic` (the
  option already sitting inert in Settings) stays inert. This document
  only specifies "manual." Automatic apply is a different, larger trust
  decision this add-on is not making today, and shipping the "manual"
  path is not permission to quietly build toward "automatic" later
  without this document being revisited on its own terms.
- **It never becomes possible by accident.** Existing as a feature in the
  codebase must not mean existing as a live capability on a given
  install — see §5.

## 3. The flow

1. A recommendation is **Accepted** (existing behavior, unchanged: local
   bookkeeping, no network call).
2. An accepted, not-yet-implemented zero-trust recommendation gets a new
   **Apply** button. Clicking it does not write anything yet — it opens a
   preview.
3. The preview shows the *exact* policy object this add-on is about to
   create: name, action, source/destination scope, protocol/port, in the
   same structured shape UniFi itself would show it back. Not the LLM's
   prose summary — the literal payload, so "what did this actually do"
   is answerable by reading the confirmation screen, not by trusting it.
4. Before the preview is even shown, the pattern is re-checked against
   the current live ruleset with the same `rule_match.py` coverage logic
   already used to skip redundant recommendations and to compute
   "Implemented." If something now covers it — created by the user by
   hand in the meantime, for instance — applying is refused with that
   explanation instead of creating a duplicate.
5. The user confirms **from the preview screen itself**, not from the
   original recommendation card. Confirming and previewing must not be
   collapsible into one click.
6. Exactly one API call is made: create one firewall policy. Success or
   failure is shown immediately, synchronously — this is not a
   fire-and-poll background job like the LLM calls elsewhere in this
   add-on. A write this consequential does not get to happen invisibly
   while the user is looking at something else.
7. On success, the real policy `id` UniFi returns is stored back on the
   recommendation row (new `applied_at`, `applied_policy_id` columns),
   and its "Implemented" check from then on is a direct lookup by that
   id, not the port-based best-effort match used for everything applied
   by hand. On failure, nothing is stored, the recommendation stays
   exactly as accepted-but-not-applied, and the real error is shown, not
   a generic failure message.

## 4. Rollback story

There isn't a rollback *button*, and that's deliberate rather than a gap.
Anything this add-on creates is a completely ordinary UniFi firewall
policy — visible, editable, and deletable in UniFi's own UI exactly like
one the user typed in by hand. If this add-on is wrong, broken, or
uninstalled entirely, nothing it applied becomes stuck, hidden, or
harder to manage than any other rule. Building a "delete what I created"
button would mean building delete capability at all, which §2 already
rules out — the cost of that capability existing is higher than the
convenience of not opening the UniFi UI once to remove a rule.

## 5. Making it possible requires more than one switch

Today, enabling anything in Settings only ever changes what this add-on
*reads* or *recommends*. Once Apply exists in the codebase, turning it on
for a given install must require **all** of the following, not any one of
them alone:

- `unifi_apply_mode` set to `manual` in Settings (already exists, already
  defaults off).
- A **separate, explicit acknowledgment** at the point of turning it on —
  not the same checkbox as enabling the read-only integration, and not
  something that can be pre-checked or scripted past via the Supervisor
  options store without the user having seen the in-app copy explaining
  what it does.
- A UniFi API key that has actually been granted write access at the
  console level. The existing read-only key continuing to work for
  everything else it already does is not, on its own, "the user opted
  into write access" — UniFi API keys are scoped per account role, not
  per operation, so a key that happens to be able to write is not
  evidence anyone decided it should be used that way. `apply.py` (see
  §7) checks for this explicitly and fails closed with a clear message
  if the configured key can't actually perform the write, rather than
  discovering that live against the router.

## 6. What "wrong" looks like, and how each is contained

| Failure mode | Contained by |
|---|---|
| A bad LLM recommendation gets applied | Accept already exists as a human checkpoint; Apply adds a second one with the literal payload shown, not the model's prose |
| The same rule gets created twice | The live re-check in step 4, every time, not just at recommendation-generation time |
| A rule is applied broader than intended | §2's create-only, single-policy scope — there's no "apply category" or "apply all," so broadening only ever happens per-rule, reviewed |
| The add-on is compromised or has a bug that tries to write unexpectedly | No background/automatic path exists to abuse (§2); every write requires a synchronous, in-session human click through the preview screen |
| The write silently fails or half-completes | Step 6 is synchronous and the real API response is surfaced; nothing is written to `recommendations` unless UniFi actually confirmed the policy exists |
| The user changes their mind after applying | §4 — it's an ordinary UniFi rule; delete it in UniFi like any other |
| Write access was enabled without the user realizing | §5 — three independent conditions must all be true, not one setting |

## 7. Where this lives in code (once built)

- `app/unifi/apply.py` — new, isolated module. The only place that ever
  constructs a write request or calls a write endpoint. Nothing else in
  this codebase should import it except the one route that needs it.
- `UnifiClientAPI` gains one new method for this — not a generic
  "request with any HTTP verb" helper. If a second write operation is
  ever needed later, it gets its own equally-narrow method, not a
  widened one.
- `recommendations` table gains `applied_at REAL` and `applied_policy_id
  TEXT`, both nullable, both untouched by anything except a successful
  apply.
- One new route, `POST /recommendations/<id>/apply-preview` (returns the
  literal payload, makes no network call) and `POST
  /recommendations/<id>/apply` (makes the one call, synchronous). Same
  one-segment-flat, relative-URL convention as every other route in this
  add-on.
- Every prior real bug this project has hit while integrating with a real
  UniFi console — the missing subnet field, the wrong client `network_id`
  fallback, the discovery that raw policy JSON is richer than assumed —
  is a reminder to verify the *actual* create-policy request/response
  shape against a real console before trusting any assumed schema, the
  same way §-worth of read-side bugs this session were only found by
  testing live, not by reading docs.

## 8. Explicitly deferred, not rejected

These are reasonable future asks that are out of scope for the first
version of Apply, listed here so they don't get built by accident under
the assumption that writing this document once covers them:

- Automatic apply (`unifi_apply_mode: automatic`).
- Modifying or deleting a policy this add-on previously created.
- Bulk apply.
- Recommending *deletion* of unused existing rules (already discussed
  separately, blocked on the UniFi hit-count field) — even once that
  exists as a *recommendation*, actually deleting anything still falls
  under §2 and would need this document revisited, not just extended.
