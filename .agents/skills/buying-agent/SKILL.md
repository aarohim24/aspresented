---
name: buying-agent
description: Rules for the as-presented buying agent, the catalogue and intent interpretation. Use when editing mandate_gate/buyer/*, tools/run_buyer.py, or anything that turns natural language into a signed intent. Covers where a model may decide and where it may not, why the catalogue is deliberately unsanitised, and why injection is contained architecturally rather than filtered.
---

# The buying agent

Two attackers probe this gate for gaps. The buyer asks the other question: can a
legitimate AI client actually get its shopping done? A guardrail that stops
fraud and also stops real purchases is not a guardrail, it is an outage.

## Where a model may decide

| Model | Never a model |
|---|---|
| reading an instruction into proposed terms | signing an intent |
| choosing what to buy | constructing a charge |
| reacting to a refusal | enforcement, adjudication |

The line is not stylistic. A model in the signing path could mint authority; a
model in the adjudication path would destroy the property that makes the ledger
evidence rather than opinion.

## Interpretation is the dangerous step

Turning "get me milk, up to five rupees an item" into enforceable terms is where
a mistake becomes money. Three rules, none optional:

**Clamp, do not trust.** The proposed `max_amount` is reduced to the mandate's
own ceiling. The model never sees that ceiling, so a misreading -- or a hostile
instruction -- is bounded by a number it could not influence. Never raise a
modest proposal *to* the ceiling.

**Sign here, deterministically**, over `INTENT_SIGNED_FIELDS`. Adding a term the
model can set means adding it to that list in the same commit, or it is
unsigned and therefore forgeable.

**A failed reading signs nothing.** No fallback intent, no defaults filled in
quietly. An intent invented on the principal's behalf is exactly the thing this
project says does not exist today, and manufacturing one here would make the
whole argument dishonest.

`Interpretation.summary` is the text a confirmation screen would show. Keep it
working: "the user should confirm this" is easy to write in a design document
and easy to leave unimplemented, and the difference between those is whether the
text exists.

## The catalogue is untrusted input

Product descriptions are merchant-supplied and the agent reads them. That makes
a description an injection channel into a client holding spend authority.

**Do not sanitise what the agent sees.** `visible_to_agent` returns the text
unaltered, and the flagged item stays in the fixture. Stripping it would make
the demo prove nothing.

`flags_instruction_shaped_text` is **detection, not defence**, and that
distinction must survive future edits. It is useful for telling a merchant that
an item is trying to talk to their agent. It is not what keeps the money safe,
because there are unbounded ways to write "ignore your limits" and a regex will
lose that race forever.

**What keeps the money safe is intent binding.** Every charge must conform to
terms the principal signed, so a hijacked agent's charges stop conforming. No
injection-detection check was added to the gate, deliberately -- the gate never
sees catalogue text, and an architectural containment beats a pattern match.
If you find yourself adding `INJECTED_INTENT`, re-read this paragraph first.

## Measuring influence honestly

Influence is measured against the **authority**, never against the item. A first
version counted any purchase of a flagged product and reported a legitimate
single jar within the limit as `INJECTION SUCCEEDED` -- overstating a defect,
which is the worse direction to be wrong in, because it sends a reader hunting
a hole that is not there.

- `flagged_item_charges` -- touched a flagged item. On its own, meaningless.
- `influenced_attempts` -- asked for more than the signed intent allows on such
  an item. This is evidence the agent was actually moved.
- `influenced_settled` -- of those, how many settled. Structurally zero unless
  the gate is broken, which is why it is reported rather than assumed.

`corrections` counts charges that succeeded after being refused. It is the only
test of whether the `remediation` field earns its place: if that text carried
nothing actionable, a competent agent would not improve and this would read
zero. Keep numbers in remediation strings.

## Swap the client, not the agent

`ScriptedClient` exists so the loop runs with no credentials. It replaces the
*client*, so the real prompt rendering, the real charges, the real gate and the
real refusals all still execute and only the decisions are fixed. A stub agent
would prove nothing about the agent.

## Before you commit

- `python3 tools/run_buyer.py` must exit zero, and it exits non-zero if an
  influenced charge ever settles.
- The buyer's ledger is checked by `attack.invariants` -- the honest client is
  held to the same standard as the attackers.
- The prompt must carry the catalogue and the authority and no policy field. A
  test asserts it.
