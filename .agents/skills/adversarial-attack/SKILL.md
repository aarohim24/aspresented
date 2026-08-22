---
name: adversarial-attack
description: How to write or extend an attacker for as-presented, and how to read an adversarial sweep honestly. Use when editing mandate_gate/attack/*, tools/run_attack.py, or adding a model-driven attacker. Covers the information asymmetry an attacker must respect, why the oracle states properties instead of re-checking logic, and the difference between value extracted and an invariant violation.
---

# Adversarial attack

The harness scores traffic its author wrote. This package exists because that
cannot find a flaw in its author's model of the attacker -- as it did not find
the caller-controlled clock, which lived in *how* a limit was evaluated rather
than in the limit itself.

## The asymmetry is the measurement

An attacker sees a `Briefing` and nothing else: the mandate's own terms, the
merchants and intents it has observed, and every refusal it has received.

**It must not see the merchant's policy.** `_mandate_view` exposes the rail tier
only, and a test asserts it. An attacker handed the policy is testing
arithmetic; an attacker that reaches into the gate, the ledger, or
`envelope.policy` is testing nothing.

The refusal channel is deliberate. Every `Refusal` carries a code, a field and a
remediation, written so an agent could correct itself. Letting the attacker read
them tests that claim from the other side -- the fuzzer's `headroom` strategy
parses an amount out of the remediation text, so if those strings ever stop
carrying a usable number, that strategy silently stops firing. Keep the numbers
in the remediation.

## The oracle states properties, it does not re-check logic

`invariants.check` reads the finished ledger and asks whether anything that
settled should not have. It is not a second copy of the gate's checks, and it
must not become one: a re-implementation reading the same request field would
have agreed with the clock bug.

Every new constraint needs a matching invariant **and** a test showing that
invariant firing on a ledger crafted to break it. An oracle that only ever
reports "clean" is indistinguishable from no oracle.

The load-bearing test is `TestOracleCatchesABrokenGate`: with the cumulative
check removed, the attacker must exceed the cap and the oracle must say so. If
that test ever passes trivially -- because the attacker stopped reaching the
cap, say -- the whole sweep has quietly stopped meaning anything.

## Two results, two meanings

**Extracted** is what the attacker got away with. A mandate is meant to be
spent, so this is not a defect. Approaching the cap is the expected outcome; the
only question is whether anything crossed it.

**Violations** are invariants the gate allowed to be broken. Every one is a
defect, whatever provoked it, and CI fails on any.

Never report extraction as if it were a finding, and never report a clean sweep
as proof of correctness. The honest statement is: one attacker, at these
tempos, within this budget, found nothing.

## Tempo decides which constraint binds

This surprised the first version of the sweep and it is worth remembering.
Charging everything at one instant exhausts the rate window after four charges
and never reaches the cumulative cap. Twenty minutes apart walks past the rate
window and puts the cap and the count under pressure. A day apart outlives the
mandate. **A single tempo under-covers**, so the tool sweeps and the report
names any refusal code no tempo provoked.

An unreached code is either a gap in the attacker or a check nothing exercises.
Both are worth seeing; neither may be hidden. The `unbind` strategy exists
because the coverage report said `INTENT_UNBOUND` was never provoked.

## Adding a strategy

Rotate, do not randomise -- coverage should be systematic and reproducible, and
the seed must fully determine the run. A strategy returning `None` has nothing
to work with yet and is retried on a later round.

Vary amounts. The duplicate check fingerprints (intent, merchant, amount), so
repeated round numbers get absorbed as one purchase retried; a first version
spent 32 of 40 attempts that way. This is also the honest reading of
`DUPLICATE_CHARGE`: it is hygiene against a client that lost its key, not a
security control, and one paise defeats it.

## A model-driven attacker

Keep it behind the same `Attacker` protocol and the same `Briefing`. The core
package stays dependency-free; the model client belongs in an optional extra.

Record every transcript under `evidence/` and commit it, so a finding survives
without credentials and CI can replay it. Report model attackers separately
from the fuzzer -- never merge author-written, deterministic and model-driven
results into one recall figure.
