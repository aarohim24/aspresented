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

## The model attacker

Same `Attacker` protocol, same `Briefing`, raw HTTP against an
OpenAI-compatible endpoint so the core package keeps no dependencies. Point
`base_url` and `model` at any provider; the defaults are Groq's free tier and
throttle to stay inside 30 requests/minute.

Rules that are not negotiable, each of them learned the hard way:

**A run with no attempts is INCONCLUSIVE, never clean.** With a rejected key
every call failed and an earlier version of the tool printed "no invariant
violations" -- nothing tested, reported as a pass. Check `total_attempts` before
reporting anything and exit non-zero.

**Record the prompt, not just the reply.** The prompt is the evidence that the
attacker was not shown the policy. A reader should not have to trust the claim.

**Redact before writing.** Error bodies echo the credential that failed and
transcripts get committed. Be eager: a false positive costs readability, a
false negative commits a key to a public repository.

**Parse defensively.** Extraction must be string-aware -- a blind brace count
returns None on `"rationale": "the } case"`, which ends the run silently and
looks exactly like a model with nothing to propose.

**Replay, because there is no seed.** A model finding that is not committed as a
transcript is not reproducible and therefore is not a finding. `ReplayAttacker`
re-issues recorded proposals with no credentials, which is how CI and a reader
verify a result.

**Never merge attacker results.** Author-written, deterministic and
model-driven recall mean different things and go in different rows.

**Budget visibly.** A model costs a call per attempt against a free tier of
roughly a thousand a day. Model runs default to one tempo and print the
projected call count; the fuzzer, being free, sweeps five.
