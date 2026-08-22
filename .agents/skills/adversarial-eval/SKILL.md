---
name: adversarial-eval
description: How to add abuse classes and boundary scenarios to the as-presented harness, and how to read its numbers honestly. Use when editing mandate_gate/harness/*, tools/run_harness.py, or interpreting recall and false-decline figures. Covers the labelling contract, why the integrity preflight gates every score, stratified splits, and which numbers are trustworthy.
---

# Adversarial evaluation

The harness exists to make a claim measurable. It is easy to make it flattering
instead. These rules keep it adversarial.

## The three eval shapes

Following the taxonomy this project's evaluation is modelled on:

- **Golden set** — known inputs, known correct outputs. Our boundary scenarios.
- **A/B** — same corpus, two configurations. Our policy-stripped control.
- **Adversarial** — failure-finding. Our abuse classes, and the reason the
  harness exists at all.

Adversarial is the primary mode here. If a change makes the harness better at
confirming the gate works and worse at finding where it doesn't, reject it.

## The labelling contract

Ground truth comes from construction, never from judgement. Every `Attempt`
carries `label` — `"honest"` or an abuse class name — decided when it is built.

Two rules that are load-bearing:

**Honest attempts must appear inside abusive sessions.** Draining a mandate
requires four legitimate charges first. Those are labelled honest and count
toward the false-decline rate, so a gate that panics after the third charge is
penalised rather than praised. A session of pure abuse is not a test, it is a
demonstration.

**One realistic policy governs every session.** Do not give an abuse class its
own tailored policy to isolate it — that inflates recall by removing the chance
of constraint interference. The cost is that several codes can fire at once, so
recall means "refused at all" and attribution is reported separately.

## Boundary scenarios are the real test

`BOUNDARY_SESSIONS` are honest attempts sitting *exactly* on a limit: charges
summing to the cumulative cap to the paisa, precisely `max_charges` charges, the
rate limit filled inside one window, the final second before expiry, a correct
retry reusing its key.

Comfortable mid-range honest traffic can never expose an inclusive/exclusive
slip. These can. **Every new constraint needs a boundary scenario in the same
commit**, or the false-decline rate stops meaning anything for that constraint.

Abuse classes deserve the same treatment: prefer `drain_by_one_paisa` over a
gross overshoot. A check that only catches obvious violations is not a check.

## The integrity preflight gates every score

`tools/run_harness.py` prints nothing until two controls pass.

**Control A — policy stripped.** The rail alone must decline almost nothing and
catch little. If recall is already high with no policy, the labelled abuse was
never abusive and the headline is measuring nothing. Expected recall is low and
non-zero: the remainder is the rail catching its own ceiling violations.

**Control B — refuse everything.** Both metrics must saturate. If either stays
low, they are not wired to the decisions.

If you change the corpus and a control fails, **the corpus is wrong**, not the
control. Do not loosen a threshold to make a run pass.

## Splits

Stratify by scenario family. A plain shuffle once dropped an entire abuse class
out of the holdout, and the report omitted it silently rather than scoring it.
`run_harness.py` asserts every abuse class survives into the holdout and exits
non-zero otherwise.

Seed everything. `random.Random(seed)` only — no module-level `random`, no wall
clock. Every published number must be reproducible by a stranger.

## Reading the numbers honestly

**Recall from author-written attacks is an upper bound, not a measurement.** The
same person wrote the abuse generator and the checks, so each class trips the
check built for it. 100% demonstrates wiring. It does not demonstrate that
detection is hard, and it must never be reported without that caveat.

**The false-decline rate is the trustworthy half.** It measures whether the
policy layer breaks legitimate use, and the boundary scenarios make it a real
test rather than a formality.

**A third-party attacker changes the standing of the recall figure.** An
attacker that neither wrote nor read the checks — a fuzzer searching the
boundary space, or a model given the schema and a goal — produces recall that is
evidence rather than tautology. Report attacker classes separately; never merge
author-written and independent results into one number.

## No silent caps

If a run bounds coverage — sampling, top-N, a retry limit — `log()` what was
dropped. Silent truncation reads as full coverage.
