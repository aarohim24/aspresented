---
name: evidence-integrity
description: Rules for touching the as-presented decision ledger, signed intents, or the dispute adjudicator. Use when editing mandate_gate/ledger.py, mandate_gate/adjudicate.py, or anything that writes decisions. Covers append-only discipline, why the ledger is the state, what the adjudicator may and may not trust, and the UNPROVABLE verdict that must never be softened.
---

# Evidence integrity

Everything in this layer exists to answer one question weeks after the fact:
*was this charge authorised?* Any change that makes the answer less provable is
a regression, even if it makes the code nicer.

## Append-only, and that is the whole guarantee

Entries are written once. Each commits to its predecessor's digest, so editing
or removing any entry breaks verification of everything after it.

- **Never rewrite an entry.** A correction is a new entry, not an edit.
- **Never reorder.** `seq` and `prev_hash` are checked together.
- **Never add a field to the hashed payload without versioning.** Changing what
  is hashed invalidates every existing ledger, which is a migration, not a
  refactor.
- The chain is **tamper-evident, not tamper-proof.** It proves nobody rewrote
  history between the charge and the dispute. It claims nothing about
  distributed consensus, and the docstring must keep saying so.

## The ledger is the state

Cumulative totals, charge counts, rate windows and idempotency records are all
derived by replaying the ledger. There is no counter beside it.

This is deliberate: the number the gate enforces on is the same number it can
later prove. A cache would let the two diverge, and the divergence would surface
as an unexplainable dispute.

If replay cost becomes a problem, the fix is a **verifiable** checkpoint —
derived from the chain, re-derivable, and validated against it — not a
free-standing counter. Do not add a cache that cannot be recomputed.

## Intents

An `Intent` is signed with HMAC and the **signature is recorded in the ledger**,
so an adjudicator can re-verify from the record alone rather than trusting
whatever is in memory at dispute time.

- Sign over a canonical serialisation. Sorted keys, no incidental whitespace.
  Any change to the signed payload shape is a breaking change.
- Compare with `hmac.compare_digest`, never `==`.
- **Server-side HMAC proves the record was not altered. It does not prove a
  human authored it.** Real non-repudiation needs a device-held key. Say so
  wherever the guarantee is described; do not let it drift into implying more.
- Demo secrets must never be the default in library code. Read from the
  environment and fail loudly when absent.

## What the adjudicator may trust

**Nothing in memory.** At dispute time the process has restarted, the operator
may have changed, and the merchant has an incentive. So:

- Verify the chain **before** interpreting anything. A broken chain returns
  `UNPROVABLE` — it does not return a verdict with a warning attached.
- Re-derive intent signatures from the recorded copy.
- Recompute the position at the time of the charge from preceding entries. Never
  read a running total.
- Never consult `Gate.intents` or any live object.

## UNPROVABLE is a feature

Three verdicts: `AUTHORISED`, `UNAUTHORISED`, `UNPROVABLE`.

`UNPROVABLE` means the charge was allowed and nothing on record establishes what
the principal asked for. **This is the evidence gap the project describes.** A
mandate without intent binding returns it every time, and that is correct — it
is the state every agent purchase on today's rails is in.

Do not soften it. Do not add a "probably authorised" verdict, a confidence
score, or a fallback that infers intent from behaviour. The value of the verdict
is that it refuses to guess.

## No model in the verdict path

Adjudication must be deterministic and reproducible. An LLM anywhere in the
verdict path destroys the property that makes this evidence rather than opinion.

Models belong in the attacker and in interpreting natural-language intent
*before* it is signed. They do not belong in deciding what happened.

## Before you commit

- Tests must cover the tamper cases, not just the happy path: edited payload,
  removed entry, rewritten intent terms, wrong secret.
- `python3 -W error::ResourceWarning -m unittest discover -s tests -t .` — a
  leaked file handle in an append-only-log project is a real defect.
