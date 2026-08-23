# as-presented

Python library and local console that supply the constraints a payment mandate
cannot express, bind each charge to the intent that justified it, and record
every decision in a tamper-evident log so a merchant can show what was
authorised when a charge is disputed.

Not a payment gateway, not a fraud model, and not a replacement for a rail's
own enforcement. It sits in front of a rail and adds what the rail has no field
to hold.

## Tech Stack

Python 3.9+ · standard library only · `unittest` · `http.server` for the
console. AI tooling (the adversarial attacker) is an optional extra so the core
stays dependency-free.

## Quick Start

```bash
pip install -e .                    # installable library; no dependencies
python3 -W error::ResourceWarning -m unittest discover -s tests -t .  # 238 tests
python3 tools/run_harness.py        # integrity preflight, then held-out scores
python3 tools/gen_coverage.py       # regenerate the README coverage table
python3 tools/gen_hero.py           # regenerate the README figure, by measuring
python3 tools/run_attack.py          # adversarial sweep + invariant oracle
python3 tools/run_buyer.py           # an AI buyer shopping end to end
python3 tools/run_delegation.py      # delegation: narrow offline, never widen
python3 tools/serve.py              # console at http://127.0.0.1:8700

export RZP_KEY_ID=rzp_test_... RZP_KEY_SECRET=...
python3 probes/probe3_schema.py     # reproduce the finding against the live API
```

## Architecture

```
native mandate JSON
  -> adapters/<rail>.py            normalise, declare only what the rail enforces
  -> envelope.MandateEnvelope      rail limits | policy limits -> effective
  -> gate.Gate.authorize()         policy checks, then the rail
       -> ledger.Ledger            append-only hash chain (also the state)
       -> rail.RailSimulator       documented enforcement only
  -> adjudicate.Adjudicator        dispute-time verdict, from the ledger alone

attack/  an attacker sees only what a mandate holder sees; the gate decides;
         invariants.check judges the finished ledger independently
buyer/   a person's instruction -> a signed, clamped intent -> shopping ->
         refusals read and acted on. Catalogue text is untrusted input.
llm.py   shared OpenAI-compatible chat client for both
```

- **Owns:** the constraint vocabulary, policy evaluation, the decision log, and
  dispute adjudication.
- **Does NOT own:** authorising mandates, moving money, or deciding what a rail
  should enforce.
- **The ledger is the state.** Cumulative totals, counts and rate windows are
  derived by replaying it, never from a counter kept alongside.
- **Adjudication trusts nothing in memory.** Signatures are re-derived from the
  recorded copy; position is recomputed from preceding entries.

## Domain Entities

- **`Limits`** — a constraint set. `declared()` reports which constraints it
  actually pins down; `None` means unconstrained, which is the whole problem
  when it describes a rail.
- **`MandateEnvelope`** — `rail` + `policy`, with `effective` taking the tighter
  of each field and `unenforced_by_rail` naming what only this layer supplies.
- **`Authority`** — a chain of caveats over a mandate. Any holder can narrow it
  offline; nobody can widen it. Folds into `Limits`, so the gate needed no
  change. Verification needs the root secret, so it secures delegation between
  holders, not issuance against the merchant.
- **`Intent`** — what the principal asked for. HMAC-signed; the thing a charge
  must be justified by.
- **`ChargeRequest` / `Decision` / `Refusal`** — a charge attempt, its outcome,
  and a refusal that names the field *and* the fix.
- **`Ledger`** — hash-chained JSONL. Editing or removing an entry breaks
  verification of everything after it.
- **`Adjudicator`** — `AUTHORISED` / `UNAUTHORISED` / `UNPROVABLE`.

## Key Patterns & Gotchas

- **Amounts are integer paise.** Never floats, never rupees. 100 paise = ₹1.
- **`frequency: "as_presented"` is not a rate limit.** It means *charge whenever
  presented*, and it is the default for new Razorpay merchants. Fixed buckets
  (`daily`/`weekly`/`monthly`/`quarterly`/`yearly`) do impose one debit per
  cycle — that distinction is load-bearing and must not be flattened.
- **The Razorpay token object is a strict allowlist** of `max_amount`,
  `expire_at`, `frequency`, `type`. The adapter raises on anything else,
  mirroring the live API. Never widen it to be helpful.
- **An adapter must never invent a constraint** the rail does not enforce. A
  false `rail` limit makes the gate stand down where it should act.
- **A policy limit with no check is worse than no limit.** `per_charge_max` sat
  in `effective` for weeks, computed correctly, consulted by nothing. When you
  add a field to `Limits`, add the check and a boundary scenario in the same
  commit.
- **The server clock is authoritative for policy.** A caller-supplied timestamp
  is untrusted input; using it for rate or expiry decisions is exploitable.
- **Rail limits, never effective limits, go into `RailSimulator`.** Passing
  policy limits there silently moves enforcement and erases what is measured.
- **`token.confirmed` signals mandate success; auth-time `payment.failed` must
  be ignored.** Razorpay's own SBMD guide says so. Getting it backwards
  misfires the whole gate.
- **A repeated idempotency key is answered, not refused.** Refusing correct
  retries was a real bug here; `DUPLICATE_CHARGE` targets the keyless retry
  storm instead.
- **The rail simulator must stay dumb.** A generous simulator flatters the gate
  and makes every measured number meaningless.
- **`tools/gen_coverage.py` generates the README table.** Edit adapters, not the
  table. `tests/test_readme.py` compares the committed copy against the
  generator's output, so drift fails the build.
- **The README's quickstart is executed by the test suite.** It is the only
  claim a reader can paste and run, so changing a public signature means
  changing that block in the same commit. Same rule for `docs/hero.svg`, which
  is measured by `tools/gen_hero.py` rather than drawn.
- **Claims are scoped to the trust boundary they hold in.** Signing here is
  symmetric, so the evidence is sound where issuer and verifier share a
  boundary (a merchant constraining its own agents; an agent subcontracting)
  and insufficient for adjudication against the principal. Never let prose
  widen past that -- weaken the claim instead.

## Working Rules

Derived from Andrej Karpathy's observations on how coding agents fail, and
enforced here because a project whose subject is *provable restraint* cannot
afford speculative code.

1. **Think before coding.** Don't assume, don't hide confusion, surface
   tradeoffs. If two readings of a request differ materially, ask.
2. **Simplicity first.** The minimum code that solves the problem. Nothing
   speculative, no premature abstraction. A dead field pretending to be a
   feature is worse than an absent one.
3. **Surgical changes.** Touch only what the task requires. Match the
   surrounding style rather than improving it. Clean up your own mess only.
4. **Goal-driven execution.** State the success criterion, then loop until it
   verifies. For this repo that means: tests green under
   `-W error::ResourceWarning`, the harness preflight passing, and the coverage
   table regenerated.

Two repo-specific additions:

5. **Never overclaim in prose.** Every number in the README is reproducible and
   every limitation is stated before results. If a change makes a claim less
   provable, weaken the claim in the same commit.
6. **Prefer a narrower true statement to a broader plausible one.** The
   `frequency` correction above began as a broad claim that did not survive
   contact with the docs.

## Skills Index

| Skill | Trigger |
|-------|---------|
| **mandate-invariants** | Touching envelopes, adapters, limits, or anything money-shaped |
| **adversarial-eval** | Adding an abuse class, a boundary case, or reading harness numbers |
| **adversarial-attack** | Writing or extending an attacker; reading a sweep |
| **buying-agent** | Touching the buyer, the catalogue, or intent interpretation |
| **delegated-authority** | Touching authority, caveats, or attenuation |
| **evidence-integrity** | Touching the ledger, intents, or the adjudicator |
| **rail-adapter** | Adding support for a new payment rail |

## Agent Config

| File | Purpose |
|------|---------|
| `AGENTS.md` | This file — service map and invariants |
| `CLAUDE.md` | Symlink → `AGENTS.md` |
| `.agents/skills/*/SKILL.md` | Task-scoped rules, loaded on the triggers above |
