---
name: mandate-invariants
description: Rules that must hold whenever you touch mandate envelopes, rail adapters, limits, or any money-carrying value in as-presented. Use when editing mandate_gate/envelope.py, mandate_gate/adapters/*, mandate_gate/gate.py, or adding a constraint type. Covers paise arithmetic, the rail-versus-policy boundary, why an adapter may never invent a constraint, and the frequency semantics that are easy to flatten.
---

# Mandate invariants

The project's entire claim is that it states honestly what each rail does and
does not enforce. Every rule here protects that claim.

## Money

Amounts are **integer paise**, everywhere, always. 100 paise = ₹1.

Never introduce a float into an amount path. Never accept rupees at an API
boundary and convert inside — convert at the edge and keep paise internal.
Razorpay's own integration guide flags this as the most common integration bug:
passing `20` creates an order for ₹0.20, not ₹20.

Display conversion belongs in presentation code only (`tools/serve.py`,
`harness/metrics.py`).

## The rail / policy boundary

`Limits` appears twice in an envelope and the two are not interchangeable.

- `rail` — what the payment network will enforce on its own, with no help.
- `policy` — what the merchant additionally requires, enforced by this layer.

**`effective` takes the tighter of each field.** Policy may narrow, never widen:
a policy that tried to raise a rail ceiling would be unenforceable anyway,
because the rail refuses first.

Three consequences:

1. **An adapter must never declare a constraint the rail does not enforce.** A
   false `rail` limit makes the gate stand down where it should act — the worst
   possible failure for this project, because it is silent.
2. **`RailSimulator` takes `rail` limits, never `effective`.** Passing effective
   limits moves enforcement into the simulated rail and erases the distinction
   the whole harness exists to measure.
3. **If `unenforced_by_rail` is ever empty, something is wrong.** Either the
   adapter is overclaiming or policy is not configured. It is never legitimately
   empty in this codebase.

## Constraint semantics that are easy to get wrong

**`frequency: "as_presented"` is not a rate limit.** It means charge whenever
presented. It is the default frequency for new Razorpay merchants, and it is the
setting the project is named after.

The fixed buckets — `daily`, `weekly`, `monthly`, `quarterly`, `yearly` — *do*
impose a cadence: one debit per billing cycle, with NPCI permitting up to three
retries inside a cycle. So Razorpay expresses a **coarse** rate limit for those
values and **none** under `as_presented`.

Do not flatten this into "Razorpay has no rate limit". That statement is false
and a reviewer who knows the product will catch it. The true statement is
narrower and stronger.

**`max_amount` is per charge, not cumulative.** The token exposes a running
`amount_debited` that is observable and not enforced against. Reading it is
fine; treating it as a limit is the bug this project is about.

**Expiry is a ceiling, not a schedule.** `expire_at` caps at 90 days out and
says nothing about cadence within that window.

## The Razorpay token allowlist

Verified against the live orders API: the token object accepts exactly
`max_amount`, `expire_at`, `frequency`, `type`. Seven other field names were
rejected with `<field> is/are not required and should not be sent`. Evidence in
`evidence/schema-findings.json`.

`RazorpayUpiAdapter.normalise` raises on any field outside that set. **Do not
widen it to be accommodating.** Accepting a field the API rejects would let a
caller believe a cap took effect when no such limit exists anywhere.

If you believe the allowlist has changed, re-run `probes/probe3_schema.py` and
update the evidence file in the same commit. Do not update the code from memory.

## Clocks

**The server clock is authoritative for every policy decision.** A timestamp
supplied by the caller is untrusted input.

Using a caller-supplied time for rate limiting, expiry, or duplicate detection
is exploitable: an agent that advances the timestamp it reports walks straight
through a rate limit. Caller-supplied time may be recorded as a claim; it may
not be evaluated against.

## Before you commit

- `python3 -W error::ResourceWarning -m unittest discover -s tests -t .`
- `python3 tools/gen_coverage.py` — if the table changed, the README changes too
- If a claim in the README is now less provable, weaken the claim in the same
  commit
