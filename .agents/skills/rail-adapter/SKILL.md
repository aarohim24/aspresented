---
name: rail-adapter
description: How to add a payment rail adapter to as-presented without weakening its central claim. Use when adding a file under mandate_gate/adapters/ or extending an existing one. Covers the honesty contract, the WIRED distinction between live and fixture-backed adapters, where fixtures must come from, and the tests a new adapter owes.
---

# Adding a rail adapter

An adapter does one job: translate a rail's native mandate into a
`MandateEnvelope`, declaring honestly what that rail enforces. It holds no
policy and makes no decisions.

## The honesty contract

**Declare only what the rail actually enforces, unaided.**

Every `None` in a `rail` limit is a claim: *this network will not stop that.* If
you set a value the rail does not enforce, the gate stands down where it should
act — and it does so silently. That is the worst failure mode available to this
codebase.

When uncertain whether a rail enforces something, **leave it `None` and note the
uncertainty in the docstring.** An over-cautious gate costs a false decline you
will measure. An over-trusting one costs money you will not.

**Reject what the upstream API rejects.** If the rail refuses a field, the
adapter raises. `RazorpayUpiAdapter` does this for its token allowlist, so no
caller can believe a constraint took effect when the rail has no field for it.

**Read the constraint, do not infer it from the name.** `frequency:
"as_presented"` reads like a cadence setting and imposes none. Names lie;
schemas and documented behaviour do not.

## WIRED is a factual claim, not a label

```python
WIRED = True    # this adapter talks to a live API in this build
WIRED = False   # mapper verified against recorded fixtures
```

A test asserts exactly one adapter is `WIRED`. If you wire a second, update that
test deliberately — and update the README, which states which is which. Blurring
this is the one thing that would make the project's measured numbers dishonest.

## Fixtures

A `WIRED = False` adapter is only as good as its fixture.

- **Best:** a payload captured from a live API or a conformance suite, with its
  provenance recorded in the docstring or `evidence/`.
- **Acceptable:** a payload transcribed from the published specification, cited.
- **Not acceptable:** a payload written from memory of roughly what the format
  looks like. That produces an adapter that maps a rail nobody has ever seen,
  and a generalisation claim resting on your own guess.

If a fixture's provenance is weak, say so in the README rather than letting the
coverage table imply parity with the verified rail.

## Tests a new adapter owes

1. Maps its fixture to the expected envelope.
2. `rail.declared()` equals exactly the intended constraint set — this is the
   assertion that pins the honesty contract.
3. `rail.declared()` intersected with `UNIVERSALLY_ABSENT` is empty, unless the
   rail genuinely expresses one of those, in which case
   `tests/test_adapters.py::TestTheGeneralClaim` must be updated and the README
   claim narrowed in the same commit.
4. Rejects a field the upstream API rejects, if the rail has an allowlist.
5. Any name-versus-behaviour trap has its own named test, as
   `test_as_presented_is_not_a_rate_limit` does.

## Then regenerate

```bash
python3 tools/gen_coverage.py
```

Paste the output into the README. The table is generated so it cannot drift from
the adapters — CI regenerates it and fails on a mismatch. If a new adapter
changes which constraints are absent everywhere, the prose around the table
changes too.
