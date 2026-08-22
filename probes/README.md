# Probes

Live API reconnaissance, kept because the negative results are part of the
evidence and because anyone reproducing the finding should see what was tried.

| Probe | Outcome |
|---|---|
| `probe2_authorize.py` | **Blocked at its own preflight**, which is what it is for. Probes `/v1/payments/create/recurring` with deliberately invalid ids: a route-not-found means the whole recurring surface needs account activation, and it stops before sending anyone to a browser for nothing. |
| `probe2_drain.py` | **Not reached.** Would run six charges at the ceiling against a live mandate. Waiting on recurring activation. |
| `probe3_schema.py` | **The one that answered the question.** Needs no gated endpoint. Establishes the documented SBMD token shape is accepted, then tries seven ways to express a total, a rate or a scope. All seven rejected by name. Output in `../evidence/schema-findings.json`. |

A first probe that guessed `/v1/payments/create/upi` has been removed rather
than kept as decoration -- it was a wrong guess, and the reusable idea lives in
probe2's preflight. The lesson worth keeping: `"The requested URL was not found on the server"` is
how this API reports a route that exists but is not enabled for the merchant.
It reads like a wrong path. Distinguishing the two -- by probing with knowingly
invalid data and reading whether the complaint is about routing or about
fields -- is what unblocked the work.

## Reproducing the finding

```bash
export RZP_KEY_ID=rzp_test_...
export RZP_KEY_SECRET=...
python3 probes/probe3_schema.py
```

Creates orders only. No money moves.
