#!/usr/bin/env python3
"""
One agent hiring another, without handing over the wallet.

    python3 tools/run_delegation.py

Agents already subcontract. A shopping agent calls a delivery agent, an
orchestrator fans work out to workers, a tool calls a tool. Every payment
mandate in production today is a single flat grant, so the only way to let a
sub-agent spend is to give it the whole credential. There is no way to hand over
less.

This walks a three-link chain -- principal, shopping agent, delivery agent --
where each link narrows what the next one may do, offline, with no round trip to
the principal and no new credential issued. Then it tries the three ways a holder
might cheat.

The gate is unchanged. Authority folds into limits and limits are what the gate
already enforces, so delegation cost the enforcement path nothing.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mandate_gate.attack import scenario                         # noqa: E402
from mandate_gate.authority import Authority, Caveat, admit      # noqa: E402
from mandate_gate.charge import ChargeRequest, Intent            # noqa: E402
from mandate_gate.envelope import MandateEnvelope                # noqa: E402
from mandate_gate.gate import Gate                               # noqa: E402
from mandate_gate.ledger import Ledger                           # noqa: E402
from mandate_gate.rail import RailSimulator                      # noqa: E402

#: Held by the principal's side. The merchant verifies with it, which is the
#: limitation this feature does not fix -- see the module docstring in
#: mandate_gate/authority.py.
ROOT_SECRET = os.environ.get("MANDATE_GATE_ROOT_SECRET",
                             "DEMO-ONLY-principal-root").encode()
SECRET = os.environ.get("MANDATE_GATE_INTENT_SECRET",
                        "DEMO-ONLY-not-a-secret-delegation").encode()
T0 = scenario.T0


def gate_for(limits, label):
    envelope = MandateEnvelope(
        mandate_id=scenario.MANDATE_ID, source="razorpay-upi-autopay",
        subject="cust_delegation", rail=scenario.RAIL, policy=limits)
    clock = {"now": T0}
    ledger = Ledger(os.path.join(tempfile.mkdtemp(), f"{label}.jsonl"),
                    clock=lambda: clock["now"])
    gate = Gate(envelope, ledger, RailSimulator(limits=scenario.RAIL), SECRET,
                clock=lambda: clock["now"])
    intent = gate.record_intent(Intent(
        intent_id="int_delegated", mandate_id=scenario.MANDATE_ID,
        max_amount=scenario.RAIL.per_charge_max,
        expires_at=T0 + 7 * 86400, merchant=None))
    return gate, intent


def try_charge(gate, intent, amount, merchant, label):
    decision = gate.authorize(ChargeRequest(
        mandate_id=scenario.MANDATE_ID, amount=amount,
        idempotency_key=f"{label}-{amount}-{merchant}",
        intent_id=intent.intent_id, merchant=merchant))
    verdict = "allowed" if decision.allowed else f"REFUSED {list(decision.codes)}"
    print(f"      {amount:>5} paise at {merchant:<11} -> {verdict}")
    return decision


def main() -> int:
    print("\n" + "=" * 70)
    print("  DELEGATION -- handing over less, not everything")
    print("=" * 70)

    # --- link 1: the principal issues
    principal = Authority.issue(
        ROOT_SECRET, authority_id="auth-root",
        mandate_id=scenario.MANDATE_ID,
        caveats=[Caveat("per_charge_max", 500),
                 Caveat("cumulative_max", 2000),
                 Caveat("merchant_in", ("shop-a", "shop-b")),
                 Caveat("expires_at", T0 + 7 * 86400)])
    print(f"\n  1. principal issues")
    print(f"     {principal.describe()}")

    # --- link 2: the shopping agent narrows for a sub-agent, offline
    shopping = principal.attenuate(
        Caveat("per_charge_max", 200),
        Caveat("merchant_in", ("shop-a",)))
    print(f"\n  2. shopping agent narrows for a delivery agent")
    print(f"     adds: per_charge_max<=200, merchant_in=['shop-a']")
    print(f"     no root secret used, no round trip to the principal")

    # --- link 3: the delivery agent narrows again
    delivery = shopping.attenuate(Caveat("max_charges", 3))
    print(f"\n  3. delivery agent narrows again before calling a tool")
    print(f"     adds: max_charges<=3   (depth now {delivery.depth} caveats)")

    admission = admit(delivery, ROOT_SECRET, mandate_id=scenario.MANDATE_ID)
    if not admission.ok:
        print(f"\n  admission failed: {admission.reason}")
        return 1
    limits = admission.limits
    print(f"\n     folds to: per_charge<={limits.per_charge_max}, "
          f"total<={limits.cumulative_max}, "
          f"charges<={limits.max_charges}, "
          f"merchants={sorted(limits.scope.merchants)}")

    # --- what the last holder can actually do
    print("\n  " + "-" * 66)
    print("  WHAT THE LAST HOLDER CAN SPEND")
    print("  " + "-" * 66)
    # A fresh gate per probe. Sharing one lets an earlier refusal's counter
    # mask the constraint a later probe is meant to demonstrate -- which is how
    # a first version of this demo showed CHARGE_COUNT_EXCEEDED three times and
    # proved nothing about the ceiling or the scope.
    for amount, merchant, note in ((150, "shop-a", "inside every narrowing"),
                                   (400, "shop-a",
                                    "inside the principal's 500, outside its own 200"),
                                   (100, "shop-b",
                                    "inside the principal's scope, outside its own")):
        gate, intent = gate_for(limits, f"probe-{amount}-{merchant}")
        try_charge(gate, intent, amount, merchant, "probe")
        print(f"            {note}")

    gate, intent = gate_for(limits, "count")
    print("\n     and its own count cap, on one gate:")
    for i in range(4):
        try_charge(gate, intent, 100 + i, "shop-a", "count")

    print("\n     A holder is bound by every narrowing above it, including its own.")

    # --- the three ways to cheat
    print("\n  " + "-" * 66)
    print("  THE THREE WAYS TO TRY TO WIDEN IT")
    print("  " + "-" * 66)

    widened = delivery.attenuate(Caveat("per_charge_max", 100_000))
    folded = widened.to_limits()
    print(f"\n  a. append a looser caveat (per_charge_max<=100000)")
    print(f"     verifies: {widened.verify(ROOT_SECRET)}   "
          f"effective per_charge_max: {folded.per_charge_max}")
    print(f"     Inert. Folding takes the tighter, so a loose caveat says nothing.")

    stripped = Authority(delivery.authority_id, delivery.mandate_id,
                         delivery.caveats[:-1], delivery.signature)
    print(f"\n  b. drop the caveat it added itself, keep the signature")
    print(f"     verifies: {stripped.verify(ROOT_SECRET)}")
    print(f"     The chain is keyed on every link. Removing one breaks it.")

    edited = list(delivery.caveats)
    edited[0] = Caveat("per_charge_max", 100_000)
    tampered = Authority(delivery.authority_id, delivery.mandate_id,
                         tuple(edited), delivery.signature)
    print(f"\n  c. edit the principal's own caveat")
    print(f"     verifies: {tampered.verify(ROOT_SECRET)}")
    print(f"     Same reason. Recomputing needs the root secret it does not have.")

    print("\n  " + "=" * 66)
    print("  AUTHORITY ONLY EVER NARROWS")
    print("  " + "-" * 66)
    print("  Narrowing needs no secret, so an agent can subcontract mid-task.")
    print("  Widening needs the root secret, which no holder downstream has.")
    print("  The gate did not change: authority folds into limits, and limits")
    print("  are what it already enforced.")
    print("\n  Not solved: verification still needs the root secret, so a")
    print("  merchant holding it could forge an authority outright. That needs")
    print("  asymmetric signing, and it is named as such rather than implied.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
