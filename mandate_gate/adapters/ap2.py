"""
AP2 (Agent Payments Protocol) open mandates.

Mapped against the published schemas, not from memory. An earlier version of
this file modelled "IntentMandate" and "CartMandate" objects that do not exist
in the specification, and consequently understated what AP2 can express by a
wide margin. The real objects are `checkout_mandate` and `payment_mandate`,
each with an `open_*` standing-authority variant. Copies of the two `open_*`
schemas live in `evidence/` so this mapping can be checked.

AP2 expresses a rich constraint vocabulary -- richer than anything a payment
rail offers today:

    amount_range          per-charge ceiling (min/max, minor units)
    budget                maximum TOTAL spend under agent_recurrence
    agent_recurrence      frequency + max_occurrences
    allowed_payees        merchant scope
    allowed_payment_instruments / allowed_pisps
    execution_date        not_before / not_after window
    cnf                   RFC 7800 key binding
    exp                   expiry

**These map to `policy`, not `rail`, and that placement is the point.** AP2 is
a credential format, not a network. The constraints are signed claims carried
to the merchant; the specification does not say who checks them, and no network
enforces them on the merchant's behalf. A signed constraint is a claim, not a
control -- so under this model AP2's rail tier declares only what a network
would guarantee unaided, which is nothing, and everything the credential
asserts becomes policy for this layer to enforce.

Mapper only; not wired to a live AP2 endpoint.
"""

from __future__ import annotations

from ..envelope import Limits, MandateEnvelope, Scope, Window

#: `agent_recurrence.frequency` is an open string in the schema. These are the
#: conventional cycle lengths; an unrecognised value yields no cadence rather
#: than a guess.
RECURRENCE_SECONDS = {
    "daily": 86_400,
    "weekly": 604_800,
    "monthly": 30 * 86_400,
    "quarterly": 90 * 86_400,
    "yearly": 365 * 86_400,
}


def _by_type(constraints) -> dict:
    """Index a constraints array by its `type` discriminator."""
    return {c.get("type"): c for c in (constraints or []) if isinstance(c, dict)}


class AP2Adapter:
    SOURCE = "ap2-open-mandate"
    WIRED = False         # schema-verified mapper; no live AP2 endpoint

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        payment = raw.get("open_payment_mandate") or {}
        checkout = raw.get("open_checkout_mandate") or {}

        pay_c = _by_type(payment.get("constraints"))
        chk_c = _by_type(checkout.get("constraints"))

        # --- per-charge ceiling
        amount_range = pay_c.get("payment.amount_range") or {}
        per_charge = amount_range.get("max")

        # --- cumulative cap: this is the constraint the project claimed no
        #     format expressed. AP2 names it outright.
        budget = pay_c.get("payment.budget") or {}
        cumulative = budget.get("max")

        # --- recurrence: both a cadence and a count
        recurrence = pay_c.get("payment.agent_recurrence") or {}
        seconds = RECURRENCE_SECONDS.get(recurrence.get("frequency"))
        occurrences = recurrence.get("max_occurrences")
        rate = (Window(seconds=seconds, max_charges=1)
                if seconds is not None else None)

        # --- scope: payees on the payment mandate, merchants on the checkout one
        payees = (pay_c.get("payment.allowed_payees") or {}).get("allowed") or []
        merchants = (chk_c.get("checkout.allowed_merchants") or {}).get("allowed") or []
        names = frozenset(
            str(m.get("id") or m.get("name") or m) if isinstance(m, dict) else str(m)
            for m in list(payees) + list(merchants)
        )
        scope = Scope(merchants=names) if names else None

        # --- key binding is AP2's intent binding
        bound = bool(payment.get("cnf") or checkout.get("cnf"))

        expiry = payment.get("exp") or checkout.get("exp")

        return MandateEnvelope(
            mandate_id=(payment.get("jti") or checkout.get("jti")
                        or payment.get("vct") or checkout.get("vct") or ""),
            source=cls.SOURCE,
            subject=str(payment.get("sub") or checkout.get("sub") or ""),
            # Nothing. AP2 is a credential format; no network enforces these
            # claims for the merchant. Declaring them here would tell the gate
            # to stand down on constraints that in fact nobody is checking.
            rail=Limits(),
            policy=Limits(
                per_charge_max=int(per_charge) if per_charge is not None else None,
                expires_at=int(expiry) if expiry is not None else None,
                cumulative_max=(int(cumulative)
                                if cumulative is not None else None),
                max_charges=(int(occurrences)
                             if occurrences is not None else None),
                rate_limit=rate,
                scope=scope,
                requires_intent_binding=bound,
            ),
            raw=raw,
        )
