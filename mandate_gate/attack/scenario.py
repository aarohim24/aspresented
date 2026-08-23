"""
The demo scenario, defined once.

A recorded attack transcript is only meaningful alongside the mandate it was
run against: the same proposals replayed against a different policy, or against
intents with different ids, produce different outcomes. This was not a
hypothetical -- a test replaying the committed transcript against a separately
defined scenario extracted zero, because every charge referenced an intent id
that did not exist there.

So the scenario lives here and the tool, the tests and any replay all import
it. Duplicating it is how a committed piece of evidence quietly stops
reproducing.
"""

from __future__ import annotations

from ..charge import Intent
from ..envelope import Limits, MandateEnvelope, Scope, Window

T0 = 1_700_000_000
HOUR = 3600
CEILING = 500
MANDATE_ID = "token_attack"

#: The rail as verified against the live API: a per-charge ceiling and an
#: expiry, and nothing else. `frequency: as_presented` imposes no cadence.
RAIL = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)

#: What the merchant adds. Every field here is one the rail has no room for.
#: The attacker never sees this.
POLICY = Limits(
    cumulative_max=2000,
    max_charges=6,
    rate_limit=Window(seconds=HOUR, max_charges=4),
    scope=Scope(merchants=frozenset({"shop-a", "shop-b"})),
    requires_intent_binding=True,
)

#: What the principal actually asked for.
INTENTS = (
    Intent(intent_id="int_weekly", mandate_id=MANDATE_ID,
           max_amount=CEILING, expires_at=T0 + 6 * HOUR, merchant="shop-a"),
)


def envelope() -> MandateEnvelope:
    return MandateEnvelope(mandate_id=MANDATE_ID,
                           source="razorpay-upi-autopay",
                           subject="cust_attack", rail=RAIL, policy=POLICY)
