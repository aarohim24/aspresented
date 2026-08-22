"""
AP2 (Agent Payments Protocol) intent and cart mandates.

AP2's mandates are signed verifiable credentials: an Intent Mandate delegating
authority, and a Cart Mandate binding a signature to a specific cart at a
specific price. That signature chain is genuinely valuable -- it is the one
format of the three that gives intent binding for free.

What it does not give is any spend ceiling at all. There is no per-charge
maximum in an intent mandate, let alone a cumulative one. AP2 answers "did the
user approve this cart" and is silent on "how much may be spent in total".

Mapper only in this build; not wired to a live AP2 endpoint.
"""

from __future__ import annotations

from ..envelope import Limits, MandateEnvelope


class AP2Adapter:
    SOURCE = "ap2-intent-mandate"
    WIRED = False         # fixture-verified mapper

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        intent = raw.get("intent_mandate") or {}
        cart = raw.get("cart_mandate") or {}

        # A cart mandate binds a signature to one cart, which is intent
        # binding in the strict sense: this charge, this basket, this price.
        has_binding = bool(cart.get("cart_hash") and cart.get("signature"))

        expiry = intent.get("expires_at")
        return MandateEnvelope(
            mandate_id=intent.get("id") or cart.get("id") or "",
            source=cls.SOURCE,
            subject=intent.get("subject") or "",
            rail=Limits(
                # No spend ceiling exists anywhere in the AP2 mandate chain.
                per_charge_max=None,
                expires_at=int(expiry) if expiry is not None else None,
                cumulative_max=None,
                max_charges=None,
                rate_limit=None,
                scope=None,
                requires_intent_binding=has_binding,
            ),
            raw=raw,
        )
