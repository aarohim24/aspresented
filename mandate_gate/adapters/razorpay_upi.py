"""
Razorpay UPI Autopay / Reserve Pay (SBMD).

The native mandate is the `token` object on an authorization order. Its schema
is a strict allowlist of exactly four fields:

    max_amount   -- per-charge ceiling, in paise
    expire_at    -- unix expiry, max 90 days out
    frequency    -- "as_presented" and friends
    type         -- e.g. "single_block_multiple_debit"

Verified against the live orders API on 2026-08-22: seven attempts to add a
cumulative cap, a charge count, a rate or a scope were each rejected with
"<field> is/are not required and should not be sent". Evidence lives in
evidence/schema-findings.json.

So this rail enforces a per-charge ceiling and an expiry. Nothing else. Note
what `frequency: "as_presented"` actually means: charge whenever presented.
It reads like a rate limit and is not one.
"""

from __future__ import annotations

from ..envelope import Limits, MandateEnvelope

#: Fields the token object accepts. Anything else is rejected by the API.
ALLOWED_TOKEN_FIELDS = frozenset({
    "max_amount", "expire_at", "frequency", "type",
})

#: `frequency` values that impose no rate limit whatsoever.
UNBOUNDED_FREQUENCIES = frozenset({"as_presented"})


class RazorpayUpiAdapter:
    SOURCE = "razorpay-upi-autopay"
    WIRED = True          # live test-mode API; mandate orders created for real

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        token = raw.get("token") or {}

        unexpected = set(token) - ALLOWED_TOKEN_FIELDS
        if unexpected:
            # The live API would refuse this too. Fail here rather than let a
            # caller believe an unsupported constraint took effect.
            raise ValueError(
                f"fields not in the Razorpay token allowlist: "
                f"{sorted(unexpected)} -- the API rejects these by name"
            )

        max_amount = token.get("max_amount")
        return MandateEnvelope(
            mandate_id=raw.get("token_id") or raw.get("id") or "",
            source=cls.SOURCE,
            subject=raw.get("customer_id") or "",
            rail=Limits(
                per_charge_max=int(max_amount) if max_amount is not None else None,
                expires_at=(int(token["expire_at"])
                            if token.get("expire_at") is not None else None),
                # Deliberately left None. The rail has no field for any of
                # these, so claiming otherwise here would be a lie the gate
                # would then act on.
                cumulative_max=None,
                max_charges=None,
                rate_limit=None,
                scope=None,
                requires_intent_binding=False,
            ),
            raw=raw,
        )

    @classmethod
    def rate_is_unbounded(cls, raw: dict) -> bool:
        """True when `frequency` permits charges at any rate."""
        freq = (raw.get("token") or {}).get("frequency")
        return freq in UNBOUNDED_FREQUENCIES
