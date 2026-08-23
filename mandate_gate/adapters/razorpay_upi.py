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

`frequency` is the subtle one, and an earlier version of this adapter got it
wrong. The fixed buckets -- daily, weekly, monthly, quarterly, yearly -- do
impose a cadence: one debit per billing cycle. So Razorpay *does* express a
coarse rate limit, for those values.

`as_presented` expresses none. It means charge whenever presented, and it is
the default frequency for new Razorpay merchants. The rail this project is
named after is the rail configured the default way.

So: a per-charge ceiling, an expiry, and a cycle cadence that vanishes under
the default. No cumulative cap and no charge-count cap under any value.
"""

from __future__ import annotations

from ..envelope import Limits, MandateEnvelope, Window

#: Fields the token object accepts. Anything else is rejected by the API.
ALLOWED_TOKEN_FIELDS = frozenset({
    "max_amount", "expire_at", "frequency", "type",
})

#: `frequency` values that impose no cadence whatsoever.
UNBOUNDED_FREQUENCIES = frozenset({"as_presented"})

#: Cycle length in seconds for the fixed buckets. One debit per cycle.
#: Month/quarter/year are the conventional 30/90/365-day approximations --
#: the rail bills on calendar boundaries, so treat these as indicative.
CYCLE_SECONDS = {
    "daily": 86_400,
    "weekly": 604_800,
    "monthly": 30 * 86_400,
    "quarterly": 90 * 86_400,
    "yearly": 365 * 86_400,
}


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
                # One debit per billing cycle for the fixed buckets; nothing
                # at all under `as_presented`. NPCI permits up to three
                # retries inside a cycle, so this bounds settled debits, not
                # attempts.
                rate_limit=cls._cadence(token.get("frequency")),
                # Deliberately None. The rail has no field for either, so
                # claiming otherwise would be a lie the gate would act on.
                cumulative_max=None,
                max_charges=None,
                scope=None,
                requires_intent_binding=False,
            ),
            raw=raw,
        )

    @classmethod
    def _cadence(cls, frequency) -> "Window | None":
        """The rate limit `frequency` actually implies, if any."""
        if frequency in UNBOUNDED_FREQUENCIES or frequency is None:
            return None
        seconds = CYCLE_SECONDS.get(frequency)
        if seconds is None:
            # Unknown value: claim nothing rather than guess a cadence.
            return None
        return Window(seconds=seconds, max_charges=1)

