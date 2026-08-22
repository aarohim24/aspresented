"""
Card-on-file / network token.

The thinnest vocabulary of the three. A stored credential carries an expiry and
sometimes a merchant-category restriction, and that is the whole of it. There
is no per-charge ceiling, no total, no rate, and nothing tying a charge to a
stated intent -- which is why card-not-present disputes lean so heavily on
circumstantial evidence like IP and device fingerprints.

Mapper only in this build; not wired to a live card API.
"""

from __future__ import annotations

from ..envelope import Limits, MandateEnvelope, Scope


class CardOnFileAdapter:
    SOURCE = "card-on-file"
    WIRED = False         # fixture-verified mapper

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        mccs = raw.get("allowed_mcc") or []
        scope = Scope(categories=frozenset(str(m) for m in mccs)) if mccs else None
        expiry = raw.get("expires_at")

        return MandateEnvelope(
            mandate_id=raw.get("token_id") or "",
            source=cls.SOURCE,
            subject=raw.get("cardholder_ref") or "",
            rail=Limits(
                per_charge_max=None,
                expires_at=int(expiry) if expiry is not None else None,
                cumulative_max=None,
                max_charges=None,
                rate_limit=None,
                scope=scope,
                requires_intent_binding=False,
            ),
            raw=raw,
        )
