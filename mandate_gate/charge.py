"""
Charges, intents, and decisions.

An `Intent` is the record of what the principal actually asked for: spend up to
this much, at this merchant, before this time. A `ChargeRequest` is an agent
asking to move money. The gate's job is to decide whether the second is
justified by the first, and to say why not in terms an agent can act on.

Intents are signed server-side with an HMAC. That proves the record was not
altered after it was written. It does *not* prove a specific human authored it
-- real non-repudiation needs a device-held key. The README says so plainly;
so does this docstring, because the distinction matters.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


#: The fields an intent's signature covers. Anything added to `Intent` without
#: being added here is unsigned and therefore forgeable, so the list is
#: explicit rather than derived from the dataclass.
INTENT_SIGNED_FIELDS = ("intent_id", "mandate_id", "max_amount",
                        "expires_at", "merchant", "category")


def intent_signature(fields: dict, secret: bytes) -> str:
    """
    Derive an intent signature from a mapping of the signed fields.

    Both the signer and the dispute-time verifier call this. They used to build
    the payload separately, which meant a new signed field could be added in
    one place and silently ignored in the other -- leaving a verifier that
    validates a subset of what was signed.
    """
    payload = {k: fields.get(k) for k in INTENT_SIGNED_FIELDS}
    return hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Intent:
    """What the principal asked for. The thing a charge must be justified by."""

    intent_id: str
    mandate_id: str
    max_amount: int                  # paise; ceiling for charges under this intent
    expires_at: int
    merchant: str | None = None
    category: str | None = None
    signature: str = ""

    def _payload(self) -> dict:
        return {k: getattr(self, k) for k in INTENT_SIGNED_FIELDS}

    def signed(self, secret: bytes) -> "Intent":
        return replace(self,
                       signature=intent_signature(self._payload(), secret))

    def signature_valid(self, secret: bytes) -> bool:
        if not self.signature:
            return False
        return hmac.compare_digest(
            intent_signature(self._payload(), secret), self.signature)


@dataclass(frozen=True)
class ChargeRequest:
    """
    An agent asking to move money against a mandate.

    Note what is absent: a timestamp the gate will act on. `claimed_at` is
    whatever the caller says the time is, and it is untrusted -- recorded as a
    claim, compared against the server clock for skew, and never used to decide
    anything. An earlier version of this class carried an authoritative `at`,
    and an agent that simply advanced it walked straight through the rate limit.
    """

    mandate_id: str
    amount: int                      # paise
    idempotency_key: str
    intent_id: str | None = None
    merchant: str | None = None
    category: str | None = None
    #: Caller-asserted time. Untrusted input. Optional -- most clients send none.
    claimed_at: int | None = None

    def __post_init__(self) -> None:
        if self.amount <= 0:
            raise ValueError("charge amount must be positive")
        if not self.idempotency_key:
            raise ValueError("idempotency_key is required")


@dataclass(frozen=True)
class Refusal:
    """
    Why a charge was refused, in terms an agent can act on.

    `remediation` exists because a bare 403 teaches an agent nothing: it will
    retry the same call. Naming the field and the fix is what lets a
    well-behaved agent correct itself instead of hammering.
    """

    code: str
    field: str
    detail: str
    remediation: str

    def as_dict(self) -> dict:
        return {"code": self.code, "field": self.field,
                "detail": self.detail, "remediation": self.remediation}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    refusals: tuple = ()
    rail_error: str | None = None
    charge_id: str | None = None
    refused_by: str | None = None    # "policy" | "rail" | None
    #: True when this is the recorded answer to a key already seen. A correct
    #: idempotent replay is not a refusal -- see Gate.authorize.
    replayed: bool = False

    @property
    def codes(self) -> tuple:
        return tuple(r.code for r in self.refusals)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "replayed": self.replayed,
            "refused_by": self.refused_by,
            "refusals": [r.as_dict() for r in self.refusals],
            "rail_error": self.rail_error,
            "charge_id": self.charge_id,
        }
