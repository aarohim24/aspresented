"""
Authority that can be narrowed by whoever holds it, and never widened.

Every mandate this project has looked at is a single flat grant. You hold it or
you do not. That was tolerable when a person held it, and it stops being
tolerable the moment agents subcontract -- which they already do: a shopping
agent calls a delivery agent, an orchestrator fans work out to workers, a tool
calls a tool. Today the only way to let a sub-agent spend is to hand it the
whole credential. There is no way to hand over *less*.

So: an `Authority` is a chain of caveats over a mandate, signed by chaining
HMACs the way macaroons do. Two properties fall out, and they are the point.

**Narrowing needs no secret.** `attenuate` uses the current signature as the key
for the next link, so any holder can add a restriction offline -- no round trip
to the principal, no new credential issued, no shared secret. A shopping agent
can hand a delivery agent a strictly weaker authority in the middle of a
purchase.

**Widening is impossible, three different ways.** Remove a caveat and the chain
no longer verifies. Edit one and the chain no longer verifies. Append a *looser*
caveat and it simply does nothing, because `to_limits` folds every caveat by
taking the tighter -- the same intersect-and-minimise logic that a bug in
`MandateEnvelope.effective` once got backwards. Attenuation is safe here
precisely because that was fixed.

## What this does not do

Verification needs the root secret, so a merchant holding it can still forge an
authority outright. Macaroons do not solve that and neither does this. Closing
it means asymmetric signing -- the principal signs with a private key, everyone
else verifies with the public one -- which needs a real crypto library and is
named in the README as the next thing rather than pretended away.

The honest summary: this makes *delegation* trustworthy between holders. It does
not yet make *issuance* provable to a third party.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace

from .envelope import Limits, Scope, Window

#: Caveat kinds, and the `Limits` field each one narrows. A caveat that does not
#: map to a limit could not be enforced, so the mapping is the whole vocabulary.
CAVEAT_KINDS = {
    "per_charge_max": "per_charge_max",
    "cumulative_max": "cumulative_max",
    "max_charges": "max_charges",
    "expires_at": "expires_at",
    "merchant_in": "scope",
    "category_in": "scope",
    "rate": "rate_limit",
}


def _canonical(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


@dataclass(frozen=True)
class Caveat:
    """One restriction. Values are plain data so a caveat is inspectable."""

    kind: str
    value: object

    def __post_init__(self) -> None:
        if self.kind not in CAVEAT_KINDS:
            raise ValueError(
                f"unknown caveat kind {self.kind!r}; a caveat that maps to no "
                f"limit could not be enforced. Known: "
                f"{sorted(CAVEAT_KINDS)}")

    def as_dict(self) -> dict:
        value = self.value
        if isinstance(value, (set, frozenset, tuple, list)):
            value = sorted(str(v) for v in value)
        return {"kind": self.kind, "value": value}

    def describe(self) -> str:
        if self.kind in ("merchant_in", "category_in"):
            return f"{self.kind}={sorted(str(v) for v in self.value)}"
        if self.kind == "rate":
            per, n = self.value
            return f"rate<={n} per {per}s"
        return f"{self.kind}<={self.value}"


def _tighter(a, b):
    """The more restrictive of two optional numbers."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


@dataclass(frozen=True)
class Authority:
    """
    A mandate, plus every restriction anyone has added to it on the way here.

    `signature` covers the identity and every caveat in order. It is not a
    field a holder can usefully set: any change to the caveats without the root
    secret leaves it inconsistent, and verification fails.
    """

    authority_id: str
    mandate_id: str
    caveats: tuple = ()
    signature: str = ""

    # ------------------------------------------------------------- issuance
    @staticmethod
    def _root(root_secret: bytes, authority_id: str, mandate_id: str) -> str:
        return hmac.new(root_secret,
                        _canonical([authority_id, mandate_id]),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _link(previous: str, caveat: Caveat) -> str:
        """
        Next signature in the chain, keyed by the previous signature.

        This is what makes narrowing possible without the root secret, and it
        is the only reason delegation can happen offline.
        """
        return hmac.new(bytes.fromhex(previous),
                        _canonical(caveat.as_dict()),
                        hashlib.sha256).hexdigest()

    @classmethod
    def issue(cls, root_secret: bytes, *, authority_id: str, mandate_id: str,
              caveats=()) -> "Authority":
        """Mint a root authority. Only the principal's side can do this."""
        if not root_secret:
            raise ValueError("a root secret is required to issue authority")
        signature = cls._root(root_secret, authority_id, mandate_id)
        caveats = tuple(caveats)
        for caveat in caveats:
            signature = cls._link(signature, caveat)
        return cls(authority_id=authority_id, mandate_id=mandate_id,
                   caveats=caveats, signature=signature)

    # ----------------------------------------------------------- delegation
    def attenuate(self, *caveats: Caveat) -> "Authority":
        """
        A strictly weaker authority. No secret needed.

        Anyone holding this can narrow it and pass it on. They cannot widen it:
        a looser caveat is inert because `to_limits` folds by taking the
        tighter, and tampering with an existing caveat breaks verification.
        """
        signature = self.signature
        for caveat in caveats:
            signature = self._link(signature, caveat)
        return replace(self, caveats=self.caveats + tuple(caveats),
                       signature=signature)

    @property
    def depth(self) -> int:
        """How many hands this has passed through, in caveats."""
        return len(self.caveats)

    # --------------------------------------------------------- verification
    def verify(self, root_secret: bytes) -> bool:
        """
        Recompute the chain. Any removal, reorder or edit fails.

        Note the trust model: this needs the root secret, so it establishes
        that a *holder* did not tamper. It does not establish that the verifier
        did not forge the whole thing. See the module docstring.
        """
        if not self.signature or not root_secret:
            return False
        expected = self._root(root_secret, self.authority_id, self.mandate_id)
        for caveat in self.caveats:
            expected = self._link(expected, caveat)
        return hmac.compare_digest(expected, self.signature)

    # -------------------------------------------------------------- folding
    def to_limits(self) -> Limits:
        """
        Every caveat folded into one set of limits, taking the tighter.

        Order does not matter and repetition is harmless, which is what makes
        appending a looser caveat inert rather than dangerous.
        """
        limits = Limits()
        for caveat in self.caveats:
            value = caveat.value
            if caveat.kind == "per_charge_max":
                limits = limits.tighten(per_charge_max=_tighter(
                    limits.per_charge_max, int(value)))
            elif caveat.kind == "cumulative_max":
                limits = limits.tighten(cumulative_max=_tighter(
                    limits.cumulative_max, int(value)))
            elif caveat.kind == "max_charges":
                limits = limits.tighten(max_charges=_tighter(
                    limits.max_charges, int(value)))
            elif caveat.kind == "expires_at":
                limits = limits.tighten(expires_at=_tighter(
                    limits.expires_at, int(value)))
            elif caveat.kind == "merchant_in":
                incoming = Scope(merchants=frozenset(str(v) for v in value))
                limits = limits.tighten(
                    scope=incoming if limits.scope is None
                    else limits.scope.intersect(incoming))
            elif caveat.kind == "category_in":
                incoming = Scope(categories=frozenset(str(v) for v in value))
                limits = limits.tighten(
                    scope=incoming if limits.scope is None
                    else limits.scope.intersect(incoming))
            elif caveat.kind == "rate":
                seconds, max_charges = value
                incoming = Window(seconds=int(seconds),
                                  max_charges=int(max_charges))
                current = limits.rate_limit
                limits = limits.tighten(
                    rate_limit=incoming if current is None
                    else min((current, incoming), key=lambda w: w.rate))
        return limits

    def describe(self) -> str:
        if not self.caveats:
            return "unrestricted"
        return " AND ".join(c.describe() for c in self.caveats)


@dataclass
class Admission:
    """The result of presenting an authority."""

    limits: Limits | None = None
    reason: str | None = None
    authority: Authority | None = None

    @property
    def ok(self) -> bool:
        return self.limits is not None


def admit(authority: Authority, root_secret: bytes, *,
          mandate_id: str, requires_intent_binding: bool = True) -> Admission:
    """
    Verify an authority and fold it into limits a gate can enforce.

    Deliberately thin, and deliberately outside the gate. The gate's job is to
    enforce limits; where those limits came from is a separate question, and
    keeping them separate means adding delegation required no change to the
    enforcement path at all.
    """
    if authority.mandate_id != mandate_id:
        return Admission(reason=(
            f"authority is for mandate {authority.mandate_id!r}, "
            f"presented against {mandate_id!r}"))
    if not authority.verify(root_secret):
        return Admission(reason=(
            "authority fails verification -- a caveat was removed, reordered "
            "or edited, or it was not issued by this principal"))

    limits = authority.to_limits()
    if requires_intent_binding:
        limits = limits.tighten(requires_intent_binding=True)
    return Admission(limits=limits, authority=authority)
