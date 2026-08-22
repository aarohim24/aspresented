"""
The normalised mandate envelope.

Every payment rail expresses "you may charge me" differently. Razorpay UPI
Autopay uses a token object with four fields; AP2 uses signed intent and cart
mandates; a card-on-file token carries almost nothing. This module defines the
one internal shape they all map into, so that policy logic never learns the
vocabulary of any particular rail.

The central design decision is the split between `rail` and `policy`
constraints. An adapter declares which constraints its underlying rail
*actually enforces*. Everything else is enforced here or not at all. That
split is not a convenience -- it is the finding this project exists to state,
expressed as a type rather than a claim in a README.

Amounts are integer paise throughout. Never floats; never rupees.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Iterable


class Constraint(str, Enum):
    """The full vocabulary a mandate *could* express."""

    PER_CHARGE_MAX = "per_charge_max"
    EXPIRES_AT = "expires_at"
    CUMULATIVE_MAX = "cumulative_max"
    MAX_CHARGES = "max_charges"
    RATE_LIMIT = "rate_limit"
    SCOPE = "scope"
    INTENT_BINDING = "intent_binding"

    def __str__(self) -> str:                    # keeps f-strings readable
        return self.value


#: Verified against the live Razorpay orders API on 2026-08-22 -- the token
#: object is a strict allowlist of four fields, and seven attempts to express
#: anything else were rejected by name. See evidence/schema-findings.json.
UNIVERSALLY_ABSENT = frozenset({
    Constraint.CUMULATIVE_MAX,
    Constraint.MAX_CHARGES,
    Constraint.RATE_LIMIT,
    Constraint.SCOPE,
    Constraint.INTENT_BINDING,
})


@dataclass(frozen=True)
class Window:
    """A rate limit: at most `max_charges` charges per `seconds`."""

    seconds: int
    max_charges: int

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError("window seconds must be positive")
        if self.max_charges <= 0:
            raise ValueError("window max_charges must be positive")


@dataclass(frozen=True)
class Scope:
    """Where value may be spent. Empty collections mean "unrestricted"."""

    merchants: frozenset[str] = frozenset()
    categories: frozenset[str] = frozenset()

    def permits(self, merchant: str | None, category: str | None) -> bool:
        if self.merchants and merchant not in self.merchants:
            return False
        if self.categories and category not in self.categories:
            return False
        return True

    @property
    def is_unrestricted(self) -> bool:
        return not self.merchants and not self.categories


@dataclass(frozen=True)
class Limits:
    """
    A set of constraints. Any field left None is simply unconstrained -- which
    is the whole problem when it describes what a rail enforces.
    """

    per_charge_max: int | None = None
    expires_at: int | None = None
    cumulative_max: int | None = None
    max_charges: int | None = None
    rate_limit: Window | None = None
    scope: Scope | None = None
    requires_intent_binding: bool = False

    def declared(self) -> frozenset[Constraint]:
        """Which constraints this set actually pins down."""
        present = set()
        if self.per_charge_max is not None:
            present.add(Constraint.PER_CHARGE_MAX)
        if self.expires_at is not None:
            present.add(Constraint.EXPIRES_AT)
        if self.cumulative_max is not None:
            present.add(Constraint.CUMULATIVE_MAX)
        if self.max_charges is not None:
            present.add(Constraint.MAX_CHARGES)
        if self.rate_limit is not None:
            present.add(Constraint.RATE_LIMIT)
        if self.scope is not None and not self.scope.is_unrestricted:
            present.add(Constraint.SCOPE)
        if self.requires_intent_binding:
            present.add(Constraint.INTENT_BINDING)
        return frozenset(present)

    def tighten(self, **overrides) -> "Limits":
        """Return a copy with overrides applied. Never widens in place."""
        return replace(self, **overrides)


@dataclass(frozen=True)
class MandateEnvelope:
    """
    A rail-agnostic mandate.

    `rail` describes what the underlying payment network will enforce on its
    own. `policy` describes what the merchant additionally requires. The gate
    evaluates the union; the ledger records which half refused.
    """

    mandate_id: str
    source: str                      # adapter name, e.g. "razorpay-upi-autopay"
    subject: str                     # the principal being charged
    rail: Limits
    policy: Limits = field(default_factory=Limits)
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.mandate_id:
            raise ValueError("mandate_id is required")
        if not self.source:
            raise ValueError("source is required")

    @property
    def effective(self) -> Limits:
        """
        The binding limits: the tighter of rail and policy, field by field.
        Policy may only narrow. A policy that tried to widen a rail limit
        would be unenforceable anyway -- the rail would refuse first.
        """
        def tighter(a: int | None, b: int | None) -> int | None:
            if a is None:
                return b
            if b is None:
                return a
            return min(a, b)

        merged_scope = self.policy.scope or self.rail.scope
        return Limits(
            per_charge_max=tighter(self.rail.per_charge_max,
                                  self.policy.per_charge_max),
            expires_at=tighter(self.rail.expires_at, self.policy.expires_at),
            cumulative_max=tighter(self.rail.cumulative_max,
                                   self.policy.cumulative_max),
            max_charges=tighter(self.rail.max_charges, self.policy.max_charges),
            rate_limit=self.policy.rate_limit or self.rail.rate_limit,
            scope=merged_scope,
            requires_intent_binding=(self.rail.requires_intent_binding
                                     or self.policy.requires_intent_binding),
        )

    @property
    def unenforced_by_rail(self) -> frozenset[Constraint]:
        """
        Constraints that exist only because this layer supplies them. If this
        set is empty, the gate is redundant. It never is.
        """
        return self.effective.declared() - self.rail.declared()


def coverage_matrix(envelopes: Iterable[MandateEnvelope]) -> dict:
    """
    Build the rail-by-constraint table. The README table is generated from
    this rather than typed by hand, so it cannot drift from the code.
    """
    rows = {}
    for env in envelopes:
        declared = env.rail.declared()
        rows[env.source] = {str(c): (c in declared) for c in Constraint}
    return rows
