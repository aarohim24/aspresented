"""
The oracle.

An attacker proposes charges and the gate decides. Something independent has to
say whether the gate was right, or the exercise is just the author grading
their own homework.

This module does not re-implement the checks. It states the **properties that
must hold over the finished ledger**, then verifies them:

    no sequence of allowed charges exceeds the total cap
    no sequence of allowed charges exceeds the count cap
    no allowed charge exceeds the per-charge ceiling
    no allowed charge falls outside an applicable scope
    no window contains more allowed charges than it permits
    no allowed charge lacks a binding when binding was required
    no allowed charge settled after expiry

That distinction matters. A second copy of the check logic would share the
check logic's blind spots -- the clock bug lived in *how* a limit was
evaluated, not in the limit itself, and a re-implementation reading the same
request field would have agreed with the bug. Properties evaluated over the
recorded outcome cannot: they read what actually happened.

A violation here is a defect in the gate, whatever the attacker did to provoke
it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Violation:
    """An invariant the gate allowed to be broken."""

    invariant: str
    detail: str
    #: Charge refs implicated, in ledger order.
    charges: tuple = ()

    def as_dict(self) -> dict:
        return {"invariant": self.invariant, "detail": self.detail,
                "charges": list(self.charges)}


def _allowed(ledger, mandate_id: str) -> list:
    """Settled charges for one mandate, in the order they were recorded."""
    out = []
    for entry in ledger.entries():
        p = entry.payload
        if (entry.kind == "decision" and p.get("mandate_id") == mandate_id
                and p.get("allowed") and not p.get("replayed")):
            out.append(p)
    return out


def check(ledger, envelope) -> list:
    """Every invariant violation the finished ledger reveals."""
    limits = envelope.effective
    charges = _allowed(ledger, envelope.mandate_id)
    refs = tuple(c.get("idempotency_key") for c in charges)
    violations: list = []

    def amount(c) -> int:
        return int(c.get("amount") or 0)

    def at(c) -> int:
        return int(c.get("at") or 0)

    # --- per-charge ceiling
    if limits.per_charge_max is not None:
        over = [c for c in charges if amount(c) > limits.per_charge_max]
        if over:
            violations.append(Violation(
                "per_charge_max",
                f"{len(over)} charge(s) above the {limits.per_charge_max} "
                f"paise ceiling; largest was {max(amount(c) for c in over)}",
                tuple(c.get("idempotency_key") for c in over)))

    # --- total
    if limits.cumulative_max is not None:
        total = sum(amount(c) for c in charges)
        if total > limits.cumulative_max:
            violations.append(Violation(
                "cumulative_max",
                f"{total} paise settled against a {limits.cumulative_max} "
                f"paise cap, an overrun of {total - limits.cumulative_max}",
                refs))

    # --- count
    if limits.max_charges is not None and len(charges) > limits.max_charges:
        violations.append(Violation(
            "max_charges",
            f"{len(charges)} charges settled against a limit of "
            f"{limits.max_charges}",
            refs))

    # --- expiry
    if limits.expires_at is not None:
        late = [c for c in charges if at(c) > limits.expires_at]
        if late:
            violations.append(Violation(
                "expires_at",
                f"{len(late)} charge(s) settled after the mandate lapsed at "
                f"{limits.expires_at}",
                tuple(c.get("idempotency_key") for c in late)))

    # --- scope: every applicable scope, not the union
    for scope in envelope.scopes:
        outside = [c for c in charges
                   if not scope.permits(c.get("merchant"), c.get("category"))]
        if outside:
            violations.append(Violation(
                "scope",
                f"{len(outside)} charge(s) outside the authorised scope, "
                f"e.g. merchant={outside[0].get('merchant')!r}",
                tuple(c.get("idempotency_key") for c in outside)))

    # --- rate: a sliding window over recorded settle times
    for window in envelope.rate_windows:
        times = sorted(at(c) for c in charges)
        for i, start in enumerate(times):
            inside = [t for t in times[i:] if t - start < window.seconds]
            if len(inside) > window.max_charges:
                violations.append(Violation(
                    "rate_limit",
                    f"{len(inside)} charges within {window.seconds}s "
                    f"(limit {window.max_charges}), starting at {start}",
                    refs))
                break

    # --- binding
    if limits.requires_intent_binding:
        unbound = [c for c in charges if not c.get("intent_id")]
        if unbound:
            violations.append(Violation(
                "intent_binding",
                f"{len(unbound)} charge(s) settled with no intent referenced "
                f"while binding was required",
                tuple(c.get("idempotency_key") for c in unbound)))

    return violations
