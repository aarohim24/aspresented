"""
Rail simulator.

Stands in for `/v1/payments/create/recurring`, which requires account-level
activation this build does not have -- a fresh test account answers
"The requested URL was not found on the server".

The important property is restraint. This simulator enforces *exactly* what
Razorpay documents and the schema probe confirmed: a per-charge ceiling and an
expiry. Nothing else. It is deliberately no smarter than the real rail, because
a generous simulator would flatter the gate and make every measured number
meaningless.

Error codes mirror the ones in Razorpay's own SBMD integration guide.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .envelope import Limits


@dataclass
class RailSimulator:
    """
    `limits` must be the *rail* limits from an envelope, never the effective
    ones -- passing policy limits here would silently move enforcement into
    the rail and erase the very distinction being measured.
    """

    limits: Limits
    #: Cumulative total, mirroring the token's observable `amount_debited`.
    #: Observable, and -- this is the whole point -- not enforced against.
    amount_debited: int = 0
    charges: list = field(default_factory=list)

    def charge(self, amount: int, now: int) -> tuple:
        """
        Returns (ok, charge_id_or_error_code).

        `now` is server time, passed down from the gate. A real rail reads its
        own clock; nothing here may be driven by a caller-asserted timestamp.
        """
        if self.limits.expires_at is not None and now > self.limits.expires_at:
            return False, "invalid_request"          # token expired

        if (self.limits.per_charge_max is not None
                and amount > self.limits.per_charge_max):
            return False, "transaction_limit_exceeded"

        # No cumulative check. No rate check. No scope check. There is no field
        # in the mandate for any of them, so the rail has nothing to check
        # against -- which is precisely the finding this project rests on.
        self.amount_debited += amount
        charge_id = f"pay_sim_{len(self.charges):04d}"
        self.charges.append({"id": charge_id, "amount": amount, "at": now})
        return True, charge_id
