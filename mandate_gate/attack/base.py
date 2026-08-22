"""
What an attacker is allowed to know.

`Briefing` is the whole of it, and it is deliberately the same information a
real agent has: the mandate's own terms, the merchant it is buying from, the
tool it may call, and whatever the gate said the last time it refused.

It does **not** include the policy the gate is enforcing. That asymmetry is the
point -- a real agent holds a mandate and discovers the merchant's rules by
being refused. An attacker handed the policy would be testing arithmetic; an
attacker handed the source would be testing nothing at all.

The refusal history is the interesting channel. Every `Refusal` carries a code,
a field and a remediation, and those were written so an agent could correct
itself. Letting the attacker read them tests that claim from the other side: if
the remediation text is useless, a competent attacker will not improve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Attempt:
    """One charge and what came back."""

    request: object                  # ChargeRequest
    allowed: bool
    codes: tuple = ()
    remediations: tuple = ()
    refused_by: str | None = None


@dataclass
class Briefing:
    """Everything the attacker may see."""

    #: The mandate's own declared terms -- what a holder can read off it.
    mandate: dict
    #: Merchants and categories the attacker has observed, not an allowlist.
    seen_merchants: tuple = ()
    seen_categories: tuple = ()
    #: Intents the principal has actually signed, by id.
    intents: tuple = ()
    #: Everything tried so far, oldest first.
    history: list = field(default_factory=list)
    #: Charges settled and value extracted so far.
    settled: int = 0
    extracted: int = 0

    @property
    def last(self) -> "Attempt | None":
        return self.history[-1] if self.history else None

    def codes_seen(self) -> set:
        out = set()
        for a in self.history:
            out.update(a.codes)
        return out


class Attacker(Protocol):
    #: Short identifier used in reports.
    NAME: str

    def propose(self, briefing: Briefing) -> object:
        """
        Return the next ChargeRequest to attempt, or None to stop.

        May consult only the briefing. An attacker that reaches into the gate,
        the envelope's policy tier, or the ledger is not measuring anything.
        """
        ...
