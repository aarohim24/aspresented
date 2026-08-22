"""
Running an attacker against a real gate.

The loop is deliberately dull: ask the attacker for a charge, let the gate
decide, hand the outcome back, repeat. What makes it a measurement rather than a
demo is what happens either side of it.

Before: the attacker is briefed with only what a mandate holder can see.
After: the finished ledger is checked against the invariants, independently of
what the gate said at the time.

Two very different results come out. **Value extracted** is what the attacker
got away with -- interesting but not by itself a defect, since a mandate is
meant to be spent. **Violations** are invariants the gate allowed to be broken,
and those are defects regardless of how they were provoked.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field

from ..envelope import MandateEnvelope
from ..gate import Gate
from ..ledger import Ledger
from ..rail import RailSimulator
from . import invariants
from .base import Attempt, Briefing


@dataclass
class AttackResult:
    attacker: str
    attempts: int = 0
    allowed: int = 0
    extracted: int = 0
    codes: dict = field(default_factory=dict)
    violations: list = field(default_factory=list)
    #: Refusal codes the attacker provoked at least once. Breadth of probing.
    coverage: tuple = ()
    transcript: list = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict:
        return {
            "attacker": self.attacker,
            "attempts": self.attempts,
            "allowed": self.allowed,
            "extracted": self.extracted,
            "codes": self.codes,
            "coverage": list(self.coverage),
            "violations": [v.as_dict() for v in self.violations],
            "clean": self.clean,
        }


def _mandate_view(envelope: MandateEnvelope) -> dict:
    """
    What a mandate holder can read off the mandate itself.

    Only the rail tier plus expiry: the terms the network published. The
    merchant's own policy is not in here, because a real agent cannot see it.
    """
    rail = envelope.rail
    return {
        "mandate_id": envelope.mandate_id,
        "per_charge_max": rail.per_charge_max,
        "expires_at": rail.expires_at,
        "frequency_bounded": rail.rate_limit is not None,
    }


def run(envelope: MandateEnvelope, attacker, secret: bytes,
        intents=(), budget: int = 40, start_time: int = 0,
        seconds_per_attempt: int = 0, workdir: str | None = None,
        duplicate_window: int = 300) -> AttackResult:
    """
    Turn `attacker` loose on a fresh gate built from `envelope`.

    `seconds_per_attempt` advances the server clock between attempts. Zero
    means the whole run happens at one instant, which is the harshest setting
    for rate limits and the right default for an attack.
    """
    workdir = workdir or tempfile.mkdtemp(prefix="attack-")
    server_time = {"now": start_time}
    ledger = Ledger(os.path.join(workdir, f"{envelope.mandate_id}.jsonl"),
                    clock=lambda: server_time["now"])
    rail = RailSimulator(limits=envelope.rail)
    gate = Gate(envelope, ledger, rail, secret,
                duplicate_window=duplicate_window,
                clock=lambda: server_time["now"])

    for intent in intents:
        gate.record_intent(intent)

    briefing = Briefing(
        mandate=_mandate_view(envelope),
        seen_merchants=tuple({i.merchant for i in intents if i.merchant}),
        intents=tuple(i.intent_id for i in intents),
    )

    result = AttackResult(attacker=getattr(attacker, "NAME", "unknown"))

    for _ in range(budget):
        request = attacker.propose(briefing)
        if request is None:
            break

        decision = gate.authorize(request)
        attempt = Attempt(
            request=request,
            allowed=decision.allowed,
            codes=decision.codes,
            remediations=tuple(r.remediation for r in decision.refusals),
            refused_by=decision.refused_by,
        )
        briefing.history.append(attempt)

        result.attempts += 1
        if decision.allowed and not decision.replayed:
            result.allowed += 1
            result.extracted += request.amount
            briefing.settled += 1
            briefing.extracted += request.amount
        for code in decision.codes:
            result.codes[code] = result.codes.get(code, 0) + 1

        result.transcript.append({
            "key": request.idempotency_key,
            "amount": request.amount,
            "merchant": request.merchant,
            "claimed_at": request.claimed_at,
            "allowed": decision.allowed,
            "codes": list(decision.codes),
        })
        server_time["now"] += seconds_per_attempt

    ledger.verify()                      # a fictional log proves nothing
    result.violations = invariants.check(ledger, envelope)
    result.coverage = tuple(sorted(result.codes))
    return result
