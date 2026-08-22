"""
Execution.

Each session gets its own mandate, ledger and rail, because the whole point is
that state accumulates: draining a mandate is a property of the sequence, not
of any single charge. Sessions are independent, so nothing leaks between them.

Ledger integrity is verified after every session. A harness that produced
numbers from a log that no longer verifies would be reporting fiction.

Time is driven by advancing an injected server clock per attempt, never by a
field on the request. That is deliberate: if the harness could set the time the
gate evaluates against, it would be reproducing the bug it exists to catch.
"""

from __future__ import annotations

import os
import tempfile

from ..charge import Intent
from ..envelope import Limits, MandateEnvelope
from ..gate import Gate
from ..ledger import Ledger
from ..rail import RailSimulator
from .metrics import Outcome
from .scenarios import POLICY, RAIL

SECRET = b"harness-intent-secret"


def _install_intents(gate: Gate, session) -> None:
    """
    Sign and register the session's intents. A ("TAMPER", id, amount) marker
    means: sign the intent honestly, then alter it while keeping the old
    signature -- the forgery the gate must reject.
    """
    tampers = []
    for item in session.intents:
        if isinstance(item, tuple):
            tampers.append(item)
            continue
        gate.record_intent(item)

    for _marker, intent_id, new_amount in tampers:
        original = gate.intents[intent_id]
        gate.intents[intent_id] = Intent(
            intent_id=original.intent_id, mandate_id=original.mandate_id,
            max_amount=new_amount, expires_at=original.expires_at,
            merchant=original.merchant, category=original.category,
            signature=original.signature,          # stale on purpose
        )


def run(sessions, policy: Limits = POLICY, rail_limits: Limits = RAIL,
        duplicate_window: int = 300, workdir: str | None = None) -> list:
    """Returns a flat list of Outcome, one per attempt."""
    workdir = workdir or tempfile.mkdtemp(prefix="mandate-gate-harness-")
    outcomes = []

    for session in sessions:
        effective_policy = policy
        if session.policy_expires_at is not None:
            effective_policy = policy.tighten(
                expires_at=session.policy_expires_at)

        envelope = MandateEnvelope(
            mandate_id=session.session_id, source="razorpay-upi-autopay",
            subject=f"cust-{session.session_id}",
            rail=rail_limits, policy=effective_policy,
        )
        server_time = {"now": 0}
        ledger = Ledger(os.path.join(workdir, f"{session.session_id}.jsonl"),
                        clock=lambda: server_time["now"])
        rail = RailSimulator(limits=rail_limits)
        gate = Gate(envelope, ledger, rail, SECRET,
                    duplicate_window=duplicate_window,
                    clock=lambda: server_time["now"])

        _install_intents(gate, session)

        for attempt in session.attempts:
            server_time["now"] = attempt.at        # the clock moves, not the request
            decision = gate.authorize(attempt.request)
            outcomes.append(Outcome(
                label=attempt.label,
                expected_code=attempt.expected_code,
                allowed=decision.allowed,
                codes=decision.codes,
                refused_by=decision.refused_by,
                amount=attempt.request.amount,
                replayed=decision.replayed,
            ))

        ledger.verify()          # raises BrokenChain rather than mislead

    return outcomes
