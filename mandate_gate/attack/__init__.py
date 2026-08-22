"""
Adversarial attackers, and the oracle that judges them.

An attacker sees what a mandate holder sees and nothing more. The gate decides.
The invariants -- properties over the finished ledger, not a second copy of the
check logic -- decide whether the gate was right.

Three attackers, and their results are never merged into one figure:

    Fuzzer          deterministic, systematic, no credentials. Bounded by the
                    strategies its author imagined.
    ModelAttacker   any OpenAI-compatible endpoint. Not bounded by that, and
                    not reproducible either, which is why it records.
    ReplayAttacker  re-issues a committed model transcript, so a finding
                    survives without credentials and CI can verify it.
"""

from .base import Attacker, Attempt, Briefing
from .fuzzer import Fuzzer
from .invariants import Violation, check
from .model import ModelAttacker, ReplayAttacker
from .session import AttackResult, run

__all__ = ["Attacker", "Attempt", "Briefing", "Fuzzer", "ModelAttacker",
           "ReplayAttacker", "Violation", "check", "AttackResult", "run"]
