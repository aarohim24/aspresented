"""
Adversarial attackers, and the oracle that judges them.

An attacker sees what a mandate holder sees and nothing more. The gate decides.
The invariants -- properties over the finished ledger, not a second copy of the
check logic -- decide whether the gate was right.

The fuzzer needs no credentials. A model-driven attacker is an optional extra;
the core of this package stays dependency-free.
"""

from .base import Attacker, Attempt, Briefing
from .fuzzer import Fuzzer
from .invariants import Violation, check
from .session import AttackResult, run

__all__ = ["Attacker", "Attempt", "Briefing", "Fuzzer", "Violation", "check",
           "AttackResult", "run"]
