"""
Mandate Gate -- the enforcement and evidence layer a payment mandate lacks.

A mandate says "you may charge up to X per charge, until Y". It does not say
how many times, how fast, or where. This package supplies the missing
constraints, binds each charge to the intent that justified it, and records
every decision in a tamper-evident log so the merchant can show what was
authorised when a charge is later disputed.
"""

from .adjudicate import (AUTHORISED, UNAUTHORISED, UNPROVABLE, Adjudicator)
from .charge import ChargeRequest, Decision, Intent, Refusal
from .envelope import (ABSENT, DECLARED, ENFORCED, Constraint, Limits,
                       MandateEnvelope, Scope, Window, coverage_matrix)
from .gate import Gate
from .ledger import BrokenChain, Ledger
from .rail import RailSimulator

__all__ = [
    "Constraint", "Limits", "MandateEnvelope", "Scope", "Window",
    "ENFORCED", "DECLARED", "ABSENT",
    "coverage_matrix", "Ledger", "BrokenChain", "Gate", "RailSimulator",
    "ChargeRequest", "Decision", "Intent", "Refusal",
    "Adjudicator", "AUTHORISED", "UNAUTHORISED", "UNPROVABLE",
]
