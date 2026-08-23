"""
The honest client.

Two attackers already probe this gate for gaps. This package is the other half
of the question: can a legitimate AI buyer actually get its shopping done? A
guardrail that stops fraud and also stops real purchases is not a guardrail, it
is an outage.

    catalogue   merchant-supplied text, unsanitised on purpose
    interpret   what a person said -> a signed, clamped Intent
    agent       shop, get refused, read the remediation, correct, complete
"""

from .agent import BuyingAgent, Outcome, Step
from .catalogue import CATALOGUE, Item, flags_instruction_shaped_text, suspicious
from .interpret import Interpretation, interpret

__all__ = ["BuyingAgent", "Outcome", "Step", "CATALOGUE", "Item",
           "flags_instruction_shaped_text", "suspicious",
           "Interpretation", "interpret"]
