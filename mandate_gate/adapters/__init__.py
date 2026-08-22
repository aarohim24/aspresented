"""
Rail adapters.

An adapter does one job: turn a rail's native mandate representation into a
`MandateEnvelope`, declaring honestly what that rail enforces. Adapters hold no
policy and make no decisions.

Only one adapter is wired to a live API. The others are mappers verified
against recorded fixtures. `WIRED` on each adapter says which, and the README
repeats it, because blurring that line is the one thing that would make the
measured numbers dishonest.
"""

from .ap2 import AP2Adapter
from .card_on_file import CardOnFileAdapter
from .razorpay_upi import RazorpayUpiAdapter

ADAPTERS = {
    a.SOURCE: a for a in (RazorpayUpiAdapter, AP2Adapter, CardOnFileAdapter)
}

__all__ = ["ADAPTERS", "RazorpayUpiAdapter", "AP2Adapter", "CardOnFileAdapter"]
