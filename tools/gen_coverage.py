#!/usr/bin/env python3
"""
Generate the constraint coverage table as Markdown.

Run this rather than hand-editing the table in the README: a table typed by
hand drifts from the adapters, and CI regenerates this one to catch that.

Cells are tri-state, and the distinction is the project's whole argument:

    enforced  -- the network guarantees it unaided
    declared  -- written into the mandate, enforced only by this layer
    --        -- nothing says it at all

    python3 tools/gen_coverage.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mandate_gate.adapters import ADAPTERS                            # noqa: E402
from mandate_gate.adapters.ap2 import AP2Adapter                      # noqa: E402
from mandate_gate.adapters.card_on_file import CardOnFileAdapter      # noqa: E402
from mandate_gate.adapters.razorpay_upi import RazorpayUpiAdapter     # noqa: E402
from mandate_gate.envelope import (ABSENT, DECLARED, ENFORCED,        # noqa: E402
                                   Constraint)
from mandate_gate.fixtures import (AP2_OPEN_MANDATE, CARD_ON_FILE,    # noqa: E402
                                   RAZORPAY_AS_PRESENTED,
                                   RAZORPAY_MONTHLY)

# Razorpay appears twice on purpose: same rail, one field apart. The default
# configuration for a new merchant is the weaker of the two.
COLUMNS = [
    ("razorpay (as_presented, default)", RazorpayUpiAdapter, RAZORPAY_AS_PRESENTED),
    ("razorpay (monthly)", RazorpayUpiAdapter, RAZORPAY_MONTHLY),
    ("ap2 (open mandate)", AP2Adapter, AP2_OPEN_MANDATE),
    ("card-on-file", CardOnFileAdapter, CARD_ON_FILE),
]

LABELS = {
    Constraint.PER_CHARGE_MAX: "Per-charge ceiling",
    Constraint.EXPIRES_AT: "Expiry",
    Constraint.CUMULATIVE_MAX: "Total cap",
    Constraint.MAX_CHARGES: "Charge count cap",
    Constraint.RATE_LIMIT: "Rate limit",
    Constraint.SCOPE: "Spend scope",
    Constraint.INTENT_BINDING: "Intent binding",
}

CELL = {ENFORCED: "**enforced**", DECLARED: "declared", ABSENT: "--"}

envelopes = [(label, adapter.normalise(raw)) for label, adapter, raw in COLUMNS]

print("| Constraint | " + " | ".join(label for label, _ in envelopes) + " |")
print("|---|" + "---|" * len(envelopes))
for c in Constraint:
    cells = [CELL[env.state_of(c)] for _, env in envelopes]
    print(f"| {LABELS[c]} | " + " | ".join(cells) + " |")

print()
for source, adapter in ADAPTERS.items():
    state = "wired to live API" if adapter.WIRED else "mapper, not wired"
    print(f"- `{source}` -- {state}")

never_enforced = [LABELS[c] for c in Constraint
                  if all(env.state_of(c) != ENFORCED for _, env in envelopes)]
declared_only = [LABELS[c] for c in Constraint
                 if any(env.state_of(c) == DECLARED for _, env in envelopes)
                 and all(env.state_of(c) != ENFORCED for _, env in envelopes)]

never_list = ", ".join(never_enforced)
declared_list = ", ".join(declared_only)
print()
print(f"Enforced by no network: {never_list}")
print(f"Declared somewhere but enforced nowhere: {declared_list}")
