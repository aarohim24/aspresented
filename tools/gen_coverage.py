#!/usr/bin/env python3
"""
Generate the rail coverage table as Markdown.

Run this rather than hand-editing the table in the README: a table typed by
hand drifts from the adapters, and this one is the assertion the tests check.

    python3 tools/gen_coverage.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mandate_gate.adapters import ADAPTERS                       # noqa: E402
from mandate_gate.adapters.ap2 import AP2Adapter                 # noqa: E402
from mandate_gate.adapters.card_on_file import CardOnFileAdapter  # noqa: E402
from mandate_gate.adapters.razorpay_upi import RazorpayUpiAdapter  # noqa: E402
from mandate_gate.envelope import Constraint, coverage_matrix     # noqa: E402

FIXTURES = {
    RazorpayUpiAdapter: {
        "id": "order_TSlIkcPX1mMW9W",
        "customer_id": "cust_TSlIk33v6oM6N3",
        "token": {"max_amount": 500, "expire_at": 1789982013,
                  "frequency": "as_presented",
                  "type": "single_block_multiple_debit"},
    },
    AP2Adapter: {
        "intent_mandate": {"id": "im_1", "subject": "user_1",
                           "expires_at": 1789982013},
        "cart_mandate": {"id": "cm_1", "cart_hash": "abc", "signature": "sig"},
    },
    CardOnFileAdapter: {"token_id": "tok_1", "cardholder_ref": "ch_1",
                        "expires_at": 1789982013, "allowed_mcc": ["5411"]},
}

LABELS = {
    Constraint.PER_CHARGE_MAX: "Per-charge ceiling",
    Constraint.EXPIRES_AT: "Expiry",
    Constraint.CUMULATIVE_MAX: "Total cap",
    Constraint.MAX_CHARGES: "Charge count cap",
    Constraint.RATE_LIMIT: "Rate limit",
    Constraint.SCOPE: "Spend scope",
    Constraint.INTENT_BINDING: "Intent binding",
}

envelopes = [a.normalise(raw) for a, raw in FIXTURES.items()]
matrix = coverage_matrix(envelopes)
rails = list(matrix)

print("| Constraint | " + " | ".join(rails) + " |")
print("|---|" + "---|" * len(rails))
for c in Constraint:
    cells = ["yes" if matrix[r][str(c)] else "**no**" for r in rails]
    print(f"| {LABELS[c]} | " + " | ".join(cells) + " |")

print()
for source, adapter in ADAPTERS.items():
    state = "wired to live API" if adapter.WIRED else "fixture-verified mapper"
    print(f"- `{source}` -- {state}")

absent = [LABELS[c] for c in Constraint
          if not any(matrix[r][str(c)] for r in rails)]
print(f"\nExpressed by no rail: {', '.join(absent)}")
