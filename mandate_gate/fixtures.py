"""
Canonical sample mandates.

One home for the payloads used by the tests, the coverage generator and the
console. They were triplicated across all three, which is exactly how a
fixture drifts from the thing it documents.

Provenance is recorded per fixture, because a mapper is only as trustworthy as
the payload it was written against.
"""

#: Captured from the live Razorpay test-mode orders API on 2026-08-22. This
#: exact token object was accepted; see evidence/schema-findings.json for the
#: seven fields that were rejected.
RAZORPAY_AS_PRESENTED = {
    "id": "order_TSlIkcPX1mMW9W",
    "customer_id": "cust_TSlIk33v6oM6N3",
    "token": {
        "max_amount": 500,
        "expire_at": 1789982013,
        "frequency": "as_presented",       # the default for new merchants
        "type": "single_block_multiple_debit",
    },
}

#: The same mandate with one field changed, to show what the default gives up.
RAZORPAY_MONTHLY = {
    **RAZORPAY_AS_PRESENTED,
    "id": "order_monthly",
    "token": {**RAZORPAY_AS_PRESENTED["token"], "frequency": "monthly"},
}

#: Transcribed from the published AP2 schemas (copies in evidence/). Exercises
#: every constraint AP2 can express, including the total cap and charge count
#: this project once claimed no format had.
AP2_OPEN_MANDATE = {
    "open_payment_mandate": {
        "vct": "mandate.payment.open.1",
        "jti": "opm_1",
        "sub": "user_1",
        "exp": 1789982013,
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256"}},
        "constraints": [
            {"type": "payment.amount_range", "currency": "INR",
             "min": 0, "max": 500},
            {"type": "payment.budget", "currency": "INR", "max": 2000},
            {"type": "payment.agent_recurrence",
             "frequency": "weekly", "max_occurrences": 4},
            {"type": "payment.allowed_payees", "allowed": [{"id": "shop-a"}]},
        ],
    },
    "open_checkout_mandate": {
        "vct": "mandate.checkout.open.1",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256"}},
        "constraints": [
            {"type": "checkout.allowed_merchants",
             "allowed": [{"id": "shop-b"}]},
        ],
    },
}

#: Illustrative. A stored-credential representation varies by processor; this
#: is the common shape -- an expiry and sometimes a category restriction.
CARD_ON_FILE = {
    "token_id": "tok_1",
    "cardholder_ref": "ch_1",
    "expires_at": 1789982013,
    "allowed_mcc": ["5411"],
}
