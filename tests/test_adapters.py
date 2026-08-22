import unittest

from mandate_gate.adapters import (ADAPTERS, AP2Adapter, CardOnFileAdapter,
                                   RazorpayUpiAdapter)
from mandate_gate.envelope import UNIVERSALLY_ABSENT, Constraint

# Captured from the live test-mode orders API on 2026-08-22. The exact token
# object that /v1/orders accepted -- see evidence/schema-findings.json.
RAZORPAY_ACCEPTED = {
    "id": "order_TSlIkcPX1mMW9W",
    "customer_id": "cust_TSlIk33v6oM6N3",
    "token": {
        "max_amount": 500,
        "expire_at": 1789982013,
        "frequency": "as_presented",
        "type": "single_block_multiple_debit",
    },
}

AP2_FIXTURE = {
    "intent_mandate": {"id": "im_1", "subject": "user_1",
                       "expires_at": 1789982013},
    "cart_mandate": {"id": "cm_1", "cart_hash": "abc123", "signature": "sig"},
}

CARD_FIXTURE = {"token_id": "tok_1", "cardholder_ref": "ch_1",
                "expires_at": 1789982013, "allowed_mcc": ["5411"]}


class TestRazorpayAdapter(unittest.TestCase):
    def test_maps_the_accepted_shape(self):
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertEqual(env.rail.per_charge_max, 500)
        self.assertEqual(env.rail.expires_at, 1789982013)
        self.assertEqual(env.subject, "cust_TSlIk33v6oM6N3")

    def test_rail_enforces_only_ceiling_and_expiry(self):
        """The finding, asserted. Verified live: 7/7 other fields rejected."""
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertEqual(env.rail.declared(),
                         {Constraint.PER_CHARGE_MAX, Constraint.EXPIRES_AT})

    def test_rail_declares_none_of_the_absent_constraints(self):
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertFalse(env.rail.declared() & UNIVERSALLY_ABSENT)

    def test_rejects_fields_the_live_api_rejects(self):
        """
        Refusing here mirrors the API. Accepting silently would let a caller
        believe a cumulative cap took effect when the rail has no such field.
        """
        payload = {**RAZORPAY_ACCEPTED,
                   "token": {**RAZORPAY_ACCEPTED["token"],
                             "cumulative_max_amount": 1500}}
        with self.assertRaises(ValueError) as ctx:
            RazorpayUpiAdapter.normalise(payload)
        self.assertIn("cumulative_max_amount", str(ctx.exception))

    def test_as_presented_is_not_a_rate_limit(self):
        self.assertTrue(RazorpayUpiAdapter.rate_is_unbounded(RAZORPAY_ACCEPTED))
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertIsNone(env.rail.rate_limit)


class TestAP2Adapter(unittest.TestCase):
    def test_cart_mandate_gives_intent_binding(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertTrue(env.rail.requires_intent_binding)
        self.assertIn(Constraint.INTENT_BINDING, env.rail.declared())

    def test_but_no_spend_ceiling_at_all(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertIsNone(env.rail.per_charge_max)
        self.assertIsNone(env.rail.cumulative_max)

    def test_unsigned_cart_gives_no_binding(self):
        payload = {**AP2_FIXTURE, "cart_mandate": {"id": "cm_2"}}
        self.assertFalse(AP2Adapter.normalise(payload).rail.requires_intent_binding)


class TestCardOnFileAdapter(unittest.TestCase):
    def test_thinnest_vocabulary(self):
        env = CardOnFileAdapter.normalise(CARD_FIXTURE)
        self.assertEqual(env.rail.declared(),
                         {Constraint.EXPIRES_AT, Constraint.SCOPE})
        self.assertIsNone(env.rail.per_charge_max)


class TestTheGeneralClaim(unittest.TestCase):
    def test_no_rail_expresses_a_cumulative_cap(self):
        """
        The claim the project generalises to. If any adapter ever declares
        CUMULATIVE_MAX at the rail level, this test fails and the thesis
        needs narrowing -- which is exactly what it is here to catch.
        """
        for raw, adapter in ((RAZORPAY_ACCEPTED, RazorpayUpiAdapter),
                             (AP2_FIXTURE, AP2Adapter),
                             (CARD_FIXTURE, CardOnFileAdapter)):
            env = adapter.normalise(raw)
            self.assertNotIn(Constraint.CUMULATIVE_MAX, env.rail.declared(),
                             f"{adapter.SOURCE} unexpectedly has a total cap")
            self.assertNotIn(Constraint.RATE_LIMIT, env.rail.declared(),
                             f"{adapter.SOURCE} unexpectedly has a rate limit")

    def test_exactly_one_adapter_is_wired(self):
        wired = [a.SOURCE for a in ADAPTERS.values() if a.WIRED]
        self.assertEqual(wired, ["razorpay-upi-autopay"])


if __name__ == "__main__":
    unittest.main()
