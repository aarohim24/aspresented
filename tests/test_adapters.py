import unittest

from mandate_gate.adapters import (ADAPTERS, AP2Adapter, CardOnFileAdapter,
                                   RazorpayUpiAdapter)
from mandate_gate.adapters.base import Adapter
from mandate_gate.envelope import (ABSENT, DECLARED, ENFORCED,
                                   UNIVERSALLY_ABSENT, Constraint,
                                   MandateEnvelope)
from mandate_gate.fixtures import (AP2_OPEN_MANDATE, CARD_ON_FILE,
                                   RAZORPAY_AS_PRESENTED, RAZORPAY_MONTHLY)

# Fixtures live in mandate_gate/fixtures.py so the tests, the coverage
# generator and the console cannot drift apart.
RAZORPAY_ACCEPTED = RAZORPAY_AS_PRESENTED
AP2_FIXTURE = AP2_OPEN_MANDATE
CARD_FIXTURE = CARD_ON_FILE


class TestRazorpayAdapter(unittest.TestCase):
    def test_maps_the_accepted_shape(self):
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertEqual(env.rail.per_charge_max, 500)
        self.assertEqual(env.rail.expires_at, 1789982013)
        self.assertEqual(env.subject, "cust_TSlIk33v6oM6N3")

    def test_razorpay_enforces_rather_than_merely_declares(self):
        """The contrast with AP2: these are network guarantees, not claims."""
        env = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED)
        self.assertEqual(env.state_of(Constraint.PER_CHARGE_MAX), ENFORCED)
        self.assertEqual(env.state_of(Constraint.CUMULATIVE_MAX), ABSENT)

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

    def test_fixed_frequency_buckets_DO_impose_a_cadence(self):
        """
        The correction. An earlier version claimed Razorpay expressed no rate
        limit at all -- false for daily/weekly/monthly/quarterly/yearly, which
        allow one debit per billing cycle. Only `as_presented` expresses none,
        and `as_presented` is the default for new merchants.
        """
        env = RazorpayUpiAdapter.normalise(RAZORPAY_MONTHLY)
        self.assertIsNotNone(env.rail.rate_limit)
        self.assertEqual(env.rail.rate_limit.max_charges, 1)
        self.assertEqual(env.rail.rate_limit.seconds, 30 * 86_400)
        self.assertIn(Constraint.RATE_LIMIT, env.rail.declared())

    def test_the_default_frequency_is_the_weaker_one(self):
        """One field apart, and the cadence disappears."""
        default = RazorpayUpiAdapter.normalise(RAZORPAY_ACCEPTED).rail.declared()
        monthly = RazorpayUpiAdapter.normalise(RAZORPAY_MONTHLY).rail.declared()
        self.assertEqual(monthly - default, {Constraint.RATE_LIMIT})

    def test_an_unknown_frequency_claims_nothing(self):
        """Guessing a cadence would be worse than admitting ignorance."""
        odd = {**RAZORPAY_ACCEPTED,
               "token": {**RAZORPAY_ACCEPTED["token"], "frequency": "fortnightly"}}
        self.assertIsNone(RazorpayUpiAdapter.normalise(odd).rail.rate_limit)


class TestAP2Adapter(unittest.TestCase):
    """
    AP2 expresses more than any rail. The correction that matters most: it
    names a total cap and a charge count outright, which an earlier version of
    this project claimed no format did.
    """

    def test_ap2_expresses_a_cumulative_cap(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertEqual(env.policy.cumulative_max, 2000)   # payment.budget

    def test_ap2_expresses_a_charge_count_and_a_cadence(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertEqual(env.policy.max_charges, 4)         # max_occurrences
        self.assertEqual(env.policy.rate_limit.seconds, 604_800)

    def test_ap2_expresses_a_ceiling_and_a_scope(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertEqual(env.policy.per_charge_max, 500)    # amount_range.max
        self.assertEqual(env.policy.scope.merchants,
                         frozenset({"shop-a", "shop-b"}))

    def test_cnf_key_binding_is_intent_binding(self):
        self.assertTrue(
            AP2Adapter.normalise(AP2_FIXTURE).policy.requires_intent_binding)

    def test_but_the_rail_tier_is_empty_and_that_is_the_point(self):
        """
        AP2 is a credential format, not a network. Nothing enforces these
        claims for the merchant -- so they are policy for this layer, and the
        rail tier declares nothing.
        """
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertEqual(env.rail.declared(), frozenset())

    def test_declared_but_not_enforced(self):
        env = AP2Adapter.normalise(AP2_FIXTURE)
        self.assertEqual(env.state_of(Constraint.CUMULATIVE_MAX), DECLARED)
        self.assertEqual(env.state_of(Constraint.MAX_CHARGES), DECLARED)

    def test_absent_constraints_read_as_absent(self):
        bare = {"open_payment_mandate": {"vct": "mandate.payment.open.1",
                                         "constraints": []}}
        env = AP2Adapter.normalise(bare)
        self.assertEqual(env.state_of(Constraint.CUMULATIVE_MAX), ABSENT)

    def test_unknown_recurrence_frequency_claims_no_cadence(self):
        payload = {"open_payment_mandate": {
            "vct": "v", "constraints": [
                {"type": "payment.agent_recurrence", "frequency": "fortnightly",
                 "max_occurrences": 2}]}}
        env = AP2Adapter.normalise(payload)
        self.assertIsNone(env.policy.rate_limit)
        self.assertEqual(env.policy.max_charges, 2)


class TestCardOnFileAdapter(unittest.TestCase):
    def test_thinnest_vocabulary(self):
        env = CardOnFileAdapter.normalise(CARD_FIXTURE)
        self.assertEqual(env.rail.declared(),
                         {Constraint.EXPIRES_AT, Constraint.SCOPE})
        self.assertIsNone(env.rail.per_charge_max)

    def test_mcc_scope_restricts_by_category(self):
        """The one place `Scope.categories` is load-bearing."""
        scope = CardOnFileAdapter.normalise(CARD_FIXTURE).rail.scope
        self.assertTrue(scope.permits("any-merchant", "5411"))
        self.assertFalse(scope.permits("any-merchant", "5812"))

    def test_no_mcc_means_unrestricted(self):
        bare = {k: v for k, v in CARD_FIXTURE.items() if k != "allowed_mcc"}
        self.assertIsNone(CardOnFileAdapter.normalise(bare).rail.scope)


class TestAdapterContract(unittest.TestCase):
    """
    Enforces mandate_gate/adapters/base.py. Without this, the Protocol is
    decoration -- Python never checks it at runtime.
    """

    def test_every_registered_adapter_satisfies_the_protocol(self):
        for source, adapter in ADAPTERS.items():
            self.assertIsInstance(adapter, Adapter, source)

    def test_source_and_wired_are_the_declared_types(self):
        for source, adapter in ADAPTERS.items():
            self.assertIsInstance(adapter.SOURCE, str, source)
            self.assertIsInstance(adapter.WIRED, bool, source)
            self.assertEqual(adapter.SOURCE, source)

    def test_normalise_returns_an_envelope_tagged_with_its_source(self):
        for raw, adapter in ((RAZORPAY_ACCEPTED, RazorpayUpiAdapter),
                             (AP2_FIXTURE, AP2Adapter),
                             (CARD_FIXTURE, CardOnFileAdapter)):
            env = adapter.normalise(raw)
            self.assertIsInstance(env, MandateEnvelope)
            self.assertEqual(env.source, adapter.SOURCE)


class TestTheGeneralClaim(unittest.TestCase):
    """
    The surviving claim, stated as narrowly as the evidence allows.

    An earlier version asserted no rail expressed a rate limit, a scope, or
    intent binding. All three were wrong: Razorpay's fixed frequency buckets
    impose a cadence, a card token can carry an MCC scope, and an AP2 cart
    mandate binds intent. What no rail expresses is a total and a count.
    """

    ALL = ((RAZORPAY_ACCEPTED, RazorpayUpiAdapter),
           (RAZORPAY_MONTHLY, RazorpayUpiAdapter),
           (AP2_FIXTURE, AP2Adapter),
           (CARD_FIXTURE, CardOnFileAdapter))

    def test_no_rail_expresses_a_cumulative_cap_or_a_charge_count(self):
        for raw, adapter in self.ALL:
            declared = adapter.normalise(raw).rail.declared()
            self.assertNotIn(Constraint.CUMULATIVE_MAX, declared,
                             f"{adapter.SOURCE} unexpectedly has a total cap")
            self.assertNotIn(Constraint.MAX_CHARGES, declared,
                             f"{adapter.SOURCE} unexpectedly caps charge count")

    def test_universally_absent_means_enforced_by_no_network(self):
        """
        Keeps the constant honest. Note it is about *enforcement*: AP2 declares
        a total cap and a count, and this assertion still holds because AP2
        enforces nothing.
        """
        enforced = set()
        for raw, adapter in self.ALL:
            enforced |= adapter.normalise(raw).rail.declared()
        for c in UNIVERSALLY_ABSENT:
            self.assertNotIn(c, enforced,
                             f"{c} is enforced somewhere; narrow the claim")

    def test_ap2_declares_what_no_network_enforces(self):
        """The sharp version of the finding, asserted."""
        env = AP2Adapter.normalise(AP2_FIXTURE)
        for c in UNIVERSALLY_ABSENT:
            self.assertEqual(env.state_of(c), DECLARED,
                             f"expected AP2 to declare {c}")

    def test_exactly_one_adapter_is_wired(self):
        wired = [a.SOURCE for a in ADAPTERS.values() if a.WIRED]
        self.assertEqual(wired, ["razorpay-upi-autopay"])


if __name__ == "__main__":
    unittest.main()
