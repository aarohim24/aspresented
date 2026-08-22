import unittest

from mandate_gate.envelope import (Constraint, Limits, MandateEnvelope, Scope,
                                   Window, coverage_matrix)


class TestLimits(unittest.TestCase):
    def test_declared_reports_only_pinned_constraints(self):
        limits = Limits(per_charge_max=500, expires_at=1789982013)
        self.assertEqual(limits.declared(),
                         {Constraint.PER_CHARGE_MAX, Constraint.EXPIRES_AT})

    def test_unrestricted_scope_is_not_a_constraint(self):
        self.assertNotIn(Constraint.SCOPE, Limits(scope=Scope()).declared())

    def test_populated_scope_is_a_constraint(self):
        limits = Limits(scope=Scope(merchants=frozenset({"acme"})))
        self.assertIn(Constraint.SCOPE, limits.declared())

    def test_tighten_does_not_mutate(self):
        original = Limits(per_charge_max=500)
        tightened = original.tighten(per_charge_max=100)
        self.assertEqual(original.per_charge_max, 500)
        self.assertEqual(tightened.per_charge_max, 100)


class TestWindow(unittest.TestCase):
    def test_rejects_nonsense(self):
        for kwargs in ({"seconds": 0, "max_charges": 1},
                       {"seconds": 60, "max_charges": 0}):
            with self.assertRaises(ValueError):
                Window(**kwargs)


class TestScope(unittest.TestCase):
    def test_empty_scope_permits_everything(self):
        self.assertTrue(Scope().permits("anyone", "9999"))

    def test_merchant_allowlist(self):
        scope = Scope(merchants=frozenset({"acme"}))
        self.assertTrue(scope.permits("acme", None))
        self.assertFalse(scope.permits("other", None))

    def test_both_dimensions_must_pass(self):
        scope = Scope(merchants=frozenset({"acme"}),
                      categories=frozenset({"5411"}))
        self.assertTrue(scope.permits("acme", "5411"))
        self.assertFalse(scope.permits("acme", "5812"))


class TestEnvelope(unittest.TestCase):
    def rail_only(self, **policy):
        return MandateEnvelope(
            mandate_id="token_x", source="test-rail", subject="cust_x",
            rail=Limits(per_charge_max=500, expires_at=2000),
            policy=Limits(**policy),
        )

    def test_requires_identity(self):
        with self.assertRaises(ValueError):
            MandateEnvelope(mandate_id="", source="s", subject="c",
                            rail=Limits())

    def test_policy_narrows_per_charge_max(self):
        env = self.rail_only(per_charge_max=100)
        self.assertEqual(env.effective.per_charge_max, 100)

    def test_policy_cannot_widen_per_charge_max(self):
        env = self.rail_only(per_charge_max=9999)
        self.assertEqual(env.effective.per_charge_max, 500)

    def test_policy_supplies_what_rail_lacks(self):
        env = self.rail_only(cumulative_max=1500,
                             rate_limit=Window(seconds=86400, max_charges=2))
        self.assertEqual(env.effective.cumulative_max, 1500)
        self.assertEqual(env.effective.rate_limit.max_charges, 2)

    def test_unenforced_by_rail_names_the_gap(self):
        """The property that makes the finding structural rather than rhetorical."""
        env = self.rail_only(cumulative_max=1500, max_charges=3,
                             rate_limit=Window(seconds=3600, max_charges=1),
                             scope=Scope(merchants=frozenset({"acme"})),
                             requires_intent_binding=True)
        self.assertEqual(env.unenforced_by_rail, {
            Constraint.CUMULATIVE_MAX, Constraint.MAX_CHARGES,
            Constraint.RATE_LIMIT, Constraint.SCOPE,
            Constraint.INTENT_BINDING,
        })

    def test_gate_is_not_redundant(self):
        self.assertTrue(self.rail_only(cumulative_max=1500).unenforced_by_rail)


class TestCoverageMatrix(unittest.TestCase):
    def test_matrix_shape(self):
        env = MandateEnvelope(
            mandate_id="m", source="rail-a", subject="s",
            rail=Limits(per_charge_max=500),
        )
        matrix = coverage_matrix([env])
        self.assertTrue(matrix["rail-a"]["per_charge_max"])
        self.assertFalse(matrix["rail-a"]["cumulative_max"])


if __name__ == "__main__":
    unittest.main()
