import unittest

from mandate_gate.authority import Authority, Caveat, admit
from mandate_gate.envelope import Scope

ROOT = b"principal-root-key"
OTHER = b"someone-elses-key"
MANDATE = "token_x"
T0 = 1_700_000_000


def issued(*caveats):
    return Authority.issue(ROOT, authority_id="a1", mandate_id=MANDATE,
                           caveats=caveats)


class TestIssuance(unittest.TestCase):
    def test_a_root_authority_verifies(self):
        self.assertTrue(issued(Caveat("per_charge_max", 500)).verify(ROOT))

    def test_it_does_not_verify_under_another_key(self):
        self.assertFalse(issued(Caveat("per_charge_max", 500)).verify(OTHER))

    def test_issuing_needs_a_secret(self):
        with self.assertRaises(ValueError):
            Authority.issue(b"", authority_id="a", mandate_id=MANDATE)

    def test_an_unknown_caveat_kind_is_refused_at_construction(self):
        """
        A caveat that maps to no limit could never be enforced, so accepting one
        would mean carrying a restriction that silently does nothing.
        """
        with self.assertRaises(ValueError) as ctx:
            Caveat("vibes", 1)
        self.assertIn("vibes", str(ctx.exception))

    def test_caveat_order_is_part_of_the_signature(self):
        a = issued(Caveat("per_charge_max", 500), Caveat("max_charges", 3))
        reordered = Authority(a.authority_id, a.mandate_id,
                              tuple(reversed(a.caveats)), a.signature)
        self.assertFalse(reordered.verify(ROOT))


class TestNarrowingNeedsNoSecret(unittest.TestCase):
    """
    The property that makes delegation possible at all. A holder can hand over
    less mid-task, with no round trip to the principal and no shared secret.
    """

    def test_attenuating_produces_a_valid_authority(self):
        sub = issued(Caveat("per_charge_max", 500)).attenuate(
            Caveat("per_charge_max", 100))
        self.assertTrue(sub.verify(ROOT))

    def test_the_narrower_value_wins(self):
        sub = issued(Caveat("per_charge_max", 500)).attenuate(
            Caveat("per_charge_max", 100))
        self.assertEqual(sub.to_limits().per_charge_max, 100)

    def test_scopes_intersect_rather_than_replace(self):
        sub = issued(Caveat("merchant_in", ("a", "b", "c"))).attenuate(
            Caveat("merchant_in", ("b", "c", "d")))
        self.assertEqual(sub.to_limits().scope.merchants, frozenset({"b", "c"}))

    def test_a_chain_of_three_holders_composes(self):
        root = issued(Caveat("per_charge_max", 500),
                      Caveat("cumulative_max", 2000))
        mid = root.attenuate(Caveat("per_charge_max", 200))
        leaf = mid.attenuate(Caveat("max_charges", 2))
        limits = leaf.to_limits()
        self.assertEqual(limits.per_charge_max, 200)
        self.assertEqual(limits.cumulative_max, 2000)
        self.assertEqual(limits.max_charges, 2)
        self.assertEqual(leaf.depth, 4)
        self.assertTrue(leaf.verify(ROOT))

    def test_the_original_is_unchanged(self):
        root = issued(Caveat("per_charge_max", 500))
        root.attenuate(Caveat("per_charge_max", 1))
        self.assertEqual(root.to_limits().per_charge_max, 500)


class TestWideningIsImpossible(unittest.TestCase):
    """Three ways to try. All three fail, for two different reasons."""

    def setUp(self):
        self.root = issued(Caveat("per_charge_max", 500),
                           Caveat("merchant_in", ("shop-a", "shop-b")))
        self.sub = self.root.attenuate(Caveat("per_charge_max", 100))

    def test_appending_a_looser_caveat_is_inert(self):
        """
        It verifies -- anyone may append -- and it changes nothing, because
        folding takes the tighter value.
        """
        wider = self.sub.attenuate(Caveat("per_charge_max", 100_000))
        self.assertTrue(wider.verify(ROOT))
        self.assertEqual(wider.to_limits().per_charge_max, 100)

    def test_appending_a_wider_scope_is_inert(self):
        wider = self.sub.attenuate(Caveat("merchant_in", ("anywhere",)))
        self.assertEqual(wider.to_limits().scope.merchants, frozenset())

    def test_dropping_a_caveat_breaks_the_chain(self):
        stripped = Authority(self.sub.authority_id, self.sub.mandate_id,
                             self.sub.caveats[:-1], self.sub.signature)
        self.assertFalse(stripped.verify(ROOT))

    def test_editing_a_caveat_breaks_the_chain(self):
        edited = list(self.sub.caveats)
        edited[0] = Caveat("per_charge_max", 100_000)
        tampered = Authority(self.sub.authority_id, self.sub.mandate_id,
                             tuple(edited), self.sub.signature)
        self.assertFalse(tampered.verify(ROOT))

    def test_reissuing_from_scratch_needs_the_root_secret(self):
        forged = Authority.issue(OTHER, authority_id="a1",
                                 mandate_id=MANDATE,
                                 caveats=(Caveat("per_charge_max", 100_000),))
        self.assertFalse(forged.verify(ROOT))


class TestFolding(unittest.TestCase):
    def test_repeated_caveats_are_harmless(self):
        a = issued(*(Caveat("per_charge_max", v) for v in (500, 300, 700, 200)))
        self.assertEqual(a.to_limits().per_charge_max, 200)

    def test_order_does_not_matter_to_the_result(self):
        one = issued(Caveat("per_charge_max", 500),
                     Caveat("per_charge_max", 100)).to_limits()
        two = issued(Caveat("per_charge_max", 100),
                     Caveat("per_charge_max", 500)).to_limits()
        self.assertEqual(one.per_charge_max, two.per_charge_max)

    def test_the_tighter_rate_window_wins(self):
        a = issued(Caveat("rate", (3600, 10))).attenuate(
            Caveat("rate", (3600, 2)))
        self.assertEqual(a.to_limits().rate_limit.max_charges, 2)

    def test_no_caveats_constrains_nothing(self):
        self.assertEqual(issued().to_limits().declared(), frozenset())

    def test_every_caveat_kind_folds_into_a_limit(self):
        """
        A kind that produced no limit would be a restriction that silently does
        nothing, which is the failure mode this vocabulary exists to prevent.
        """
        samples = {
            "per_charge_max": 100, "cumulative_max": 500, "max_charges": 2,
            "expires_at": T0 + 60, "merchant_in": ("a",),
            "category_in": ("5411",), "rate": (60, 1),
        }
        from mandate_gate.authority import CAVEAT_KINDS
        self.assertEqual(set(samples), set(CAVEAT_KINDS))
        for kind, value in samples.items():
            limits = issued(Caveat(kind, value)).to_limits()
            self.assertTrue(limits.declared(), f"{kind} constrained nothing")


class TestAdmission(unittest.TestCase):
    def test_a_valid_authority_yields_limits(self):
        result = admit(issued(Caveat("per_charge_max", 200)), ROOT,
                       mandate_id=MANDATE)
        self.assertTrue(result.ok)
        self.assertEqual(result.limits.per_charge_max, 200)

    def test_intent_binding_is_required_by_default(self):
        result = admit(issued(), ROOT, mandate_id=MANDATE)
        self.assertTrue(result.limits.requires_intent_binding)

    def test_a_tampered_authority_is_refused_with_a_reason(self):
        sub = issued(Caveat("per_charge_max", 500)).attenuate(
            Caveat("per_charge_max", 100))
        stripped = Authority(sub.authority_id, sub.mandate_id,
                             sub.caveats[:-1], sub.signature)
        result = admit(stripped, ROOT, mandate_id=MANDATE)
        self.assertFalse(result.ok)
        self.assertIn("verification", result.reason)

    def test_an_authority_for_another_mandate_is_refused(self):
        result = admit(issued(), ROOT, mandate_id="a-different-mandate")
        self.assertFalse(result.ok)
        self.assertIn("mandate", result.reason)


class TestTheTrustModelIsStated(unittest.TestCase):
    """
    Guards against the claim drifting wider than the mechanism. Verification
    needs the root secret, so this makes delegation between holders trustworthy
    and does not make issuance provable to a third party.
    """

    def test_anyone_with_the_root_secret_can_forge(self):
        forged = Authority.issue(ROOT, authority_id="whatever",
                                 mandate_id=MANDATE,
                                 caveats=(Caveat("per_charge_max", 999_999),))
        self.assertTrue(forged.verify(ROOT))

    def test_the_module_says_so(self):
        import mandate_gate.authority as mod
        doc = (mod.__doc__ or "").lower()
        self.assertIn("does not", doc)
        self.assertIn("asymmetric", doc)


if __name__ == "__main__":
    unittest.main()
