import os
import tempfile
import unittest

from mandate_gate.charge import ChargeRequest, Intent
from mandate_gate.envelope import Limits, MandateEnvelope, Scope, Window
from mandate_gate.gate import Gate
from mandate_gate.ledger import Ledger
from mandate_gate.rail import RailSimulator

T0 = 1_700_000_000
CEILING = 500          # paise, per charge -- what the rail enforces
SECRET = b"test-secret"


class GateTestCase(unittest.TestCase):
    """A Razorpay-shaped mandate: per-charge ceiling and expiry, nothing else."""

    def build(self, **policy):
        rail_limits = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)
        env = MandateEnvelope(
            mandate_id="token_test", source="razorpay-upi-autopay",
            subject="cust_test", rail=rail_limits, policy=Limits(**policy),
        )
        path = os.path.join(tempfile.mkdtemp(), "ledger.jsonl")
        self.ledger = Ledger(path, clock=lambda: T0)
        self.rail = RailSimulator(limits=rail_limits)
        self.rail_limits = rail_limits
        self.n = 0
        return Gate(env, self.ledger, self.rail, SECRET)

    def charge(self, gate, amount=CEILING, at=T0, key=None, **kw):
        """
        Distinct purchases by default: each call gets its own merchant unless
        the test names one. Tests that mean to probe duplicate detection pass
        the same merchant deliberately.
        """
        self.n += 1
        kw.setdefault("merchant", f"shop-{self.n}")
        return gate.authorize(ChargeRequest(
            mandate_id="token_test", amount=amount, at=at,
            idempotency_key=key or f"k-{self.n}", **kw))


class TestTheGapItself(GateTestCase):
    def test_bare_rail_lets_the_mandate_be_drained(self):
        """
        The finding, executable.

        This talks to the rail directly rather than through a gate with its
        features switched off, because "no policy layer" has to mean the rail
        alone or the comparison is rigged. Six charges at the ceiling, all
        accepted, nothing objecting.
        """
        self.build()                                  # sets up self.rail
        allowed = sum(self.rail.charge(CEILING, T0 + i * 60)[0]
                      for i in range(6))
        self.assertEqual(allowed, 6)
        self.assertEqual(self.rail.amount_debited, CEILING * 6)
        self.assertGreater(self.rail.amount_debited,
                           self.rail_limits.per_charge_max * 5)

    def test_a_total_cap_stops_it(self):
        gate = self.build(cumulative_max=CEILING * 2)
        outcomes = [self.charge(gate, at=T0 + i * 60).allowed for i in range(6)]
        self.assertEqual(outcomes, [True, True, False, False, False, False])
        self.assertEqual(self.rail.amount_debited, CEILING * 2)


class TestRailStillEnforcesItsOwn(GateTestCase):
    def test_above_ceiling_refused_by_rail_not_policy(self):
        gate = self.build()
        d = self.charge(gate, amount=CEILING * 3)
        self.assertFalse(d.allowed)
        self.assertEqual(d.refused_by, "rail")
        self.assertEqual(d.rail_error, "transaction_limit_exceeded")

    def test_under_ceiling_allowed(self):
        self.assertTrue(self.charge(self.build(), amount=CEILING - 100).allowed)


class TestPolicyChecks(GateTestCase):
    def test_repeated_key_is_answered_not_refused(self):
        """
        A correct retry must get the original answer back. Refusing it -- as an
        earlier version did -- turns well-behaved clients into false declines.
        """
        gate = self.build()
        first = self.charge(gate, key="same")
        self.assertTrue(first.allowed)

        again = self.charge(gate, key="same")
        self.assertTrue(again.allowed)
        self.assertTrue(again.replayed)
        self.assertEqual(again.charge_id, first.charge_id)
        # and it must not move money a second time
        self.assertEqual(self.rail.amount_debited, CEILING)

    def test_repeated_key_replays_a_refusal_too(self):
        gate = self.build(cumulative_max=100)
        first = self.charge(gate, key="same")
        self.assertFalse(first.allowed)
        again = self.charge(gate, key="same")
        self.assertFalse(again.allowed)
        self.assertTrue(again.replayed)

    def test_keyless_retry_storm_is_caught(self):
        """Same purchase, new key, moments later: the real double-charge bug."""
        gate = self.build()
        self.assertTrue(self.charge(gate, key="k1", merchant="acme").allowed)
        d = self.charge(gate, key="k2", at=T0 + 5, merchant="acme")
        self.assertFalse(d.allowed)
        self.assertIn("DUPLICATE_CHARGE", d.codes)
        self.assertEqual(self.rail.amount_debited, CEILING)

    def test_same_purchase_long_after_is_allowed(self):
        gate = self.build()
        self.assertTrue(self.charge(gate, key="k1", merchant="acme").allowed)
        self.assertTrue(
            self.charge(gate, key="k2", at=T0 + 4000, merchant="acme").allowed)

    def test_charge_count_cap(self):
        gate = self.build(max_charges=2)
        outcomes = [self.charge(gate, at=T0 + i * 60).allowed for i in range(4)]
        self.assertEqual(outcomes, [True, True, False, False])

    def test_rate_limit(self):
        gate = self.build(rate_limit=Window(seconds=3600, max_charges=2))
        burst = [self.charge(gate, at=T0 + i).allowed for i in range(3)]
        self.assertEqual(burst, [True, True, False])
        # after the window, permitted again
        self.assertTrue(self.charge(gate, at=T0 + 3601).allowed)

    def test_scope_violation(self):
        gate = self.build(scope=Scope(merchants=frozenset({"acme"})))
        self.assertTrue(self.charge(gate, merchant="acme").allowed)
        d = self.charge(gate, merchant="rogue")
        self.assertFalse(d.allowed)
        self.assertIn("SCOPE_VIOLATION", d.codes)

    def test_policy_expiry_tighter_than_rail(self):
        gate = self.build(expires_at=T0 + 100)
        self.assertTrue(self.charge(gate, at=T0 + 50).allowed)
        d = self.charge(gate, at=T0 + 200)
        self.assertFalse(d.allowed)
        self.assertIn("POLICY_EXPIRED", d.codes)

    def test_all_failures_reported_together(self):
        """One round trip should reveal every problem, not just the first."""
        gate = self.build(cumulative_max=100,
                          scope=Scope(merchants=frozenset({"acme"})))
        d = self.charge(gate, merchant="rogue")
        self.assertFalse(d.allowed)
        self.assertIn("CUMULATIVE_EXCEEDED", d.codes)
        self.assertIn("SCOPE_VIOLATION", d.codes)


class TestIntentBinding(GateTestCase):
    def bound_gate(self):
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(
            intent_id="int_1", mandate_id="token_test", max_amount=CEILING,
            expires_at=T0 + 3600, merchant="acme"))
        return gate

    def test_charge_without_intent_refused(self):
        d = self.charge(self.bound_gate())
        self.assertFalse(d.allowed)
        self.assertIn("INTENT_UNBOUND", d.codes)

    def test_unknown_intent_refused(self):
        d = self.charge(self.bound_gate(), intent_id="int_nope")
        self.assertIn("INTENT_UNBOUND", d.codes)

    def test_bound_charge_allowed(self):
        d = self.charge(self.bound_gate(), intent_id="int_1", merchant="acme")
        self.assertTrue(d.allowed)

    def test_amount_above_intent_refused(self):
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="int_1", mandate_id="token_test",
                                  max_amount=200, expires_at=T0 + 3600))
        d = self.charge(gate, amount=CEILING, intent_id="int_1")
        self.assertFalse(d.allowed)
        self.assertIn("INTENT_MISMATCH", d.codes)

    def test_merchant_substitution_refused(self):
        d = self.charge(self.bound_gate(), intent_id="int_1", merchant="rogue")
        self.assertFalse(d.allowed)
        self.assertIn("INTENT_MISMATCH", d.codes)

    def test_tampered_intent_fails_verification(self):
        gate = self.bound_gate()
        good = gate.intents["int_1"]
        # keep the signature, change the amount -- the classic forgery
        gate.intents["int_1"] = good.__class__(
            intent_id=good.intent_id, mandate_id=good.mandate_id,
            max_amount=999_999, expires_at=good.expires_at,
            merchant=good.merchant, signature=good.signature)
        d = self.charge(gate, intent_id="int_1", merchant="acme")
        self.assertFalse(d.allowed)
        self.assertIn("INTENT_UNBOUND", d.codes)


class TestRefusalsAreActionable(GateTestCase):
    def test_every_refusal_names_a_field_and_a_fix(self):
        gate = self.build(cumulative_max=100)
        d = self.charge(gate)
        for refusal in d.refusals:
            self.assertTrue(refusal.field, refusal.code)
            self.assertTrue(refusal.remediation, refusal.code)

    def test_cumulative_refusal_states_the_remaining_headroom(self):
        gate = self.build(cumulative_max=CEILING + 100)
        self.charge(gate)
        d = self.charge(gate, at=T0 + 60)
        self.assertIn("100", d.refusals[0].remediation)


class TestLedgerIsTheState(GateTestCase):
    def test_state_survives_a_fresh_gate_over_the_same_ledger(self):
        gate = self.build(cumulative_max=CEILING * 2)
        self.charge(gate, at=T0)
        self.charge(gate, at=T0 + 60)

        reopened = Gate(gate.envelope, self.ledger, self.rail, SECRET)
        d = reopened.authorize(ChargeRequest(
            mandate_id="token_test", amount=CEILING, at=T0 + 120,
            idempotency_key="fresh"))
        self.assertFalse(d.allowed)
        self.assertIn("CUMULATIVE_EXCEEDED", d.codes)

    def test_ledger_verifies_and_records_refusals_too(self):
        gate = self.build(cumulative_max=100)
        self.charge(gate)
        self.ledger.verify()
        pack = self.ledger.evidence_pack("token_test")
        self.assertTrue(pack["integrity"]["ok"])
        kinds = [e["kind"] for e in pack["entries"]]
        self.assertIn("decision", kinds)
        refused = [e for e in pack["entries"]
                   if e["kind"] == "decision" and not e["payload"]["allowed"]]
        self.assertEqual(len(refused), 1)


if __name__ == "__main__":
    unittest.main()
