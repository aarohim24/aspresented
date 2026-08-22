import os
import random
import tempfile
import unittest

from mandate_gate.attack import Fuzzer, check, run
from mandate_gate.attack.base import Attempt, Briefing
from mandate_gate.charge import ChargeRequest, Intent
from mandate_gate.envelope import Limits, MandateEnvelope, Scope, Window
from mandate_gate.gate import Gate
from mandate_gate.ledger import Ledger
from mandate_gate.rail import RailSimulator

T0 = 1_700_000_000
HOUR = 3600
CEILING = 500
SECRET = b"attack-test-secret"

RAIL = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)
POLICY = Limits(cumulative_max=2000, max_charges=6,
                rate_limit=Window(seconds=HOUR, max_charges=4),
                scope=Scope(merchants=frozenset({"shop-a", "shop-b"})),
                requires_intent_binding=True)

INTENTS = (Intent(intent_id="int_1", mandate_id="m", max_amount=CEILING,
                  expires_at=T0 + 30 * 86_400, merchant="shop-a"),)


def envelope(**policy_overrides):
    policy = POLICY.tighten(**policy_overrides) if policy_overrides else POLICY
    return MandateEnvelope(mandate_id="m", source="razorpay-upi-autopay",
                           subject="c", rail=RAIL, policy=policy)


def ledger_with(charges, path=None):
    """A ledger written directly, to test the oracle in isolation."""
    path = path or os.path.join(tempfile.mkdtemp(), "l.jsonl")
    led = Ledger(path, clock=lambda: T0)
    led.append("mandate", {"mandate_id": "m"})
    for c in charges:
        led.append("decision", {"mandate_id": "m", "allowed": True,
                                "replayed": False, **c})
    return led


class TestOracleDetectsEachViolation(unittest.TestCase):
    """
    The oracle's own integrity check. An oracle that only ever reports "clean"
    is indistinguishable from no oracle, so each invariant is shown firing on a
    ledger crafted to break it.
    """

    def kinds(self, violations):
        return {v.invariant for v in violations}

    def test_per_charge_ceiling(self):
        led = ledger_with([{"idempotency_key": "a", "amount": CEILING * 3,
                            "at": T0, "merchant": "shop-a",
                            "intent_id": "int_1"}])
        self.assertIn("per_charge_max", self.kinds(check(led, envelope())))

    def test_cumulative_cap(self):
        led = ledger_with([
            {"idempotency_key": f"c{i}", "amount": CEILING, "at": T0 + i * HOUR * 2,
             "merchant": "shop-a", "intent_id": "int_1"} for i in range(5)])
        self.assertIn("cumulative_max", self.kinds(check(led, envelope())))

    def test_charge_count(self):
        led = ledger_with([
            {"idempotency_key": f"c{i}", "amount": 1, "at": T0 + i * HOUR * 2,
             "merchant": "shop-a", "intent_id": "int_1"} for i in range(8)])
        self.assertIn("max_charges", self.kinds(check(led, envelope())))

    def test_rate_window(self):
        led = ledger_with([
            {"idempotency_key": f"c{i}", "amount": 1, "at": T0 + i,
             "merchant": "shop-a", "intent_id": "int_1"} for i in range(6)])
        self.assertIn("rate_limit", self.kinds(check(led, envelope())))

    def test_scope(self):
        led = ledger_with([{"idempotency_key": "a", "amount": 1, "at": T0,
                            "merchant": "shop-rogue", "intent_id": "int_1"}])
        self.assertIn("scope", self.kinds(check(led, envelope())))

    def test_expiry(self):
        led = ledger_with([{"idempotency_key": "a", "amount": 1,
                            "at": T0 + 86_400 * 40, "merchant": "shop-a",
                            "intent_id": "int_1"}])
        self.assertIn("expires_at", self.kinds(check(led, envelope())))

    def test_intent_binding(self):
        led = ledger_with([{"idempotency_key": "a", "amount": 1, "at": T0,
                            "merchant": "shop-a", "intent_id": None}])
        self.assertIn("intent_binding", self.kinds(check(led, envelope())))

    def test_a_compliant_ledger_is_clean(self):
        led = ledger_with([
            {"idempotency_key": f"c{i}", "amount": 100, "at": T0 + i * HOUR * 2,
             "merchant": "shop-a", "intent_id": "int_1"} for i in range(3)])
        self.assertEqual(check(led, envelope()), [])

    def test_refused_charges_are_not_counted_against_the_gate(self):
        """A refusal is the gate working, not a violation."""
        path = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        led = Ledger(path, clock=lambda: T0)
        led.append("decision", {"mandate_id": "m", "allowed": False,
                                "amount": CEILING * 9, "at": T0,
                                "idempotency_key": "x"})
        self.assertEqual(check(led, envelope()), [])


class TestOracleCatchesABrokenGate(unittest.TestCase):
    """
    The test that gives the sweep meaning: with a check removed, the attacker
    must extract past the cap and the oracle must say so.
    """

    def run_with_cumulative_check_removed(self):
        original = Gate._check

        def without_cumulative(self, req, st, now):
            return [r for r in original(self, req, st, now)
                    if r.code != "CUMULATIVE_EXCEEDED"]

        Gate._check = without_cumulative
        try:
            return run(envelope(max_charges=None), 
                       Fuzzer("m", random.Random(5), ceiling_hint=CEILING),
                       secret=SECRET, intents=INTENTS, budget=40,
                       start_time=T0, seconds_per_attempt=1200)
        finally:
            Gate._check = original

    def test_removing_the_cumulative_check_is_detected(self):
        result = self.run_with_cumulative_check_removed()
        self.assertGreater(result.extracted, POLICY.cumulative_max,
                           "attacker failed to exceed the cap at all")
        self.assertFalse(result.clean)
        self.assertIn("cumulative_max",
                      {v.invariant for v in result.violations})

    def test_the_intact_gate_is_clean_on_the_same_run(self):
        result = run(envelope(max_charges=None),
                     Fuzzer("m", random.Random(5), ceiling_hint=CEILING),
                     secret=SECRET, intents=INTENTS, budget=40,
                     start_time=T0, seconds_per_attempt=1200)
        self.assertTrue(result.clean, [v.detail for v in result.violations])
        self.assertLessEqual(result.extracted, POLICY.cumulative_max)


class TestAttackerIsBlindToPolicy(unittest.TestCase):
    """
    The asymmetry that makes the run a measurement. An attacker handed the
    policy would be testing arithmetic.
    """

    def test_briefing_carries_only_the_rail_terms(self):
        result_briefing = Briefing(mandate={"per_charge_max": CEILING})
        for forbidden in ("cumulative_max", "max_charges", "rate_limit",
                          "scope", "requires_intent_binding"):
            self.assertNotIn(forbidden, result_briefing.mandate)

    def test_the_session_briefs_only_rail_terms(self):
        from mandate_gate.attack.session import _mandate_view
        view = _mandate_view(envelope())
        self.assertIn("per_charge_max", view)
        self.assertNotIn("cumulative_max", view)
        self.assertNotIn("scope", view)


class TestFuzzer(unittest.TestCase):
    def test_is_deterministic(self):
        def keys():
            f = Fuzzer("m", random.Random(1), ceiling_hint=CEILING)
            b = Briefing(mandate={"per_charge_max": CEILING},
                         seen_merchants=("shop-a",), intents=("int_1",))
            out = []
            for _ in range(10):
                req = f.propose(b)
                out.append((req.idempotency_key, req.amount))
                b.history.append(Attempt(request=req, allowed=False,
                                         codes=("X",), remediations=("",)))
            return out
        self.assertEqual(keys(), keys())

    def test_reads_the_headroom_out_of_a_remediation(self):
        """
        Also a test of the refusal strings: if remediation carried no usable
        number, this strategy could never fire.
        """
        f = Fuzzer("m", random.Random(1), ceiling_hint=CEILING)
        b = Briefing(mandate={"per_charge_max": CEILING},
                     seen_merchants=("shop-a",), intents=("int_1",))
        b.history.append(Attempt(
            request=ChargeRequest(mandate_id="m", amount=500,
                                  idempotency_key="k"),
            allowed=False, codes=("CUMULATIVE_EXCEEDED",),
            remediations=("Charge at most 137 paise.",)))
        self.assertEqual(f._hinted_amount(b), 137)

    def test_varies_amounts_so_the_duplicate_check_does_not_absorb_it(self):
        """
        A first version sent round numbers and spent most of its budget being
        refused as a duplicate, never reaching the deeper constraints.
        """
        result = run(envelope(), Fuzzer("m", random.Random(2),
                                        ceiling_hint=CEILING),
                     secret=SECRET, intents=INTENTS, budget=40,
                     start_time=T0, seconds_per_attempt=1200)
        dupes = result.codes.get("DUPLICATE_CHARGE", 0)
        self.assertLess(dupes, result.attempts // 2)

    def test_reaches_several_distinct_constraints(self):
        result = run(envelope(), Fuzzer("m", random.Random(4),
                                        ceiling_hint=CEILING),
                     secret=SECRET, intents=INTENTS, budget=50,
                     start_time=T0, seconds_per_attempt=1200)
        self.assertGreaterEqual(len(result.coverage), 3)


class TestSessionHygiene(unittest.TestCase):
    def test_ledger_verifies_after_an_attack(self):
        result = run(envelope(), Fuzzer("m", random.Random(6),
                                        ceiling_hint=CEILING),
                     secret=SECRET, intents=INTENTS, budget=20,
                     start_time=T0)
        self.assertTrue(result.attempts > 0)   # run() verifies, or raises

    def test_transcript_records_every_attempt(self):
        result = run(envelope(), Fuzzer("m", random.Random(7),
                                        ceiling_hint=CEILING),
                     secret=SECRET, intents=INTENTS, budget=15,
                     start_time=T0)
        self.assertEqual(len(result.transcript), result.attempts)


if __name__ == "__main__":
    unittest.main()
