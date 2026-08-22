import json
import os
import tempfile
import unittest

from mandate_gate.adjudicate import (AUTHORISED, UNAUTHORISED, UNPROVABLE,
                                     Adjudicator)
from mandate_gate.charge import ChargeRequest, Intent
from mandate_gate.envelope import Limits, MandateEnvelope, Scope
from mandate_gate.gate import Gate
from mandate_gate.ledger import Ledger
from mandate_gate.rail import RailSimulator

T0 = 1_700_000_000
CEILING = 500
SECRET = b"adj-secret"
RAIL = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)


class AdjTestCase(unittest.TestCase):
    def build(self, **policy):
        env = MandateEnvelope(
            mandate_id="m1", source="razorpay-upi-autopay", subject="c1",
            rail=RAIL, policy=Limits(**policy))
        self.path = os.path.join(tempfile.mkdtemp(), "l.jsonl")
        self.clock = {"now": T0}
        self.ledger = Ledger(self.path, clock=lambda: self.clock["now"])
        self.rail = RailSimulator(limits=RAIL)
        self.gate = Gate(env, self.ledger, self.rail, SECRET,
                         clock=lambda: self.clock["now"])
        self.adj = Adjudicator(self.ledger, SECRET)
        return self.gate

    def charge(self, key, amount=300, at=T0, merchant="shop-a", intent_id=None):
        self.clock["now"] = at
        return self.gate.authorize(ChargeRequest(
            mandate_id="m1", amount=amount, idempotency_key=key,
            merchant=merchant, intent_id=intent_id))


class TestTheEvidenceGap(AdjTestCase):
    def test_no_intent_binding_gives_unprovable(self):
        """
        The state every agent purchase on today's rails is in: the charge was
        permitted, and nothing on record shows it was authorised.
        """
        self.build()
        self.charge("k1")
        result = self.adj.adjudicate("k1")
        self.assertEqual(result.verdict, UNPROVABLE)
        self.assertIn("cannot be", " ".join(result.reasons))

    def test_intent_binding_turns_unprovable_into_authorised(self):
        """The before/after that justifies the whole project."""
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="i1", mandate_id="m1",
                                  max_amount=300, expires_at=T0 + 3600,
                                  merchant="shop-a"))
        self.charge("k1", intent_id="i1")
        result = self.adj.adjudicate("k1")
        self.assertEqual(result.verdict, AUTHORISED)


class TestVerdicts(AdjTestCase):
    def bound(self):
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="i1", mandate_id="m1",
                                  max_amount=300, expires_at=T0 + 3600,
                                  merchant="shop-a"))
        return gate

    def test_refused_charge_is_unauthorised(self):
        self.bound()
        self.charge("k1")                      # no intent -> refused
        self.assertEqual(self.adj.adjudicate("k1").verdict, UNAUTHORISED)

    def test_unknown_charge_is_unprovable(self):
        self.build()
        self.assertEqual(self.adj.adjudicate("nope").verdict, UNPROVABLE)

    def test_position_is_recomputed_not_trusted(self):
        self.build()
        self.charge("k1", amount=200, at=T0)
        self.charge("k2", amount=300, at=T0 + 4000, merchant="shop-b")
        pos = self.adj.adjudicate("k2").position_at_charge
        self.assertEqual(pos["charged_before"], 200)
        self.assertEqual(pos["charges_before"], 1)
        self.assertEqual(pos["total_after"], 500)


class TestTamperResistance(AdjTestCase):
    def test_broken_chain_refuses_to_adjudicate(self):
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="i1", mandate_id="m1",
                                  max_amount=300, expires_at=T0 + 3600,
                                  merchant="shop-a"))
        self.charge("k1", intent_id="i1")
        self.assertEqual(self.adj.adjudicate("k1").verdict, AUTHORISED)

        with open(self.path) as fh:
            rows = [json.loads(line) for line in fh]
        rows[0]["payload"]["mandate_id"] = "tampered"
        with open(self.path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True,
                                    separators=(",", ":")) + "\n")

        result = self.adj.adjudicate("k1")
        self.assertFalse(result.chain_ok)
        self.assertEqual(result.verdict, UNPROVABLE)

    def test_intent_terms_rewritten_in_the_ledger_are_caught(self):
        """
        The forgery that matters at dispute time: enlarge the approved amount
        in the record, keep the old signature, claim the charge conformed.
        """
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="i1", mandate_id="m1",
                                  max_amount=300, expires_at=T0 + 3600,
                                  merchant="shop-a"))
        self.charge("k1", amount=300, intent_id="i1")

        with open(self.path) as fh:
            rows = [json.loads(line) for line in fh]
        for row in rows:
            if row["kind"] == "intent":
                row["payload"]["max_amount"] = 999_999
        with open(self.path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True,
                                    separators=(",", ":")) + "\n")

        result = Adjudicator(Ledger(self.path), SECRET).adjudicate("k1")
        # The hash chain catches it first, which is the stronger guarantee.
        self.assertEqual(result.verdict, UNPROVABLE)
        self.assertFalse(result.chain_ok)

    def test_wrong_secret_cannot_validate_intents(self):
        gate = self.build(requires_intent_binding=True)
        gate.record_intent(Intent(intent_id="i1", mandate_id="m1",
                                  max_amount=300, expires_at=T0 + 3600,
                                  merchant="shop-a"))
        self.charge("k1", intent_id="i1")
        impostor = Adjudicator(self.ledger, b"wrong-secret")
        self.assertEqual(impostor.adjudicate("k1").verdict, UNPROVABLE)


class TestSignedShapeIsSharedWithTheSigner(AdjTestCase):
    def setUp(self):
        self.build()

    def test_verification_covers_every_signed_field(self):
        """
        The signer and the verifier build the signed payload through one
        function. They used to build it separately, so a field added to Intent
        could be signed and then silently ignored at dispute time.
        """
        from mandate_gate.charge import INTENT_SIGNED_FIELDS, Intent
        signed = Intent(intent_id="i", mandate_id="m", max_amount=1,
                        expires_at=2).signed(SECRET)
        for name in INTENT_SIGNED_FIELDS:
            self.assertTrue(hasattr(signed, name), name)


class TestMandateScoping(AdjTestCase):
    def setUp(self):
        self.build()

    def test_the_same_key_on_two_mandates_is_disambiguated(self):
        """
        Idempotency keys are unique per mandate, not globally. A shared ledger
        can hold the same key twice, and the first match is not necessarily the
        charge under dispute.
        """
        env_b = MandateEnvelope(
            mandate_id="m2", source="razorpay-upi-autopay", subject="c2",
            rail=RAIL, policy=Limits())
        gate_b = Gate(env_b, self.ledger, RailSimulator(limits=RAIL), SECRET,
                      clock=lambda: self.clock["now"])

        self.charge("shared-key", amount=100)                      # on m1
        gate_b.authorize(ChargeRequest(mandate_id="m2", amount=400,
                                       idempotency_key="shared-key",
                                       merchant="shop-b"))

        first = self.adj.adjudicate("shared-key")
        second = self.adj.adjudicate("shared-key", mandate_id="m2")
        self.assertEqual(first.mandate_id, "m1")
        self.assertEqual(second.mandate_id, "m2")
        self.assertEqual(second.charge["amount"], 400)

    def test_unknown_charge_keeps_the_mandate_it_was_asked_about(self):
        result = self.adj.adjudicate("nope", mandate_id="m9")
        self.assertEqual(result.mandate_id, "m9")
        self.assertEqual(result.verdict, UNPROVABLE)


class TestDisputable(AdjTestCase):
    def test_lists_only_settled_charges(self):
        gate = self.build(scope=Scope(merchants=frozenset({"shop-a"})))
        self.charge("k1", merchant="shop-a")
        self.charge("k2", merchant="rogue")            # refused
        refs = [c["charge_ref"] for c in self.adj.disputable()]
        self.assertEqual(refs, ["k1"])


if __name__ == "__main__":
    unittest.main()
