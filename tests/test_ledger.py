import json
import os
import tempfile
import unittest

from mandate_gate.ledger import GENESIS, BrokenChain, Ledger


class LedgerTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "ledger.jsonl")
        self.tick = 1000
        self.ledger = Ledger(self.path, clock=lambda: self.tick)


class TestAppend(LedgerTestCase):
    def test_first_entry_chains_to_genesis(self):
        entry = self.ledger.append("decision", {"mandate_id": "m1"})
        self.assertEqual(entry.seq, 0)
        self.assertEqual(entry.prev_hash, GENESIS)

    def test_each_entry_commits_to_its_predecessor(self):
        first = self.ledger.append("decision", {"mandate_id": "m1"})
        second = self.ledger.append("decision", {"mandate_id": "m1"})
        self.assertEqual(second.prev_hash, first.digest())

    def test_survives_reopening(self):
        self.ledger.append("decision", {"mandate_id": "m1"})
        reopened = Ledger(self.path, clock=lambda: self.tick)
        self.assertEqual(reopened.append("decision", {}).seq, 1)


class TestVerify(LedgerTestCase):
    def test_clean_chain_verifies(self):
        for _ in range(5):
            self.ledger.append("decision", {"mandate_id": "m1"})
        self.assertEqual(self.ledger.verify(), 5)

    def test_empty_ledger_verifies(self):
        self.assertEqual(self.ledger.verify(), 0)

    def test_edited_payload_breaks_the_chain(self):
        for i in range(3):
            self.ledger.append("decision", {"mandate_id": "m1", "amount": i})

        with open(self.path) as fh:
            rows = [json.loads(line) for line in fh]
        rows[0]["payload"]["amount"] = 9999          # rewrite history
        with open(self.path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True,
                                    separators=(",", ":")) + "\n")

        with self.assertRaises(BrokenChain):
            self.ledger.verify()

    def test_removed_entry_breaks_the_chain(self):
        for _ in range(3):
            self.ledger.append("decision", {"mandate_id": "m1"})
        with open(self.path) as fh:
            rows = fh.readlines()
        with open(self.path, "w") as fh:
            fh.writelines([rows[0], rows[2]])        # drop the middle
        with self.assertRaises(BrokenChain):
            self.ledger.verify()


class TestEvidencePack(LedgerTestCase):
    def test_collects_only_the_named_mandate(self):
        self.ledger.append("decision", {"mandate_id": "m1", "verdict": "allow"})
        self.ledger.append("decision", {"mandate_id": "m2", "verdict": "allow"})
        self.ledger.append("decision", {"mandate_id": "m1", "verdict": "refuse"})

        pack = self.ledger.evidence_pack("m1")
        self.assertEqual(pack["entry_count"], 2)
        self.assertTrue(pack["integrity"]["ok"])
        self.assertEqual([e["payload"]["verdict"] for e in pack["entries"]],
                         ["allow", "refuse"])

    def test_reports_tampering_rather_than_hiding_it(self):
        self.ledger.append("decision", {"mandate_id": "m1"})
        self.ledger.append("decision", {"mandate_id": "m1"})
        with open(self.path) as fh:
            rows = [json.loads(line) for line in fh]
        rows[0]["payload"]["mandate_id"] = "m1"
        rows[0]["kind"] = "note"                     # tamper
        with open(self.path, "w") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True,
                                    separators=(",", ":")) + "\n")

        pack = self.ledger.evidence_pack("m1")
        self.assertFalse(pack["integrity"]["ok"])


if __name__ == "__main__":
    unittest.main()
