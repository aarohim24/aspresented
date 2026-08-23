import random
import unittest

from mandate_gate.envelope import Limits
from mandate_gate.harness import runner
from mandate_gate.harness.metrics import Outcome, render, score
from mandate_gate.harness.scenarios import (ABUSE_CLASSES, BOUNDARY_SESSIONS,
                                            POLICY, RAIL, build_sessions)


def corpus(seed=11, honest=6, per_class=2):
    return build_sessions(random.Random(seed), honest_sessions=honest,
                          per_abuse_class=per_class)


class TestScenarioConstruction(unittest.TestCase):
    def test_every_abuse_class_is_generated(self):
        kinds = {s.kind for s in corpus()}
        for cls in ABUSE_CLASSES:
            self.assertIn(cls, kinds)

    def test_every_boundary_session_is_generated(self):
        kinds = {s.kind for s in corpus()}
        for name in BOUNDARY_SESSIONS:
            self.assertIn(f"boundary:{name}", kinds)

    def test_boundary_sessions_contain_only_honest_attempts(self):
        """
        If a boundary session smuggled in an abusive attempt it would inflate
        recall and understate the false-decline rate simultaneously.
        """
        for s in corpus():
            if s.kind.startswith("boundary:"):
                labels = {a.label for a in s.attempts}
                self.assertEqual(labels, {"honest"}, s.session_id)

    def test_abuse_sessions_carry_honest_prefixes(self):
        """
        Draining requires legitimate charges first, and those must count toward
        the false-decline rate -- so a gate that panics before the cap is
        reached is penalised rather than praised.

        The count is derived rather than hardcoded: the policy ceiling does not
        divide the cumulative cap evenly, so the prefix is ceiling-sized charges
        plus a remainder.
        """
        from mandate_gate.harness.scenarios import POLICY
        drains = [s for s in corpus() if s.kind == "drain_cumulative"]
        self.assertTrue(drains)
        labels = [a.label for a in drains[0].attempts]

        step = POLICY.per_charge_max
        expected = -(-POLICY.cumulative_max // step)      # ceil division
        self.assertEqual(labels.count("honest"), expected)
        self.assertEqual(labels[-1], "drain_cumulative")

        # and the prefix must land on the cap exactly, or the boundary case
        # is not a boundary case
        prefix = [a for a in drains[0].attempts if a.label == "honest"]
        self.assertEqual(sum(a.request.amount for a in prefix),
                         POLICY.cumulative_max)

    def test_generation_is_deterministic(self):
        a = [s.session_id for s in corpus(seed=3)]
        b = [s.session_id for s in corpus(seed=3)]
        self.assertEqual(a, b)


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.sessions = corpus()

    def test_boundary_traffic_is_never_refused(self):
        """The real test of the gate. Exactly-on-the-limit must pass."""
        boundary = [s for s in self.sessions if s.kind.startswith("boundary:")]
        outcomes = runner.run(boundary, policy=POLICY, rail_limits=RAIL)
        refused = [o for o in outcomes if not o.allowed]
        self.assertEqual(refused, [], f"false declines: {refused}")

    def test_every_abuse_class_is_caught(self):
        report = score(runner.run(self.sessions, policy=POLICY,
                                  rail_limits=RAIL))
        for cls in ABUSE_CLASSES:
            self.assertIn(cls, report.classes)
            self.assertEqual(report.classes[cls].recall, 1.0, cls)

    def test_over_ceiling_is_the_rails_catch_once_policy_is_out_of_the_way(self):
        """
        A control that the rail simulator does its own job.

        With a policy in force the policy ceiling is tighter and fires first,
        which is correct -- and it means the rail's own check can only be
        observed with policy stripped. That is also what makes the preflight's
        recall non-zero rather than zero.
        """
        sessions = [s for s in self.sessions if s.kind == "over_ceiling"]

        with_policy = runner.run(sessions, policy=POLICY, rail_limits=RAIL)
        for o in with_policy:
            if o.label == "over_ceiling":
                self.assertFalse(o.allowed)
                self.assertEqual(o.refused_by, "policy")

        bare = runner.run(sessions, policy=Limits(), duplicate_window=-1)
        caught_by_rail = [o for o in bare
                          if o.label == "over_ceiling" and o.refused_by == "rail"]
        self.assertTrue(caught_by_rail, "the rail caught nothing on its own")

    def test_correct_retry_is_replayed_not_refused(self):
        sessions = [s for s in self.sessions
                    if s.kind == "boundary:correct_retry_same_key"]
        outcomes = runner.run(sessions, policy=POLICY, rail_limits=RAIL)
        self.assertTrue(any(o.replayed for o in outcomes))
        self.assertTrue(all(o.allowed for o in outcomes))


class TestPreflightControls(unittest.TestCase):
    """The checks that make the headline numbers trustworthy."""

    def test_stripping_policy_collapses_recall(self):
        sessions = corpus()
        with_policy = score(runner.run(sessions, policy=POLICY))
        without = score(runner.run(sessions, policy=Limits(),
                                   duplicate_window=-1))
        self.assertGreater(with_policy.recall, 0.95)
        self.assertLess(without.recall, 0.25)

    def test_stripping_policy_declines_nothing_honest(self):
        without = score(runner.run(corpus(), policy=Limits(),
                                   duplicate_window=-1))
        self.assertEqual(without.honest_refused, 0)


class TestMetrics(unittest.TestCase):
    def test_false_decline_rate(self):
        outcomes = [
            Outcome("honest", None, True, (), None, 100),
            Outcome("honest", None, False, ("X",), "policy", 100),
        ]
        self.assertAlmostEqual(score(outcomes).false_decline_rate, 0.5)

    def test_attribution_requires_the_expected_code(self):
        right = score([Outcome("cls", "WANT", False, ("WANT",), "policy", 10)])
        wrong = score([Outcome("cls", "WANT", False, ("OTHER",), "policy", 10)])
        self.assertEqual(right.classes["cls"].attribution, 1.0)
        self.assertEqual(wrong.classes["cls"].attribution, 0.0)
        self.assertEqual(wrong.classes["cls"].recall, 1.0)   # caught anyway

    def test_weak_classes_named_not_averaged(self):
        report = score([
            Outcome("strong", None, False, ("A",), "policy", 10),
            Outcome("weak", None, True, (), None, 10),
        ])
        self.assertEqual(report.weak_classes(), ["weak"])

    def test_value_blocked_counts_only_refused(self):
        report = score([
            Outcome("cls", None, False, ("A",), "policy", 500),
            Outcome("cls", None, True, (), None, 900),
        ])
        self.assertEqual(report.amount_blocked, 500)

    def test_render_is_safe_on_empty(self):
        self.assertIn("False-decline", render(score([])))


if __name__ == "__main__":
    unittest.main()
