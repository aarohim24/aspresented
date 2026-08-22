#!/usr/bin/env python3
"""
Run the adversarial harness and print the report.

Order matters. The integrity preflight runs first, because a score from an
evaluator nobody has stress-tested is decoration. Two controls:

  Control A -- policy limits stripped. What remains is the rail plus the gate's
    structural input validation (clock-skew detection is not a merchant policy
    choice, so it still fires). Nearly everything honest should pass and recall
    should collapse. If recall is already high here, the labelled "abuse" was
    not abusive and the headline recall is measuring nothing.

  Control B -- a gate that refuses everything. Recall must hit 100% and the
    false-decline rate must hit 100%. If either stays low, the metric is not
    wired to the decisions it claims to score.

Only then the held-out score.

    python3 tools/run_harness.py [--seed 7] [--sessions 40]
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mandate_gate.envelope import Limits                      # noqa: E402
from mandate_gate.gate import Gate                            # noqa: E402
from mandate_gate.harness import runner                       # noqa: E402
from mandate_gate.harness.metrics import render, score        # noqa: E402
from mandate_gate.harness.scenarios import (ABUSE_CLASSES, POLICY,  # noqa: E402
                                            RAIL, build_sessions)


class _RefuseEverything(Gate):
    """Control B. Deliberately useless, to prove the metrics are wired."""

    def _check(self, req, st, now):
        from mandate_gate.charge import Refusal
        return [Refusal("CONTROL_REFUSE_ALL", "amount",
                        "control: refuses unconditionally",
                        "not a real policy")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--sessions", type=int, default=40,
                    help="honest sessions (abuse sessions scale with classes)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    sessions = build_sessions(rng, honest_sessions=args.sessions)

    # Stratified, deterministic split. Stratifying matters: a plain shuffle
    # can drop an entire abuse class out of the holdout, and the report would
    # then quietly omit it rather than score it.
    by_kind: dict = {}
    for session in sessions:
        by_kind.setdefault(session.kind, []).append(session)

    calibration, holdout = [], []
    for kind in sorted(by_kind):
        group = by_kind[kind]
        rng.shuffle(group)
        cut = len(group) // 2
        calibration.extend(group[:cut])
        holdout.extend(group[cut:])
    rng.shuffle(calibration)
    rng.shuffle(holdout)

    missing = sorted(set(ABUSE_CLASSES) - {s.kind for s in holdout})
    if missing:
        print(f"\n  Stratification failed -- absent from holdout: {missing}")
        return 1

    print("\n" + "=" * 70)
    print("  MANDATE GATE -- adversarial harness")
    print("=" * 70)
    print(f"\n  seed {args.seed}   "
          f"{len(sessions)} sessions   "
          f"{len(ABUSE_CLASSES)} abuse classes")
    print(f"  split: {len(calibration)} calibration / {len(holdout)} holdout\n")

    # ------------------------------------------------ integrity preflight
    print("  " + "-" * 66)
    print("  EVALUATOR INTEGRITY PREFLIGHT")
    print("  " + "-" * 66 + "\n")

    bare = score(runner.run(holdout, policy=Limits(), duplicate_window=-1))
    print(f"  A. policy limits off   "
          f"false-decline {bare.false_decline_rate:6.2%}   "
          f"recall {bare.recall:6.2%}")
    a_ok = bare.false_decline_rate < 0.02 and bare.recall < 0.35
    print(f"     {'PASS' if a_ok else 'FAIL'} -- expect near-zero declines and "
          f"collapsed recall\n"
          f"          (what survives: the rail's own ceiling, plus clock-skew "
          f"validation)")

    original_check = Gate._check
    try:
        Gate._check = _RefuseEverything._check
        broken = score(runner.run(holdout))
    finally:
        Gate._check = original_check
    print(f"\n  B. refuse everything   "
          f"false-decline {broken.false_decline_rate:6.2%}   "
          f"recall {broken.recall:6.2%}")
    b_ok = broken.false_decline_rate > 0.98 and broken.recall > 0.98
    print(f"     {'PASS' if b_ok else 'FAIL'} -- both must saturate, or the "
          f"metrics are not wired to the decisions")

    if not (a_ok and b_ok):
        print("\n  Preflight failed. The scores below cannot be trusted.\n")
        return 1
    print("\n  Preflight passed. Scores below are meaningful.\n")

    # -------------------------------------------------------- real scores
    cal = score(runner.run(calibration, policy=POLICY, rail_limits=RAIL))
    hold = score(runner.run(holdout, policy=POLICY, rail_limits=RAIL))

    print("  " + "=" * 66)
    print(render(hold, "HELD-OUT RESULTS"))
    print("\n  " + "-" * 66)
    print(f"  (calibration split, for comparison: "
          f"false-decline {cal.false_decline_rate:.2%}, "
          f"recall {cal.recall:.2%})")

    print("\n  " + "-" * 66)
    print("  WHAT THIS DOES AND DOES NOT SHOW")
    print("  " + "-" * 66)
    print("  Charges execute against a rail simulator that enforces exactly")
    print("  what Razorpay documents -- a per-charge ceiling and an expiry --")
    print("  because /v1/payments/create/recurring needs account activation")
    print("  this build does not have. Traffic is synthetic and generated by")
    print("  the same author as the gate, so recall is an upper bound, not a")
    print("  production estimate. The false-decline rate is the honest half:")
    print("  it measures whether the policy layer breaks legitimate use.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
