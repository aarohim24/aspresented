#!/usr/bin/env python3
"""
Turn an attacker loose on the gate and report what it found.

    python3 tools/run_attack.py [--budget 40] [--seed 3]

Two numbers, and they mean different things.

**Extracted** is what the attacker got away with. A mandate is meant to be
spent, so this is not by itself a defect -- it is the cost of doing business,
bounded by policy.

**Violations** are invariants the gate allowed to be broken, judged over the
finished ledger rather than by asking the gate whether it agreed with itself.
Any violation is a defect, whatever provoked it.

The run sweeps several tempos, because the attacker's pacing decides which
constraint binds and a single choice under-covers. Charging everything at one
instant exhausts the rate window after four charges and never reaches the
cumulative cap; spacing charges twenty minutes apart walks past the rate
window and puts the cumulative cap and the count under real pressure; spacing
them further outlives the signed intent and tests nothing but binding; a day
between charges outlives the mandate itself. Only the union of tempos covers the
policy, and the coverage report at the end names any check no tempo reached.

A sweep with zero violations is not proof of correctness. It means one attacker,
at these tempos, within this budget, did not find a hole -- which is the most
any adversarial run can tell you.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mandate_gate.attack import Fuzzer, run                       # noqa: E402
from mandate_gate.charge import REFUSAL_CODES, Intent             # noqa: E402
from mandate_gate.envelope import (Limits, MandateEnvelope, Scope,  # noqa: E402
                                   Window)

T0 = 1_700_000_000
HOUR = 3600
CEILING = 500

SECRET = os.environ.get("MANDATE_GATE_INTENT_SECRET",
                        "DEMO-ONLY-not-a-secret-attack").encode()

#: The rail as verified: a per-charge ceiling and an expiry, nothing more.
RAIL = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)

#: What the merchant adds. The attacker cannot see this.
POLICY = Limits(
    cumulative_max=2000,
    max_charges=6,
    rate_limit=Window(seconds=HOUR, max_charges=4),
    scope=Scope(merchants=frozenset({"shop-a", "shop-b"})),
    requires_intent_binding=True,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=40,
                    help="maximum charge attempts")
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--tempos", type=int, nargs="+",
                    default=[0, 600, 1200, 4000, 86_400],
                    help="seconds between attempts; each is a separate run")
    args = ap.parse_args()

    envelope = MandateEnvelope(
        mandate_id="token_attack", source="razorpay-upi-autopay",
        subject="cust_attack", rail=RAIL, policy=POLICY)

    intents = (
        Intent(intent_id="int_weekly", mandate_id="token_attack",
               max_amount=CEILING, expires_at=T0 + 6 * HOUR,
               merchant="shop-a"),
    )

    print("\n" + "=" * 70)
    print("  ADVERSARIAL SWEEP")
    print("=" * 70)
    print("\n  attacker         fuzzer (deterministic, no credentials)")
    print(f"  budget           {args.budget} attempts per tempo")
    print(f"  tempos           {', '.join(str(t) + 's' for t in args.tempos)}")
    print("  what it sees     the mandate's own terms, plus every refusal")
    print("  what it cannot   the merchant's policy, and this repository\n")

    cap = POLICY.cumulative_max
    print(f"  {'tempo':>8}  {'settled':>7}  {'extracted':>11}  "
          f"{'of cap':>7}  codes reached")
    print("  " + "-" * 66)

    all_violations, all_codes, best = [], set(), 0
    for tempo in args.tempos:
        result = run(
            envelope,
            Fuzzer("token_attack", random.Random(args.seed),
                   ceiling_hint=CEILING),
            secret=SECRET, intents=intents, budget=args.budget,
            start_time=T0, seconds_per_attempt=tempo)

        share = result.extracted / cap if cap else 0
        best = max(best, share)
        all_codes |= set(result.coverage)
        for v in result.violations:
            all_violations.append((tempo, v))

        print(f"  {str(tempo) + 's':>8}  {result.allowed:>7}  "
              f"{'Rs ' + format(result.extracted / 100, ',.2f'):>11}  "
              f"{share:>6.0%}  {len(result.coverage)}")

    print("\n  " + "-" * 66)
    print(f"  refusal codes reached: {len(all_codes)}/{len(REFUSAL_CODES)}")
    for code in REFUSAL_CODES:
        mark = "reached" if code in all_codes else "     --"
        print(f"    {mark}  {code}")
    unreached = [c for c in REFUSAL_CODES if c not in all_codes]
    if unreached:
        print("\n  Not provoked. Each is either a gap in this attacker or a")
        print("  check nothing exercises -- both worth knowing, neither hidden:")
        for code in unreached:
            print(f"    {code}")
    print(f"\n  closest approach to the cumulative cap: {best:.0%} "
          f"(Rs {cap / 100:,.2f})")
    print("  Getting close is expected -- a mandate is meant to be spent. The")
    print("  question is only whether anything crossed the line.")

    print("\n  " + "=" * 66)
    if not all_violations:
        print("  NO INVARIANT VIOLATIONS AT ANY TEMPO")
        print("  " + "-" * 66)
        print("  The gate held. That is not a proof of correctness -- it is one")
        print("  attacker, at four tempos, failing to find a hole, which is the")
        print("  most an adversarial run can establish. A model-driven attacker")
        print("  that never read these checks is the next thing to try.")
    else:
        print(f"  {len(all_violations)} INVARIANT VIOLATION(S) -- these are defects")
        print("  " + "-" * 66)
        for tempo, v in all_violations:
            print(f"\n  [{v.invariant}] at {tempo}s  {v.detail}")
            if v.charges:
                print(f"    charges: {', '.join(str(c) for c in v.charges[:6])}")
    print()
    return 1 if all_violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
