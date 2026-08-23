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
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mandate_gate.attack import (Fuzzer, ModelAttacker,           # noqa: E402
                                 ReplayAttacker, run)
from mandate_gate.attack.model import (DEFAULT_MODEL,              # noqa: E402
                                       GROQ_BASE_URL)
from mandate_gate.attack.scenario import (CEILING, INTENTS,        # noqa: E402
                                          MANDATE_ID, POLICY, T0,
                                          envelope as build_envelope)
from mandate_gate.charge import REFUSAL_CODES                     # noqa: E402
from mandate_gate.envelope import Limits                          # noqa: E402

SECRET = os.environ.get("MANDATE_GATE_INTENT_SECRET",
                        "DEMO-ONLY-not-a-secret-attack").encode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=40,
                    help="maximum charge attempts")
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--tempos", type=int, nargs="+", default=None,
                    help="seconds between attempts; each is a separate run. "
                         "Defaults to a five-tempo sweep for the fuzzer and a "
                         "single tempo for a model, which pays per call.")
    ap.add_argument("--attacker", choices=("fuzzer", "model", "replay"),
                    default="fuzzer",
                    help="fuzzer needs nothing; model needs GROQ_API_KEY; "
                         "replay re-runs a committed transcript")
    ap.add_argument("--base-url", default=None,
                    help="OpenAI-compatible endpoint (default: Groq)")
    ap.add_argument("--model", default=None, help="model id")
    ap.add_argument("--transcript", default=str(ROOT / "evidence" /
                                                "model-attack-transcript.json"),
                    help="where a model run is recorded and replay reads from")
    args = ap.parse_args()

    # The fuzzer is free, so it sweeps. A model costs a call per attempt and
    # Groq's free tier allows ~1000 a day: a five-tempo sweep at budget 40
    # would spend a fifth of that in one run. Default it to one tempo and make
    # the projection visible rather than surprising.
    if args.tempos is None:
        args.tempos = ([1200] if args.attacker in ("model", "replay")
                       else [0, 600, 1200, 4000, 86_400])

    # Imported, not redefined: a transcript recorded against one scenario and
    # replayed against another silently produces different numbers.
    envelope = build_envelope()
    intents = INTENTS

    print("\n" + "=" * 70)
    print("  ADVERSARIAL SWEEP")
    print("=" * 70)
    label = {"fuzzer": "fuzzer (deterministic, no credentials)",
             "model": "model (OpenAI-compatible endpoint)",
             "replay": "replay of a committed model transcript"}[args.attacker]
    print(f"\n  attacker         {label}")
    if args.attacker == "model" and not (os.environ.get("GROQ_API_KEY")
                                         or os.environ.get("OPENAI_API_KEY")):
        print("\n  No GROQ_API_KEY or OPENAI_API_KEY in the environment.")
        print("  The model attacker will propose nothing, so this run would")
        print("  report zeros that mean 'not attempted', not 'nothing found'.")
        print("  Set a key, or use --attacker fuzzer / --attacker replay.\n")
        return 2
    print(f"  budget           {args.budget} attempts per tempo")
    print(f"  tempos           {', '.join(str(t) + 's' for t in args.tempos)}")
    print("  what it sees     the mandate's own terms, plus every refusal")
    print("  what it cannot   the merchant's policy, and this repository")
    if args.attacker == "model":
        calls = args.budget * len(args.tempos)
        # Throttled to stay inside a free tier, so a run takes real time. Say
        # how long rather than letting it look hung.
        seconds = calls * 2.1
        print(f"  projected calls  up to {calls} "
              f"({args.budget} x {len(args.tempos)} tempo(s))")
        print(f"  expected wall    ~{seconds / 60:.1f} min "
              f"(throttled to stay inside 30 req/min)")
    print()

    cap = POLICY.cumulative_max
    print(f"  {'tempo':>8}  {'settled':>7}  {'extracted':>11}  "
          f"{'of cap':>7}  codes reached")
    print("  " + "-" * 66)

    def make_attacker():
        if args.attacker == "fuzzer":
            return Fuzzer(MANDATE_ID, random.Random(args.seed),
                          ceiling_hint=CEILING)
        if args.attacker == "model":
            kwargs = {}
            if args.base_url:
                kwargs["base_url"] = args.base_url
            if args.model:
                kwargs["model"] = args.model
            return ModelAttacker(mandate_id=MANDATE_ID, **kwargs)
        with open(args.transcript) as fh:
            return ReplayAttacker(mandate_id=MANDATE_ID,
                                  transcript=json.load(fh)["calls"])

    all_violations, all_codes, best = [], set(), 0
    total_attempts = 0
    recorded: dict = {}
    for tempo in args.tempos:
        attacker = make_attacker()
        result = run(
            envelope, attacker,
            secret=SECRET, intents=intents, budget=args.budget,
            start_time=T0, seconds_per_attempt=tempo)
        if args.attacker == "model":
            # Every tempo, not just the first: a finding at one tempo that is
            # not recorded is a finding nobody else can reproduce.
            recorded[str(tempo)] = attacker.transcript()

        total_attempts += result.attempts
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

    if recorded:
        # Model runs have no seed, so an unrecorded finding is unverifiable.
        Path(args.transcript).parent.mkdir(parents=True, exist_ok=True)
        flat = [c for calls in recorded.values() for c in calls]
        with open(args.transcript, "w") as fh:
            json.dump({"model": args.model or DEFAULT_MODEL,
                       "base_url": args.base_url or GROQ_BASE_URL,
                       "tempos": {k: v for k, v in recorded.items()},
                       "calls": flat}, fh, indent=1)
        # A reply can parse as JSON and still not be a charge -- `amount: 0`
        # parses fine. Counting parsed JSON overstated this by three on a live
        # run, which is exactly the kind of number nobody checks.
        became_charge = sum(1 for c in flat
                            if c.get("parsed") and not c.get("error"))
        parsed_json = sum(1 for c in flat if c.get("parsed"))
        print(f"\n  transcript written to {args.transcript}")
        print(f"  {became_charge}/{len(flat)} exchanges became a charge "
              f"({parsed_json} parsed as JSON; the rest were unusable). "
              f"Commit it; --attacker replay reproduces this run with no "
              f"credentials.")
        errors = [c["error"] for c in flat if c.get("error")]
        if errors:
            print(f"  {len(errors)} call(s) failed, first: {errors[0]}")

    print("\n  " + "=" * 66)
    if total_attempts == 0:
        # A run where the attacker never proposed anything must not read as a
        # pass. Every model call failing looks identical to a clean sweep if
        # only violations are reported, and that would be the most misleading
        # output this tool could produce.
        print("  INCONCLUSIVE -- the attacker made no attempts")
        print("  " + "-" * 66)
        print("  Nothing was tested, so nothing was shown. This is not a")
        print("  passing result and must never be reported as one.")
        if recorded:
            errs = [c["error"] for calls in recorded.values() for c in calls
                    if c.get("error")]
            if errs:
                print(f"\n  {len(errs)} model call(s) failed. First:")
                print(f"    {errs[0]}")
                print("  None of these is a finding -- the error text above")
                print("  says which layer refused and what to do about it.")
        print()
        return 2

    if not all_violations:
        print("  NO INVARIANT VIOLATIONS AT ANY TEMPO")
        print("  " + "-" * 66)
        print("  The gate held. That is not a proof of correctness -- it is one")
        print(f"  attacker, over {total_attempts} attempts at "
              f"{len(args.tempos)} tempo(s), failing to find a hole -- which "
              f"is the")
        print("  most an adversarial run can establish. Results from different")
        print("  attackers are reported separately and never merged.")
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
