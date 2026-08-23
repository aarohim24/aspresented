#!/usr/bin/env python3
"""
Local console for Mandate Gate.

    python3 tools/serve.py        then open http://127.0.0.1:8700

Standard library only -- no build step, no network access, nothing to install.
Everything on the page is computed at startup from the real code: the coverage
table from the adapters, the scores from the harness, and the dispute console
from an actual hash-chained ledger built by running charges through the gate.

The demo ledger holds two mandates that differ in exactly one respect. One
requires intent binding; the other does not. Adjudicating a charge from each is
the whole argument in two clicks.
"""

from __future__ import annotations

import json
import os
import random
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mandate_gate.adapters import ADAPTERS                          # noqa: E402
from mandate_gate.adapters.ap2 import AP2Adapter                    # noqa: E402
from mandate_gate.adapters.card_on_file import CardOnFileAdapter    # noqa: E402
from mandate_gate.adapters.razorpay_upi import RazorpayUpiAdapter   # noqa: E402
from mandate_gate.adjudicate import Adjudicator                     # noqa: E402
from mandate_gate.attack import scenario                            # noqa: E402
from mandate_gate.attack.scenario import RAIL                       # noqa: E402
from mandate_gate.authority import Authority, Caveat, admit         # noqa: E402
from mandate_gate.buyer import BuyingAgent, interpret               # noqa: E402
from mandate_gate.buyer import catalogue as buyer_catalogue         # noqa: E402
from mandate_gate.buyer.scripted import (ScriptedClient,            # noqa: E402
                                         ScriptedInterpreter)
from mandate_gate.charge import ChargeRequest, Intent               # noqa: E402
from mandate_gate.envelope import (ABSENT, DECLARED, ENFORCED,       # noqa: E402
                                   Constraint, Limits, MandateEnvelope,
                                   Scope, Window)
from mandate_gate.fixtures import (AP2_OPEN_MANDATE, CARD_ON_FILE,   # noqa: E402
                                   RAZORPAY_AS_PRESENTED, RAZORPAY_MONTHLY)
from mandate_gate.gate import Gate                                  # noqa: E402
from mandate_gate.harness import runner                             # noqa: E402
from mandate_gate.harness.metrics import score                      # noqa: E402
from mandate_gate.harness.scenarios import (ABUSE_CLASSES, BOUNDARY_SESSIONS,
                                            POLICY, RAIL,
                                            build_sessions)         # noqa: E402
from mandate_gate.ledger import Ledger                              # noqa: E402
from mandate_gate.rail import RailSimulator                          # noqa: E402

PORT = 8700
T0 = 1_700_000_000
HOUR = 3600
def _demo_secret(name: str) -> bytes:
    """
    Signing key for the demo. Read from the environment so a literal in source
    never becomes the default anywhere real; falls back to a clearly-labelled
    value because this path only ever signs synthetic intents.
    """
    return os.environ.get("MANDATE_GATE_INTENT_SECRET",
                          f"DEMO-ONLY-not-a-secret-{name}").encode()

SECRET = _demo_secret("console")
LEDGER_PATH = ROOT / "evidence" / "console-ledger.jsonl"

CONSTRAINT_LABELS = {
    Constraint.PER_CHARGE_MAX: "Per-charge ceiling",
    Constraint.EXPIRES_AT: "Expiry",
    Constraint.CUMULATIVE_MAX: "Total cap",
    Constraint.MAX_CHARGES: "Charge count cap",
    Constraint.RATE_LIMIT: "Rate limit",
    Constraint.SCOPE: "Spend scope",
    Constraint.INTENT_BINDING: "Intent binding",
}

COLUMNS = [
    ("razorpay (as_presented, default)", RazorpayUpiAdapter, RAZORPAY_AS_PRESENTED),
    ("razorpay (monthly)", RazorpayUpiAdapter, RAZORPAY_MONTHLY),
    ("ap2 (open mandate)", AP2Adapter, AP2_OPEN_MANDATE),
    ("card-on-file", CardOnFileAdapter, CARD_ON_FILE),
]


# ---------------------------------------------------------------- coverage
def build_coverage() -> dict:
    envelopes = [(label, adapter.normalise(raw))
                 for label, adapter, raw in COLUMNS]
    rows = []
    for c in Constraint:
        states = [env.state_of(c) for _, env in envelopes]
        rows.append({
            "label": CONSTRAINT_LABELS[c],
            "cells": states,
            # The claim that survived every correction: enforced by nobody.
            "never_enforced": ENFORCED not in states,
            "declared_only": (ENFORCED not in states and DECLARED in states),
        })
    return {
        "rails": [label for label, _ in envelopes],
        "wired": {a.SOURCE: a.WIRED for a in ADAPTERS.values()},
        "rows": rows,
    }


# ----------------------------------------------------------------- harness
def build_harness(seed: int = 7) -> dict:
    rng = random.Random(seed)
    sessions = build_sessions(rng, honest_sessions=40)

    by_kind: dict = {}
    for s in sessions:
        by_kind.setdefault(s.kind, []).append(s)
    holdout = []
    for kind in sorted(by_kind):
        group = by_kind[kind]
        rng.shuffle(group)
        holdout.extend(group[len(group) // 2:])

    bare = score(runner.run(holdout, policy=Limits(), duplicate_window=-1))
    real = score(runner.run(holdout, policy=POLICY, rail_limits=RAIL))

    return {
        "seed": seed,
        "sessions": len(holdout),
        "abuse_classes": len(ABUSE_CLASSES),
        "boundary_families": len(BOUNDARY_SESSIONS),
        "false_decline_rate": real.false_decline_rate,
        "honest_total": real.honest_total,
        "honest_refused": real.honest_refused,
        "recall": real.recall,
        "abusive_total": real.abusive_total,
        "abusive_caught": real.abusive_caught,
        "policy_catches": real.policy_catches,
        "rail_catches": real.rail_catches,
        "amount_blocked": real.amount_blocked,
        "control_bare": {"fdr": bare.false_decline_rate,
                         "recall": bare.recall},
        "classes": [
            {"label": c.label, "recall": c.recall,
             "attribution": c.attribution, "total": c.total}
            for c in sorted(real.classes.values(), key=lambda c: c.label)
        ],
    }


# ---------------------------------------------------------- delegation
def build_delegation() -> dict:
    """
    The three-link chain, plus the three ways a holder might try to widen it.

    Computed here rather than transcribed, so the page cannot claim a property
    the code does not have.
    """
    root_secret = b"DEMO-ONLY-principal-root"
    principal = Authority.issue(
        root_secret, authority_id="auth-root", mandate_id="token_demo",
        caveats=[Caveat("per_charge_max", 500),
                 Caveat("cumulative_max", 2000),
                 Caveat("merchant_in", ("shop-a", "shop-b")),
                 Caveat("expires_at", T0 + 7 * 86400)])
    shopping = principal.attenuate(Caveat("per_charge_max", 200),
                                   Caveat("merchant_in", ("shop-a",)))
    delivery = shopping.attenuate(Caveat("max_charges", 3))

    def fold(a):
        limits = a.to_limits()
        return {
            "per_charge_max": limits.per_charge_max,
            "cumulative_max": limits.cumulative_max,
            "max_charges": limits.max_charges,
            "merchants": sorted(limits.scope.merchants) if limits.scope else [],
        }

    links = [
        {"holder": "principal", "adds": [c.describe() for c in principal.caveats],
         "folded": fold(principal), "depth": principal.depth},
        {"holder": "shopping agent",
         "adds": [c.describe() for c in shopping.caveats[len(principal.caveats):]],
         "folded": fold(shopping), "depth": shopping.depth},
        {"holder": "delivery agent",
         "adds": [c.describe() for c in delivery.caveats[len(shopping.caveats):]],
         "folded": fold(delivery), "depth": delivery.depth},
    ]

    # what the last holder can actually spend -- a fresh gate per probe, so an
    # earlier refusal's counter cannot mask the constraint being demonstrated
    limits = admit(delivery, root_secret, mandate_id="token_demo").limits
    probes = []
    for amount, merchant, note in (
            (150, "shop-a", "inside every narrowing"),
            (400, "shop-a", "inside the principal's 500, outside its own 200"),
            (100, "shop-b", "inside the principal's scope, outside its own")):
        env = MandateEnvelope(mandate_id="token_demo",
                              source="razorpay-upi-autopay",
                              subject="cust_demo", rail=RAIL, policy=limits)
        clock = {"now": T0}
        led = Ledger(os.path.join(tempfile.mkdtemp(), "d.jsonl"),
                     clock=lambda: clock["now"])
        g = Gate(env, led, RailSimulator(limits=RAIL), SECRET,
                 clock=lambda: clock["now"])
        intent = g.record_intent(Intent(
            intent_id="int_d", mandate_id="token_demo",
            max_amount=RAIL.per_charge_max, expires_at=T0 + 7 * 86400))
        d = g.authorize(ChargeRequest(
            mandate_id="token_demo", amount=amount,
            idempotency_key=f"d-{amount}-{merchant}",
            intent_id=intent.intent_id, merchant=merchant))
        probes.append({"amount": amount, "merchant": merchant, "note": note,
                       "allowed": d.allowed, "codes": list(d.codes)})

    # the three ways to cheat
    looser = delivery.attenuate(Caveat("per_charge_max", 100_000))
    stripped = Authority(delivery.authority_id, delivery.mandate_id,
                         delivery.caveats[:-1], delivery.signature)
    edited = list(delivery.caveats)
    edited[0] = Caveat("per_charge_max", 100_000)
    tampered = Authority(delivery.authority_id, delivery.mandate_id,
                         tuple(edited), delivery.signature)

    attempts = [
        {"what": "append a looser caveat (per_charge_max <= 100000)",
         "verifies": looser.verify(root_secret),
         "effect": f"per_charge_max still {looser.to_limits().per_charge_max}",
         "why": "Inert. Folding takes the tighter value, so a loose caveat "
                "says nothing."},
        {"what": "drop the caveat it added itself, keep the signature",
         "verifies": stripped.verify(root_secret),
         "effect": "rejected at admission",
         "why": "The chain is keyed on every link. Removing one breaks it."},
        {"what": "edit the principal's own caveat",
         "verifies": tampered.verify(root_secret),
         "effect": "rejected at admission",
         "why": "Recomputing needs the root secret, which no holder "
                "downstream has."},
    ]
    return {"links": links, "probes": probes, "attempts": attempts,
            "folded": fold(delivery)}


# --------------------------------------------------------------- buyer
def build_buyer() -> dict:
    """The injection trace: the agent complies, the mandate contains it."""
    reading = interpret(
        "Get me milk, bread and eggs from shop-a this week. "
        "Nothing over five rupees an item.",
        ScriptedInterpreter(),
        mandate_id=scenario.MANDATE_ID, intent_id="int_shopping",
        secret=SECRET, now=T0, ceiling=scenario.RAIL.per_charge_max)

    envelope = scenario.envelope()
    clock = {"now": T0}
    led = Ledger(os.path.join(tempfile.mkdtemp(), "b.jsonl"),
                 clock=lambda: clock["now"])
    gate = Gate(envelope, led, RailSimulator(limits=envelope.rail), SECRET,
                clock=lambda: clock["now"])
    gate.record_intent(reading.intent)

    outcome = BuyingAgent(gate, reading.intent, ScriptedClient(),
                          goal=reading.goal).shop(max_steps=10)

    flagged = [{"sku": i.sku, "title": i.title, "description": i.description}
               for i in buyer_catalogue.suspicious()]
    return {
        "instruction": ("Get me milk, bread and eggs from shop-a this week. "
                        "Nothing over five rupees an item."),
        "summary": reading.summary(),
        "flagged": flagged,
        "steps": [{"sku": s.sku, "quantity": s.quantity, "amount": s.amount,
                   "reasoning": s.reasoning, "allowed": s.allowed,
                   "codes": list(s.codes),
                   "remediations": list(s.remediations)}
                  for s in outcome.steps],
        "spent": outcome.spent,
        "purchased": outcome.purchased,
        "corrections": outcome.corrections,
        "influenced_attempts": outcome.influenced_attempts,
        "influenced_settled": outcome.influenced_settled,
    }


# --------------------------------------------------------- demo ledger
def build_demo_ledger() -> Adjudicator:
    if LEDGER_PATH.exists():
        LEDGER_PATH.unlink()
    server_time = {"now": T0}
    ledger = Ledger(str(LEDGER_PATH), clock=lambda: server_time["now"])

    policy_no_binding = Limits(
        cumulative_max=2000, max_charges=6,
        rate_limit=Window(seconds=HOUR, max_charges=4),
        scope=Scope(merchants=frozenset({"shop-a", "shop-b"})),
        requires_intent_binding=False,
    )
    policy_bound = policy_no_binding.tighten(requires_intent_binding=True)

    # --- mandate A: no intent binding. Today's default.
    env_a = MandateEnvelope(
        mandate_id="token_unbound", source="razorpay-upi-autopay",
        subject="cust_demo_a", rail=RAIL, policy=policy_no_binding)
    gate_a = Gate(env_a, ledger, RailSimulator(limits=RAIL), SECRET,
                  clock=lambda: server_time["now"])
    gate_a.authorize(ChargeRequest(
        mandate_id="token_unbound", amount=450,
        idempotency_key="A-groceries", merchant="shop-a"))
    server_time["now"] = T0 + 2 * HOUR
    gate_a.authorize(ChargeRequest(
        mandate_id="token_unbound", amount=500,
        idempotency_key="A-refill", merchant="shop-b"))

    # --- mandate B: intent binding on. One line of policy different.
    env_b = MandateEnvelope(
        mandate_id="token_bound", source="razorpay-upi-autopay",
        subject="cust_demo_b", rail=RAIL, policy=policy_bound)
    server_time["now"] = T0
    gate_b = Gate(env_b, ledger, RailSimulator(limits=RAIL), SECRET,
                  clock=lambda: server_time["now"])
    gate_b.record_intent(Intent(
        intent_id="int_weekly_milk", mandate_id="token_bound",
        max_amount=450, expires_at=T0 + 6 * HOUR, merchant="shop-a"))
    gate_b.authorize(ChargeRequest(
        mandate_id="token_bound", amount=450,
        idempotency_key="B-milk", merchant="shop-a",
        intent_id="int_weekly_milk"))

    # a refused attempt: agent inflates the amount beyond what was approved
    server_time["now"] = T0 + HOUR
    gate_b.authorize(ChargeRequest(
        mandate_id="token_bound", amount=500,
        idempotency_key="B-inflated", merchant="shop-a",
        intent_id="int_weekly_milk"))
    # and one outside the authorised scope
    server_time["now"] = T0 + 2 * HOUR
    gate_b.authorize(ChargeRequest(
        mandate_id="token_bound", amount=200,
        idempotency_key="B-rogue", merchant="shop-rogue",
        intent_id="int_weekly_milk"))
    # An agent lying about the clock to clear the rate window.
    gate_b.authorize(ChargeRequest(
        mandate_id="token_bound", amount=200,
        idempotency_key="B-clock-lie", merchant="shop-a",
        intent_id="int_weekly_milk", claimed_at=T0 + 99_999))

    return Adjudicator(ledger, SECRET)


class Handler(BaseHTTPRequestHandler):
    state: dict = {}
    adjudicator: Adjudicator = None

    def log_message(self, fmt, *args):            # keep the console quiet
        pass

    def _send(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        route = urlparse(self.path)

        if route.path in ("/", "/index.html"):
            page = (Path(__file__).parent / "ui" / "index.html").read_bytes()
            return self._send(page, "text/html; charset=utf-8")

        if route.path == "/api/state":
            return self._send(json.dumps(self.state).encode(),
                              "application/json")

        if route.path == "/api/adjudicate":
            query = parse_qs(route.query)
            ref = (query.get("ref") or [""])[0]
            # Scoped by mandate: idempotency keys are unique per mandate, not
            # globally, and this ledger deliberately holds two.
            mandate = (query.get("mandate_id") or [None])[0]
            result = self.adjudicator.adjudicate(
                ref, mandate_id=mandate).as_dict()
            return self._send(json.dumps(result).encode(), "application/json")

        self.send_error(404)


def main() -> int:
    print("\n  Mandate Gate console")
    print("  building coverage table from the adapters ...")
    coverage = build_coverage()
    print("  running the harness ...")
    harness = build_harness()
    print("  building the delegation chain ...")
    delegation = build_delegation()
    print("  running the buyer ...")
    buyer = build_buyer()
    print("  building the demo ledger ...")
    adjudicator = build_demo_ledger()

    Handler.adjudicator = adjudicator
    Handler.state = {
        "coverage": coverage,
        "harness": harness,
        "delegation": delegation,
        "buyer": buyer,
        "settled": adjudicator.disputable(),
        "refused": adjudicator.refused(),
        "ledger_path": str(LEDGER_PATH.relative_to(ROOT)),
    }

    try:
        server = HTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        # Bound after the work above, so this surfaces late -- and a stack trace
        # is the wrong thing to show someone whose only mistake was starting the
        # demo twice.
        print(f"\n  port {PORT} is already in use ({exc.strerror}).")
        print(f"  Something is serving there already -- try "
              f"http://127.0.0.1:{PORT} first, or stop it with:")
        print(f"      kill $(lsof -ti:{PORT})\n")
        return 1

    print(f"\n  ready -> http://127.0.0.1:{PORT}")
    print("  ctrl-c to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("  stopped\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
