import io
import json
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


class TestModelAttacker(unittest.TestCase):
    """
    The model attacker is exercised without a network. What matters here is
    that it degrades safely and parses whatever a model actually returns --
    the request shape itself is verified by a live run, recorded, and replayed.
    """

    def make(self, **kw):
        from mandate_gate.attack.model import ModelAttacker
        kw.setdefault("api_key", None)
        return ModelAttacker(mandate_id="m", throttle=0, **kw)

    def test_no_key_ends_the_run_rather_than_raising(self):
        """A dead attacker must stop cleanly, mid-sweep, without a traceback."""
        attacker = self.make()
        attacker.api_key = None
        self.assertIsNone(attacker.propose(Briefing(mandate={})))

    def test_names_itself_by_model_so_results_are_never_merged(self):
        default = self.make()
        other = self.make(model="some/other-model")
        self.assertIn("gpt-oss-120b", default.NAME)
        self.assertIn("some/other-model", other.NAME)
        self.assertNotEqual(default.NAME, other.NAME)

    def test_extracts_json_from_prose_and_fences(self):
        from mandate_gate.attack.model import ModelAttacker as MA
        for text in ('{"amount": 42}',
                     'Sure!\n```json\n{"amount": 42}\n```\n',
                     'I will try {"amount": 42} because boundaries.',
                     'notes {"bad": } then {"amount": 42}'):
            self.assertEqual(MA._extract_json(text), {"amount": 42}, text)

    def test_returns_none_on_unusable_output(self):
        from mandate_gate.attack.model import ModelAttacker as MA
        for text in ("", "no json here", "{}", '{"amount": "lots"}',
                     '{"amount": 0}', '{"amount": -5}'):
            parsed = MA._extract_json(text)
            if parsed is None:
                continue
            try:
                usable = int(parsed.get("amount")) > 0
            except (TypeError, ValueError):
                usable = False
            self.assertFalse(usable, text)

    def test_briefing_render_never_leaks_the_policy(self):
        """The prompt is the attacker's whole view. It must not carry policy."""
        from mandate_gate.attack.model import ModelAttacker as MA
        from mandate_gate.attack.session import _mandate_view
        rendered = MA._render(Briefing(
            mandate=_mandate_view(envelope()),
            intents=("int_1",), seen_merchants=("shop-a",)))

        # Field names, not values: a bare number like "2000" is a substring of
        # the expiry timestamp, so matching on it tests nothing.
        for leak in ("cumulative_max", "max_charges", "rate_limit",
                     "requires_intent_binding", "scope"):
            self.assertNotIn(leak, rendered, f"policy leaked: {leak}")

        # And no merchant the attacker was never shown.
        self.assertNotIn("shop-b", rendered)

    def test_the_mandate_view_is_the_only_source_for_the_prompt(self):
        """
        Belt and braces on the asymmetry: whatever _render puts in the prompt
        can only come from a dict that has no policy keys in it at all.
        """
        from mandate_gate.attack.session import _mandate_view
        view = _mandate_view(envelope())
        policy_keys = {"cumulative_max", "max_charges", "rate_limit", "scope",
                       "requires_intent_binding"}
        self.assertEqual(set(view) & policy_keys, set())

    def test_render_bounds_the_prompt(self):
        """History is truncated, or a long run grows the prompt without limit."""
        from mandate_gate.attack.model import ModelAttacker as MA
        b = Briefing(mandate={"per_charge_max": CEILING})
        for i in range(50):
            b.history.append(Attempt(
                request=ChargeRequest(mandate_id="m", amount=1,
                                      idempotency_key=f"k{i}"),
                allowed=False, codes=("X",), remediations=()))
        rendered = MA._render(b)
        self.assertLess(rendered.count("amount=1 "), 20)


class TestReplayAttacker(unittest.TestCase):
    """
    Replay is what makes a model finding verifiable. A model run has no seed,
    so an unrecorded result exists only in someone's terminal.
    """

    def transcript(self):
        return [
            {"parsed": {"amount": 500, "merchant": "shop-a",
                        "intent_id": "int_1"}},
            {"parsed": None, "error": "HTTP 429: rate limited"},
            {"parsed": {"amount": 501, "merchant": "shop-rogue"}},
            {"parsed": {"amount": 0}},
            {"parsed": {"amount": 250, "merchant": "shop-a",
                        "claimed_at": 999}},
        ]

    def replayer(self):
        from mandate_gate.attack.model import ReplayAttacker
        return ReplayAttacker(mandate_id="m", transcript=self.transcript())

    def test_reissues_usable_proposals_and_skips_the_rest(self):
        r = self.replayer()
        b = Briefing(mandate={})
        amounts = []
        while True:
            req = r.propose(b)
            if req is None:
                break
            amounts.append(req.amount)
        self.assertEqual(amounts, [500, 501, 250])

    def test_carries_the_recorded_fields_through(self):
        req = self.replayer().propose(Briefing(mandate={}))
        self.assertEqual(req.merchant, "shop-a")
        self.assertEqual(req.intent_id, "int_1")

    def test_replay_is_deterministic(self):
        def run_once():
            r, b, out = self.replayer(), Briefing(mandate={}), []
            while (req := r.propose(b)) is not None:
                out.append((req.amount, req.merchant, req.claimed_at))
            return out
        self.assertEqual(run_once(), run_once())

    def test_a_replayed_run_is_judged_by_the_same_oracle(self):
        from mandate_gate.attack.model import ReplayAttacker
        result = run(envelope(),
                     ReplayAttacker(mandate_id="m",
                                    transcript=self.transcript()),
                     secret=SECRET, intents=INTENTS, budget=10,
                     start_time=T0, seconds_per_attempt=1200)
        self.assertEqual(result.attacker, "replay")
        self.assertTrue(result.clean, [v.detail for v in result.violations])
        self.assertGreater(result.attempts, 0)


class TestModelAuditFixes(unittest.TestCase):
    """
    Regressions for defects found auditing the model attacker after writing it.
    """

    def test_unbalanced_braces_inside_a_string_still_parse(self):
        """
        A blind brace count returned None here, which ends an attack run
        silently -- indistinguishable from a model with nothing to propose. A
        red-teaming model writes about braces and quotes constantly.
        """
        from mandate_gate.attack.model import ModelAttacker as MA
        for text in ('{"amount": 42, "rationale": "the } case"}',
                     '{"amount": 42, "rationale": "the { case"}',
                     '{"amount": 42, "rationale": "a \\" } b"}',
                     '```json\n{"amount": 42, "rationale": "{x} and } odd"}\n```'):
            parsed = MA._extract_json(text)
            self.assertIsNotNone(parsed, text)
            self.assertEqual(parsed["amount"], 42, text)

    def test_key_shaped_strings_are_redacted(self):
        """Error bodies can echo the credential, and transcripts get committed."""
        from mandate_gate.attack.model import _redact
        # Deliberately unmistakable non-credentials: a secret scanner should
        # not have to judge whether a fixture is live, and nor should a reader.
        for secret in ("gsk_NOT_A_REAL_KEY_00000",
                       "sk-proj-NOT_A_REAL_KEY_0",
                       "Bearer NOT_A_REAL_KEY_000"):
            self.assertNotIn(secret, _redact(f"rejected: {secret} is invalid"))
        self.assertIn("<redacted>",
                      _redact("bad key gsk_NOT_A_REAL_KEY_00000"))

    def test_a_transcript_records_the_prompt_it_was_given(self):
        """
        The prompt is the evidence that the attacker was not fed the policy. A
        reader should not have to take that on trust.
        """
        from mandate_gate.attack.model import Call, ModelAttacker
        attacker = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        attacker.calls.append(Call(
            prompt={"role": "user", "content": "MANDATE {...}"},
            raw='{"amount": 1}', parsed={"amount": 1}))
        entry = attacker.transcript()[0]
        self.assertEqual(entry["prompt"], "MANDATE {...}")

    def test_transcript_redacts_the_raw_response_too(self):
        from mandate_gate.attack.model import Call, ModelAttacker
        attacker = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        attacker.calls.append(Call(prompt={"content": "p"},
                                   raw="leaked gsk_NOT_A_REAL_KEY_00000 oops",
                                   parsed=None))
        self.assertNotIn("gsk_NOT_A_REAL_KEY_00000",
                         attacker.transcript()[0]["raw"])

    def test_every_attacker_names_itself_the_same_way(self):
        """NAME is a class attribute on all three, not a dataclass field."""
        from mandate_gate.attack.model import ModelAttacker, ReplayAttacker
        for cls in (Fuzzer, ModelAttacker, ReplayAttacker):
            self.assertIsInstance(getattr(cls, "NAME"), str, cls.__name__)
            self.assertNotIn("NAME", getattr(cls, "__dataclass_fields__", {}),
                             f"{cls.__name__}.NAME should not be a field")


class TestTransportHeaders(unittest.TestCase):
    """
    Regression for a live failure: Groq sits behind Cloudflare, which rejects
    urllib's default "Python-urllib/3.x" signature with `403 error code: 1010`
    before the request reaches the API. It looks exactly like a bad key.
    """

    def test_a_real_user_agent_is_always_sent(self):
        import ssl
        import urllib.request

        from mandate_gate.attack.model import USER_AGENT, ModelAttacker

        captured = {}

        def fake_urlopen(req, *a, **kw):
            captured["headers"] = dict(req.header_items())
            raise RuntimeError("stop before the network")

        real = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            ModelAttacker(mandate_id="m", api_key="x", throttle=0,
                          max_retries=0)._ask([{"role": "user", "content": "hi"}])
        finally:
            urllib.request.urlopen = real
            del ssl

        headers = {k.lower(): v for k, v in captured["headers"].items()}
        self.assertIn("user-agent", headers)
        self.assertEqual(headers["user-agent"], USER_AGENT)
        self.assertNotIn("python-urllib", headers["user-agent"].lower())

    def test_a_cloudflare_block_is_not_reported_as_a_bad_key(self):
        from mandate_gate.attack.model import _explain
        self.assertIn("not your key", _explain(403, "error code: 1010"))
        self.assertIn("rejected", _explain(401, '{"error":"invalid_api_key"}'))
        self.assertIn("rate limited", _explain(429, "slow down"))


class TestPromptFraming(unittest.TestCase):
    """
    A live run failed because the model declined the task. The first prompt
    said the goal was to "extract as much value" from a mandate, which reads
    as a request for help with payment fraud and omitted every fact that makes
    this legitimate.
    """

    def test_the_prompt_states_the_facts_that_make_this_legitimate(self):
        from mandate_gate.attack.model import SYSTEM_PROMPT
        low = SYSTEM_PROMPT.lower()
        for fact in ("test harness", "synthetic", "simulator",
                     "same project", "regression test"):
            self.assertIn(fact, low, f"prompt omits: {fact}")

    def test_the_prompt_does_not_frame_the_goal_as_extraction(self):
        from mandate_gate.attack.model import SYSTEM_PROMPT
        low = SYSTEM_PROMPT.lower()
        self.assertNotIn("extract as much value", low)

    def test_a_refusal_is_reported_as_a_refusal(self):
        """
        Not as a parse failure. Reporting "0 parsed" sent the reader hunting a
        parser bug that did not exist.
        """
        from mandate_gate.attack.model import _looks_like_refusal
        for text in ("I’m sorry, but I can’t help with that.",
                     "I cannot help with this request.",
                     "I am unable to assist."):
            self.assertTrue(_looks_like_refusal(text), text)

    def test_normal_output_is_not_mistaken_for_a_refusal(self):
        from mandate_gate.attack.model import _looks_like_refusal
        for text in ('{"amount": 500, "rationale": "probing the ceiling"}',
                     '{"amount": 1, "rationale": "I will not exceed the cap"}',
                     ""):
            self.assertFalse(_looks_like_refusal(text), text)

    def test_a_declining_model_surfaces_guidance_not_silence(self):
        from mandate_gate.attack.model import ModelAttacker
        attacker = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        attacker._ask = lambda messages: ("I'm sorry, but I can't help.",
                                          "stop", None)
        self.assertIsNone(attacker.propose(Briefing(mandate={})))
        self.assertIn("declined", attacker.calls[0].error)


class TestNoSilentFailure(unittest.TestCase):
    """
    The invariant that took three live runs to learn: whenever `propose`
    returns None, a reason is recorded. A None with no error sends the reader
    to the wrong layer -- it happened with a Cloudflare block, with a model
    refusal, and it would have happened again with a null `content` and with a
    truncated reply.
    """

    def attacker(self, reply, finish=None, error=None):
        from mandate_gate.attack.model import ModelAttacker
        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        a._ask = lambda messages: (reply, finish, error)
        return a

    def cases(self):
        return [
            ("empty content", "", None, None),
            ("null content", None, None, None),
            ("whitespace only", "   \n  ", None, None),
            ("truncated json", '{"amount": 500, "rationale": "probing the ce',
             "length", None),
            ("prose, no json", "Let me think about this carefully.", "stop", None),
            ("refusal", "I'm sorry, but I can't help with that.", "stop", None),
            ("empty object", "{}", "stop", None),
            ("amount is a bool", '{"amount": true}', "stop", None),
            ("amount is text", '{"amount": "five hundred"}', "stop", None),
            ("amount is zero", '{"amount": 0}', "stop", None),
            ("amount is negative", '{"amount": -50}', "stop", None),
            ("transport error", None, None, "HTTP 500: upstream"),
        ]

    def test_every_giving_up_path_records_a_reason(self):
        for label, reply, finish, error in self.cases():
            with self.subTest(label):
                a = self.attacker(reply, finish, error)
                self.assertIsNone(a.propose(Briefing(mandate={})), label)
                self.assertTrue(a.calls, f"{label}: nothing recorded")
                self.assertTrue(a.calls[-1].error,
                                f"{label}: returned None with no error")

    def test_the_reason_is_specific_not_generic(self):
        specific = {
            "truncated json": "truncated",
            "refusal": "declined",
            "empty content": "empty",
            "amount is a bool": "unusable amount",
        }
        for label, reply, finish, error in self.cases():
            if label not in specific:
                continue
            with self.subTest(label):
                a = self.attacker(reply, finish, error)
                a.propose(Briefing(mandate={}))
                self.assertIn(specific[label], a.calls[-1].error.lower(), label)

    def test_a_good_reply_records_no_error(self):
        a = self.attacker('{"amount": 450, "merchant": "shop-a"}', "stop", None)
        req = a.propose(Briefing(mandate={}))
        self.assertIsNotNone(req)
        self.assertEqual(req.amount, 450)
        self.assertIsNone(a.calls[-1].error)

    def test_the_mandate_id_is_never_taken_from_the_model(self):
        """An attacker must not be able to charge a mandate it was not given."""
        a = self.attacker('{"amount": 100, "mandate_id": "someone-elses"}',
                          "stop", None)
        self.assertEqual(a.propose(Briefing(mandate={})).mandate_id, "m")

    def test_a_bool_never_becomes_an_amount(self):
        """isinstance(True, int) is True, so `true` would have become 1."""
        a = self.attacker('{"amount": true}', "stop", None)
        self.assertIsNone(a.propose(Briefing(mandate={})))

    def test_a_bool_never_becomes_a_timestamp(self):
        a = self.attacker('{"amount": 100, "claimed_at": true}', "stop", None)
        self.assertIsNone(a.propose(Briefing(mandate={})).claimed_at)


class TestResponseEnvelope(unittest.TestCase):
    def post(self, payload):
        import json as _json
        import urllib.request

        from mandate_gate.attack.model import ModelAttacker

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return _json.dumps(payload).encode()

        real = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **kw: FakeResponse()
        try:
            return ModelAttacker(mandate_id="m", api_key="x", throttle=0,
                                 max_retries=0)._ask([{"role": "user",
                                                       "content": "x"}])
        finally:
            urllib.request.urlopen = real

    def test_a_normal_envelope_yields_content_and_finish_reason(self):
        text, finish, error = self.post({
            "choices": [{"message": {"content": '{"amount": 1}'},
                         "finish_reason": "stop"}]})
        self.assertEqual(text, '{"amount": 1}')
        self.assertEqual(finish, "stop")
        self.assertIsNone(error)

    def test_missing_choices_is_explained_not_a_keyerror(self):
        text, finish, error = self.post({"error": "content blocked"})
        self.assertIsNone(text)
        self.assertIn("no choices", error.lower())

    def test_empty_content_falls_back_to_reasoning_text(self):
        """Reasoning-style models sometimes leave `content` null."""
        text, _, error = self.post({
            "choices": [{"message": {"content": None,
                                     "reasoning_content": '{"amount": 2}'},
                         "finish_reason": "stop"}]})
        self.assertEqual(text, '{"amount": 2}')
        self.assertIsNone(error)


class TestUnusableReplyDoesNotRetireTheAttacker(unittest.TestCase):
    """
    Regression for a live run: budget 30 produced 10 attempts. The model
    answered `amount: 0` on its eleventh call, `propose` returned None, and the
    session read that as "finished" -- discarding twenty attempts of budget on
    one bad generation.
    """

    def attacker(self, replies, **kw):
        from mandate_gate.attack.model import ModelAttacker
        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0, **kw)
        queue = list(replies)

        def fake_ask(messages):
            return queue.pop(0) if queue else ("", "stop", None)
        a._ask = fake_ask
        return a

    def test_an_unusable_amount_is_retried(self):
        a = self.attacker([('{"amount": 0}', "stop", None),
                           ('{"amount": 450}', "stop", None)])
        req = a.propose(Briefing(mandate={}))
        self.assertIsNotNone(req, "gave up after one unusable reply")
        self.assertEqual(req.amount, 450)
        self.assertEqual(len(a.calls), 2)

    def test_retries_are_bounded(self):
        a = self.attacker([('{"amount": 0}', "stop", None)] * 10,
                          max_unusable=2)
        self.assertIsNone(a.propose(Briefing(mandate={})))
        self.assertEqual(len(a.calls), 3)      # the first, plus two retries

    def test_a_refusal_is_not_retried(self):
        """It will say the same thing again, and a free-tier call is not free."""
        a = self.attacker([("I'm sorry, but I can't help.", "stop", None)] * 5)
        self.assertIsNone(a.propose(Briefing(mandate={})))
        self.assertEqual(len(a.calls), 1)

    def test_a_transport_failure_is_not_retried_here(self):
        """_ask already retries transport faults; doing it again just burns calls."""
        a = self.attacker([(None, None, "HTTP 401: rejected")] * 5)
        self.assertIsNone(a.propose(Briefing(mandate={})))
        self.assertEqual(len(a.calls), 1)

    def test_malformed_output_is_retried(self):
        a = self.attacker([("thinking out loud", "stop", None),
                           ('{"amount": 200}', "stop", None)])
        self.assertEqual(a.propose(Briefing(mandate={})).amount, 200)

    def test_a_stalled_attacker_still_stops(self):
        """Bounded, so a persistently broken endpoint cannot spin forever."""
        a = self.attacker([("", None, None)] * 20, max_unusable=1)
        self.assertIsNone(a.propose(Briefing(mandate={})))
        self.assertLessEqual(len(a.calls), 2)


class TestRecoverableJsonModeFailures(unittest.TestCase):
    """
    A live run ended at call 18 of a 30 budget. Groq returned
    `400 Failed to validate JSON` -- its own JSON mode rejecting one
    generation -- and any HTTP error was being read as terminal.
    """

    def test_a_json_validation_400_is_worth_retrying(self):
        from mandate_gate.attack.model import ModelAttacker
        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        replies = [
            (None, None, 'HTTP 400: {"error":"Failed to validate JSON"}'),
            ('{"amount": 300}', "stop", None),
        ]
        a._ask = lambda messages: replies.pop(0)
        req = a.propose(Briefing(mandate={}))
        self.assertIsNotNone(req, "gave up on a recoverable 400")
        self.assertEqual(req.amount, 300)

    def test_a_rejected_key_is_still_terminal(self):
        from mandate_gate.attack.model import ModelAttacker
        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        a._ask = lambda messages: (None, None, "HTTP 401: invalid_api_key")
        self.assertIsNone(a.propose(Briefing(mandate={})))
        self.assertEqual(len(a.calls), 1, "retried a rejected key")

    def test_a_server_error_is_worth_retrying(self):
        from mandate_gate.attack.model import ModelAttacker
        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0)
        replies = [(None, None, "HTTP 503: upstream unavailable"),
                   ('{"amount": 120}', "stop", None)]
        a._ask = lambda messages: replies.pop(0)
        self.assertEqual(a.propose(Briefing(mandate={})).amount, 120)

    def test_repeated_json_failures_fall_back_to_free_form(self):
        """Two strikes and the parameter is dropped rather than fought."""
        import urllib.error
        import urllib.request

        from mandate_gate.attack.model import ModelAttacker

        a = ModelAttacker(mandate_id="m", api_key="x", throttle=0,
                          max_retries=3)
        bodies = []

        def fake_urlopen(req, *args, **kw):
            bodies.append(json.loads(req.data.decode()))
            raise urllib.error.HTTPError(
                "u", 400, "Bad Request", {},
                io.BytesIO(b'{"error":"Failed to validate JSON"}'))

        real = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            a._ask([{"role": "user", "content": "x"}])
        finally:
            urllib.request.urlopen = real

        self.assertTrue(any("response_format" in b for b in bodies))
        self.assertFalse("response_format" in bodies[-1],
                         "kept sending response_format after two failures")
