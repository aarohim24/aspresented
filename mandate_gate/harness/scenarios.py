"""
Labelled traffic.

Ground truth comes from construction, not from judgement: every attempt is
built to be honest or to be a specific kind of abuse, and carries that label.

Two rules keep the scoring meaningful:

* **Honest attempts appear inside abusive sessions.** Draining a mandate takes
  four legitimate charges first. Those four are labelled honest and count
  toward the false-decline rate, so a gate that panics after the third charge
  is penalised rather than praised.

* **One realistic policy for every session.** Isolating each constraint behind
  its own tailor-made policy would inflate recall by removing the chance of
  interference. The cost is that several codes can fire at once, so recall is
  measured as "refused at all" and attribution is reported separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..charge import ChargeRequest, Intent
from ..envelope import Limits, Scope, Window

T0 = 1_700_000_000
HOUR = 3600
CEILING = 500                      # paise, per charge -- the rail's own limit
IN_SCOPE = ("shop-a", "shop-b", "shop-c")

#: What Razorpay actually enforces. Verified: per-charge ceiling and expiry.
RAIL = Limits(per_charge_max=CEILING, expires_at=T0 + 86_400 * 30)

#: What the merchant adds. Every field here is one the rail has no room for.
POLICY = Limits(
    #: Narrower than the rail's own 500. Present because it was absent: no
    #: scenario set a policy per-charge ceiling, so a gate that never checked
    #: one went unnoticed until an authority attenuated it.
    per_charge_max=450,
    cumulative_max=2000,
    max_charges=6,
    rate_limit=Window(seconds=HOUR, max_charges=4),
    scope=Scope(merchants=frozenset(IN_SCOPE)),
    requires_intent_binding=True,
)

HONEST = "honest"

#: Honest traffic sitting exactly on a limit. These exist because a gate that
#: refuses the charge that lands precisely on the cap is not "conservative", it
#: is broken -- and comfortable mid-range honest traffic would never reveal it.
#: This is where the false-decline rate stops being decorative.
BOUNDARY_SESSIONS = (
    "exact_cumulative_cap",
    "exact_rate_limit",
    "exact_charge_count",
    "exact_intent_amount",
    "exact_policy_ceiling",
    "correct_retry_same_key",
    "just_outside_duplicate_window",
    "final_second_before_expiry",
)

ABUSE_CLASSES = (
    "drain_cumulative",
    "burst_rate",
    "count_overrun",
    "scope_escape",
    "intent_absent",
    "intent_amount_inflation",
    "intent_merchant_substitution",
    "tampered_intent",
    "keyless_retry",
    "expired_mandate",
    "over_ceiling",
    "drain_by_one_paisa",
    "burst_one_second_early",
    "clock_advance",
    "over_policy_ceiling",
)

#: The code we expect to fire. Used for attribution, never for scoring recall.
EXPECTED_CODE = {
    "drain_cumulative": "CUMULATIVE_EXCEEDED",
    "burst_rate": "RATE_EXCEEDED",
    "count_overrun": "CHARGE_COUNT_EXCEEDED",
    "scope_escape": "SCOPE_VIOLATION",
    "intent_absent": "INTENT_UNBOUND",
    "intent_amount_inflation": "INTENT_MISMATCH",
    "intent_merchant_substitution": "INTENT_MISMATCH",
    "tampered_intent": "INTENT_UNBOUND",
    "keyless_retry": "DUPLICATE_CHARGE",
    "expired_mandate": "POLICY_EXPIRED",
    "over_ceiling": None,          # the rail's job, not policy's
    "drain_by_one_paisa": "CUMULATIVE_EXCEEDED",
    "burst_one_second_early": "RATE_EXCEEDED",
    "over_policy_ceiling": "PER_CHARGE_EXCEEDED",
    "clock_advance": "RATE_EXCEEDED",
}


@dataclass
class Attempt:
    request: ChargeRequest
    #: Server time at which this attempt is evaluated. The runner advances the
    #: injected clock to this value -- the request itself carries no
    #: authoritative timestamp.
    at: int
    label: str
    expected_code: str | None = None


@dataclass
class Session:
    session_id: str
    #: Scenario family. The split stratifies on this so no class can vanish
    #: from the reported holdout by chance.
    kind: str = HONEST
    intents: list = field(default_factory=list)
    attempts: list = field(default_factory=list)
    #: Set when the session needs a policy expiry earlier than the rail's.
    policy_expires_at: int | None = None


def _fill_to_cap(b) -> int:
    """
    Honest charges summing to exactly the cumulative cap.

    Written as a helper because the policy ceiling does not divide the cap
    evenly, and "close to the cap" is not the scenario -- the boundary cases
    only mean something if the total lands on it to the paisa.
    """
    step = POLICY.per_charge_max
    total, i = 0, 0
    while total < POLICY.cumulative_max:
        amount = min(step, POLICY.cumulative_max - total)
        b.honest_charge(amount, T0 + i * 2 * HOUR)
        total += amount
        i += 1
    return total


class _Builder:
    """Accumulates one session. Keeps ids unique and readable."""

    def __init__(self, session_id: str, rng, kind: str = HONEST):
        self.session = Session(session_id=session_id, kind=kind)
        self.rng = rng
        self._n = 0

    def intent(self, max_amount: int, merchant: str | None, at: int,
               ttl: int = 6 * HOUR) -> Intent:
        self._n += 1
        intent = Intent(
            intent_id=f"{self.session.session_id}-int-{self._n}",
            mandate_id=self.session.session_id,
            max_amount=max_amount, expires_at=at + ttl, merchant=merchant,
        )
        self.session.intents.append(intent)
        return intent

    def attempt(self, label, amount, at, merchant, intent_id=None, key=None,
                expected=None, claimed_at=None):
        self._n += 1
        self.session.attempts.append(Attempt(
            request=ChargeRequest(
                mandate_id=self.session.session_id, amount=amount,
                idempotency_key=key or f"{self.session.session_id}-k-{self._n}",
                intent_id=intent_id, merchant=merchant, claimed_at=claimed_at,
            ),
            at=at,
            label=label,
            expected_code=expected if expected is not None
            else EXPECTED_CODE.get(label),
        ))

    def honest_charge(self, amount, at, merchant=None):
        merchant = merchant or self.rng.choice(IN_SCOPE)
        intent = self.intent(amount, merchant, at)
        self.attempt(HONEST, amount, at, merchant, intent.intent_id)
        return intent


def _honest_session(sid: str, rng) -> Session:
    b = _Builder(sid, rng, kind=HONEST)
    for i in range(rng.randint(2, 4)):
        b.honest_charge(rng.choice((150, 250, 400, POLICY.per_charge_max)),
                        T0 + i * 2 * HOUR)
    return b.session


def _abuse_session(sid: str, kind: str, rng) -> Session:
    b = _Builder(sid, rng, kind=kind)

    if kind == "drain_cumulative":
        # Fill the cap exactly, then ask for a full charge more.
        _fill_to_cap(b)
        at = T0 + 24 * HOUR
        intent = b.intent(POLICY.per_charge_max, IN_SCOPE[0], at)
        b.attempt(kind, POLICY.per_charge_max, at, IN_SCOPE[0],
                  intent.intent_id)

    elif kind == "burst_rate":
        # Small amounts so the cumulative cap cannot fire first.
        for i in range(4):
            b.honest_charge(100, T0 + i * 5)
        at = T0 + 25
        intent = b.intent(100, IN_SCOPE[0], at)
        b.attempt(kind, 100, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "count_overrun":
        for i in range(6):
            b.honest_charge(100, T0 + i * 2 * HOUR)
        at = T0 + 12 * HOUR
        intent = b.intent(100, IN_SCOPE[1], at)
        b.attempt(kind, 100, at, IN_SCOPE[1], intent.intent_id)

    elif kind == "scope_escape":
        b.honest_charge(200, T0)
        at = T0 + 2 * HOUR
        intent = b.intent(200, "shop-rogue", at)
        b.attempt(kind, 200, at, "shop-rogue", intent.intent_id)

    elif kind == "intent_absent":
        b.honest_charge(200, T0)
        b.attempt(kind, 200, T0 + 2 * HOUR, IN_SCOPE[0], intent_id=None)

    elif kind == "intent_amount_inflation":
        at = T0 + 2 * HOUR
        intent = b.intent(200, IN_SCOPE[0], at)          # approved 200
        b.attempt(kind, CEILING, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "intent_merchant_substitution":
        at = T0 + 2 * HOUR
        intent = b.intent(300, IN_SCOPE[0], at)          # approved shop-a
        b.attempt(kind, 300, at, IN_SCOPE[1], intent.intent_id)

    elif kind == "tampered_intent":
        at = T0 + 2 * HOUR
        intent = b.intent(200, IN_SCOPE[0], at)
        b.session.intents.append(("TAMPER", intent.intent_id, CEILING * 10))
        b.attempt(kind, CEILING, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "keyless_retry":
        at = T0
        intent = b.intent(300, IN_SCOPE[0], at)
        b.attempt(HONEST, 300, at, IN_SCOPE[0], intent.intent_id, key=f"{sid}-orig")
        b.attempt(kind, 300, at + 5, IN_SCOPE[0], intent.intent_id,
                  key=f"{sid}-lost-key")

    elif kind == "expired_mandate":
        b.session.policy_expires_at = T0 + 3 * HOUR
        b.honest_charge(200, T0)
        at = T0 + 5 * HOUR
        intent = b.intent(200, IN_SCOPE[0], at)
        b.attempt(kind, 200, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "drain_by_one_paisa":
        # The cap exactly, then a single paisa more. Tests that the cumulative
        # check is not merely catching gross overshoot.
        _fill_to_cap(b)
        at = T0 + 24 * HOUR
        intent = b.intent(1, IN_SCOPE[0], at)
        b.attempt(kind, 1, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "burst_one_second_early":
        # Four charges inside the window, then one a second before it clears.
        for i in range(4):
            b.honest_charge(100, T0 + i)
        at = T0 + HOUR - 1
        intent = b.intent(100, IN_SCOPE[0], at)
        b.attempt(kind, 100, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "clock_advance":
        # Found by auditing this codebase, not by this harness -- which is the
        # point. An agent fills the rate window, then asserts a timestamp an
        # hour in the future to make the window look clear. Server time decides,
        # so the rate limit still bites and the lie is reported as CLOCK_SKEW.
        for i in range(4):
            b.honest_charge(100, T0 + i)
        at = T0 + 25
        intent = b.intent(100, IN_SCOPE[0], at)
        b.attempt(kind, 100, at, IN_SCOPE[0], intent.intent_id,
                  claimed_at=at + 2 * HOUR)

    elif kind == "over_policy_ceiling":
        # Above the policy ceiling, below the rail's. Only the gate can catch
        # this, which is exactly the case that was going unchecked.
        at = T0 + 2 * HOUR
        intent = b.intent(CEILING, IN_SCOPE[0], at)
        b.attempt(kind, POLICY.per_charge_max + 1, at, IN_SCOPE[0],
                  intent.intent_id)

    elif kind == "over_ceiling":
        at = T0 + 2 * HOUR
        intent = b.intent(CEILING * 4, IN_SCOPE[0], at)
        b.attempt(kind, CEILING * 3, at, IN_SCOPE[0], intent.intent_id)

    else:
        raise ValueError(f"unknown abuse class: {kind}")

    return b.session


def _boundary_session(sid: str, kind: str, rng) -> Session:
    """
    Every attempt here is labelled honest and must be allowed. Each one sits
    exactly on a limit, so an inclusive/exclusive slip shows up as a false
    decline instead of hiding.
    """
    b = _Builder(sid, rng, kind=f"boundary:{kind}")

    if kind == "exact_cumulative_cap":
        # Summing to the cap, to the paisa. A gate that refuses the charge that
        # lands exactly on a limit is broken, not conservative.
        _fill_to_cap(b)

    elif kind == "exact_rate_limit":
        # Exactly max_charges inside one window.
        for i in range(POLICY.rate_limit.max_charges):
            b.honest_charge(100, T0 + i * 5)

    elif kind == "exact_charge_count":
        for i in range(POLICY.max_charges):
            b.honest_charge(100, T0 + i * 2 * HOUR)

    elif kind == "exact_intent_amount":
        at = T0
        intent = b.intent(300, IN_SCOPE[0], at)
        b.attempt(HONEST, 300, at, IN_SCOPE[0], intent.intent_id)

    elif kind == "exact_policy_ceiling":
        # Exactly the policy ceiling, which must pass. An off-by-one in the new
        # check would show up here as a false decline.
        b.honest_charge(POLICY.per_charge_max, T0)

    elif kind == "correct_retry_same_key":
        # The behaviour an earlier version of this gate got wrong.
        at = T0
        intent = b.intent(300, IN_SCOPE[0], at)
        for _ in range(2):
            b.attempt(HONEST, 300, at, IN_SCOPE[0], intent.intent_id,
                      key=f"{sid}-stable")

    elif kind == "just_outside_duplicate_window":
        at = T0
        i1 = b.intent(300, IN_SCOPE[0], at)
        b.attempt(HONEST, 300, at, IN_SCOPE[0], i1.intent_id, key=f"{sid}-a")
        later = at + 301                       # window is 300
        i2 = b.intent(300, IN_SCOPE[0], later)
        b.attempt(HONEST, 300, later, IN_SCOPE[0], i2.intent_id,
                  key=f"{sid}-b")

    elif kind == "final_second_before_expiry":
        b.session.policy_expires_at = T0 + 3 * HOUR
        at = T0 + 3 * HOUR                     # exactly at expiry, not past it
        intent = b.intent(200, IN_SCOPE[0], at)
        b.attempt(HONEST, 200, at, IN_SCOPE[0], intent.intent_id)

    else:
        raise ValueError(f"unknown boundary session: {kind}")

    return b.session


def build_sessions(rng, honest_sessions: int = 40,
                   per_abuse_class: int = 6) -> list:
    """A mixed corpus. Honest sessions dominate, as real traffic does."""
    sessions = [_honest_session(f"honest-{i:03d}", rng)
                for i in range(honest_sessions)]
    for kind in ABUSE_CLASSES:
        for i in range(per_abuse_class):
            sessions.append(_abuse_session(f"{kind}-{i:03d}", kind, rng))
    for kind in BOUNDARY_SESSIONS:
        for i in range(per_abuse_class):
            sessions.append(_boundary_session(f"bound-{kind}-{i:03d}", kind, rng))
    rng.shuffle(sessions)
    return sessions
