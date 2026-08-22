"""
The gate.

Policy is evaluated here, before the rail is ever called. Each check maps to
one constraint the coverage table shows no rail expresses, plus the two
Razorpay specifically lacks (scope, intent binding).

Two design choices worth defending:

1. **The ledger is the state.** Cumulative totals, charge counts and rate
   windows are derived by replaying the ledger, not from a counter held beside
   it. So the number the gate enforces on is the same number it can later
   prove, and a tampered log fails verification instead of quietly changing
   what gets allowed.

2. **All policy checks run, not just the first.** An agent that gets one
   refusal at a time needs N round trips to discover N problems. Returning the
   full set lets it correct in one pass.

3. **The server clock decides; the caller's clock is evidence at most.** The
   gate reads `now` from an injected clock and evaluates every time-dependent
   check against it. A caller-asserted `claimed_at` is recorded and checked for
   skew, never acted on. An earlier version trusted the request's timestamp,
   and an agent that advanced it defeated the rate limit outright.

4. **A repeated idempotency key is answered, not refused.** An earlier version
   of this gate treated key reuse as an attack. That was wrong: reusing a key
   is exactly what a well-behaved client does after a timeout, and refusing it
   turned correct retries into false declines. The real failure is the retry
   storm that *loses* its key and resubmits the same purchase under a new one,
   which is what DUPLICATE_CHARGE catches.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .charge import ChargeRequest, Decision, Intent, Refusal
from .envelope import MandateEnvelope
from .ledger import Ledger
from .rail import RailSimulator


def _fingerprint(intent_id, merchant, amount: int) -> str:
    """
    Identity of a logical purchase, independent of its idempotency key.

    Hashed rather than delimiter-joined: a merchant name containing the
    delimiter could otherwise collide with a different purchase and be refused
    as a duplicate.
    """
    parts = repr((intent_id, merchant, amount)).encode()
    return hashlib.sha256(parts).hexdigest()[:32]


@dataclass
class MandateState:
    """Derived from the ledger. Never authoritative on its own."""

    charged_total: int = 0
    charge_count: int = 0
    charge_times: tuple = ()
    #: idempotency_key -> the decision payload recorded for it
    decisions: dict = field(default_factory=dict)
    #: (fingerprint, at) for allowed charges, used to spot keyless retries
    fingerprints: tuple = ()


class Gate:
    def __init__(self, envelope: MandateEnvelope, ledger: Ledger,
                 rail: RailSimulator, intent_secret: bytes,
                 intents: dict | None = None, duplicate_window: int = 300,
                 clock=None, max_clock_skew: int = 300):
        if not intent_secret:
            raise ValueError(
                "intent_secret is required -- an unsigned intent proves "
                "nothing, so silently accepting an empty key would make the "
                "whole evidence chain decorative")
        self.envelope = envelope
        self.ledger = ledger
        self.rail = rail
        self.intent_secret = intent_secret
        self.intents: dict = intents if intents is not None else {}
        self.duplicate_window = duplicate_window
        # Server time. Injected so tests and replays are deterministic -- but
        # authoritative, which is the point: never read from the request.
        self._clock = clock or (lambda: 0)
        self.max_clock_skew = max_clock_skew
        self.ledger.append("mandate", {
            "mandate_id": envelope.mandate_id,
            "source": envelope.source,
            "rail_enforces": sorted(str(c) for c in envelope.rail.declared()),
            "policy_adds": sorted(str(c) for c in envelope.unenforced_by_rail),
        })

    # ------------------------------------------------------------- intents
    def now(self) -> int:
        """Server time. The only clock any policy decision may consult."""
        return int(self._clock())

    def record_intent(self, intent: Intent) -> Intent:
        signed = intent.signed(self.intent_secret)
        self.intents[signed.intent_id] = signed
        self.ledger.append("intent", {
            "mandate_id": self.envelope.mandate_id,
            "intent_id": signed.intent_id,
            "max_amount": signed.max_amount,
            "merchant": signed.merchant,
            "category": signed.category,
            "expires_at": signed.expires_at,
            # Recorded so an adjudicator can re-verify from the ledger alone,
            # without trusting whatever is in memory at dispute time.
            "signature": signed.signature,
        })
        return signed

    # --------------------------------------------------------------- state
    def state(self) -> MandateState:
        """Replay the ledger. The audit trail and the enforced number agree."""
        total = count = 0
        times: list = []
        decisions: dict = {}
        prints: list = []
        for entry in self.ledger.entries():
            if entry.kind != "decision":
                continue
            p = entry.payload
            if p.get("mandate_id") != self.envelope.mandate_id:
                continue
            if p.get("replayed"):
                continue                      # not a fresh decision
            key = p.get("idempotency_key")
            if key:
                decisions[key] = p
            if p.get("allowed"):
                total += int(p.get("amount") or 0)
                count += 1
                at = int(p.get("at") or 0)
                times.append(at)
                prints.append((_fingerprint(p.get("intent_id"),
                                            p.get("merchant"),
                                            int(p.get("amount") or 0)), at))
        return MandateState(total, count, tuple(times), decisions, tuple(prints))

    # -------------------------------------------------------------- checks
    def _check(self, req: ChargeRequest, st: MandateState, now: int) -> list:
        limits = self.envelope.effective
        out: list = []

        if (req.claimed_at is not None
                and abs(req.claimed_at - now) > self.max_clock_skew):
            out.append(Refusal(
                "CLOCK_SKEW", "claimed_at",
                f"caller asserts {req.claimed_at}; server clock reads {now}",
                "Drop claimed_at, or synchronise. Policy is evaluated against "
                "server time regardless."))

        recent_dupe = self._duplicate_of(req, st, now)
        if recent_dupe is not None:
            out.append(Refusal(
                "DUPLICATE_CHARGE", "idempotency_key",
                f"an identical charge was allowed {now - recent_dupe}s ago "
                f"under a different idempotency key",
                "Reuse the original idempotency key so the retry is "
                "recognised instead of charging twice."))

        if limits.expires_at is not None and now > limits.expires_at:
            out.append(Refusal(
                "POLICY_EXPIRED", "expires_at",
                f"mandate lapsed at {limits.expires_at}, server clock {now}",
                "Obtain a fresh mandate; this one cannot be revived."))

        if limits.cumulative_max is not None:
            projected = st.charged_total + req.amount
            if projected > limits.cumulative_max:
                out.append(Refusal(
                    "CUMULATIVE_EXCEEDED", "amount",
                    f"{projected} would exceed total cap "
                    f"{limits.cumulative_max} ({st.charged_total} already used)",
                    f"Charge at most "
                    f"{max(limits.cumulative_max - st.charged_total, 0)} paise."))

        if (limits.max_charges is not None
                and st.charge_count + 1 > limits.max_charges):
            out.append(Refusal(
                "CHARGE_COUNT_EXCEEDED", "mandate_id",
                f"{st.charge_count} of {limits.max_charges} charges used",
                "No charges remain. Obtain a fresh mandate."))

        # Every window, not the collapsed one. 10/day and 5/hour each permit
        # bursts the other forbids, so satisfying the tighter-by-rate window is
        # not the same as satisfying both.
        for window in self.envelope.rate_windows:
            since = now - window.seconds
            in_window = [t for t in st.charge_times if t > since]
            if len(in_window) + 1 > window.max_charges:
                out.append(Refusal(
                    "RATE_EXCEEDED", "mandate_id",
                    f"{len(in_window)} charges in the last {window.seconds}s, "
                    f"limit {window.max_charges}",
                    f"Retry after {min(in_window) + window.seconds}."))
                break            # one refusal per constraint class is enough

        # Every scope. A charge must satisfy all of them, not the union.
        for scope in self.envelope.scopes:
            if not scope.permits(req.merchant, req.category):
                out.append(Refusal(
                    "SCOPE_VIOLATION", "merchant",
                    f"merchant={req.merchant} category={req.category} "
                    f"is outside the authorised scope",
                    "Charge only within the authorised merchants/categories."))
                break

        out.extend(self._check_intent(req, limits, now))
        return out

    def _duplicate_of(self, req: ChargeRequest, st: MandateState, now: int):
        """
        The keyless retry storm: same purchase, new key, moments later. Returns
        the timestamp of the earlier charge, or None.
        """
        fp = _fingerprint(req.intent_id, req.merchant, req.amount)
        window = self.duplicate_window
        for seen_fp, at in st.fingerprints:
            if seen_fp == fp and 0 <= now - at <= window:
                return at
        return None

    def _check_intent(self, req: ChargeRequest, limits, now: int) -> list:
        if not limits.requires_intent_binding:
            return []

        if not req.intent_id:
            return [Refusal(
                "INTENT_UNBOUND", "intent_id",
                "no intent referenced; this mandate requires one",
                "Reference the signed intent that justifies this charge.")]

        intent = self.intents.get(req.intent_id)
        if intent is None:
            return [Refusal(
                "INTENT_UNBOUND", "intent_id",
                f"intent {req.intent_id} is not on record",
                "Record the intent before charging against it.")]

        if not intent.signature_valid(self.intent_secret):
            return [Refusal(
                "INTENT_UNBOUND", "intent_id",
                f"intent {req.intent_id} fails signature verification",
                "The intent record was altered. Obtain a fresh one.")]

        out = []
        if now > intent.expires_at:
            out.append(Refusal(
                "INTENT_MISMATCH", "intent_id",
                f"intent expired at {intent.expires_at}",
                "Capture a fresh intent from the principal."))
        if req.amount > intent.max_amount:
            out.append(Refusal(
                "INTENT_MISMATCH", "amount",
                f"{req.amount} exceeds the {intent.max_amount} the "
                f"principal approved",
                f"Charge at most {intent.max_amount} paise under this intent."))
        if intent.merchant and req.merchant != intent.merchant:
            out.append(Refusal(
                "INTENT_MISMATCH", "merchant",
                f"intent named {intent.merchant}, charge names {req.merchant}",
                "Charge the merchant the principal approved."))
        return out

    # ------------------------------------------------------------ decision
    def authorize(self, req: ChargeRequest) -> Decision:
        if req.mandate_id != self.envelope.mandate_id:
            raise ValueError("charge does not belong to this mandate")

        now = self.now()
        st = self.state()

        prior = st.decisions.get(req.idempotency_key)
        if prior is not None:
            # Answer, do not refuse. This is a correct retry.
            decision = Decision(
                allowed=bool(prior.get("allowed")),
                rail_error=prior.get("rail_error"),
                charge_id=prior.get("charge_id"),
                refused_by=prior.get("refused_by"),
                replayed=True,
            )
            self._record(req, decision, now)
            return decision

        refusals = self._check(req, st, now)
        if refusals:
            decision = Decision(False, tuple(refusals), refused_by="policy")
            self._record(req, decision, now)
            return decision

        ok, result = self.rail.charge(req.amount, now)
        decision = (Decision(True, charge_id=result)
                    if ok else
                    Decision(False, rail_error=result, refused_by="rail"))
        self._record(req, decision, now)
        return decision

    def _record(self, req: ChargeRequest, decision: Decision, now: int) -> None:
        self.ledger.append("decision", {
            "mandate_id": req.mandate_id,
            "idempotency_key": req.idempotency_key,
            "amount": req.amount,
            # `at` is server time -- the authoritative record. `claimed_at` is
            # what the caller asserted, kept only as evidence.
            "at": now,
            "claimed_at": req.claimed_at,
            "merchant": req.merchant,
            "category": req.category,
            "intent_id": req.intent_id,
            "allowed": decision.allowed,
            "replayed": decision.replayed,
            "refused_by": decision.refused_by,
            "codes": list(decision.codes),
            "rail_error": decision.rail_error,
            "charge_id": decision.charge_id,
        })
