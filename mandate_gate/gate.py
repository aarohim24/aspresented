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

3. **A repeated idempotency key is answered, not refused.** An earlier version
   of this gate treated key reuse as an attack. That was wrong: reusing a key
   is exactly what a well-behaved client does after a timeout, and refusing it
   turned correct retries into false declines. The real failure is the retry
   storm that *loses* its key and resubmits the same purchase under a new one,
   which is what DUPLICATE_CHARGE catches.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .charge import ChargeRequest, Decision, Intent, Refusal
from .envelope import MandateEnvelope
from .ledger import Ledger
from .rail import RailSimulator


def _fingerprint(intent_id, merchant, amount: int) -> str:
    """Identity of a logical purchase, independent of its idempotency key."""
    return f"{intent_id or ''}|{merchant or ''}|{amount}"


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
                 intents: dict | None = None, duplicate_window: int = 300):
        self.envelope = envelope
        self.ledger = ledger
        self.rail = rail
        self.intent_secret = intent_secret
        self.intents: dict = intents if intents is not None else {}
        self.duplicate_window = duplicate_window
        self.ledger.append("mandate", {
            "mandate_id": envelope.mandate_id,
            "source": envelope.source,
            "rail_enforces": sorted(str(c) for c in envelope.rail.declared()),
            "policy_adds": sorted(str(c) for c in envelope.unenforced_by_rail),
        })

    # ------------------------------------------------------------- intents
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
    def _check(self, req: ChargeRequest, st: MandateState) -> list:
        limits = self.envelope.effective
        out: list = []

        recent_dupe = self._duplicate_of(req, st)
        if recent_dupe is not None:
            out.append(Refusal(
                "DUPLICATE_CHARGE", "idempotency_key",
                f"an identical charge was allowed {req.at - recent_dupe}s ago "
                f"under a different idempotency key",
                "Reuse the original idempotency key so the retry is "
                "recognised instead of charging twice."))

        if limits.expires_at is not None and req.at > limits.expires_at:
            out.append(Refusal(
                "POLICY_EXPIRED", "expires_at",
                f"mandate lapsed at {limits.expires_at}, charge at {req.at}",
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

        if limits.rate_limit is not None:
            window = limits.rate_limit
            since = req.at - window.seconds
            recent = sum(1 for t in st.charge_times if t > since)
            if recent + 1 > window.max_charges:
                out.append(Refusal(
                    "RATE_EXCEEDED", "at",
                    f"{recent} charges in the last {window.seconds}s, "
                    f"limit {window.max_charges}",
                    f"Retry after {min(t for t in st.charge_times if t > since) + window.seconds}."))

        if limits.scope is not None and not limits.scope.is_unrestricted:
            if not limits.scope.permits(req.merchant, req.category):
                out.append(Refusal(
                    "SCOPE_VIOLATION", "merchant",
                    f"merchant={req.merchant} category={req.category} "
                    f"is outside the authorised scope",
                    "Charge only within the authorised merchants/categories."))

        out.extend(self._check_intent(req, limits))
        return out

    def _duplicate_of(self, req: ChargeRequest, st: MandateState):
        """
        The keyless retry storm: same purchase, new key, moments later. Returns
        the timestamp of the earlier charge, or None.
        """
        fp = _fingerprint(req.intent_id, req.merchant, req.amount)
        window = self.duplicate_window
        for seen_fp, at in st.fingerprints:
            if seen_fp == fp and 0 <= req.at - at <= window:
                return at
        return None

    def _check_intent(self, req: ChargeRequest, limits) -> list:
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
        if req.at > intent.expires_at:
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
            self._record(req, decision)
            return decision

        refusals = self._check(req, st)
        if refusals:
            decision = Decision(False, tuple(refusals), refused_by="policy")
            self._record(req, decision)
            return decision

        ok, result = self.rail.charge(req.amount, req.at)
        decision = (Decision(True, charge_id=result)
                    if ok else
                    Decision(False, rail_error=result, refused_by="rail"))
        self._record(req, decision)
        return decision

    def _record(self, req: ChargeRequest, decision: Decision) -> None:
        self.ledger.append("decision", {
            "mandate_id": req.mandate_id,
            "idempotency_key": req.idempotency_key,
            "amount": req.amount,
            "at": req.at,
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
