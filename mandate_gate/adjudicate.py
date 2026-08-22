"""
Dispute-time adjudication.

A charge is disputed weeks after the fact. The question is not "is this charge
suspicious now" but "was it authorised then". Answering it requires the state
as it stood at that moment, which is why the ledger is the source of truth
rather than a log written beside one.

Everything here reads from the ledger and nothing else. Nothing in memory is
trusted: intent signatures are re-verified from the recorded copy, and the
cumulative position is recomputed from the entries that preceded the disputed
charge rather than read from a running total.

Three verdicts, and the third is the point:

  AUTHORISED   -- a signed intent covers this charge, and the charge conformed
                  to it and to the mandate's limits at the time.
  UNAUTHORISED -- the record shows it should not have happened.
  UNPROVABLE   -- the charge was allowed, but nothing on record establishes
                  what the principal actually asked for.

UNPROVABLE is not a bug in the adjudicator. It is the evidence gap this project
exists to describe, reported honestly instead of dressed up as a defence. A
mandate with no intent binding produces it every time -- which is the state
every agent purchase on today's rails is in.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

AUTHORISED = "AUTHORISED"
UNAUTHORISED = "UNAUTHORISED"
UNPROVABLE = "UNPROVABLE"


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


def _verify_intent_record(record: dict, secret: bytes) -> bool:
    """Re-derive the signature from the recorded fields alone."""
    signature = record.get("signature")
    if not signature:
        return False
    payload = {
        "intent_id": record.get("intent_id"),
        "mandate_id": record.get("mandate_id"),
        "max_amount": record.get("max_amount"),
        "expires_at": record.get("expires_at"),
        "merchant": record.get("merchant"),
        "category": record.get("category"),
    }
    expected = hmac.new(secret, _canonical(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@dataclass
class Adjudication:
    charge_ref: str
    mandate_id: str
    verdict: str
    reasons: list = field(default_factory=list)
    chain_ok: bool = True
    chain_error: str | None = None
    charge: dict = field(default_factory=dict)
    intent: dict = field(default_factory=dict)
    position_at_charge: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "charge_ref": self.charge_ref,
            "mandate_id": self.mandate_id,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "chain_ok": self.chain_ok,
            "chain_error": self.chain_error,
            "charge": self.charge,
            "intent": self.intent,
            "position_at_charge": self.position_at_charge,
        }


class Adjudicator:
    """Answers "was this charge authorised" from a ledger and a secret."""

    def __init__(self, ledger, intent_secret: bytes):
        self.ledger = ledger
        self.secret = intent_secret

    # ------------------------------------------------------------ listings
    def disputable(self) -> list:
        """Charges a cardholder could plausibly dispute: the allowed ones."""
        out = []
        for entry in self.ledger.entries():
            p = entry.payload
            if entry.kind == "decision" and p.get("allowed") \
                    and not p.get("replayed"):
                out.append({
                    "charge_ref": p.get("idempotency_key"),
                    "mandate_id": p.get("mandate_id"),
                    "amount": p.get("amount"),
                    "at": p.get("at"),
                    "merchant": p.get("merchant"),
                    "intent_id": p.get("intent_id"),
                    "charge_id": p.get("charge_id"),
                })
        return out

    def refused(self) -> list:
        """
        Charges the gate stopped. Also evidence: proof a merchant declined
        something rather than quietly letting it through.
        """
        out = []
        for entry in self.ledger.entries():
            p = entry.payload
            if entry.kind == "decision" and not p.get("allowed") \
                    and not p.get("replayed"):
                out.append({
                    "charge_ref": p.get("idempotency_key"),
                    "mandate_id": p.get("mandate_id"),
                    "amount": p.get("amount"),
                    "at": p.get("at"),
                    "merchant": p.get("merchant"),
                    "codes": p.get("codes") or [],
                    "refused_by": p.get("refused_by"),
                })
        return out

    # --------------------------------------------------------- adjudicate
    def adjudicate(self, charge_ref: str) -> Adjudication:
        entries = list(self.ledger.entries())

        chain_ok, chain_error = True, None
        try:
            self.ledger.verify()
        except Exception as exc:                     # BrokenChain
            chain_ok, chain_error = False, str(exc)

        target = None
        target_index = None
        for i, entry in enumerate(entries):
            p = entry.payload
            if (entry.kind == "decision"
                    and p.get("idempotency_key") == charge_ref
                    and not p.get("replayed")):
                target, target_index = p, i
                break

        if target is None:
            return Adjudication(
                charge_ref=charge_ref, mandate_id="", verdict=UNPROVABLE,
                reasons=["No record of this charge in the ledger."],
                chain_ok=chain_ok, chain_error=chain_error)

        mandate_id = target.get("mandate_id") or ""
        adj = Adjudication(charge_ref=charge_ref, mandate_id=mandate_id,
                           verdict=UNPROVABLE, charge=target,
                           chain_ok=chain_ok, chain_error=chain_error)

        if not chain_ok:
            adj.verdict = UNPROVABLE
            adj.reasons.append(
                "The decision log fails integrity verification, so nothing in "
                f"it can be relied on. {chain_error}")
            return adj

        # ---- what the mandate required, as recorded at setup
        mandate_entry = next(
            (e.payload for e in entries
             if e.kind == "mandate" and e.payload.get("mandate_id") == mandate_id),
            {})
        policy_adds = set(mandate_entry.get("policy_adds") or ())

        # ---- position at the time of the charge, recomputed
        prior_total = prior_count = 0
        for entry in entries[:target_index]:
            p = entry.payload
            if (entry.kind == "decision" and p.get("allowed")
                    and not p.get("replayed")
                    and p.get("mandate_id") == mandate_id):
                prior_total += int(p.get("amount") or 0)
                prior_count += 1
        adj.position_at_charge = {
            "charged_before": prior_total,
            "charges_before": prior_count,
            "this_charge": int(target.get("amount") or 0),
            "total_after": prior_total + int(target.get("amount") or 0),
        }

        if not target.get("allowed"):
            adj.verdict = UNAUTHORISED
            adj.reasons.append(
                "The gate refused this charge at the time; it never settled. "
                f"Codes: {', '.join(target.get('codes') or []) or 'none'}.")
            return adj

        # ---- was intent binding even required?
        if "intent_binding" not in policy_adds:
            adj.reasons.append(
                "This mandate did not require intent binding, so no record "
                "exists of what the principal asked for. The charge was within "
                "the mandate's limits, but authorisation cannot be "
                "demonstrated -- only permission can.")
            adj.verdict = UNPROVABLE
            return adj

        intent_id = target.get("intent_id")
        if not intent_id:
            adj.verdict = UNAUTHORISED
            adj.reasons.append(
                "Intent binding was required and this charge references no "
                "intent. It should not have been allowed.")
            return adj

        intent = next(
            (e.payload for e in entries
             if e.kind == "intent" and e.payload.get("intent_id") == intent_id),
            None)
        if intent is None:
            adj.verdict = UNPROVABLE
            adj.reasons.append(
                f"Charge references intent {intent_id}, which is not in the "
                "ledger. Nothing establishes what was approved.")
            return adj

        adj.intent = intent

        if not _verify_intent_record(intent, self.secret):
            adj.verdict = UNPROVABLE
            adj.reasons.append(
                "The intent record fails signature verification, so its terms "
                "cannot be relied on as what the principal approved.")
            return adj

        # ---- conformance of charge to intent
        problems = []
        amount = int(target.get("amount") or 0)
        if amount > int(intent.get("max_amount") or 0):
            problems.append(
                f"charged {amount} against an intent for at most "
                f"{intent.get('max_amount')}")
        if intent.get("merchant") and target.get("merchant") != intent.get("merchant"):
            problems.append(
                f"charged {target.get('merchant')} against an intent naming "
                f"{intent.get('merchant')}")
        at = int(target.get("at") or 0)
        if intent.get("expires_at") is not None and at > int(intent["expires_at"]):
            problems.append("charged after the intent expired")

        if problems:
            adj.verdict = UNAUTHORISED
            adj.reasons.append("The charge did not conform to the signed "
                               "intent: " + "; ".join(problems) + ".")
            return adj

        adj.verdict = AUTHORISED
        adj.reasons.append(
            f"A signed intent, verified from the ledger, approved up to "
            f"{intent.get('max_amount')} paise"
            + (f" at {intent.get('merchant')}" if intent.get("merchant") else "")
            + f". This charge of {amount} paise conformed to it.")
        adj.reasons.append(
            f"At the time it was the charge numbered {prior_count + 1} on this "
            f"mandate, bringing the total to "
            f"{adj.position_at_charge['total_after']} paise.")
        adj.reasons.append(
            "The decision log verifies, so this record was not altered after "
            "the fact.")
        return adj
