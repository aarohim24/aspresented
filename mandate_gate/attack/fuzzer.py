"""
A deterministic attacker. No model, no network, no API key.

It knows nothing about the checks. It knows what a mandate holder knows, plus
what it learns from being refused, and it searches the space that historically
hides bugs: boundaries, and the seams between constraints.

Six strategies, tried in a fixed order per round so runs are reproducible:

  ceiling      the per-charge ceiling exactly, and one paise over
  headroom     whatever the last refusal said was left, and one more than that
  burst        several charges with no time between them
  keyshift     the same purchase again under a fresh idempotency key
  clockshift   a claimed timestamp far from now, to see if it is believed
  scopewalk    merchants and categories never observed on this mandate
  unbind       the same purchase with no intent referenced at all

The adaptive part is `headroom`. A refusal's `remediation` text names the amount
that would have been acceptable; the fuzzer parses it and charges exactly that,
then one paise more. So the fuzzer is also a test of the remediation strings: if
they carried no usable number, this strategy would never fire.

Every amount carries a per-attempt jitter, and that is not cosmetic. The gate's
duplicate check fingerprints (intent, merchant, amount), so two charges of the
same amount look like one purchase retried. A first version of this fuzzer sent
round numbers and spent 32 of 40 attempts being refused as a duplicate, never
reaching the cumulative, rate or count limits at all. Jittering by a paise walks
straight past it.

That is worth stating plainly: DUPLICATE_CHARGE is hygiene, not a security
control. It catches the honest retry storm it was built for -- a client that
lost its key and resent the same purchase -- and an adversary defeats it by
adding one paise. The constraints that actually bound spend are the cumulative
cap and the count.
"""

from __future__ import annotations

import re

from ..charge import ChargeRequest
from .base import Briefing

#: Merchants a real agent might try that were never authorised.
UNSEEN_MERCHANTS = ("shop-unlisted", "cash-out-ltd", "")
UNSEEN_CATEGORIES = ("6011", "7995")     # ATM, gambling

_AMOUNT_IN_TEXT = re.compile(r"(\d+)\s*paise")


class Fuzzer:
    NAME = "fuzzer"

    def __init__(self, mandate_id: str, rng, ceiling_hint: int = 500):
        self.mandate_id = mandate_id
        self.rng = rng
        self.ceiling_hint = ceiling_hint
        self._n = 0
        self._jitter = 0
        self._strategies = (self._drain, self._ceiling, self._headroom,
                            self._burst, self._keyshift, self._clockshift,
                            self._scopewalk, self._unbind)

    # ------------------------------------------------------------- helpers
    def _key(self, tag: str) -> str:
        self._n += 1
        return f"fz-{tag}-{self._n:03d}"

    def _vary(self, amount: int) -> int:
        """
        Nudge the amount so the purchase fingerprint differs.

        Not an optimisation -- without it the duplicate check absorbs almost
        every attempt and the deeper constraints are never probed.
        """
        self._jitter = (self._jitter + 1) % 7
        return max(amount + self._jitter, 1)

    def _merchant(self, briefing):
        return (briefing.seen_merchants[0] if briefing.seen_merchants
                else "shop-a")

    def _intent(self, briefing):
        return briefing.intents[0] if briefing.intents else None

    def _charge(self, briefing, tag, **kw):
        kw.setdefault("merchant", self._merchant(briefing))
        kw.setdefault("intent_id", self._intent(briefing))
        return ChargeRequest(mandate_id=self.mandate_id,
                             idempotency_key=self._key(tag), **kw)

    @staticmethod
    def _hinted_amount(briefing) -> int | None:
        """The amount a refusal said would have been acceptable, if any."""
        last = briefing.last
        if last is None or last.allowed:
            return None
        for text in last.remediations:
            found = _AMOUNT_IN_TEXT.search(text or "")
            if found:
                return int(found.group(1))
        return None

    # ---------------------------------------------------------- strategies
    def _ceiling(self, briefing):
        ceiling = briefing.mandate.get("per_charge_max") or self.ceiling_hint
        # exactly the ceiling on even rounds, one paise over on odd ones
        # exactly the ceiling on even rounds, over it on odd ones
        amount = ceiling if self._n % 2 == 0 else ceiling + 1 + self._jitter
        self._jitter = (self._jitter + 1) % 7
        return self._charge(briefing, "ceil", amount=amount)

    def _headroom(self, briefing):
        hinted = self._hinted_amount(briefing)
        if hinted is None:
            return None
        # the remediation said "at most N". Try N, then N + 1.
        amount = hinted if hinted > 0 else 1
        if any("headroom" in a.request.idempotency_key
               for a in briefing.history[-2:]):
            amount = hinted + 1
        return self._charge(briefing, "headroom", amount=max(amount, 1))

    def _drain(self, briefing):
        """
        Small repeated charges at a merchant already seen to work. The dullest
        strategy and the one that actually tests a cumulative cap.
        """
        small = max((briefing.mandate.get("per_charge_max") or 500) // 5, 1)
        return self._charge(briefing, "drain", amount=self._vary(small))

    def _burst(self, briefing):
        """
        Walk amounts upward with no time between charges. Consumes whatever
        cumulative headroom exists and stresses every rate window at once.
        """
        ceiling = briefing.mandate.get("per_charge_max") or self.ceiling_hint
        step = max(ceiling // 4, 1)
        amount = min(step * (1 + (self._n % 4)), ceiling)
        return self._charge(briefing, "burst", amount=self._vary(amount))

    def _keyshift(self, briefing):
        """The same purchase again, under a key the gate has not seen."""
        prior = next((a for a in reversed(briefing.history) if a.allowed), None)
        if prior is None:
            return None
        return ChargeRequest(
            mandate_id=self.mandate_id,
            amount=prior.request.amount,
            idempotency_key=self._key("keyshift"),
            intent_id=prior.request.intent_id,
            merchant=prior.request.merchant,
            category=prior.request.category)

    def _clockshift(self, briefing):
        """Assert a time far from now and see whether it is believed."""
        small = max((briefing.mandate.get("per_charge_max") or 500) // 4, 1)
        expiry = briefing.mandate.get("expires_at") or 0
        return self._charge(briefing, "clock", amount=self._vary(small),
                            claimed_at=expiry + 86_400)

    def _unbind(self, briefing):
        """
        Drop the intent reference. Trivial, and the coverage report is what
        said it was missing: a first version of this fuzzer always attached the
        intent it knew about, so INTENT_UNBOUND was never provoked.
        """
        small = max((briefing.mandate.get("per_charge_max") or 500) // 4, 1)
        return ChargeRequest(
            mandate_id=self.mandate_id, amount=self._vary(small),
            idempotency_key=self._key("unbind"), intent_id=None,
            merchant=self._merchant(briefing))

    def _scopewalk(self, briefing):
        merchant = UNSEEN_MERCHANTS[self._n % len(UNSEEN_MERCHANTS)]
        category = UNSEEN_CATEGORIES[self._n % len(UNSEEN_CATEGORIES)]
        small = max((briefing.mandate.get("per_charge_max") or 500) // 4, 1)
        return ChargeRequest(
            mandate_id=self.mandate_id, amount=self._vary(small),
            idempotency_key=self._key("scope"),
            intent_id=self._intent(briefing),
            merchant=merchant, category=category)

    # -------------------------------------------------------------- driver
    def propose(self, briefing: Briefing):
        """
        Rotate through the strategies, skipping any that cannot fire yet.

        Rotation rather than random choice: the point is to cover the space
        systematically and reproducibly, not to wander it. A strategy that
        returns None has nothing to work with -- `headroom` needs a refusal to
        read, `keyshift` needs a settled charge to repeat -- and is retried on a
        later round once the history supports it.
        """
        start = len(briefing.history) % len(self._strategies)
        for offset in range(len(self._strategies)):
            strategy = self._strategies[(start + offset) % len(self._strategies)]
            request = strategy(briefing)
            if request is not None:
                return request
        return None
