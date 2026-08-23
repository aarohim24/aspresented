"""
Turning what a person said into something a gate can check.

This is the step the whole project depends on and the one that has been
hand-waved until now. Intents were built as dicts in test fixtures; in reality a
principal says "get me milk and bread from shop-a this week, up to twenty
rupees" and something has to render that as terms a machine can enforce.

A model does the reading, because that is what models are for. Three rules keep
it from being dangerous:

**The output is clamped, not trusted.** A caller supplies a hard ceiling and the
proposed `max_amount` is reduced to fit. If the reading were wrong -- or the
instruction were hostile -- the worst case is bounded by a number the model
never saw. A production system would also show the interpreted intent to the
principal for confirmation, and `Interpretation.summary` exists for exactly that
screen.

**The signature is not the model's business.** The model proposes terms; signing
happens here, deterministically, over a fixed field list. A model cannot mint
authority.

**A failed reading is a refusal, not a guess.** No fallback intent, no defaults
filled in silently. If the instruction cannot be read, nothing is signed --
because an intent invented on the principal's behalf is exactly the thing this
project says does not exist today.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..charge import Intent
from ..llm import as_int, extract_json

SYSTEM_PROMPT = """\
You turn a shopping instruction into machine-checkable terms.

Read the instruction and report what the person authorised. Be conservative:
if they did not say something, do not invent it. A narrower reading is safe;
a wider one spends money they did not agree to.

Reply with ONLY a JSON object:

{"max_amount": <integer paise, the most for any single charge>,
 "merchant": <the merchant they named, or null if they named none>,
 "category": <a merchant category code if they clearly implied one, else null>,
 "ttl_hours": <how long this should stay valid, in hours>,
 "goal": <one sentence restating what they want bought>}

Amounts are paise: 100 paise = 1 rupee. If they gave a total rather than a
per-item figure, report the per-charge maximum you think they meant and say so
in `goal`."""


@dataclass
class Interpretation:
    """A reading of an instruction, and how it was bounded."""

    intent: Intent | None
    goal: str = ""
    raw: dict | None = None
    error: str | None = None
    #: Set when the model proposed more than the caller's hard ceiling.
    clamped_from: int | None = None

    @property
    def ok(self) -> bool:
        return self.intent is not None

    def summary(self) -> str:
        """
        What a confirmation screen would show the principal.

        Present because "the user should confirm this" is easy to write in a
        design document and easy to leave unimplemented, and the difference
        between the two is whether the text exists.
        """
        if not self.ok:
            return f"Could not read that instruction: {self.error}"
        i = self.intent
        lines = [f"You asked: {self.goal}",
                 f"Authorising up to Rs {i.max_amount / 100:.2f} per charge"]
        if i.merchant:
            lines.append(f"at {i.merchant}")
        lines.append(f"valid until {i.expires_at}")
        if self.clamped_from:
            lines.append(
                f"(reduced from Rs {self.clamped_from / 100:.2f} to stay "
                f"within the mandate)")
        return "\n".join(lines)


def interpret(instruction: str, client, *, mandate_id: str, intent_id: str,
              secret: bytes, now: int, ceiling: int,
              max_ttl_hours: int = 24 * 7) -> Interpretation:
    """
    Read `instruction` into a signed Intent, or explain why not.

    `ceiling` is the hard bound -- the mandate's own per-charge maximum. The
    model's proposal is reduced to fit it, never raised to meet it.
    """
    text, finish, error = client.ask([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": instruction},
    ])
    if error:
        return Interpretation(intent=None, error=error)

    parsed = extract_json(text)
    if parsed is None:
        return Interpretation(
            intent=None,
            error=(f"could not read the instruction into terms "
                   f"(finish_reason={finish!r})"))

    proposed = as_int(parsed.get("max_amount"))
    if proposed is None or proposed <= 0:
        return Interpretation(
            intent=None, raw=parsed,
            error=(f"no usable spending limit in the reading: "
                   f"{parsed.get('max_amount')!r}"))

    # Clamp rather than trust. The ceiling comes from the mandate, which the
    # model never sees.
    max_amount = min(proposed, ceiling)
    clamped_from = proposed if proposed > ceiling else None

    ttl = as_int(parsed.get("ttl_hours")) or 24
    ttl = max(1, min(ttl, max_ttl_hours))

    intent = Intent(
        intent_id=intent_id,
        mandate_id=mandate_id,
        max_amount=max_amount,
        expires_at=now + ttl * 3600,
        merchant=parsed.get("merchant") or None,
        category=parsed.get("category") or None,
    ).signed(secret)

    return Interpretation(intent=intent, raw=parsed,
                          goal=str(parsed.get("goal") or "").strip(),
                          clamped_from=clamped_from)
