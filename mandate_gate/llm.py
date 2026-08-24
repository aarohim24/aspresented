"""
A minimal chat client, shared.

Extracted from the attacker when a second caller arrived. The transport, the
credential redaction, the retry policy, the JSON scavenging and the
what-does-this-status-mean guidance are none of them adversarial-specific, and
two copies of a redaction regex is one copy too many.

Provider-agnostic: the request shape is OpenAI-compatible chat completions, so
`base_url` and `model` point wherever you like. Raw HTTP over `urllib` rather
than a vendor SDK, so the core package needs no dependencies -- a project whose
thesis is that rails disagree should not hard-wire one vendor.

Everything here was learned from a live failure. The User-Agent, because
urllib's default is blocked at the edge. The JSON scavenging being
string-aware, because a stray brace in a rationale ended a run silently. The
status explanations, because guessing "your key is bad" when it is not sends
the reader to the wrong place.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "openai/gpt-oss-120b"

#: Always send a real User-Agent.
#:
#: urllib defaults to "Python-urllib/3.x", and Groq sits behind Cloudflare,
#: which rejects that signature with `403 error code: 1010` -- before the
#: request reaches the API at all. The failure is indistinguishable from a bad
#: key unless you know the code is Cloudflare's: with any real UA the same
#: invalid key returns a clean `401 invalid_api_key`.
USER_AGENT = "as-presented/0.1 (+https://github.com/aarohim24/aspresented)"

#: Token-shaped strings, redacted before anything is written down. Error bodies
#: sometimes echo the credential that failed, and transcripts get committed.
#: Two forms, because a first version required the token to abut the prefix and
#: so never matched the `Bearer <token>` header spelling at all.
_KEY_SHAPED = re.compile(
    r"(?:\b(?:gsk|sk|xai)[-_][A-Za-z0-9\-_]{8,})"
    r"|(?:\bBearer\s+[A-Za-z0-9\-_.]{8,})",
    re.I)


def redact(text: str) -> str:
    """
    Blank anything credential-shaped. Deliberately eager: a false positive
    costs a slightly less readable error message, a false negative commits a
    key to a public repository.
    """
    return _KEY_SHAPED.sub("<redacted>", text or "")


def explain(status: int, body: str) -> str:
    """
    Say what a status actually means, because guessing wastes the reader's time.

    A 403 carrying a Cloudflare code is an edge block on the client signature,
    not a rejected credential -- and telling someone their key is bad when it
    is not sends them off to regenerate a working key.
    """
    if "1010" in body or "cloudflare" in body.lower():
        return ("  <- edge block on the client signature, not your key. "
                "Check the User-Agent header is being sent.")
    if status in (401, 403):
        return "  <- the key was rejected."
    if status == 429:
        return "  <- rate limited; the free tier allows about 30 requests/min."
    if status == 404:
        return "  <- check the model id; it may be retired."
    if status >= 500:
        return "  <- provider-side; retrying later is reasonable."
    return ""


def extract_json(text: str) -> dict | None:
    """
    Pull the first JSON object out of a reply.

    Models wrap JSON in prose or fences however firmly you ask them not to, so
    this scans rather than parses strictly.

    The walk is string-aware, and that is not fussiness. A first version
    counted braces blindly, so a rationale like "testing the } edge" made
    extraction return None -- which ends a run silently, looking exactly like a
    model that had nothing to say. Braces and quotes are precisely what a model
    reasoning about JSON writes about.
    """
    if not text:
        return None

    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        found = json.loads(text[start:i + 1])
                        if isinstance(found, dict):
                            return found
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def as_int(value) -> int | None:
    """
    Coerce to int, refusing bool.

    `isinstance(True, int)` is True in Python, so a JSON `true` would otherwise
    become the amount 1 -- a value the model never proposed.
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


REFUSAL_MARKERS = ("i can't help", "i cannot help", "i can’t help",
                   "i'm sorry, but", "i’m sorry, but", "i am unable",
                   "i'm unable", "i’m unable", "i must decline")


def looks_like_refusal(text: str) -> bool:
    """
    Whether a reply is the model declining rather than answering.

    Only the opening of the reply is inspected: a refusal leads with it, and
    checking the whole body would catch the same phrases quoted inside a
    rationale. Markers are narrow for the same reason -- "i will not" was in a
    first version and matched "I will not exceed the cap".
    """
    low = (text or "").strip().lower()[:160]
    return any(marker in low for marker in REFUSAL_MARKERS)


@dataclass
class ChatClient:
    """
    One call, one reply. No conversation state -- callers build their own
    messages, because what a buyer needs to remember differs from what an
    attacker does.
    """

    base_url: str = GROQ_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    temperature: float = 0.8
    #: Generous, because a reasoning-style model spends tokens before the JSON.
    #: Too small truncates the object and the parse fails for no visible reason.
    max_tokens: int = 1200
    json_mode: bool = True
    timeout: int = 45
    max_retries: int = 2
    #: ~28 requests/minute, inside Groq's free-tier 30.
    throttle: float = 2.1
    _last_call: float = 0.0
    _json_failures: int = 0

    def __post_init__(self) -> None:
        self.api_key = (self.api_key or os.environ.get("GROQ_API_KEY")
                        or os.environ.get("OPENAI_API_KEY"))

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _post(self, body: dict) -> tuple:
        """
        Returns (content, finish_reason). Parses the envelope defensively: a
        moderation block or gateway error can return 200 with no `choices`, and
        a bare KeyError tells the reader nothing.
        """
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode(), method="POST")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", USER_AGENT)
        with urllib.request.urlopen(
                req, context=ssl.create_default_context(),
                timeout=self.timeout) as r:
            payload = json.loads(r.read().decode() or "{}")

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError(
                f"response carried no choices: "
                f"{redact(json.dumps(payload))[:200]}")

        first = choices[0] or {}
        message = first.get("message") or {}
        content = message.get("content")
        if not content:
            # Reasoning-style models sometimes leave `content` empty and put
            # the text elsewhere. Look before giving up, so an empty reply is
            # never reported as nothing at all.
            content = message.get("reasoning_content") or message.get("reasoning")
        return (content or ""), first.get("finish_reason")

    def ask(self, messages: list) -> tuple:
        """
        Returns (text, finish_reason, error). Never raises -- a dead client
        stops rather than aborting whatever loop is driving it.
        """
        if not self.configured:
            return None, None, "no API key (set GROQ_API_KEY or OPENAI_API_KEY)"

        body = {"model": self.model, "messages": messages,
                "temperature": self.temperature, "max_tokens": self.max_tokens}
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}

        for attempt in range(self.max_retries + 1):
            gap = time.monotonic() - self._last_call
            if self.throttle and gap < self.throttle:
                time.sleep(self.throttle - gap)
            self._last_call = time.monotonic()
            try:
                content, finish = self._post(body)
                return content, finish, None
            except urllib.error.HTTPError as exc:
                detail = redact(exc.read().decode()[:300])
                low = detail.lower()
                # Two different 400s, both about JSON mode, both recoverable.
                if exc.code == 400 and self.json_mode:
                    if "response_format" in low:
                        self.json_mode = False
                        body.pop("response_format", None)
                        continue
                    if "validate json" in low or "failed_generation" in low:
                        self._json_failures += 1
                        if self._json_failures >= 2:
                            self.json_mode = False
                            body.pop("response_format", None)
                        if attempt < self.max_retries:
                            continue
                if exc.code == 429 and attempt < self.max_retries:
                    time.sleep(5 * (attempt + 1))
                    continue
                return (None, None,
                        f"HTTP {exc.code}: {detail}{explain(exc.code, detail)}")
            except Exception as exc:
                if attempt < self.max_retries:
                    time.sleep(2)
                    continue
                return None, None, f"{type(exc).__name__}: {redact(str(exc))}"
        return None, None, "retries exhausted"
