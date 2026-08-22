"""
Append-only, hash-chained decision ledger.

Every decision the gate makes lands here, whether it allowed or refused. The
chain exists so that a decision can be shown to have been recorded *at the
time*, not reconstructed afterwards by whoever is now in a dispute. Each entry
commits to its predecessor, so removing or editing any earlier entry breaks
verification of everything after it.

This is deliberately not a blockchain and makes no distributed-consensus
claim. It is a tamper-evident local log: it proves nobody quietly rewrote
history between the charge and the dispute. That is the property a merchant
actually needs, and it is honest about being no more than that.

Storage is newline-delimited JSON so the file stays greppable and diffable.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator

GENESIS = "0" * 64


def _canonical(payload: Any) -> bytes:
    """Stable bytes for hashing. Sorted keys, no incidental whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode()


@dataclass(frozen=True)
class Entry:
    seq: int
    prev_hash: str
    recorded_at: int
    kind: str                       # "decision" | "mandate" | "note"
    payload: dict = field(default_factory=dict)

    def digest(self) -> str:
        return hashlib.sha256(_canonical({
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "recorded_at": self.recorded_at,
            "kind": self.kind,
            "payload": self.payload,
        })).hexdigest()

    def to_json(self) -> str:
        row = asdict(self)
        row["hash"] = self.digest()
        return json.dumps(row, sort_keys=True, separators=(",", ":"),
                          default=str)


class BrokenChain(Exception):
    """Raised when verification finds the log has been altered."""


class Ledger:
    """
    A hash-chained log backed by one file.

    `clock` is injected rather than read from the wall so that tests are
    deterministic and replays are reproducible.
    """

    def __init__(self, path: str, clock=None):
        self.path = path
        self._clock = clock or (lambda: 0)
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    # ------------------------------------------------------------- writing
    def append(self, kind: str, payload: dict) -> Entry:
        tail = self._tail()
        entry = Entry(
            seq=0 if tail is None else tail.seq + 1,
            prev_hash=GENESIS if tail is None else tail.digest(),
            recorded_at=int(self._clock()),
            kind=kind,
            payload=payload,
        )
        # Append-and-flush. A crash mid-write truncates the last line, which
        # verification reports as a broken tail rather than silently accepting.
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(entry.to_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    # ------------------------------------------------------------- reading
    def entries(self) -> Iterator[Entry]:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                row.pop("hash", None)
                yield Entry(**row)

    def _tail(self) -> Entry | None:
        last = None
        for entry in self.entries():
            last = entry
        return last

    # -------------------------------------------------------- verification
    def verify(self) -> int:
        """
        Walk the chain. Returns the number of entries verified, or raises
        BrokenChain naming the first entry that does not line up.
        """
        expected_prev = GENESIS
        count = 0
        for i, entry in enumerate(self.entries()):
            if entry.seq != i:
                raise BrokenChain(f"entry {i}: seq is {entry.seq}, expected {i}")
            if entry.prev_hash != expected_prev:
                raise BrokenChain(
                    f"entry {i}: prev_hash {entry.prev_hash[:12]}... does not "
                    f"match predecessor {expected_prev[:12]}..."
                )
            expected_prev = entry.digest()
            count += 1
        return count

    # ------------------------------------------------------------- reading
    def evidence_pack(self, mandate_id: str) -> dict:
        """
        Everything recorded about one mandate, plus a verification result.
        This is what gets handed over when a charge is disputed: not a
        narrative, but the decisions as they were written down at the time.
        """
        relevant = [
            e for e in self.entries()
            if e.payload.get("mandate_id") == mandate_id
        ]
        try:
            verified = self.verify()
            integrity = {"ok": True, "entries_verified": verified}
        except BrokenChain as exc:
            integrity = {"ok": False, "error": str(exc)}

        return {
            "mandate_id": mandate_id,
            "integrity": integrity,
            "entry_count": len(relevant),
            "entries": [
                {"seq": e.seq, "recorded_at": e.recorded_at,
                 "kind": e.kind, "hash": e.digest(), "payload": e.payload}
                for e in relevant
            ],
        }
