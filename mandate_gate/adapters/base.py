"""
The adapter contract.

Python does not check Protocols at runtime, so this file would be decoration if
nothing enforced it. `tests/test_adapters.py::TestAdapterContract` does --
every adapter in the registry is checked against the shape below, including any
added later.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable

from ..envelope import MandateEnvelope


@runtime_checkable
class Adapter(Protocol):
    #: Stable identifier used as `MandateEnvelope.source`.
    SOURCE: ClassVar[str]

    #: True only when this adapter talks to a live API in this build.
    #: False means "mapper verified against fixtures". A factual claim, not a
    #: label -- the README states which is which, and a test asserts the count.
    WIRED: ClassVar[bool]

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        """
        Map a native mandate to an envelope.

        Must declare only what the rail actually enforces unaided. Inventing a
        constraint makes the gate stand down where it should act, silently --
        the worst failure available to this codebase.
        """
        ...
