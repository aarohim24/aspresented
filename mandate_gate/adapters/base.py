"""Adapter contract."""

from __future__ import annotations

from typing import ClassVar, Protocol

from ..envelope import MandateEnvelope


class Adapter(Protocol):
    #: Stable identifier used as `MandateEnvelope.source`.
    SOURCE: ClassVar[str]

    #: True only when this adapter talks to a live API in this build.
    #: False means "mapper verified against fixtures". Say so in the README.
    WIRED: ClassVar[bool]

    @classmethod
    def normalise(cls, raw: dict) -> MandateEnvelope:
        """Map a native mandate to an envelope. Must not invent constraints."""
        ...
