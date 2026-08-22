"""Adversarial harness: labelled traffic, held-out scoring, integrity checks."""

from .metrics import Report, score
from .runner import run
from .scenarios import (ABUSE_CLASSES, BOUNDARY_SESSIONS, POLICY, RAIL,
                        build_sessions)

__all__ = ["ABUSE_CLASSES", "BOUNDARY_SESSIONS", "POLICY", "RAIL",
           "build_sessions", "run", "score", "Report"]
