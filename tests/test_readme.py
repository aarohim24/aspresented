"""
The README's quickstart is executed here.

Every other number in the README is generated -- the coverage table by
`gen_coverage.py`, the figure by `gen_hero.py`, the scores by the harness. The
integration snippet was the one claim a reader could act on that nothing
checked, which is the most expensive kind of documentation to get wrong: a
coverage table that drifts embarrasses the author, an API example that drifts
wastes the reader's afternoon.

So the block is extracted from the README, executed, and its output compared
against the output the README prints beneath it. Renaming a parameter without
updating the docs now fails CI.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
import unittest
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def _quickstart() -> tuple:
    """The python block under `## Quickstart`, and the output block after it."""
    text = README.read_text()
    start = text.index("## Quickstart")
    end = text.index("\n## ", start + 1)
    section = text[start:end]

    _, _, rest = section.partition("```python\n")
    code, _, rest = rest.partition("```")
    _, _, rest = rest.partition("```\n")
    expected, _, _ = rest.partition("```")
    if not code.strip() or not expected.strip():
        raise AssertionError(
            "the Quickstart section must hold a ```python block followed by a "
            "plain block of its output -- one of them is missing")
    return code, expected


class TestGeneratedBlocksMatchTheirGenerators(unittest.TestCase):
    """
    `gen_coverage.py` prints the coverage table; the README holds a copy. CI ran
    the generator but never compared the two, so "the table is generated, not
    typed" was itself an unchecked claim -- exactly the shape of defect this
    project keeps finding in its own code. Compared here instead.
    """

    def test_the_coverage_table_is_the_generated_one(self):
        import subprocess
        import sys

        root = README.parent
        generated = subprocess.run(
            [sys.executable, "tools/gen_coverage.py"], cwd=root,
            capture_output=True, text=True, check=True).stdout
        rows = [ln for ln in generated.splitlines() if ln.startswith("| ")]
        self.assertGreater(len(rows), 5, "generator produced no table")

        readme = README.read_text()
        for row in rows:
            self.assertIn(row, readme,
                          "the README coverage table has drifted from "
                          "tools/gen_coverage.py -- regenerate it")


class TestPublishedNumbersStillReproduce(unittest.TestCase):
    """
    "Every number in this README is reproducible" was true and unchecked, so it
    stopped being true quietly: the scenario set grew when the per-charge
    ceiling gained its boundary cases, and the published false-decline
    denominator, recall counts and blocked value were all stale by the time
    anyone looked. The same happened to the fuzzer's refusal-code coverage,
    which read 9/9 after a tenth code existed.

    Both tools are seeded and take under a second, so there is no reason for
    their headline numbers to live in prose unchecked.
    """

    @staticmethod
    def _run(tool: str) -> str:
        import subprocess
        import sys

        return subprocess.run([sys.executable, f"tools/{tool}"],
                              cwd=README.parent, capture_output=True,
                              text=True, check=True).stdout

    @staticmethod
    def _flat(text: str) -> str:
        return " ".join(text.split())

    def test_harness_headline_numbers_are_the_published_ones(self):
        out = self._run("run_harness.py")
        readme = self._flat(README.read_text())
        for key in ("False-decline rate", "Abuse recall",
                    "Caught by policy/rail", "Value blocked"):
            line = next((ln for ln in out.splitlines() if key in ln), None)
            self.assertIsNotNone(line, f"harness no longer reports {key!r}")
            self.assertIn(self._flat(line), readme,
                          f"the README's {key!r} has drifted from the harness "
                          f"-- it now reports: {self._flat(line)!r}")

    def test_sweep_table_and_code_coverage_are_the_published_ones(self):
        out = self._run("run_attack.py")
        readme = self._flat(README.read_text())

        rows = [ln for ln in out.splitlines()
                if re.match(r"\s+\d+s\s+\d+\s", ln)]
        self.assertEqual(len(rows), 5, "the sweep no longer runs five tempos")
        for row in rows:
            self.assertIn(self._flat(row), readme,
                          f"a sweep row has drifted: {self._flat(row)!r}")

        codes = next((ln for ln in out.splitlines()
                      if "refusal codes reached" in ln), None)
        self.assertIsNotNone(codes)
        self.assertIn(self._flat(codes), readme,
                      f"refusal-code coverage has drifted: "
                      f"{self._flat(codes)!r}")


class TestQuickstartRuns(unittest.TestCase):
    def test_the_readme_snippet_executes_and_prints_what_it_claims(self):
        code, expected = _quickstart()
        buffer = io.StringIO()
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            # The snippet writes decisions.jsonl relative to the working
            # directory, exactly as a reader pasting it would. Run it somewhere
            # disposable rather than editing the snippet to suit the test.
            os.chdir(tmp)
            try:
                with contextlib.redirect_stdout(buffer):
                    exec(compile(code, "README.md#quickstart", "exec"), {})
            finally:
                os.chdir(cwd)

        self.assertEqual(buffer.getvalue().strip(), expected.strip())

    def test_the_snippet_leaves_a_verifiable_ledger(self):
        """
        The prose claims the run leaves a hash-chained record of all five
        decisions. Claimed in the README, so asserted here.
        """
        from mandate_gate.ledger import Ledger

        code, _ = _quickstart()
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    exec(compile(code, "README.md#quickstart", "exec"), {})
                ledger = Ledger(os.path.join(tmp, "decisions.jsonl"))
                entries = list(ledger.entries())
            finally:
                os.chdir(cwd)

        ledger.verify()                       # raises BrokenChain if it does not
        decisions = [e for e in entries if e.kind == "decision"]
        self.assertEqual(len(decisions), 5)


if __name__ == "__main__":
    unittest.main()
