"""
Scoring.

The false-decline rate leads every report. A gate that refuses honest traffic
is worse than no gate: it costs real revenue to prevent a hypothetical loss.
Recall is the easy number to move and the easy one to cheat, so it comes
second, broken out per class with the weak classes named rather than averaged
away.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Outcome:
    label: str
    expected_code: str | None
    allowed: bool
    codes: tuple
    refused_by: str | None
    amount: int
    replayed: bool = False


@dataclass
class ClassScore:
    label: str
    total: int = 0
    caught: int = 0
    attributed: int = 0            # caught for the expected reason
    amount_blocked: int = 0

    @property
    def recall(self) -> float:
        return self.caught / self.total if self.total else 0.0

    @property
    def attribution(self) -> float:
        return self.attributed / self.caught if self.caught else 0.0


@dataclass
class Report:
    honest_total: int = 0
    honest_refused: int = 0
    honest_refusal_codes: dict = field(default_factory=dict)
    classes: dict = field(default_factory=dict)
    rail_catches: int = 0
    policy_catches: int = 0

    @property
    def false_decline_rate(self) -> float:
        return (self.honest_refused / self.honest_total
                if self.honest_total else 0.0)

    @property
    def abusive_total(self) -> int:
        return sum(c.total for c in self.classes.values())

    @property
    def abusive_caught(self) -> int:
        return sum(c.caught for c in self.classes.values())

    @property
    def recall(self) -> float:
        return (self.abusive_caught / self.abusive_total
                if self.abusive_total else 0.0)

    @property
    def amount_blocked(self) -> int:
        return sum(c.amount_blocked for c in self.classes.values())

    def weak_classes(self, threshold: float = 0.9) -> list:
        return sorted(
            (c.label for c in self.classes.values() if c.recall < threshold))


def score(outcomes) -> Report:
    report = Report()
    for o in outcomes:
        if o.label == "honest":
            report.honest_total += 1
            if not o.allowed:
                report.honest_refused += 1
                for code in (o.codes or (o.refused_by or "rail",)):
                    report.honest_refusal_codes[code] = \
                        report.honest_refusal_codes.get(code, 0) + 1
            continue

        cls = report.classes.setdefault(o.label, ClassScore(label=o.label))
        cls.total += 1
        if not o.allowed:
            cls.caught += 1
            cls.amount_blocked += o.amount
            if o.expected_code is None or o.expected_code in o.codes:
                cls.attributed += 1
            if o.refused_by == "rail":
                report.rail_catches += 1
            else:
                report.policy_catches += 1
    return report


def render(report: Report, title: str = "RESULTS") -> str:
    lines = [f"  {title}", "  " + "-" * 66]

    lines.append(f"  False-decline rate      "
                 f"{report.false_decline_rate:6.2%}   "
                 f"({report.honest_refused}/{report.honest_total} honest "
                 f"charges refused)")
    if report.honest_refusal_codes:
        for code, n in sorted(report.honest_refusal_codes.items(),
                              key=lambda kv: -kv[1]):
            lines.append(f"      caused by {code}: {n}")

    lines.append(f"  Abuse recall            {report.recall:6.2%}   "
                 f"({report.abusive_caught}/{report.abusive_total} refused)")
    lines.append(f"  Caught by policy/rail   "
                 f"{report.policy_catches}/{report.rail_catches}")
    lines.append(f"  Value blocked           "
                 f"Rs {report.amount_blocked / 100:,.2f}")
    lines.append("")
    lines.append(f"  {'abuse class':<32}{'recall':>9}{'attributed':>12}")
    lines.append("  " + "-" * 66)
    for label in sorted(report.classes):
        c = report.classes[label]
        lines.append(f"  {label:<32}{c.recall:>8.0%}{c.attribution:>12.0%}")

    weak = report.weak_classes()
    lines.append("")
    if weak:
        lines.append(f"  Classes below 90% recall: {', '.join(weak)}")
    else:
        lines.append("  No class below 90% recall.")
    return "\n".join(lines)
