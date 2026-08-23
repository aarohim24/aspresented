#!/usr/bin/env python3
"""
Generate the README figure: what the rail alone permits, and what the gate does.

    python3 tools/gen_hero.py          # writes docs/hero.svg

The console's hero animates this argument, and until now the argument was
invisible to anyone who read the repository instead of running it -- which is
everyone, first. So the same thing is emitted as a static figure.

It is a measurement, not an illustration. Both rows come from actually charging
a rail and a gate here in this script; nothing about the geometry is typed in
by hand, and CI regenerates it to catch drift. If the gate ever stopped holding
the cap, this figure would change shape rather than keep flattering it.

An SVG rather than a recorded GIF: no binary blob in the history, regenerable,
and diffable. It paints its own dark ground so it reads identically on GitHub's
light and dark themes -- a transparent figure would be unreadable on one of them.
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mandate_gate.adapters.razorpay_upi import RazorpayUpiAdapter   # noqa: E402
from mandate_gate.charge import ChargeRequest, Intent               # noqa: E402
from mandate_gate.envelope import Limits                            # noqa: E402
from mandate_gate.fixtures import RAZORPAY_AS_PRESENTED             # noqa: E402
from mandate_gate.gate import Gate                                  # noqa: E402
from mandate_gate.ledger import Ledger                              # noqa: E402
from mandate_gate.rail import RailSimulator                          # noqa: E402

OUT = ROOT / "docs" / "hero.svg"

#: The merchant's cap -- the constraint no rail has a field for.
CUMULATIVE_MAX = 2000
#: Charges are spaced past the duplicate window on purpose. An agent looping
#: over an hour is the realistic shape, and it means DUPLICATE_CHARGE (hygiene,
#: not a control) does not stand in for the cap and take credit for it.
SPACING = 600

# Palette lifted from the console, so the figure and the page are one design.
GROUND, PANEL, LINE = "#08080A", "#0F1013", "#22242B"
INK, DIM, FAINT = "#F2F3F6", "#9A9FAC", "#636875"
VOLT, MINT, ROSE = "#5B6BFF", "#3DD9A4", "#FF6B76"
SANS = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,sans-serif"
MONO = "ui-monospace,Menlo,SF Mono,Consolas,monospace"


def rupees(paise: int) -> str:
    return f"₹{paise / 100:.2f}"


def measure():
    """Run the same charges twice: once at the rail, once through the gate."""
    envelope = RazorpayUpiAdapter.normalise(RAZORPAY_AS_PRESENTED)
    ceiling = envelope.rail.per_charge_max
    # Enough charges at the ceiling to overrun the cap, plus two past it, so the
    # figure shows the refusals rather than merely ending.
    count = -(-CUMULATIVE_MAX // ceiling) + 2
    t0 = envelope.rail.expires_at - 30 * 86400

    # --- the rail alone: exactly the enforcement Razorpay documents
    rail = RailSimulator(limits=envelope.rail)
    rail_row = []
    for i in range(count):
        ok, _ = rail.charge(ceiling, t0 + i * SPACING)
        rail_row.append(ok)

    # --- the same traffic through the gate, with a policy cap attached
    clock = {"now": t0}
    policy = envelope.with_policy(Limits(cumulative_max=CUMULATIVE_MAX))
    gate = Gate(policy,
                Ledger(os.path.join(tempfile.mkdtemp(), "hero.jsonl"),
                       clock=lambda: clock["now"]),
                RailSimulator(limits=policy.rail),
                b"gen-hero-figure-only",
                clock=lambda: clock["now"])
    intent = gate.record_intent(Intent(
        intent_id="int_hero", mandate_id=policy.mandate_id,
        max_amount=ceiling, expires_at=t0 + 30 * 86400))
    gate_row = []
    for i in range(count):
        clock["now"] = t0 + i * SPACING
        d = gate.authorize(ChargeRequest(
            mandate_id=policy.mandate_id, amount=ceiling,
            idempotency_key=f"hero-{i}", intent_id=intent.intent_id))
        gate_row.append(d.allowed)

    return ceiling, count, rail_row, gate_row


def bar(x, y, w, h, allowed, colour):
    if allowed:
        return (f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{h}" rx="2" '
                f'fill="{colour}"/>')
    # Refused charges are drawn as the space they would have taken: the point is
    # that the agent asked, not that nothing happened.
    return (f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{h}" rx="2" '
            f'fill="none" stroke="{ROSE}" stroke-width="1.5" '
            f'stroke-dasharray="4 3"/>')


def row(label, note, note_colour, y, per, count, flags, colour, span, cap_x):
    """One track: the label, the bars, and the total it reached."""
    out = [f'<text x="40" y="{y - 14}" font-family="{MONO}" font-size="11" '
           f'fill="{DIM}" letter-spacing="0.08em">{label}</text>']
    gap = 3
    w = (span - gap * (count - 1)) / count
    for i, ok in enumerate(flags):
        out.append(bar(40 + i * (w + gap), y, w, 34, ok, colour))
    settled = sum(flags) * per
    out.append(f'<text x="{40 + span + 18}" y="{y + 23}" font-family="{MONO}" '
               f'font-size="15" font-weight="600" fill="{note_colour}">'
               f'{rupees(settled)}</text>')
    out.append(f'<text x="40" y="{y + 56}" font-family="{SANS}" font-size="12" '
               f'fill="{FAINT}">{note}</text>')
    return out


def render() -> str:
    per, count, rail_row, gate_row = measure()
    W, H = 900, 350
    span = 560                                  # pixels for the rail's total
    overrun = count * per                       # what the rail let through
    cap_x = 40 + span * (CUMULATIVE_MAX / overrun)

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
         f'viewBox="0 0 {W} {H}" role="img" '
         f'aria-label="The rail alone settles {rupees(overrun)} against a '
         f'{rupees(CUMULATIVE_MAX)} authorised total. The gate stops at '
         f'{rupees(CUMULATIVE_MAX)}.">',
         f'<rect width="{W}" height="{H}" fill="{GROUND}"/>',
         f'<rect x="16" y="16" width="{W - 32}" height="{H - 32}" rx="6" '
         f'fill="{PANEL}" stroke="{LINE}"/>']

    s.append(f'<text x="40" y="54" font-family="{MONO}" font-size="10.5" '
             f'fill="{VOLT}" letter-spacing="0.14em">AS-PRESENTED</text>')
    s.append(f'<text x="40" y="86" font-family="{SANS}" font-size="19" '
             f'font-weight="600" fill="{INK}">'
             f'{count} charges of {rupees(per)}, each inside the mandate’s '
             f'per-charge ceiling.</text>')
    s.append(f'<text x="40" y="108" font-family="{SANS}" font-size="13" '
             f'fill="{DIM}">The mandate authorises {rupees(per)} at a time. It '
             f'has no field for a total.</text>')

    # The cap: a rule the rail cannot see and the gate will not cross. Labelled
    # above both rows -- a label between them reads as belonging to one of them.
    s.append(f'<line x1="{cap_x:.1f}" y1="150" x2="{cap_x:.1f}" y2="300" '
             f'stroke="{VOLT}" stroke-width="1.5" stroke-dasharray="3 3"/>')
    s.append(f'<text x="{cap_x + 8:.1f}" y="142" font-family="{MONO}" '
             f'font-size="10.5" fill="{VOLT}">authorised total '
             f'{rupees(CUMULATIVE_MAX)}</text>')

    s += row("THE RAIL ALONE", "Every charge is individually legitimate. "
             "Nothing objects.", ROSE, 172, per, count, rail_row, "#3A3F52",
             span, cap_x)
    s += row("WITH THE GATE", f"{rail_row.count(True) - gate_row.count(True)} "
             f"refused: CUMULATIVE_EXCEEDED. Same mandate, same charges.",
             MINT, 266, per, count, gate_row, VOLT, span, cap_x)

    s.append('</svg>')
    return "\n".join(s) + "\n"


def main() -> int:
    svg = render()
    OUT.parent.mkdir(exist_ok=True)
    previous = OUT.read_text() if OUT.exists() else None
    OUT.write_text(svg)
    if previous is not None and previous != svg:
        print(f"{OUT.relative_to(ROOT)} regenerated (it had drifted)")
    else:
        print(f"{OUT.relative_to(ROOT)} written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
