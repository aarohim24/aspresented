---
name: delegated-authority
description: Rules for as-presented's Authority, caveats and attenuation. Use when editing mandate_gate/authority.py, adding a caveat kind, or changing how authority folds into limits. Covers why narrowing needs no secret, the three ways widening must fail, the trust model this does and does not establish, and why the gate was left untouched.
---

# Delegated authority

A mandate is a flat grant. An `Authority` is a chain of caveats over one, signed
by chaining HMACs the way macaroons do, so that a holder can pass on *less*.

That exists because agents subcontract. The alternative -- and the state of
practice -- is handing a sub-agent the whole credential.

## The two properties, and how they are achieved

**Narrowing needs no secret.** `_link` keys each new signature on the previous
signature, not on the root secret. That is the whole trick and the reason
delegation can happen offline, mid-task, with no round trip to the principal.
Do not change `_link` to take the root secret; it would make attenuation
impossible and the feature pointless.

**Widening must fail three ways**, and all three need to keep working:

1. *Append a looser caveat* -- inert, because `to_limits` folds by taking the
   tighter value. This is the one that verifies and still does nothing.
2. *Remove a caveat* -- the chain no longer verifies.
3. *Edit a caveat* -- the chain no longer verifies.

Only the first depends on `to_limits`. If you add a caveat kind whose folding
takes the *looser* value, or replaces rather than intersects, you have created a
widening path with a valid signature. That is the single most dangerous edit
available in this file.

## Adding a caveat kind

Four things, all in the same commit:

- an entry in `CAVEAT_KINDS` mapping it to a `Limits` field -- a caveat that
  maps to no limit is a restriction that silently does nothing, and `Caveat`
  raises on an unknown kind for exactly that reason
- a fold branch in `to_limits` that **narrows**: `_tighter` for numbers,
  `Scope.intersect` for scopes, lowest rate for windows
- a gate check that enforces the underlying limit, if one does not already
  exist. `per_charge_max` sat in `effective` for weeks, computed correctly and
  consulted by nothing -- a policy limit with no check is worse than no limit,
  because it reads as protection
- a case in `test_every_caveat_kind_folds_into_a_limit`, which fails if a kind
  constrains nothing

## The trust model, and not overstating it

Verification needs the root secret. So:

- **Established:** a holder downstream cannot widen what it was given, cannot
  strip a restriction, and cannot edit one.
- **Not established:** that the party verifying did not forge the authority
  outright. A merchant holding the root secret can mint anything.

Closing that means asymmetric signing -- the principal signs with a private key,
everyone else verifies with the public one. It is named in the module docstring,
in the README, and asserted by `TestTheTrustModelIsStated`, which fails if the
docstring stops saying so. Do not let the claim drift wider than the mechanism.

## Why the gate was not touched

Authority folds into `Limits`, and limits are what the gate already enforces.
Where limits come from is a separate question from how they are enforced, which
is why `admit` lives outside the gate.

Keep it that way. Putting authority verification inside the gate would couple
enforcement to a credential format, and the next credential format would then
need gate surgery instead of an adapter.
