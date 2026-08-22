#!/usr/bin/env python3
"""
Probe v2, part 2 of 2 -- the experiment.

Reads state.json, finds the minted token, then asks three questions:

  6. Does a debit UNDER max_amount succeed?          expect: yes
  7. Is a debit ABOVE max_amount rejected?           expect: yes (bank ceiling)
  8. Can we debit AT max_amount, over and over?      thesis: yes, unbounded

Step 8 is the whole argument. A mandate authorised for Rs 5.00 per debit,
drained N times with nothing objecting, is the finding. The closing line --
amount_debited versus max_amount -- is the pitch.

If step 7 does NOT reject, that is important and inconvenient: it would mean
test mode enforces nothing at all, so the numbers cannot come from here and
we would have to model the bank ourselves. Report it either way.
"""

import base64, json, os, ssl, sys, time, urllib.error, urllib.request

BASE = "https://api.razorpay.com/v1"
STATE = os.path.expanduser("~/Desktop/projects/mandate-gate/state.json")
DRAIN_ATTEMPTS = 6

KEY_ID = os.environ.get("RZP_KEY_ID", "")
KEY_SECRET = os.environ.get("RZP_KEY_SECRET", "")


def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
    )
    tok = base64.b64encode(f"{KEY_ID}:{KEY_SECRET}".encode()).decode()
    req.add_header("Authorization", f"Basic {tok}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(),
                                   timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:400]}
    except Exception as e:
        return 0, {"transport_error": str(e)}


def desc(p):
    e = p.get("error") or {}
    return " | ".join(x for x in (e.get("code"), e.get("description"),
                                  e.get("reason")) if x) or json.dumps(p)[:260]


if not KEY_ID.startswith("rzp_test_"):
    sys.exit("  Test mode only. Set RZP_KEY_ID to a rzp_test_ key.")
if not os.path.exists(STATE):
    sys.exit(f"  No state at {STATE}. Run probe2_authorize.py first.")

st = json.load(open(STATE))
customer_id = st["customer_id"]
MAX_AMOUNT = st["max_amount"]

print("\n" + "=" * 70)
print("  Probe v2 -- part 2: the drain experiment")
print("=" * 70)
print(f"\n  customer   : {customer_id}")
print(f"  max_amount : {MAX_AMOUNT} paise (Rs {MAX_AMOUNT/100:.2f}) per debit\n")

# ------------------------------------------------------------ find the token
status, toks = call("GET", f"/customers/{customer_id}/tokens")
items = toks.get("items") or []
if status != 200 or not items:
    print(f"  No token yet (HTTP {status}).")
    print("  Did the registration link actually complete with success@razorpay?")
    print(f"  Reopen: {st.get('short_url')}\n")
    sys.exit(1)

tok = items[0]
token_id = tok["id"]
print("  Token found:")
print("  " + json.dumps({
    "id": token_id,
    "max_amount": tok.get("max_amount"),
    "amount_debited": tok.get("amount_debited"),
    "frequency": tok.get("frequency"),
    "expired_at": tok.get("expired_at"),
    "recurring_status": (tok.get("recurring_details") or {}).get("status"),
}, indent=2).replace("\n", "\n  "))
print()


def debit(amount, label):
    st_, o = call("POST", "/orders", {
        "amount": amount, "currency": "INR",
        "receipt": f"mg-{label}-{int(time.time())}", "payment_capture": 0,
    })
    if st_ not in (200, 201):
        return False, f"order rejected: {desc(o)}"
    st_, p = call("POST", "/payments/create/recurring", {
        "amount": amount, "currency": "INR",
        "order_id": o["id"], "customer_id": customer_id, "token": token_id,
        "recurring": "1", "contact": "9000090000",
        "email": f"probe+{st['created_at']}@example.com",
        "description": f"mandate-gate {label}",
    })
    ok = st_ in (200, 201)
    return ok, (f"payment={p.get('razorpay_payment_id') or p.get('id')}"
                if ok else f"HTTP {st_} -- {desc(p)}")


results = []

# ---------------------------------------------- 6. under the ceiling
ok, d = debit(max(MAX_AMOUNT - 100, 100), "under")
print(f"  [{'pass' if ok else 'FAIL'}] 6. debit below max_amount")
print(f"         {d}")
results.append(("6. debit below ceiling succeeds", ok))

# ---------------------------------------------- 7. above the ceiling
ok, d = debit(MAX_AMOUNT * 3, "over")
rejected = not ok
print(f"\n  [{'pass' if rejected else 'FAIL'}] 7. debit ABOVE max_amount rejected")
print(f"         {d}")
if not rejected:
    print("         *** test mode enforces NOTHING -- see the note in the header ***")
results.append(("7. debit above ceiling rejected", rejected))

# ---------------------------------------------- 8. the experiment
print("\n" + "-" * 70)
print(f"  CENTRAL EXPERIMENT: {DRAIN_ATTEMPTS} debits AT max_amount")
print("  Thesis: every one succeeds. No cumulative cap. No velocity brake.")
print("-" * 70)

succeeded = 0
for i in range(1, DRAIN_ATTEMPTS + 1):
    ok, d = debit(MAX_AMOUNT, f"drain{i}")
    succeeded += ok
    print(f"    {i}/{DRAIN_ATTEMPTS}  {'ok  ' if ok else 'STOP'}  {d}")
    if not ok:
        print("\n    >>> Something stopped us here. That error names the ONLY")
        print("        brake that exists. The project then scopes itself around")
        print("        whatever that brake does not cover. Still a finding.")
        break
    time.sleep(1)

drained = succeeded * MAX_AMOUNT
results.append((f"8. drained {succeeded}/{DRAIN_ATTEMPTS} at ceiling",
                succeeded == DRAIN_ATTEMPTS))

status, tok2 = call("GET", f"/customers/{customer_id}/tokens/{token_id}")

print("\n" + "=" * 70)
print("  SUMMARY")
print("=" * 70)
for label, ok in results:
    print(f"  {'pass' if ok else 'FAIL'}  {label}")

print(f"\n  Authorised : Rs {MAX_AMOUNT/100:.2f} per debit")
print(f"  Extracted  : Rs {drained/100:.2f} across {succeeded} debits")
if status == 200:
    ad = tok2.get("amount_debited")
    print(f"  Token now  : amount_debited={ad}  max_amount={tok2.get('max_amount')}")
    if isinstance(ad, int) and ad > MAX_AMOUNT:
        print(f"\n  >>> amount_debited is {ad/MAX_AMOUNT:.1f}x the authorised ceiling.")
        print("      Nothing in the stack objected. That is the finding.")
print()
