#!/usr/bin/env python3
"""
Go/no-go probe for Razorpay recurring-token substrate.

Answers, in order:
  1. Do test keys authenticate?
  2. Can we create a customer?
  3. Can we create an order carrying a `token` object (mandate) --
     or does it 400 with "recurring not enabled"?          <-- THE activation question
  4. Does the mocked authorization succeed with success@razorpay?
  5. Does a token come back, and what does it expose?
  6. Can we debit under max_amount?
  7. Is a debit ABOVE max_amount rejected?                  <-- per-debit ceiling: expected PASS
  8. Can we debit at max_amount repeatedly, unbounded?      <-- THE CENTRAL EXPERIMENT

Step 8 is the thesis. If N debits at the ceiling all succeed with no cumulative
brake, the gap is real and measured. If something stops us, we learn what and the
project pivots to whatever that mechanism fails to cover. Either outcome is useful.

Usage:
  export RZP_KEY_ID=rzp_test_xxxx
  export RZP_KEY_SECRET=xxxx
  python3 probe.py
"""

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

BASE = "https://api.razorpay.com/v1"
MAX_AMOUNT = 500          # paise -- Rs 5.00 per-debit ceiling
DEBIT_AMOUNT = 500        # paise -- debit AT the ceiling
DRAIN_ATTEMPTS = 6        # how many times to try draining at the ceiling

KEY_ID = os.environ.get("RZP_KEY_ID", "")
KEY_SECRET = os.environ.get("RZP_KEY_SECRET", "")

results = []


def fail(msg):
    print(f"\n  STOP: {msg}\n")
    summary()
    sys.exit(1)


def record(step, ok, detail):
    results.append((step, ok, detail))
    mark = "pass" if ok else "FAIL"
    print(f"  [{mark}] {step}")
    if detail:
        print(f"         {detail}")


def call(method, path, body=None):
    """Returns (status, parsed_json). Never raises on HTTP error -- we want the error."""
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    token = base64.b64encode(f"{KEY_ID}:{KEY_SECRET}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:400]}
    except Exception as e:                                    # network, TLS, DNS
        return 0, {"transport_error": str(e)}


def err_desc(payload):
    e = payload.get("error") or {}
    bits = [e.get("code"), e.get("description"), e.get("reason")]
    return " | ".join(b for b in bits if b) or json.dumps(payload)[:300]


def summary():
    print("\n" + "=" * 68)
    print("  SUMMARY")
    print("=" * 68)
    for step, ok, detail in results:
        print(f"  {'pass' if ok else 'FAIL'}  {step}")
    print()


# ---------------------------------------------------------------- preflight
print("\n" + "=" * 68)
print("  Razorpay recurring-token substrate probe")
print("=" * 68 + "\n")

if not KEY_ID or not KEY_SECRET:
    fail("Set RZP_KEY_ID and RZP_KEY_SECRET first.")
if not KEY_ID.startswith("rzp_test_"):
    fail(f"Refusing to run: {KEY_ID[:12]}... is not a rzp_test_ key. Test mode only.")

# ------------------------------------------------------- 1. authentication
status, payload = call("GET", "/payments?count=1")
if status != 200:
    record("1. authenticate", False, f"HTTP {status} -- {err_desc(payload)}")
    fail("Keys rejected. Check the key id/secret pair from the test-mode dashboard.")
record("1. authenticate", True, "test keys accepted")

# ------------------------------------------------------- 2. create customer
stamp = int(time.time())
status, cust = call("POST", "/customers", {
    "name": "Mandate Gate Probe",
    "contact": "9000090000",
    "email": f"probe+{stamp}@example.com",
    "fail_existing": 0,
})
if status not in (200, 201) or not cust.get("id"):
    record("2. create customer", False, f"HTTP {status} -- {err_desc(cust)}")
    fail("Cannot create a customer; nothing downstream will work.")
customer_id = cust["id"]
record("2. create customer", True, customer_id)

# ------------------------------- 3. mandate order (THE activation question)
expire_at = stamp + 60 * 60 * 24 * 30          # 30 days out

# Variant A: SBMD shape, straight from PR #88.
order_body_sbmd = {
    "amount": MAX_AMOUNT,
    "currency": "INR",
    "customer_id": customer_id,
    "method": "upi",
    "receipt": f"probe-sbmd-{stamp}",
    "token": {
        "max_amount": MAX_AMOUNT,
        "expire_at": expire_at,
        "frequency": "as_presented",
        "type": "single_block_multiple_debit",
    },
}
# Variant B: plain UPI Autopay mandate -- no `type`.
order_body_autopay = {
    "amount": MAX_AMOUNT,
    "currency": "INR",
    "customer_id": customer_id,
    "method": "upi",
    "receipt": f"probe-autopay-{stamp}",
    "token": {
        "max_amount": MAX_AMOUNT,
        "expire_at": expire_at,
        "frequency": "as_presented",
    },
}

order_id = None
variant = None
for name, body in (("SBMD (token.type set)", order_body_sbmd),
                   ("UPI Autopay (no token.type)", order_body_autopay)):
    status, order = call("POST", "/orders", body)
    if status in (200, 201) and order.get("id"):
        order_id, variant = order["id"], name
        record(f"3. mandate order -- {name}", True, order_id)
        break
    record(f"3. mandate order -- {name}", False, f"HTTP {status} -- {err_desc(order)}")

if not order_id:
    fail("Neither mandate shape was accepted. Read the two errors above:\n"
         "         - 'not enabled'/'not allowed' => account activation needed. Ask support,\n"
         "           and meanwhile consider a different substrate.\n"
         "         - a field/validation complaint => the shape is wrong, not the account.")

# ------------------------------------------ 4. authorization (mocked in test)
status, auth = call("POST", "/payments/create/upi", {
    "amount": MAX_AMOUNT,
    "currency": "INR",
    "order_id": order_id,
    "customer_id": customer_id,
    "email": f"probe+{stamp}@example.com",
    "contact": "9000090000",
    "method": "upi",
    "recurring": "1",
    "upi": {"flow": "collect", "vpa": "success@razorpay"},
})
if status not in (200, 201):
    record("4. authorization payment", False, f"HTTP {status} -- {err_desc(auth)}")
    print("\n         Not necessarily fatal: the intent flow returns a URL/QR instead.")
    print("         Retry with upi.flow='intent' if the error names the flow.\n")
else:
    record("4. authorization payment", True,
           f"payment_id={auth.get('razorpay_payment_id') or auth.get('id')}")

# ------------------------------------------------- 5. did a token get created?
print("\n  ...waiting 6s for token.confirmed to settle\n")
time.sleep(6)

status, toks = call("GET", f"/customers/{customer_id}/tokens")
token_id = None
if status == 200 and toks.get("items"):
    tok = toks["items"][0]
    token_id = tok.get("id")
    record("5. token created", True, json.dumps({
        "id": token_id,
        "max_amount": tok.get("max_amount"),
        "amount_debited": tok.get("amount_debited"),
        "frequency": tok.get("frequency"),
        "expired_at": tok.get("expired_at"),
        "recurring": tok.get("recurring"),
    }))
else:
    record("5. token created", False, f"HTTP {status} -- no tokens on customer")
    fail("No mandate token. In test mode auth is mocked, so this usually means the\n"
         "         authorization call above did not actually complete. Fix step 4 first.")


def debit(amount, label):
    """One debit: fresh order, then recurring payment against the token."""
    st, o = call("POST", "/orders", {
        "amount": amount, "currency": "INR",
        "receipt": f"debit-{label}-{int(time.time())}", "payment_capture": 0,
    })
    if st not in (200, 201):
        return False, f"order rejected: {err_desc(o)}"
    st, p = call("POST", "/payments/create/recurring", {
        "amount": amount, "currency": "INR",
        "order_id": o["id"], "customer_id": customer_id, "token": token_id,
        "recurring": "1", "contact": "9000090000",
        "email": f"probe+{stamp}@example.com",
        "description": f"probe debit {label}",
    })
    ok = st in (200, 201)
    return ok, (f"payment_id={p.get('razorpay_payment_id') or p.get('id')}"
                if ok else f"HTTP {st} -- {err_desc(p)}")

# ------------------------------------------------- 6. debit under the ceiling
ok, detail = debit(MAX_AMOUNT - 100, "under-ceiling")
record("6. debit below max_amount", ok, detail)

# --------------------------------- 7. debit above ceiling -- expected REJECT
ok, detail = debit(MAX_AMOUNT * 3, "over-ceiling")
record("7. debit ABOVE max_amount is rejected", (not ok),
       "correctly rejected -- " + detail if not ok
       else "*** ACCEPTED -- the per-debit ceiling is not enforced either ***")

# -------------------------------------- 8. THE EXPERIMENT: drain the ceiling
print("\n" + "-" * 68)
print(f"  CENTRAL EXPERIMENT: {DRAIN_ATTEMPTS} debits at max_amount ({MAX_AMOUNT} paise)")
print("  Thesis: all succeed. No cumulative cap, no velocity brake.")
print("-" * 68)

succeeded = 0
for i in range(1, DRAIN_ATTEMPTS + 1):
    ok, detail = debit(DEBIT_AMOUNT, f"drain-{i}")
    succeeded += ok
    print(f"    debit {i}/{DRAIN_ATTEMPTS}: {'ok  ' if ok else 'STOP'}  {detail}")
    if not ok:
        print(f"\n    >>> Something stopped us at attempt {i}. Read that error --")
        print("        it names the only brake that exists, and the project scopes")
        print("        itself around whatever that brake does NOT cover.")
        break
    time.sleep(1)

total = succeeded * DEBIT_AMOUNT
record(f"8. drained {succeeded}/{DRAIN_ATTEMPTS} debits at ceiling",
       succeeded == DRAIN_ATTEMPTS,
       f"Rs {total/100:.2f} extracted from a mandate authorised for "
       f"Rs {MAX_AMOUNT/100:.2f} per debit"
       + ("  <-- THESIS CONFIRMED" if succeeded == DRAIN_ATTEMPTS else ""))

status, tok = call("GET", f"/customers/{customer_id}/tokens/{token_id}")
if status == 200:
    print(f"\n  Final token state: amount_debited="
          f"{tok.get('amount_debited')}  max_amount={tok.get('max_amount')}")
    print("  If amount_debited far exceeds max_amount with nothing objecting,")
    print("  that single line is your pitch.\n")

summary()
print("  Next: if step 3 and step 8 both passed, the substrate holds -- build.")
print("  If step 3 failed on activation, tell me the exact error and we pivot.\n")
