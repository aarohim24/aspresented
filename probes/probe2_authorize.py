#!/usr/bin/env python3
"""
Probe v2, part 1 of 2 -- mint one mandate token.

S2S (/payments/create/upi) is gated on a fresh account: it answers
"The requested URL was not found on the server". The registration-link path
is not gated. It needs one human click, once, and then every interesting
call is pure API.

Order of business:
  A. Does /payments/create/recurring even EXIST for this account?
     Probed with deliberately-invalid data. A route-not-found means stop now,
     before spending a click. A validation complaint means the route is live.
  B. Create customer + registration link. Print the URL.
  C. You open it, pay with success@razorpay, and run probe2_drain.py.

Notifications are explicitly disabled -- no SMS or email goes anywhere.
"""

import base64, json, os, ssl, sys, time, urllib.error, urllib.request

BASE = "https://api.razorpay.com/v1"
STATE = os.path.expanduser("~/Desktop/projects/mandate-gate/state.json")
MAX_AMOUNT = 500        # paise -- Rs 5.00 per-debit ceiling
AUTH_AMOUNT = 100       # paise -- token-registration charge

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
                                  e.get("reason")) if x) or json.dumps(p)[:300]


def route_missing(p):
    """Razorpay signals a disabled/absent route with this phrasing."""
    return "requested URL was not found" in json.dumps(p)


print("\n" + "=" * 70)
print("  Probe v2 -- part 1: mint a mandate token")
print("=" * 70 + "\n")

if not KEY_ID.startswith("rzp_test_"):
    sys.exit("  Refusing to run outside test mode. Set RZP_KEY_ID to a rzp_test_ key.")

# ---------------------------------------------------------------- STEP A
print("  A. Is the debit route available on this account?")
print("     (probing /payments/create/recurring with invalid data on purpose)\n")

status, resp = call("POST", "/payments/create/recurring", {
    "amount": 100, "currency": "INR",
    "order_id": "order_probe_invalid", "customer_id": "cust_probe_invalid",
    "token": "token_probe_invalid", "recurring": "1",
    "contact": "9000090000", "email": "probe@example.com",
})

if route_missing(resp):
    print("     [FAIL] route not found -- subsequent debits are gated too.\n")
    print("     Do NOT spend a browser click. The whole recurring surface is")
    print("     off for this account. Two options, in order of preference:")
    print("       1. Dashboard -> Account & Settings -> request Recurring")
    print("          Payments / UPI Autopay. Free, usually same-day on test.")
    print("       2. Tell me and we pivot the substrate. The thesis survives --")
    print("          it is about mandate vocabulary, not this one endpoint.\n")
    sys.exit(1)

print(f"     [pass] route is live (HTTP {status}, rejected our fake ids as expected)")
print(f"            {desc(resp)}\n")

# ---------------------------------------------------------------- STEP B
stamp = int(time.time())
expire_at = stamp + 60 * 60 * 24 * 30

print("  B. Creating registration link\n")

link = None
used_frequency = None
for freq in ("as_presented", "monthly"):
    status, resp = call("POST", "/subscriptions/registration", {
        "customer": {
            "name": "Mandate Gate Probe",
            "email": f"probe+{stamp}@example.com",
            "contact": "9000090000",
        },
        "type": "link",
        "amount": AUTH_AMOUNT,
        "currency": "INR",
        "description": "Mandate Gate probe registration",
        "subscription_registration": {
            "method": "upi",
            "max_amount": MAX_AMOUNT,
            "expire_at": expire_at,
            "frequency": freq,
        },
        "receipt": f"mg-probe-{stamp}",
        "sms_notify": 0,          # do not text a fake number
        "email_notify": 0,        # do not email anyone
        "expire_by": stamp + 60 * 60 * 24,
    })
    if status in (200, 201) and (resp.get("short_url") or resp.get("id")):
        link, used_frequency = resp, freq
        print(f"     [pass] created with frequency={freq}")
        break
    print(f"     [fail] frequency={freq}: HTTP {status} -- {desc(resp)}")

if not link:
    print("\n     Both frequencies rejected. Paste the errors to me verbatim.\n")
    sys.exit(1)

customer_id = (link.get("customer_id")
               or (link.get("customer") or {}).get("id"))

state = {
    "created_at": stamp,
    "customer_id": customer_id,
    "invoice_id": link.get("id"),
    "short_url": link.get("short_url"),
    "max_amount": MAX_AMOUNT,
    "frequency": used_frequency,
    "expire_at": expire_at,
}
with open(STATE, "w") as f:
    json.dump(state, f, indent=2)

print(f"\n     customer_id : {customer_id}")
print(f"     invoice_id  : {link.get('id')}")
print(f"     max_amount  : {MAX_AMOUNT} paise (Rs {MAX_AMOUNT/100:.2f}) per debit")
print(f"     frequency   : {used_frequency}")
print(f"     state saved : {STATE}")

print("\n" + "=" * 70)
print("  C. ONE MANUAL STEP")
print("=" * 70)
print(f"\n  Open this URL:\n\n     {link.get('short_url')}\n")
print("  Then, on the Razorpay page:")
print("     - choose UPI")
print("     - enter VPA:  success@razorpay")
print("     - any random UPI PIN if it asks")
print("\n  That mints the mandate token. Then run:\n")
print("     python3 ~/Desktop/projects/mandate-gate/probe2_drain.py\n")
