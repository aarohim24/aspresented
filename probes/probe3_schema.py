#!/usr/bin/env python3
"""
Probe v3 -- the schema probe. Needs no gated endpoint.

The thesis was never "you can drain a mandate." It is "there is nowhere in a
mandate to express a total cap, a rate, or a scope." That is a claim about the
schema, and /v1/orders validates the schema for free.

Method:
  1. Establish the baseline: does the documented SBMD token shape get accepted?
  2. For each constraint the vocabulary is missing, send the same mandate with
     that one extra field added, and classify the response:

       REJECTED         -> the vocabulary is closed and honest about it
       ACCEPTED+ECHOED  -> the field exists after all; thesis is wrong here
       ACCEPTED+DROPPED -> accepted, then silently discarded. The worst case:
                           an integrator believes they set a cap and did not.

  3. Read each order back and diff what we sent against what was stored.

Only creates orders. Orders move no money and expire on their own.
"""

import base64, json, os, ssl, sys, time, urllib.error, urllib.request

BASE = "https://api.razorpay.com/v1"
OUT = os.path.expanduser("~/Desktop/projects/mandate-gate/schema-findings.json")
MAX_AMOUNT = 500

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
                                  e.get("field"), e.get("reason")) if x) \
        or json.dumps(p)[:220]


if not KEY_ID.startswith("rzp_test_"):
    sys.exit("  Test mode only. Set RZP_KEY_ID to a rzp_test_ key.")

print("\n" + "=" * 74)
print("  Probe v3 -- can a Razorpay mandate express a total cap?")
print("=" * 74 + "\n")

stamp = int(time.time())
expire_at = stamp + 60 * 60 * 24 * 30

status, cust = call("POST", "/customers", {
    "name": "Schema Probe", "contact": "9000090000",
    "email": f"schema+{stamp}@example.com", "fail_existing": 0,
})
if not cust.get("id"):
    sys.exit(f"  Cannot create customer: {desc(cust)}")
customer_id = cust["id"]
print(f"  customer: {customer_id}\n")


def mandate_order(extra_token_fields, label):
    token = {
        "max_amount": MAX_AMOUNT,
        "expire_at": expire_at,
        "frequency": "as_presented",
        "type": "single_block_multiple_debit",
    }
    token.update(extra_token_fields)
    body = {
        "amount": MAX_AMOUNT, "currency": "INR",
        "customer_id": customer_id, "method": "upi",
        "receipt": f"schema-{label}-{stamp}",
        "token": token,
    }
    status, resp = call("POST", "/orders", body)
    return status, resp, token


# ------------------------------------------------------------- 1. baseline
print("  1. BASELINE -- documented SBMD shape\n")
status, resp, sent = mandate_order({}, "baseline")
if status not in (200, 201):
    print(f"     [FAIL] baseline rejected: {desc(resp)}")
    sys.exit("\n  If the documented shape is refused, stop and tell me.\n")

order_id = resp["id"]
stored = resp.get("token") or {}
print(f"     [pass] accepted -> {order_id}")
print(f"     sent  : {json.dumps(sent)}")
print(f"     stored: {json.dumps(stored)}")
missing_baseline = [k for k in sent if k not in stored]
if missing_baseline:
    print(f"     note  : even documented fields not echoed back: {missing_baseline}")
print()

# ------------------------------------- 2. probe the missing vocabulary
CANDIDATES = [
    ("cumulative cap",   {"cumulative_max_amount": MAX_AMOUNT * 3}),
    ("cumulative cap alt", {"total_amount": MAX_AMOUNT * 3}),
    ("debit count cap",  {"max_debits": 3}),
    ("debit count alt",  {"total_count": 3}),
    ("velocity / rate",  {"max_debits_per_day": 1}),
    ("merchant scope",   {"allowed_merchants": ["acme-grocery"]}),
    ("category scope",   {"allowed_mcc": ["5411"]}),
]

print("  2. THE MISSING VOCABULARY\n")
print(f"     {'constraint':<22} {'verdict':<18} detail")
print("     " + "-" * 64)

findings = []
for label, extra in CANDIDATES:
    status, resp, sent = mandate_order(extra, label.replace(" ", "-")[:18])
    key = next(iter(extra))

    if status not in (200, 201):
        verdict, detail = "REJECTED", desc(resp)[:60]
    else:
        stored = resp.get("token") or {}
        oid = resp["id"]
        # read it back -- the stored copy is the source of truth
        st2, back = call("GET", f"/orders/{oid}")
        stored_back = (back.get("token") or {}) if st2 == 200 else stored
        if key in stored_back:
            verdict = "ACCEPTED+ECHOED"
            detail = f"{key}={stored_back[key]}"
        else:
            verdict = "ACCEPTED+DROPPED"
            detail = f"{key} silently discarded ({oid})"

    findings.append({"constraint": label, "field": key,
                     "verdict": verdict, "detail": detail})
    print(f"     {label:<22} {verdict:<18} {detail}")

# ----------------------------------------------------------------- verdict
print("\n" + "=" * 74)
print("  VERDICT")
print("=" * 74 + "\n")

dropped = [f for f in findings if f["verdict"] == "ACCEPTED+DROPPED"]
rejected = [f for f in findings if f["verdict"] == "REJECTED"]
echoed = [f for f in findings if f["verdict"] == "ACCEPTED+ECHOED"]

if echoed:
    print("  !! Some constraints DO exist. The thesis needs narrowing:")
    for f in echoed:
        print(f"       - {f['constraint']} via {f['field']}")
    print("     Rescope the gate to whatever remains uncovered.\n")

if rejected and not echoed:
    print(f"  {len(rejected)}/{len(findings)} constraints REJECTED outright.")
    print("  The mandate vocabulary is closed: per-debit ceiling and expiry only.")
    print("  There is no field in which to express a total, a rate, or a scope.\n")

if dropped:
    print(f"  {len(dropped)}/{len(findings)} constraints ACCEPTED THEN SILENTLY DROPPED.")
    print("  This is the sharper finding. The API takes a cap-shaped field without")
    print("  complaint and stores nothing. An integrator can believe a total cap")
    print("  is in force when no such limit exists anywhere in the system.\n")

json.dump({"generated_at": stamp, "customer_id": customer_id,
           "baseline_order": order_id, "findings": findings},
          open(OUT, "w"), indent=2)
print(f"  Findings written to {OUT}")
print("  This file is evidence. Cite it in the README.\n")
