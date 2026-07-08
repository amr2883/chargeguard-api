#!/usr/bin/env python3
"""
chargeguard_verify.py
----------------------------------------------------------------------
Post-run verification harness for the ChargeGuard Store API simulation.

Reads:
  1. The k6 summary JSON (from `k6 run ... --summary-export=summary.json`
     or the stdout JSON from handleSummary in chargeguard-simulation.js)
  2. ChargeGuard's own decision log for the simulation's time window

Asserts:
  - 100% of attack-shaped requests resulted in review or block (never approve)
  - 0% of legit-shaped requests were blocked
  - <=10% of legit-shaped requests were flagged review
  - After the ramp-up window (5 requests OR 10s, whichever first),
    attack traffic blocking is consistent (no gaps)

Usage:
  python chargeguard_verify.py \
      --k6-summary summary.json \
      --api-base https://staging.example.com \
      --api-token $CHARGEGUARD_ADMIN_TOKEN \
      --run-start "2026-07-08T12:00:00Z" \
      --run-end   "2026-07-08T12:02:00Z"
----------------------------------------------------------------------
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError

# ----------------------------------------------------------------------
# CONFIG DEFAULTS — adjust these once you confirm ChargeGuard's real
# decisions-log endpoint shape.
# ----------------------------------------------------------------------
DECISIONS_ENDPOINT_PATH = "/api/admin/decisions"   # <-- confirm/replace
REVIEW_THRESHOLD_PCT = 10.0   # legit requests allowed to be flagged review
RAMP_UP_REQUEST_COUNT = 5
RAMP_UP_SECONDS = 10


def fetch_decisions(api_base, api_token, since_iso, until_iso):
    """
    Pulls ChargeGuard's decision log for the simulation window.
    Assumes: GET {api_base}/api/admin/decisions?since=...&until=...
             Authorization: Bearer {api_token}
             Response: { "decisions": [ { "request_id", "decision",
                                           "request_type_tag"?, "timestamp",
                                           "score" }, ... ] }

    request_type_tag is optional — if your log doesn't tag attack vs legit,
    the harness falls back to matching by response body/email pattern
    (see `classify_by_payload` below). Simplest is to have ChargeGuard log
    whatever tag/header k6 sent, if you can add that field cheaply.
    """
    params = urlencode({"since": since_iso, "until": until_iso, "limit": 100000})
    url = f"{api_base}{DECISIONS_ENDPOINT_PATH}?{params}"
    req = Request(url, headers={"Authorization": f"Bearer {api_token}"})

    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("decisions", data if isinstance(data, list) else [])
    except HTTPError as e:
        print(f"ERROR: decisions-log request failed with HTTP {e.code}: {e.reason}", file=sys.stderr)
        sys.exit(2)
    except URLError as e:
        print(f"ERROR: could not reach ChargeGuard admin API: {e.reason}", file=sys.stderr)
        sys.exit(2)


def classify_by_payload(decision_record):
    """
    Fallback classifier if your decision log doesn't carry an explicit
    request_type tag from k6. Uses the same signal your k6 script planted:
    attack requests have Origin=Unknown / missing UA; legit requests have
    a full browser UA and matching Origin.

    Expects decision_record to include the raw request metadata that
    ChargeGuard evaluated (origin, user_agent, email prefix, etc.) —
    adjust field names to match what your /api/risk/evaluate logs.
    """
    origin = (decision_record.get("origin") or "").lower()
    user_agent = decision_record.get("user_agent") or ""
    email = decision_record.get("email") or ""

    if origin == "unknown" or not user_agent:
        return "attack"
    if email.startswith("legit+"):
        return "legit"
    if email.startswith("synthetic+"):
        return "attack"
    return "unclassified"


def load_k6_summary(path):
    with open(path, "r") as f:
        return json.load(f)


def run_verification(decisions, ramp_up_cutoff_index, ramp_up_cutoff_time):
    """
    Core assertions. Returns (passed: bool, violations: list[str], stats: dict)
    """
    violations = []

    attack_decisions = []
    legit_decisions = []
    unclassified_count = 0

    for d in decisions:
        req_type = d.get("request_type_tag")
        if req_type not in ("attack", "legit"):
            req_type = classify_by_payload(d)

        if req_type == "attack":
            attack_decisions.append(d)
        elif req_type == "legit":
            legit_decisions.append(d)
        else:
            unclassified_count += 1

    if unclassified_count > 0:
        print(f"WARNING: {unclassified_count} decision records could not be "
              f"classified as attack/legit and were excluded from assertions. "
              f"Consider adding an explicit tag field to ChargeGuard's log.",
              file=sys.stderr)

    # --- Assertion 1: no attack request approved ---
    approved_attacks = [d for d in attack_decisions if d.get("decision") == "approve"]
    if approved_attacks:
        violations.append(
            f"FAIL [Assertion 1]: {len(approved_attacks)} attack-shaped request(s) "
            f"were APPROVED (expected review or block). Sample request_ids: "
            f"{[d.get('request_id') for d in approved_attacks[:5]]}"
        )

    # --- Assertion 2: zero legit requests blocked ---
    blocked_legit = [d for d in legit_decisions if d.get("decision") == "block"]
    if blocked_legit:
        violations.append(
            f"FAIL [Assertion 2]: {len(blocked_legit)} legit-shaped request(s) "
            f"were BLOCKED (expected zero). Sample request_ids: "
            f"{[d.get('request_id') for d in blocked_legit[:5]]}"
        )

    # --- Assertion 3: <=10% legit requests flagged review ---
    reviewed_legit = [d for d in legit_decisions if d.get("decision") == "review"]
    legit_total = len(legit_decisions)
    review_pct = (len(reviewed_legit) / legit_total * 100.0) if legit_total else 0.0
    if review_pct > REVIEW_THRESHOLD_PCT:
        violations.append(
            f"FAIL [Assertion 3]: {review_pct:.1f}% of legit-shaped requests were "
            f"flagged 'review' (threshold: {REVIEW_THRESHOLD_PCT}%). "
            f"{len(reviewed_legit)}/{legit_total} affected."
        )

    # --- Assertion 4: consistent blocking after ramp-up window ---
    # Sort attack decisions chronologically, then look past the ramp-up
    # cutoff (5th request or 10s in, whichever comes first) and confirm
    # no approve/gaps appear in the post-ramp-up tail.
    attack_sorted = sorted(attack_decisions, key=lambda d: d.get("timestamp", ""))
    post_rampup = []
    for i, d in enumerate(attack_sorted):
        ts = d.get("timestamp")
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
        except ValueError:
            ts_dt = None

        past_count_cutoff = i >= ramp_up_cutoff_index
        past_time_cutoff = (ts_dt is not None and ramp_up_cutoff_time is not None
                             and ts_dt >= ramp_up_cutoff_time)

        if past_count_cutoff or past_time_cutoff:
            post_rampup.append(d)

    non_blocking_post_rampup = [
        d for d in post_rampup if d.get("decision") not in ("review", "block")
    ]
    if non_blocking_post_rampup:
        violations.append(
            f"FAIL [Assertion 4]: {len(non_blocking_post_rampup)} attack-shaped "
            f"request(s) after the ramp-up window were NOT review/block "
            f"(inconsistent blocking). Sample request_ids: "
            f"{[d.get('request_id') for d in non_blocking_post_rampup[:5]]}"
        )

    stats = {
        "total_decisions": len(decisions),
        "attack_total": len(attack_decisions),
        "legit_total": legit_total,
        "unclassified": unclassified_count,
        "attack_blocked": len([d for d in attack_decisions if d.get("decision") == "block"]),
        "attack_reviewed": len([d for d in attack_decisions if d.get("decision") == "review"]),
        "attack_approved": len(approved_attacks),
        "legit_approved": len([d for d in legit_decisions if d.get("decision") == "approve"]),
        "legit_reviewed": len(reviewed_legit),
        "legit_blocked": len(blocked_legit),
        "legit_review_pct": round(review_pct, 2),
        "post_rampup_attack_count": len(post_rampup),
        "post_rampup_non_blocking": len(non_blocking_post_rampup),
    }

    return (len(violations) == 0), violations, stats


def main():
    parser = argparse.ArgumentParser(description="ChargeGuard simulation verification harness")
    parser.add_argument("--k6-summary", required=True, help="Path to k6 summary JSON")
    parser.add_argument("--api-base", required=True, help="ChargeGuard staging API base URL")
    parser.add_argument("--api-token", required=True, help="ChargeGuard admin API bearer token")
    parser.add_argument("--run-start", required=True, help="ISO8601 UTC timestamp, sim start")
    parser.add_argument("--run-end", required=True, help="ISO8601 UTC timestamp, sim end")
    args = parser.parse_args()

    print("Loading k6 summary...")
    k6_summary = load_k6_summary(args.k6_summary)
    metrics = k6_summary.get("metrics", {})
    k6_attack_sent = metrics.get("attack_requests_sent", {}).get("values", {}).get("count", 0)
    k6_legit_sent = metrics.get("legit_requests_sent", {}).get("values", {}).get("count", 0)
    print(f"  k6 reported: {k6_attack_sent} attack-shaped, {k6_legit_sent} legit-shaped requests sent")

    print(f"Querying ChargeGuard decision log ({args.run_start} to {args.run_end})...")
    decisions = fetch_decisions(args.api_base, args.api_token, args.run_start, args.run_end)
    print(f"  Retrieved {len(decisions)} decision records")

    # Ramp-up cutoff: 5th attack request OR 10 seconds into the run,
    # whichever comes first (per your stated tolerance).
    try:
        run_start_dt = datetime.fromisoformat(args.run_start.replace("Z", "+00:00"))
        ramp_up_cutoff_time = run_start_dt.replace(
            second=run_start_dt.second  # placeholder; timedelta applied below
        )
        from datetime import timedelta
        ramp_up_cutoff_time = run_start_dt + timedelta(seconds=RAMP_UP_SECONDS)
    except ValueError:
        ramp_up_cutoff_time = None

    passed, violations, stats = run_verification(
        decisions,
        ramp_up_cutoff_index=RAMP_UP_REQUEST_COUNT,
        ramp_up_cutoff_time=ramp_up_cutoff_time,
    )

    print("\n" + "=" * 70)
    print("CHARGEGUARD SIMULATION VERIFICATION — SUMMARY")
    print("=" * 70)
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print("-" * 70)

    if passed:
        print("RESULT: PASS — all assertions satisfied.")
    else:
        print(f"RESULT: FAIL — {len(violations)} violation(s):\n")
        for v in violations:
            print(f"  - {v}")

    print("=" * 70)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()