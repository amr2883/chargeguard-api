# Incident: API Auth Failure After DB Outage Recovery (Tenant Mismatch)

**Date discovered:** 2026-09-23
**Severity:** High (blocked all checkout testing for ~2 hours; masked as multiple false leads)
**Status:** Resolved — root cause fixed in test environment; needs a production runbook entry

## Summary

After a ~13-hour Postgres container outage and WAL-based automatic recovery,
the `Tenant` row that the WordPress plugin's stored `chargeguard_api_key` /
`chargeguard_merchant_id` pointed to (`cmtsiuurw0008cht00yeq7toj`) no longer
existed in the database. The only tenant present after recovery was a
different, auto-created row (`cmud2ep5a0000f2ob50jkuhu7`,
`e2e-test@chargeguard.local`), created *after* the outage.

Every `evaluate_risk()` call therefore received a real, correct
`401 Invalid or inactive API key` from `authenticate.js` — not a bug,
not a network issue, not a stale circuit breaker. But because the plugin's
`resolve_api_unavailable_decision()` fail-closed fallback treats *any*
`WP_Error` from `evaluate_risk()` identically (whether it's a real 401, a
5xx, or a timeout), all checkout attempts were blocked with
`chargeguard_order_blocked_api_unavailable`, which looks identical to a
connectivity problem from the outside.

## Root cause

DB recovery after the outage did not preserve/restore the original tenant.
Root cause of *that* (fresh seed script running post-recovery vs. partial
WAL replay vs. manual re-init) was not conclusively determined — flagged
as a follow-up investigation, not blocking for launch since this is a
test-environment-only DB.

## Diagnostic path (false leads, in order, for future reference)

1. **Assumed:** stale `chargeguard_circuit_open` transient.
   **Reality:** transient did not exist — circuit was closed. Ruled out by
   `wp option get _transient_chargeguard_circuit_open` returning "does not exist".

2. **Assumed:** `chargeguard_api_down_status` option (hourly window, admin-facing).
   **Reality:** informational only, not itself gating. Deleting it had no effect.

3. **Assumed:** per-IP rate limiter (`ChargeGuard_Atomic_Rate_Limiter`,
   rows named `cg_apidown_ip_{md5(ip)}_{window}` directly in `wp_options`,
   NOT under the `_transient_` prefix — this is a custom atomic counter,
   not a WP Transient). This WAS real and contributing (our own repeated
   failed attempts kept incrementing it), but clearing it did not fix the
   underlying problem — every fresh attempt immediately failed again and
   re-populated a new bucket, because the true cause (below) kept firing.

4. **Assumed:** local device fingerprint blacklist
   (`chargeguard_device_blacklist`). Ruled out — the fingerprint in use for
   this test session was not in the 35-entry list from prior swarm tests.

5. **Root cause found:** `wp eval-file` reproduction of `evaluate_risk()`
   with full, correct HMAC auth (decrypted via `chargeguard_get_secret_option()`,
   signed via the plugin's real `generate_hmac()` logic) returned
   `HTTP 401 {"error":"Invalid or inactive API key"}` directly from
   `src/middleware/authenticate.js`. Traced to `resolveTenantByApiKey()`
   in `src/lib/apiKeyAuth.js` → the tenant simply did not exist:
   `SELECT * FROM "Tenant" WHERE id = 'cmtsiuurw0008cht00yeq7toj'` → 0 rows.
   `SELECT COUNT(*) FROM "Tenant"` → 1 row total, a different tenant.

## Fix applied (test environment)

1. Generated a new random API key (`cg_test_...`).
2. Computed its hash with the backend's own algorithm
   (`HMAC-SHA256(rawKey, process.env.API_KEY_HASH_SECRET)`,
   see `src/lib/apiKeyHash.js`).
3. `UPDATE "Tenant" SET "apiKeyHash" = '<hash>' WHERE id = '<existing tenant id>'`.
4. Wrote the raw key back into WordPress via the plugin's own
   `chargeguard_update_secret_option('chargeguard_api_key', '<raw key>')`
   (NOT a direct `update_option()` call — this preserves the `cgenc1:`
   AES-256-GCM encryption the plugin expects on read).
5. Updated `chargeguard_merchant_id` option to the existing tenant's id.
6. Verified with the same `wp eval-file` HMAC diagnostic script:
   `401` → `403 email_hard_block` (auth now succeeds; the 403 was a
   correct, expected block of a throwaway test email address) →
   full success once a real session email was used.

## Operational lessons for the checklist (Section 6 / 10 — Infra & CI guardrails)

- [ ] **New guardrail needed:** after any DB outage + recovery, verify
      tenant/API-key continuity explicitly — do not assume "DB accepting
      connections" implies "the same tenants still exist". A dedicated
      post-recovery health check (compare stored plugin credentials
      against the DB) would have caught this in seconds instead of ~2 hours.
- [ ] `resolve_api_unavailable_decision()`'s fail-closed design worked
      exactly as intended from a security standpoint (never silently
      approved unscored orders) — no code change needed there. Documented
      as a **positive finding**, not a defect.
- [ ] Consider distinguishing "real auth failure (401)" from "API
      unreachable (timeout/5xx/connection refused)" in the plugin's error
      handling/logging, so this specific failure mode is diagnosable from
      the WordPress admin/logs alone next time, without needing backend
      shell access.
- [ ] `ChargeGuard_Atomic_Rate_Limiter` bucket keys are plain
      `wp_options` rows (`cg_apidown_ip_*`), not WP Transients — searching
      `_transient_cg_apidown*` will never find them. Worth a one-line
      comment update or an internal wiki note so this isn't rediscovered
      the hard way again.

## Next step

Proceed to Stripe test-card checkout flow (original Section 9 goal).