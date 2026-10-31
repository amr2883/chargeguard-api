'use strict';

const logger = require('../lib/logger');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');

// Uniform timing-delay on every auth failure, applied across all routers, to
// avoid the situation where some endpoints respond to invalid keys faster
// than others — a differential that itself becomes an enumeration side
// channel (OWASP ASVS V4.1.1 — consistent, centralized access control;
// CWE-208 Observable Timing Discrepancy as the adjacent risk this closes).
const AUTH_FAIL_DELAY_MS = 200;

// S2 — failed-attempt limiter (per-IP). Purpose: cap the number of auth
// failures (which each trigger up to 4 DB lookups in resolveTenantByApiKey)
// that a single IP can produce inside one window, without turning this into
// a product-level fairness ceiling. Counted only on 401 (invalid/inactive
// key, or previous-key-rejected). Successful auth and 403 (email not
// verified) do NOT count. Keyed on req.ip; the deploy prerequisite
// TRUST-PROXY-VERIFY must be satisfied before shipping this to production.
const AUTH_FAIL_WINDOW_MS = 60 * 1000;
const AUTH_FAIL_MAX_ATTEMPTS = 60;

if (!globalThis.__cgAuthFailMap) globalThis.__cgAuthFailMap = new Map();
const authFailMap = globalThis.__cgAuthFailMap;
const authFailSweep = setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of authFailMap) {
    if (now - rec.firstAt > AUTH_FAIL_WINDOW_MS) authFailMap.delete(key);
  }
}, AUTH_FAIL_WINDOW_MS);
authFailSweep.unref();

const authFailKey = (req) => req.ip || 'unknown';

const isAuthFailLimited = (req) => {
  const key = authFailKey(req);
  const now = Date.now();
  const rec = authFailMap.get(key);
  if (!rec) return false;
  if (now - rec.firstAt > AUTH_FAIL_WINDOW_MS) {
    authFailMap.delete(key);
    return false;
  }
  return rec.count >= AUTH_FAIL_MAX_ATTEMPTS;
};

const recordAuthFail = (req) => {
  const key = authFailKey(req);
  const now = Date.now();
  const rec = authFailMap.get(key);
  if (!rec || now - rec.firstAt > AUTH_FAIL_WINDOW_MS) {
    authFailMap.set(key, { count: 1, firstAt: now });
  } else {
    rec.count++;
  }
};

// S6 - Retry-After value in seconds for the S2/S3 429 responses. Per RFC 7231
// section 7.1.3, the client should wait this many seconds before retrying.
// Computed from the record's firstAt + WINDOW_MS, clamped to [1, WINDOW_MS/1000]
// so we never send '0' (retry immediately) or overflow the header value.
const authFailRetryAfterSec = (req) => {
  const key = authFailKey(req);
  const rec = authFailMap.get(key);
  if (!rec) return Math.ceil(AUTH_FAIL_WINDOW_MS / 1000);
  const remainingMs = rec.firstAt + AUTH_FAIL_WINDOW_MS - Date.now();
  return Math.max(1, Math.ceil(remainingMs / 1000));
};
const delayedJson = (res, status, body) =>
  setTimeout(() => res.status(status).json(body), AUTH_FAIL_DELAY_MS);

const delayedAuthFailure = (req, res, status, body) => {
  recordAuthFail(req);
  return delayedJson(res, status, body);
};

const _resetAuthFailLimiterForTests = () => authFailMap.clear();

/**
 * requireAuth(select) — single source of truth for X-Api-Key authentication.
 *
 * Replaces the four independently-maintained apiKeyAuth/authByApiKey copies
 * that previously lived in risk.js, dashboard.js, settings.js, and
 * payments.js. Consolidation matters here for two independent reasons:
 *
 *   1. OWASP ASVS V4.1.1 requires access control checks to be enforced by a
 *      single, centralized mechanism rather than re-implemented per route,
 *      specifically so that a change to the policy (e.g. adding the
 *      emailVerified check) cannot silently fail to propagate to one of the
 *      copies — which is exactly the bug this consolidation fixes.
 *   2. CWE-306 (Missing Authentication for Critical Function) — the prior
 *      dashboard.js implementation omitted the emailVerified check entirely,
 *      letting unverified tenants reach /rotate-key and other dashboard
 *      endpoints that every other route family already gated.
 *
 * @param {object} select - Prisma `select` object, forwarded verbatim to
 *   resolveTenantByApiKey so each router only fetches the Tenant fields it
 *   actually needs (principle of least privilege at the query layer).
 */
function requireAuth(select, opts = {}) {
  return async function authenticate(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(401).json({ error: 'API key is required' });
    }

    // S2: fail-fast BEFORE any DB lookup. The counter is per-IP and only
    // counts failed attempts; a valid key never increments it.
    if (!opts.skipInternalLimiter && isAuthFailLimited(req)) {
      res.set('Retry-After', String(authFailRetryAfterSec(req)));
      return res.status(429).json({ error: 'Too Many Requests' });
    }

    try {
      const { tenant, usedPreviousKey } = await resolveTenantByApiKey(apiKey, select);

      if (!tenant || !tenant.isActive) {
        return delayedAuthFailure(req, res, 401, { error: 'Invalid or inactive API key' });
      }

      if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
        return res.status(403).json({
          error: 'Email not verified. Please check your inbox and click the confirmation link.',
          code: 'EMAIL_NOT_VERIFIED',
        });
      }

      if (usedPreviousKey && opts.allowPreviousKey === false) {
        // N51: this route does not accept the grace-period (previous) key. The response is
        // identical to an invalid key, so it does not reveal that the key was once valid.
        logger.warn({ module: 'authenticate', tenantId: tenant.id }, 'Previous (grace-period) API key rejected on a route that does not accept it');
        return delayedAuthFailure(req, res, 401, { error: 'Invalid or inactive API key' });
      }

      if (usedPreviousKey) {
        res.set('X-ChargeGuard-Key-Deprecated', 'true');
        logger.warn(
          { module: 'authenticate', tenantId: tenant.id },
          'Request authenticated using previous (grace-period) API key — plugin should be updated'
        );
      }

      req.tenant = tenant;
      next();
    } catch (err) {
      logger.error({ module: 'authenticate', error: err.message }, 'Auth error');
      res.status(500).json({ error: 'Internal Server Error' });
    }
  };
}

module.exports = {
  requireAuth,
  isAuthFailLimited,
  authFailRetryAfterSec,
  recordAuthFail,
  _resetAuthFailLimiterForTests,
  _authFailLimiter: { AUTH_FAIL_WINDOW_MS, AUTH_FAIL_MAX_ATTEMPTS },
};