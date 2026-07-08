'use strict';

const logger = require('../lib/logger');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');

// Uniform timing-delay on every auth failure, applied across all routers, to
// avoid the situation where some endpoints respond to invalid keys faster
// than others — a differential that itself becomes an enumeration side
// channel (OWASP ASVS V4.1.1 — consistent, centralized access control;
// CWE-208 Observable Timing Discrepancy as the adjacent risk this closes).
const AUTH_FAIL_DELAY_MS = 200;

const delayedJson = (res, status, body) =>
  setTimeout(() => res.status(status).json(body), AUTH_FAIL_DELAY_MS);

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
function requireAuth(select) {
  return async function authenticate(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(401).json({ error: 'API key is required' });
    }

    try {
      const { tenant, usedPreviousKey } = await resolveTenantByApiKey(apiKey, select);

      if (!tenant || !tenant.isActive) {
        return delayedJson(res, 401, { error: 'Invalid or inactive API key' });
      }

      if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
        return res.status(403).json({
          error: 'Email not verified. Please check your inbox and click the confirmation link.',
          code: 'EMAIL_NOT_VERIFIED',
        });
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

module.exports = { requireAuth };