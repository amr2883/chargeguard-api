'use strict';

const db     = require('../lib/db');
const logger = require('../lib/logger');
const { isAgency } = require('../lib/planAccess');

const AGENCY_STORE_LIMIT = 5;

/**
 * autoRegisterStoreMiddleware — Solution D, "verify" half.
 *
 * MUST run after verifyHmacSignature. Resolves req.pendingStoreDomain
 * (set by domainAuthMiddlewareWithAutoRegister) into a Store row and
 * req.storeId, or rejects — never silently passes an unresolved domain
 * through.
 *
 * Kill switch: AGENCY_AUTO_REGISTER_ENABLED. Unset/false reproduces the
 * exact pre-change reject behavior with no code deploy required.
 */
async function autoRegisterStoreMiddleware(req, res, next) {
  try {
    if (!req.pendingStoreDomain) {
      return next();
    }

    if (process.env.AGENCY_AUTO_REGISTER_ENABLED !== 'true') {
      logger.debug(
        { module: 'autoRegisterStore', tenantId: req.tenant?.id },
        'Auto-registration disabled via AGENCY_AUTO_REGISTER_ENABLED — rejecting'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key. Add this domain as a Store first.',
        code:  'DOMAIN_MISMATCH',
      });
    }

    // Domain is only trustworthy if THIS request's signature bound it.
    // v1's signed string never included the domain — accepting it here
    // would let a leaked API key + a still-valid v1 signature register
    // an arbitrary domain, exactly the gap Solution D exists to close.
    if (req.hmacSignatureVersion !== 'v2') {
      logger.warn(
        { module: 'autoRegisterStore', tenantId: req.tenant?.id, path: req.path, sigVersion: req.hmacSignatureVersion },
        'Domain unresolved and signature is not domain-bound (v2) — rejecting rather than auto-registering'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key. Add this domain as a Store first.',
        code:  'DOMAIN_MISMATCH',
      });
    }

    if (!isAgency(req.tenant?.plan)) {
      // Should be unreachable — domainAuthMiddlewareWithAutoRegister only
      // defers for Agency tenants — fail closed rather than trust it.
      logger.error(
        { module: 'autoRegisterStore', tenantId: req.tenant?.id, plan: req.tenant?.plan },
        'pendingStoreDomain set for a non-Agency tenant — should be unreachable'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key. Add this domain as a Store first.',
        code:  'DOMAIN_MISMATCH',
      });
    }

    const tenantId         = req.tenant.id;
    const normalizedDomain = req.pendingStoreDomain;

    const existing = await db.store.findUnique({
      where: { tenantId_normalizedDomain: { tenantId, normalizedDomain } },
    });

    if (existing) {
      if (!existing.isActive) {
        // Explicit constraint: never reactivate a soft-deleted store —
        // that's a deliberate merchant action taken via PUT /stores/:id.
        logger.warn(
          { module: 'autoRegisterStore', tenantId, normalizedDomain, storeId: existing.id },
          'Domain matches a soft-deleted Store — not auto-reactivating'
        );
        return res.status(403).json({
          error: 'This domain was previously removed as a Store. Reactivate it from your dashboard to resume.',
          code:  'STORE_DEACTIVATED',
        });
      }
      // Already active — a concurrent request resolved it since
      // domainAuthMiddleware ran. Idempotent: attribute and continue.
      req.storeId     = existing.id;
      req.storeDomain = normalizedDomain;
      return next();
    }

    const activeCount = await db.store.count({ where: { tenantId, isActive: true } });
    if (activeCount >= AGENCY_STORE_LIMIT) {
      logger.warn(
        { module: 'autoRegisterStore', tenantId, normalizedDomain, activeCount },
        'Agency store cap reached — declining to auto-register'
      );
      return res.status(403).json({
        error: `Store limit reached. Agency plan supports up to ${AGENCY_STORE_LIMIT} active stores.`,
        code:  'STORE_LIMIT_REACHED',
      });
    }

    try {
      const store = await db.store.create({
        data: {
          tenantId,
          storeUrl: req.headers['x-store-domain'],
          normalizedDomain,
          label: null,
        },
      });
      req.storeId     = store.id;
      req.storeDomain = normalizedDomain;
      logger.info(
        { module: 'autoRegisterStore', tenantId, storeId: store.id, normalizedDomain },
        'Store auto-registered from a verified domain-bound (v2) request'
      );
      return next();
    } catch (err) {
      if (err.code === 'P2002') {
        // Concurrent create race — re-fetch and attribute; never create twice.
        const race = await db.store.findUnique({
          where: { tenantId_normalizedDomain: { tenantId, normalizedDomain } },
        });
        if (race?.isActive) {
          req.storeId     = race.id;
          req.storeDomain = normalizedDomain;
          return next();
        }
        return res.status(403).json({
          error: 'Domain not authorized for this API key. Add this domain as a Store first.',
          code:  'DOMAIN_MISMATCH',
        });
      }
      throw err;
    }
  } catch (err) {
    logger.error(
      { module: 'autoRegisterStore', error: err.message, stack: err.stack },
      'Unexpected error in autoRegisterStoreMiddleware — failing closed'
    );
    return res.status(503).json({
      error: 'Unable to verify request origin. Please try again.',
      code:  'DOMAIN_CHECK_UNAVAILABLE',
    });
  }
}

module.exports = autoRegisterStoreMiddleware;