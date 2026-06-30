'use strict';

const db = require('./db');
const logger = require('./logger');
const { hashApiKey } = require('./apiKeyHash');

/**
 * Resolves a tenant from a raw X-Api-Key header value.
 *
 * Lookup order:
 *   1. apiKeyHash (source of truth going forward)
 *   2. apiKey plaintext (DEPRECATED — migration fallback only; self-heals
 *      by writing apiKeyHash on match so this path is exercised at most
 *      once per tenant)
 *   3. previousApiKeyHash / previousApiKey (rotation grace period, same
 *      hash-first/fallback/self-heal pattern)
 *
 * This guarantees zero-downtime migration: no existing client using an
 * old plaintext-issued key is ever rejected during the transition window.
 */
async function resolveTenantByApiKey(apiKey, select) {
  if (!apiKey) return { tenant: null, usedPreviousKey: false };

  const apiKeyHash = hashApiKey(apiKey);

  let tenant = await db.tenant.findUnique({ where: { apiKeyHash }, select });

  if (!tenant) {
    const plain = await db.tenant.findUnique({ where: { apiKey }, select });
    if (plain) {
      tenant = plain;
      db.tenant.update({ where: { id: plain.id }, data: { apiKeyHash } })
        .catch(err => logger.error({ module: 'apiKeyAuth', err: err.message }, 'apiKeyHash backfill failed'));
    }
  }

  let usedPreviousKey = false;
  if (!tenant) {
    const selectPrev = { ...select, previousApiKeyExpiresAt: true };
    let prevTenant = await db.tenant.findUnique({ where: { previousApiKeyHash: apiKeyHash }, select: selectPrev });

    if (!prevTenant) {
      const prevPlain = await db.tenant.findUnique({ where: { previousApiKey: apiKey }, select: selectPrev });
      if (prevPlain) {
        prevTenant = prevPlain;
        db.tenant.update({ where: { id: prevPlain.id }, data: { previousApiKeyHash: apiKeyHash } })
          .catch(err => logger.error({ module: 'apiKeyAuth', err: err.message }, 'previousApiKeyHash backfill failed'));
      }
    }

    if (prevTenant && prevTenant.previousApiKeyExpiresAt && new Date() < new Date(prevTenant.previousApiKeyExpiresAt)) {
      tenant = prevTenant;
      usedPreviousKey = true;
    }
  }

  return { tenant, usedPreviousKey };
}

module.exports = { resolveTenantByApiKey };