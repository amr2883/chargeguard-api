// src/jobs/replayPendingEnrichments.js
//
// Periodic replay of PendingEnrichment rows for orders that WERE
// resolvable by the plugin (a real WooCommerce order ID — NOT PayPal's
// synthetic 'paypal_<txnId>' placeholder) but whose backend Order row
// didn't exist yet at /enrich time. Synthetic-ID rows are deliberately
// NEVER targeted here — see class-paypal-webhook.php's
// consume_pending_enrichment(), which is the only thing that can resolve
// those, since only the plugin ever learns the real order ID.

const logger = require('../lib/logger');
const db = require('../lib/db');
const { processEnrichment } = require('../lib/enrichmentProcessor');

const REPLAY_INTERVAL_MS = 2 * 60 * 1000;        // run every 2 minutes
const MIN_AGE_MS = 60 * 1000;                     // give the order-linking race 60s to resolve
const EXPIRE_AFTER_MS = 24 * 60 * 60 * 1000;      // give up after 24h

async function replayOnce() {
  const now = Date.now();
  const cutoff = new Date(now - MIN_AGE_MS);
  const expireCutoff = new Date(now - EXPIRE_AFTER_MS);

  let rows;
  try {
    rows = await db.pendingEnrichment.findMany({
      where: {
        status: 'pending',
        createdAt: { lte: cutoff },
        // Never touch PayPal's synthetic placeholder rows — only the
        // plugin can resolve those (see class-paypal-webhook.php).
        NOT: { orderId: { startsWith: 'paypal_' } },
      },
      take: 100,
    });
  } catch (err) {
    logger.error({ module: 'replayPendingEnrichments', error: err.message }, 'Failed to load pending rows');
    return;
  }

  for (const row of rows) {
    try {
      // Expire rows nobody ever linked, tenant-scoped or not (legacy
      // rows created before the merchantId migration have merchantId
      // null and can only ever be expired, never safely replayed).
      if (new Date(row.createdAt).getTime() < expireCutoff.getTime() || !row.merchantId) {
        await db.pendingEnrichment.update({ where: { id: row.id }, data: { status: 'expired', processedAt: new Date() } });
        continue;
      }

      const existingOrder = await db.order.findUnique({
        where: { merchantId_orderId: { merchantId: row.merchantId, orderId: row.orderId } },
        select: { id: true },
      });
      if (!existingOrder) {
        continue; // still not linked — try again next sweep
      }

      const tenant = await db.tenant.findUnique({ where: { id: row.merchantId }, select: { id: true, plan: true, countryOverrides: true, fraudIsolationMode: true } });
      if (!tenant) {
        await db.pendingEnrichment.update({ where: { id: row.id }, data: { status: 'failed', processedAt: new Date() } });
        continue;
      }

      let body;
      try {
        body = JSON.parse(row.enrichData);
      } catch (err) {
        logger.error({ module: 'replayPendingEnrichments', rowId: row.id, error: err.message }, 'Failed to parse stored enrichData — marking failed');
        await db.pendingEnrichment.update({ where: { id: row.id }, data: { status: 'failed', processedAt: new Date() } });
        continue;
      }

      // limitedScoring explicitly false: this cron replays enrichments
      // that were originally queued (as PendingEnrichment) at live
      // /enrich time, potentially hours or days ago — by replay time the
      // tenant's quota window may have reset, rolled over, or simply no
      // longer reflects the state that was relevant when the order was
      // actually placed. Re-checking checkQuotaGate() here would require
      // reconstructing a req-like object this job doesn't have, and would
      // gate a replay against a quota snapshot with no clear relationship
      // to the original event. Per design: quota enforcement is a live,
      // real-time protection against ongoing external-intel cost, not a
      // retroactive one — replays intentionally always get full-strength
      // scoring. This mirrors, not duplicates, the /evaluate and
      // /woocommerce-webhook quota gate: same parameter, deliberately
      // different, documented input.
      const result = await processEnrichment({ merchantId: row.merchantId, orderId: row.orderId, body, storeId: null, tenant, limitedScoring: false });

      // processEnrichment() itself deletes the row via its own
      // pendingEnrichment.deleteMany({ merchantId, orderId, status: 'pending' })
      // call on every success path — nothing further to do here except log.
      logger.info({ module: 'replayPendingEnrichments', rowId: row.id, orderId: row.orderId, status: result.status }, 'Replayed pending enrichment');
    } catch (err) {
      logger.error({ module: 'replayPendingEnrichments', rowId: row.id, error: err.message }, 'Replay attempt failed — will retry next sweep');
    }
  }
}

function start() {
  setInterval(() => {
    replayOnce().catch(err => logger.error({ module: 'replayPendingEnrichments', error: err.message }, 'Replay sweep crashed'));
  }, REPLAY_INTERVAL_MS).unref();
}

module.exports = { start, replayOnce };