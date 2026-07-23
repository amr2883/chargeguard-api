'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../lib/db');
const logger  = require('../lib/logger');
const { isAgency }       = require('../lib/planAccess');
const { normalizeDomain, domainAuthMiddleware, domainAuthMiddlewareWithAutoRegister } = require('../lib/domainAuth');
const { requireAuth }     = require('../middleware/authenticate');
const verifyHmacSignature = require('../middleware/verifyHmac');

// webhookSecret MUST be selected here — verifyHmacSignature reads
// req.tenant.webhookSecret to compute the expected HMAC. Omitting it (as
// the previous select did) would make every signed request 401 with
// HMAC_NO_SECRET_CONFIGURED, since req.tenant.webhookSecret would always
// be undefined regardless of what's actually in the database.
const apiKeyAuth = requireAuth({ id: true, plan: true, isActive: true, emailVerified: true, webhookSecret: true });

// All routes here require Agency plan — Store rows are the mechanism that
// puts a tenant into "store-managed" mode for domainAuthMiddleware (§3), so
// gating creation here is the only enforcement point needed.
const requireAgency = (req, res, next) => {
  if (!isAgency(req.tenant.plan)) {
    return res.status(403).json({
      error: 'Multi-store management is an Agency feature.',
      code:  'AGENCY_REQUIRED',
    });
  }
  next();
};

// GET /api/stores — list this tenant's stores (regardless of plan — see
// note below). Response is always scoped to req.tenant.id, so a
// non-Agency tenant only ever sees their own (possibly stale) rows.
//
// requireAgency intentionally NOT applied here, unlike POST/PUT below.
// This route only reads existing state; it grants no new capability. A
// tenant downgraded from Agency needs this to discover which store IDs
// remain from before the downgrade so they can call the (also
// non-Agency-gated) DELETE /:id self-service cleanup route — without
// this, that safety net is reachable only via a direct API call with a
// pre-known ID, not through any real UI/workflow a merchant can use.
router.get('/', apiKeyAuth, domainAuthMiddleware, async (req, res) => {
  try {
    const stores = await db.store.findMany({
      where:   { tenantId: req.tenant.id },
      orderBy: { createdAt: 'asc' },
    });
    // count reflects only ACTIVE stores — this is what's compared against
    // `limit` (the Agency plan's concurrent-store cap, enforced in POST /
    // via a separate isActive:true count query). Inactive rows are still
    // included in `stores` itself so the UI can render them with a
    // Reactivate action; they must not inflate this cap-facing count.
    const activeCount = stores.filter((s) => s.isActive).length;
    res.json({ success: true, stores, count: activeCount, limit: 5 });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to list stores');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/stores — add (or reactivate) a store
router.post('/', apiKeyAuth, requireAgency, domainAuthMiddlewareWithAutoRegister, verifyHmacSignature, async (req, res) => {
  try {
    const { storeUrl, label } = req.body;
    if (!storeUrl) {
      return res.status(400).json({ error: 'storeUrl is required' });
    }
    const normalizedDomain = normalizeDomain(storeUrl);
    if (!normalizedDomain) {
      return res.status(400).json({ error: 'storeUrl could not be parsed into a valid domain' });
    }

    const tenantId = req.tenant.id;

    const existing = await db.store.findUnique({
      where: { tenantId_normalizedDomain: { tenantId, normalizedDomain } },
    });

    if (existing?.isActive) {
      return res.status(409).json({ error: 'This domain is already registered as an active store', code: 'STORE_EXISTS' });
    }

    // Cap check — concurrent active count, not lifetime creation count (§2).
    const activeCount = await db.store.count({ where: { tenantId, isActive: true } });
    if (activeCount >= 5) {
      return res.status(403).json({
        error: 'Store limit reached. Agency plan supports up to 5 active stores.',
        code:  'STORE_LIMIT_REACHED',
      });
    }

    const store = existing
      ? await db.store.update({
          where: { id: existing.id },
          data:  { isActive: true, deactivatedAt: null, storeUrl, label: label ?? existing.label },
        })
      : await db.store.create({
          data: { tenantId, storeUrl, normalizedDomain, label: label ?? null },
        });

    logger.info({ module: 'stores', tenantId, storeId: store.id }, 'Store added/reactivated');
    res.status(201).json({ success: true, store, reactivated: !!existing });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to add store');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// DELETE /api/stores/:id — soft-delete (frees a slot immediately, §2)
// INTENTIONALLY NOT gated by requireAgency. A tenant downgraded from Agency
// (see subscriptionScheduler.js processGraceToExpired) may still have stale
// Store rows if server-side cleanup fails, hasn't run yet, or ran before
// this fix existed — this route is the self-service safety net for that
// case. This cannot be used to gain any capability beyond "delete a Store
// row this tenant already owns": the ownership check below is scoped to
// req.tenant.id, and a non-Agency tenant can never CREATE a Store row
// (POST above stays requireAgency-gated).
router.delete('/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.store.findFirst({ where: { id, tenantId: req.tenant.id } });
    if (!existing) {
      return res.status(404).json({ error: 'Store not found or not owned by this tenant' });
    }
    await db.store.update({
      where: { id },
      data:  { isActive: false, deactivatedAt: new Date() },
    });
    res.json({ success: true, message: 'Store removed' });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to remove store');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// PUT /api/stores/:id — rename and/or reactivate a store.
// requireAgency IS enforced here (unlike DELETE above) because this route
// grants capability — reactivating a store re-enables an active slot, the
// same capability POST / grants on creation — rather than DELETE's
// self-service cleanup role for tenants who've already lost Agency access.
router.put('/:id', apiKeyAuth, requireAgency, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.store.findFirst({ where: { id, tenantId: req.tenant.id } });
    if (!existing) {
      return res.status(404).json({ error: 'Store not found or not owned by this tenant' });
    }

    const { label, isActive } = req.body;
    const updateData = {};
    if (label !== undefined) updateData.label = label;
    if (isActive !== undefined) {
      updateData.isActive = isActive;
      updateData.deactivatedAt = isActive ? null : new Date();
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ error: 'Provide at least one of: label, isActive' });
    }

    const store = await db.store.update({
      where: { id },
      data:  updateData,
    });

    logger.info({ module: 'stores', tenantId: req.tenant.id, storeId: store.id }, 'Store updated');
    res.json({ success: true, store });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to update store');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;