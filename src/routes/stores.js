'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../lib/db');
const logger  = require('../lib/logger');
const { isAgency }       = require('../lib/planAccess');
const { normalizeDomain } = require('../lib/domainAuth');
const { requireAuth }     = require('../middleware/authenticate');

const apiKeyAuth = requireAuth({ id: true, plan: true, isActive: true, emailVerified: true });

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

// GET /api/stores — list this tenant's stores
router.get('/', apiKeyAuth, requireAgency, async (req, res) => {
  try {
    const stores = await db.store.findMany({
      where:   { tenantId: req.tenant.id, isActive: true },
      orderBy: { createdAt: 'asc' },
    });
    res.json({ success: true, stores, count: stores.length, limit: 5 });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to list stores');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/stores — add (or reactivate) a store
router.post('/', apiKeyAuth, requireAgency, async (req, res) => {
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
    res.status(201).json({ success: true, store });
  } catch (err) {
    logger.error({ module: 'stores', error: err.message }, 'Failed to add store');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// DELETE /api/stores/:id — soft-delete (frees a slot immediately, §2)
router.delete('/:id', apiKeyAuth, requireAgency, async (req, res) => {
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

module.exports = router;