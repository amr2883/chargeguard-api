'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../lib/db');
const logger  = require('../lib/logger');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const { getAvailableCountries, calculateCountryRiskPenalty } = require('../lib/countryRisk');

// ── Constants ─────────────────────────────────────────────────────────────
const SETTINGS_RATE  = new Map();
const MAX_REQ        = 20;
const WINDOW_MS      = 15 * 60 * 1000; // 15 دقيقة
const VALID_OVERRIDES = new Set(['allow', 'escalate', 'smart']);

// ── Rate Limiter ──────────────────────────────────────────────────────────
const rateLimit = (req, res, next) => {
  const key = req.headers['x-api-key'] || req.ip || 'unknown';
  const now = Date.now();
  const rec = SETTINGS_RATE.get(key);
  if (rec) {
    if (now - rec.firstAt > WINDOW_MS) {
      SETTINGS_RATE.delete(key);
    } else if (rec.count >= MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    SETTINGS_RATE.set(key, { count: 1, firstAt: now });
  }
  next();
};

// ── Auth Middleware ───────────────────────────────────────────────────────
const apiKeyAuth = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API key is required' });
  try {
    const { tenant, usedPreviousKey } = await resolveTenantByApiKey(apiKey, {
      id: true, email: true, isActive: true,
      emailVerified: true, plan: true,
      countryOverrides: true,
    });

    if (!tenant || !tenant.isActive) {
      return setTimeout(() => res.status(401).json({ error: 'Unauthorized' }), 200);
    }

    if (usedPreviousKey) {
      res.set('X-ChargeGuard-Key-Deprecated', 'true');
      logger.warn({ module: 'settings', tenantId: tenant.id }, 'Request authenticated using previous (grace-period) API key');
    }
    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({ error: 'Email not verified', code: 'EMAIL_NOT_VERIFIED' });
    }
    req.tenant = tenant;
    next();
  } catch (err) {
    logger.error({ module: 'settings', err: err.message }, 'Auth error');
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// ── Validation Middleware ─────────────────────────────────────────────────
const validateCountryOverrides = (req, res, next) => {
  const { updates } = req.body;

  if (!updates || !Array.isArray(updates) || updates.length === 0) {
    return res.status(400).json({ error: 'updates must be a non-empty array' });
  }

  const supportedCodes = new Set(getAvailableCountries().map(c => c.code));
  const errors = [];

  for (const update of updates) {
    if (!update.countryCode || !update.override) {
      errors.push(`Each update must have countryCode and override`);
      continue;
    }
    if (!supportedCodes.has(update.countryCode.toUpperCase())) {
      errors.push(`Unsupported country code: ${update.countryCode}`);
    }
    if (!VALID_OVERRIDES.has(update.override)) {
      errors.push(`Invalid override value for ${update.countryCode}: must be allow, escalate, or smart`);
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
  }

  next();
};

// ── Helper: حساب effectivePenalty لكل دولة ────────────────────────────────
const getEffectivePenalty = (basePenalty, override) => {
  if (override === 'allow')    return 0;
  if (override === 'escalate') return Math.min(basePenalty * 2, 20);
  return basePenalty; // smart = default
};

// ── GET /api/settings/country-overrides ──────────────────────────────────
router.get('/country-overrides', rateLimit, apiKeyAuth, async (req, res) => {
  try {
    const currentOverrides = req.tenant.countryOverrides || {};
    const countries        = getAvailableCountries();

    const availableCountries = countries.map(c => {
      const override       = currentOverrides[c.code] ?? 'smart';
      const effectivePenalty = getEffectivePenalty(c.basePenalty, override);
      return {
        ...c,
        currentOverride:  override,
        effectivePenalty,
        isModified:       override !== 'smart',
      };
    });

    const modifiedCount  = availableCountries.filter(c => c.isModified).length;
    const allowCount     = availableCountries.filter(c => c.currentOverride === 'allow').length;
    const escalateCount  = availableCountries.filter(c => c.currentOverride === 'escalate').length;

    res.json({
      success: true,
      countryOverrides:   currentOverrides,
      availableCountries,
      summary: {
        totalCountries: countries.length,
        modifiedCount,
        allowCount,
        escalateCount,
      },
    });
  } catch (err) {
    logger.error({ module: 'settings', err: err.message }, 'GET country-overrides error');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ── PUT /api/settings/country-overrides ──────────────────────────────────
router.put('/country-overrides', rateLimit, apiKeyAuth, validateCountryOverrides, async (req, res) => {
  try {
    const { updates }      = req.body;
    const currentOverrides = { ...(req.tenant.countryOverrides || {}) };
    const countries        = getAvailableCountries();
    const countryMap       = Object.fromEntries(countries.map(c => [c.code, c]));
    const warnings         = [];

    // تطبيق كل update
    for (const update of updates) {
      const code     = update.countryCode.toUpperCase();
      const override = update.override;

      if (override === 'smart') {
        // smart = حذف الـ key → يرجع للـ default
        delete currentOverrides[code];
      } else {
        currentOverrides[code] = override;
      }

      // تحذير لو allow على دولة critical tier
      if (override === 'allow' && countryMap[code]?.tier === 'critical') {
        warnings.push({
          countryCode: code,
          message: `${countryMap[code].name} is a critical-risk region with high fraud rates — allowing may increase chargebacks`,
        });
      }
    }

    // حفظ في DB
    await db.tenant.update({
      where: { id: req.tenant.id },
      data: {
        countryOverrides:          currentOverrides,
        countryOverridesUpdatedAt: new Date(),
      },
    });

    logger.info({
      module:   'settings',
      tenantId: req.tenant.id,
      updates,
    }, 'Country overrides updated');

    res.json({
      success:          true,
      countryOverrides: currentOverrides,
      warnings,
      updatedAt:        new Date().toISOString(),
    });
  } catch (err) {
    logger.error({ module: 'settings', err: err.message }, 'PUT country-overrides error');
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

module.exports = router;