const crypto = require('crypto');

// ?? IP Hashing (GDPR-safe) ????????????????????????????????????????????????
const RISK_SECRET_SALT = process.env.SECRET_SALT;
if (!RISK_SECRET_SALT) {
  throw new Error('[risk] SECRET_SALT environment variable is required');
}

const hashIp = (ip) => {
  return crypto.createHmac('sha256', RISK_SECRET_SALT).update(ip).digest('hex');
};

// [Discovery 4 fix] Prefix للـ synthetic per-order device fingerprint
// اللي بيتصنّع في /woocommerce-webhook لما مفيش fingerprint حقيقي متاح
// (تجار بدون JS pixel كامل، زي Classic Checkout). مركزّة هنا كمصدر واحد
// عشان المكانين اللي لازم يتفقوا عليها — نقطة البناء (fallback)، ونقطة
// الاستثناء في استعلام device-rotation — ميتفرقوش عن بعض بمرور الوقت.
const WC_SYNTHETIC_DEVICE_PREFIX = 'wc_';
// ?????????????????????????????????????????????????????????????????????????
const logger = require('../lib/logger');
const express = require('express');
const router = express.Router();
const { calculateRiskScore } = require('../lib/riskScoring');
const { checkVelocity, recordFailedAttempt } = require('../lib/velocityDetector');
const { checkBINSequence } = require('../lib/binSequenceDetector');
const db = require('../lib/db');
const emergencyPause = require('../lib/emergencyPause');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const { hashApiKey } = require('../lib/apiKeyHash');
const { normalizeBin } = require('../lib/binIntelligence');
const { checkEmailHardBlock } = require('../lib/emailIntelligence');
const { recordAndCheckGlobalRotation } = require('../lib/globalRotationDetector');
const { checkRawDeviceVelocity, checkRawIpVelocityFallback } = require('../lib/rawVelocityDetector');
const { shouldIncrementQuota } = require('../lib/quotaDedup');
const { buildGraphFromOrder } = require('../lib/identityGraph');const prometheus = require('../lib/prometheus');

const { domainAuthMiddleware, domainAuthMiddlewareWithAutoRegister, normalizeDomain, resolveStoreIdBestEffort } = require('../lib/domainAuth');
const autoRegisterStoreMiddleware = require('../middleware/autoRegisterStore');const { notifyBINSequenceAlert }               = require('../lib/notify');
const { isAgency, FREE_PLANS, getStoreScope }   = require('../lib/planAccess');
const { checkQuotaGate }                        = require('../lib/quotaGate');
const { mintDeviceToken, verifyDeviceToken }     = require('../lib/deviceToken');
const { isPlausibleClientIp, normalizeEmail }    = require('../lib/utils');
const { getCloudflareRanges }                    = require('../lib/cloudflareRanges');
const { safeErrorPayload }                       = require('../lib/errorResponse');

// [Bug #7 fix, relocated] المنطق نُقل لـ lib/blacklistGate.js عشان يبقى
// مصدر واحد يستخدمه هذا الملف (POST /blacklist, POST /whitelist, 0b
// gate, webhook gate الجديدة) وكمان riskScoring.js (الـ inBlacklist
// defense-in-depth check). راجع blacklistGate.js للتعليق الكامل.
const { computeNormalizedValue, findBlacklistMatch } = require('../lib/blacklistGate');

// ── Early Access Pro Grant ────────────────────────────────────────────────
// Marketing promise (index.html): "Early Access cohort members receive
// 3 months of Shield Pro at no cost." Applied at registration time only —
// see /tenants/register below. EARLY_ACCESS_END_DATE is optional; if unset,
// the promo has no cutoff and applies to every new registration.
// Early Access promo removed — every new registration starts free.

// ── BIN Sequence Alert Persistence ───────────────────────────────────────
const persistBinSequenceAlert = async (tenantId, bin, binSeq, storeId = null) => {
  if (!tenantId) return; // webhook بدون tenant — TODO: ربط webhook بالـ tenant
  try {
    const prefix     = String(bin).replace(/\D/g, '').slice(0, 4);
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

    const existing = await db.binSequenceAlert.findFirst({
      where: {
        tenantId,
        binPrefix: prefix,
        status:    'active',
        detectedAt: { gte: oneHourAgo },
      },
    });

    if (existing) {
      // storeId is deliberately NOT touched on increment — the detection
      // window (binSequenceDetector.js) is tenant-wide/pooled by design, so
      // a single alert row can legitimately be incremented by requests from
      // several stores. storeId records only which store's request FIRST
      // created this alert, not a claim that the whole attack is confined
      // to one store.
      await db.binSequenceAlert.update({
        where: { id: existing.id },
        data:  { cardsCount: { increment: 1 } },
      });
    } else {
      const newAlert = await db.binSequenceAlert.create({
        data: {
          tenantId,
          storeId:       storeId ?? null,
          binPrefix:     prefix,
          layer:         binSeq.layer    || 0,
          reason:        binSeq.reason   || 'BIN sequence detected',
          cardsCount:    1,
          entitiesCount: 1,
          riskAddition:  binSeq.riskAddition || 0,
          status:        'active',
        },
      });

      // إشعار التاجر — fire-and-forget مع cooldown
      const tenant = await db.tenant.findUnique({
        where:  { id: tenantId },
        select: { id: true, email: true, webhookUrl: true, webhookType: true, plan: true },
      });
      if (tenant) {
        notifyBINSequenceAlert(tenant, newAlert)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BIN notification failed'));
      }
    }
  } catch (err) {
    logger.error({ module: 'risk', err: err.message }, 'persistBinSequenceAlert failed');
  }
};

const { requireAuth } = require('../middleware/authenticate');
const verifyHmacSignature = require('../middleware/verifyHmac');
const { isProOrAbove } = require('../lib/planAccess');

const apiKeyAuth = requireAuth({
  id: true, email: true, isActive: true, emailVerified: true, webhookSecret: true,
  countryOverrides: true, plan: true, subscriptionStatus: true, subscriptionEndDate: true,
  monthlyBlockedCount: true, quotaResetDate: true, fraudIsolationMode: true,
});

// Shared auth middleware for the WooCommerce webhook, reusing the same
// centralized requireAuth() the rest of the file uses, instead of a manual
// resolveTenantByApiKey/isActive/emailVerified copy (CWE-1059 drift fix).
const webhookAuth = requireAuth({ id: true, isActive: true, emailVerified: true, plan: true, monthlyBlockedCount: true, quotaResetDate: true, fraudIsolationMode: true, webhookSecret: true });

// Invokes an Express-style middleware inline and resolves true/false
// depending on whether next() was called or the middleware sent its own
// response (e.g. requireAuth's 401/403). Needed because the webhook route
// can't take requireAuth as a normal router-level middleware — it must run
// after the raw-body buffer is already on req.body.
const runAuthMiddleware = (req, res, mw) => new Promise((resolve) => {
  let settled = false;
  res.once('finish', () => { if (!settled) { settled = true; resolve(false); } });
  mw(req, res, () => { if (!settled) { settled = true; resolve(true); } });
});
// ── recordBlockedAttempt Helper ──────────────────────────────────────────
// Shared by all four /evaluate block paths (blacklist, velocity, BIN
// sequence, risk-scoring) so every backend-authoritative block decision
// creates a BlockedAttempt row AND increments monthlyBlockedCount in the
// same atomic transaction. Accepts the Prisma client (db, or an
// interactive tx) and returns an array of unexecuted query promises meant
// to be passed straight into db.$transaction([...]).
const recordBlockedAttempt = (tx, {
  merchantId,
  reason,
  ipHash = null,
  cardBin = null,
  cardType = null,
  riskScore = null,
  amountAttempted = null,
  storeId = null,
  // Quota-dedup fix: when false (see lib/quotaDedup.js), this block is a
  // repeat from an entity already blocked for the same reason within the
  // dedup window — the BlockedAttempt row is still written for dashboard/
  // audit purposes, but monthlyBlockedCount is NOT incremented again.
  // Defaults to true so any caller that doesn't pass it gets the original,
  // unconditional-increment behavior.
  incrementQuota = true,
}) => {
  const ops = [
    tx.blockedAttempt.create({
      data: {
        tenantId:        merchantId,
        storeId:         storeId ?? null,
        cardBin:         cardBin ?? null,
        cardType:        cardType ?? null,
        reason,
        ipHash:          ipHash ?? null,
        amountAttempted: amountAttempted ?? null,
        riskScore:       riskScore ?? null,
      },
    }),
  ];

  if (incrementQuota) {
    ops.push(
      tx.tenant.update({
        where: { id: merchantId },
        data:  { monthlyBlockedCount: { increment: 1 } },
      })
    );
  }

  return ops;
};

// ── POST /risk/device-token ──────────────────────────────────────────────
// Mints a server-signed device token for the WooCommerce plugin to store
// as an HttpOnly cookie (chargeguard_dt). See src/lib/deviceToken.js for
// the rationale. Rate-limited per-tenant so a compromised/misbehaving
// plugin install can't hammer this into a token-minting DoS vector.
const DEVICE_TOKEN_RATE = new Map(); // keyed on tenant id
const DT_MAX_REQ   = 30;
const DT_WINDOW_MS = 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of DEVICE_TOKEN_RATE.entries()) {
    if (now - rec.firstAt > DT_WINDOW_MS) DEVICE_TOKEN_RATE.delete(key);
  }
}, DT_WINDOW_MS).unref();

const deviceTokenRateLimit = (req, res, next) => {
  const key = req.tenant?.id || req.ip || 'unknown';
  const now = Date.now();
  const rec = DEVICE_TOKEN_RATE.get(key);
  if (rec) {
    if (now - rec.firstAt > DT_WINDOW_MS) {
      DEVICE_TOKEN_RATE.delete(key);
    } else if (rec.count >= DT_MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    DEVICE_TOKEN_RATE.set(key, { count: 1, firstAt: now });
  }
  next();
};

// deviceTokenRateLimit runs BEFORE domain resolution, keyed on
// req.tenant?.id — unaffected by the change below.
//
// domainAuthMiddlewareWithAutoRegister (in place of domainAuthMiddleware)
// + autoRegisterStoreMiddleware (after verifyHmacSignature) closes the
// "brand-new store's first visitor never gets a device token" gap: for
// Agency tenants (or any tenant with Store rows) whose domain has no
// Store row yet, this defers the domain-binding decision until AFTER the
// HMAC signature is verified — the same "Solution D" pattern already
// used on /evaluate and /blocked-attempt — then auto-registers the Store
// from that signature-verified domain. Non-Agency tenants are completely
// unaffected: they still resolve via the tenant.allowedDomains fallback
// inside domainAuthCore, exactly as before. No new unauthenticated
// store-creation path is introduced — auto-registration only ever fires
// after the request has already proven possession of this tenant's
// webhookSecret.
router.post('/device-token', apiKeyAuth, deviceTokenRateLimit, domainAuthMiddlewareWithAutoRegister, verifyHmacSignature, autoRegisterStoreMiddleware, async (req, res) => {
  try {
    const rawIp = typeof req.body.ip === 'string' ? req.body.ip : '';
    // Never bind a device token to a private/reserved or unverified
    // Cloudflare-edge IP — see isPlausibleClientIp() in lib/utils.js. Doing
    // so would make ipMatches:true a false trust signal for every visitor
    // who happens to share that same non-unique address, rather than a
    // genuine per-visitor correlation.
    const ipCheck = isPlausibleClientIp(rawIp);
    const ip = ipCheck.ok ? rawIp.trim() : '';
    if (!ipCheck.ok && rawIp) {
      logger.warn({ module: 'risk', endpoint: 'device-token', tenantId: req.tenant?.id, reason: ipCheck.reason }, 'Implausible ip on device-token mint — minting without IP binding');
    }
    const token = mintDeviceToken(ip);
    return res.status(200).json({ token });
  } catch (err) {
    logger.error({ module: 'risk', endpoint: 'device-token', error: err.message }, 'Failed to mint device token');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ── GET /risk/cloudflare-ranges ───────────────────────────────────────────
// Single source of truth for Cloudflare's published IP ranges (see
// lib/cloudflareRanges.js, which owns the daily fetch/cache). The
// WooCommerce plugin's WP-Cron job (ChargeGuard_Trusted_Proxy::
// refresh_cf_ranges()) polls this instead of hitting cloudflare.com
// directly, so both systems ultimately derive their ranges from this one
// backend fetch — eliminating the drift risk between the plugin's and
// backend's previously-independent hardcoded copies. Protected by the
// same auth stack as the other internal endpoints (e.g. /device-token):
// API key, domain binding, HMAC signature.
router.get('/cloudflare-ranges', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, (req, res) => {
  try {
    return res.status(200).json({ ranges: getCloudflareRanges() });
  } catch (err) {
    logger.error({ module: 'risk', endpoint: 'cloudflare-ranges', error: err.message }, 'Failed to return Cloudflare ranges');
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

/**
 * @swagger
 * /risk/evaluate:
 *   post:
 *     summary: Evaluate an order for fraud risk
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/EvaluateRequest'
 *     responses:
 *       200:
 *         description: Risk assessment result
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/EvaluateResponse'
 *       400:
 *         description: Missing required fields
 *       403:
 *         description: Blocked (blacklist or velocity)
 *       500:
 *         description: Internal server error
 */
router.post('/evaluate', apiKeyAuth, domainAuthMiddlewareWithAutoRegister, verifyHmacSignature, autoRegisterStoreMiddleware, async (req, res) => {
  try {
    // ── -1. Emergency Pause Check — the very first thing in the handler,
    // before any DB query or detection logic. Pure in-memory read (see
    // lib/emergencyPause.js) — deliberately ahead of even the quota gate,
    // so a paused tenant doesn't pay for a single DB round trip on the
    // highest-traffic endpoint in this file. Does NOT touch /enrich or
    // /woocommerce-webhook — see emergencyPause.js's module comment.
    const pauseState = emergencyPause.isPaused(req.tenant.id);
    if (pauseState.paused) {
      logger.warn(
        { module: 'risk', endpoint: 'evaluate', merchantId: req.tenant.id, scope: pauseState.scope, expiresAt: pauseState.expiresAt },
        'Emergency pause active — auto-approving without running detection'
      );
      return res.json({
        orderId: req.body?.orderId || null,
        score: 0,
        decision: 'approve',
        flags: [{ severity: 'warning', text: 'Emergency override active — all orders are being approved' }],
        connectedRisk: 0,
        scored: false,
        emergencyPause: pauseState.scope, // 'global' | 'tenant'
      });
    }

    // ── 0. Subscription & Quota Status ───────────────────────────────────
    // NOTE: this no longer short-circuits the request. Quota only decides
    // whether calculateRiskScore() below is allowed to call expensive
    // external intel APIs (IP/email/BIN). Blacklist, velocity, BIN-sequence,
    // identity graph, and pattern-sharing checks always run, and the order
    // can still be blocked purely on their output — closing the "burn the
    // quota, then everything approves" bypass.
    const quotaStatus = await checkQuotaGate(req, 'evaluate');
    const limitedScoring = quotaStatus.exceeded;
    // ── End Subscription & Quota Status ──────────────────────────────────

    // ������� ��������
    const { orderId, ipAddress: rawIpAddress, email, bin, deviceFingerprint, amount, billingCountry, shippingCountry, isNewCustomer, deviceToken } = req.body;
    // merchantId is derived from the authenticated tenant (CWE-639 / OWASP API1:2023 fix).
    // It is never read from the request body or x-merchant-id header.
    const merchantId = req.tenant.id;

    // Defense-in-depth (see lib/utils.js isPlausibleClientIp() and the
    // WooCommerce plugin's ChargeGuard_Trusted_Proxy redesign): this
    // backend does not trust get_client_ip()'s output blindly. A private/
    // reserved IP, or an unverified Cloudflare edge IP, getting used
    // as-is here would corrupt every IP-anchored control below —
    // whitelist/blacklist matching, velocity counting, and identity-graph
    // anchoring — usually by silently collapsing many distinct visitors
    // onto one address. Gating ONCE here, rather than at each of those
    // call sites, is sufficient because every downstream use of
    // `ipAddress` in this file already null-guards correctly
    // (`ipAddress ? ... : null` / `: 0`) — nulling it out here flows
    // through cleanly with no further changes needed. This never blocks
    // the order by itself; it only excludes IP from this evaluation's
    // signals and is recorded in signalsSnapshot.ipAnomaly for visibility.
    const ipPlausibility = isPlausibleClientIp(rawIpAddress);
    const ipAddress = ipPlausibility.ok ? rawIpAddress.trim() : null;
    const ipAnomaly = ipPlausibility.ok ? null : ipPlausibility.reason;
    if (ipAnomaly) {
      logger.warn(
        { module: 'risk', endpoint: 'evaluate', merchantId, orderId, ipAnomaly },
        'ipAddress failed plausibility check — excluding from IP-based detection for this request'
      );
    }

    // Tier-1 fraud-isolation scope (opt-in). {} unless this tenant is in
    // 'per_store' mode AND req.storeId was resolved by domainAuthMiddleware —
    // see getStoreScope() in planAccess.js. Deliberately NOT applied to
    // checkBINSequence() or buildGraphFromOrder() below (Tier 2, always pooled).
    const storeScope = getStoreScope(req.tenant, req.storeId);


        // Idempotency: ������ �� ������� ������� ���� ��� 5 �����
    const idempotencyWindow = 5 * 60 * 1000; // 5 �����
    const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId } },
      select: { merchantId: true, decision: true, riskScore: true, connectedRisk: true, signalsSnapshot: true, createdAt: true }
    });
    // Defense-in-depth (C3): the compound key above already scopes this
    // lookup to this tenant, so existingOrder.merchantId !== merchantId
    // should be unreachable — but asserting it explicitly costs nothing
    // and mirrors /enrich's existing check, guarding against any future
    // regression (e.g. someone simplifying this back to a bare orderId).
    if (existingOrder && existingOrder.merchantId !== merchantId) {
      logger.error({ module: 'risk', endpoint: 'evaluate', merchantId, orderId }, 'C3 guard tripped — compound key returned a different merchant\'s row; should be unreachable');
      return res.status(403).json({ error: 'Merchant ID mismatch.' });
    }
    if (existingOrder && (Date.now() - new Date(existingOrder.createdAt).getTime()) < idempotencyWindow) {
      // ����� ���� ������
      const oldSnapshot = existingOrder.signalsSnapshot ? JSON.parse(existingOrder.signalsSnapshot) : {};
      prometheus.recordIdempotencyHit();
      return res.json({
        orderId,
        score: existingOrder.riskScore,
        decision: existingOrder.decision,
        flags: oldSnapshot.flags || [],
        connectedRisk: existingOrder.connectedRisk || 0,
        cached: true
      });
    }

    logger.debug({ module: 'risk', orderId, bin, deviceFingerprint, merchantId }, 'Received evaluate request');

      

    // [Bug #7 fix] يُحسب مرة واحدة، يُستخدم في whitelist/blacklist/disputes
    // تحت. undefined (مش null) عمدًا لما email غايب — Prisma بيتجاهل شروط
    // undefined في الـ where تلقائيًا، بنفس سلوك email الخام الأصلي.
    const normalizedEmailForMatch = email ? normalizeEmail(email) : undefined;
    // [Discovery 2 fix] نفس مبدأ normalizedEmailForMatch بالحرف — يُحسب
    // مرة واحدة، يُستخدم في whitelist (0a تحت) وblacklist (0b) معًا، بدل
    // تكرار String(bin).replace(...) منفصل في أكتر من مكان.
    const normalizedBinForMatch = bin ? String(bin).replace(/\D/g, '').slice(0, 6) : undefined;

    // 0a. Whitelist Check — bypass all checks for trusted entities
    const whitelistConditions = [];
    if (normalizedEmailForMatch) whitelistConditions.push({ type: 'EMAIL', normalizedValue: normalizedEmailForMatch });
    if (ipAddress)               whitelistConditions.push({ type: 'IP',    value: ipAddress });
    if (normalizedBinForMatch)   whitelistConditions.push({ type: 'BIN',   value: normalizedBinForMatch });

    if (whitelistConditions.length > 0) {
      const whitelistCheck = await db.whitelistEntry.findFirst({
        where: {
          merchantId,
          ...storeScope,
          OR: whitelistConditions,
          AND: [{ OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } }
          ]}]
        }
      });

      if (whitelistCheck) {
        prometheus.recordWhitelistBypass(whitelistCheck.type);
        logger.info(
          { module: 'risk', merchantId, type: whitelistCheck.type, orderId },
          'Request bypassed all checks — whitelisted'
        );
        return res.json({
          orderId,
          score: 0,
          decision: 'approve',
          flags:    [],
          connectedRisk: 0,
          whitelisted: true
        });
      }
    }

    // 0b. Blacklist Check — منطق الاستعلام دلوقتي جوه lib/blacklistGate.js
    // (مصدر واحد، يستخدمه كمان /woocommerce-webhook's gate تحت).
    // [Discovery 2 fix] bin مُضافة — كانت غايبة من هذا الفحص خالص، بالرغم
    // من إن الـ schema بيدعمها (BlacklistEntry.type='BIN') والـ whitelist
    // فوق بالفعل بتفحصها. راجع blacklistGate.js's findBlacklistMatch.
    const blacklistCheck = await findBlacklistMatch(db, {
      merchantId,
      storeScope,
      normalizedEmail: normalizedEmailForMatch,
      ip: ipAddress,
      deviceFingerprint,
      bin: normalizedBinForMatch,
    });
    if (blacklistCheck) {
      prometheus.recordBlacklistHit(blacklistCheck.type);

      let blacklistCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) blacklistCardBin = b;
      }
      let blacklistCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        blacklistCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }
      const blacklistIpHash = ipAddress ? hashIp(ipAddress) : null;
      let blacklistAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) blacklistAmount = amt;
      }

       try {
        // Dedup entity: the blacklist row's own matched value (email, IP,
        // or device fingerprint) — whichever actually triggered this hit —
        // is the most precise identity to dedupe repeat blocks on.
        const blacklistIncrementQuota = shouldIncrementQuota(merchantId, 'blacklist', blacklistCheck.value);

        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         blacklistCardBin,
          cardType:        blacklistCardType,
          reason:          'blacklist',
          ipHash:          blacklistIpHash,
          amountAttempted: blacklistAmount,
          riskScore:       null,
          incrementQuota:  blacklistIncrementQuota,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'evaluate', path: 'blacklist', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (blacklist path)'
        );
      }
       return res.status(403).json({
        error: 'Request blocked: entity is blacklisted',
        reason: blacklistCheck.reason || 'Blacklisted',
        decision: 'block'
      });
    }

    // 0c. Email Hard-Block — disposable domain / no-MX. Deliberately calls
    // checkEmailHardBlock() directly rather than going through
    // calculateRiskScore()'s getEmailIntelligence() call, so this runs even
    // when limitedScoring is true (quota exhausted). Placed after blacklist
    // (cheapest possible reject first) and before velocity/BIN/rotation,
    // per the same "cheapest, most definitive gate first" ordering already
    // used by the other hard gates in this handler.
    if (email) {
      const emailHardBlock = await checkEmailHardBlock(email);
      if (emailHardBlock.blocked) {
        let emailBlockCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) emailBlockCardBin = b;
        }
        let emailBlockCardType = null;
        if (req.body.cardType != null) {
          const ct = String(req.body.cardType).toLowerCase().trim();
          emailBlockCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
        }
        const emailBlockIpHash = ipAddress ? hashIp(ipAddress) : null;
        let emailBlockAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) emailBlockAmount = amt;
        }

      try {
          const emailIncrementQuota = shouldIncrementQuota(merchantId, 'email', email);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         emailBlockCardBin,
            cardType:        emailBlockCardType,
            reason:          'email',
            ipHash:          emailBlockIpHash,
            amountAttempted: emailBlockAmount,
            riskScore:       null,
            incrementQuota:  emailIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'email_hard_block', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (email hard-block path)'
          );
        }
        return res.status(403).json({
          error: 'Request blocked: email address failed validation',
          reason: 'email_hard_block',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'email_hard_block' }]
        });
      }
    }

    // 1. فحص السرعة (Velocity Check)
    const velocityCheck = await checkVelocity({ ip: ipAddress, deviceFingerprint, merchantId, storeId: storeScope.storeId ?? null });

    // Observability only — checkVelocity() now degrades to a local
    // in-memory fallback rather than failing open on a DB error (see
    // velocityDetector.js). This does not change control flow here:
    // velocityCheck.blocked (from either the authoritative or the
    // fallback path) is handled identically below, exactly as before.
    if (velocityCheck.dbError) {
      logger.warn(
        { module: 'risk', endpoint: 'evaluate', merchantId, fallbackBlocked: velocityCheck.blocked },
        'Velocity check ran in degraded mode — CardTestAttempt query failed, local fallback used'
      );
      try {
        if (typeof prometheus.recordVelocityDbError === 'function') {
          prometheus.recordVelocityDbError();
        }
      } catch (metricErr) {
        // Metrics must never affect request handling.
      }
    }

    if (velocityCheck.blocked) {
      let velocityCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) velocityCardBin = b;
      }
      let velocityCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        velocityCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }
      const velocityIpHash = ipAddress ? hashIp(ipAddress) : null;
      let velocityAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) velocityAmount = amt;
      }

           try {
        const velocityIncrementQuota = shouldIncrementQuota(merchantId, 'velocity', deviceFingerprint || ipAddress);

        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         velocityCardBin,
          cardType:        velocityCardType,
          reason:          'velocity',
          ipHash:          velocityIpHash,
          amountAttempted: velocityAmount,
          riskScore:       null,
          incrementQuota:  velocityIncrementQuota,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'evaluate', path: 'velocity', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (velocity path)'
        );
      }

      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        reason: 'velocity_blocked',
        decision: 'block'
      });
    }

    // 1b. BIN Sequence Detection
    if (bin) {
      // tenantId is required here for tenant-scoped storage in
      // binSequenceDetector.js — without it, attacks against one tenant
      // could false-block a different tenant's legitimate customers (CWE-653).
      const binSeq = await checkBINSequence({ tenantId: req.tenant.id, bin, ipAddress, deviceFingerprint });
      // L-fix: layer 0 means an existing active block is still rejecting
      // requests — not a newly detected BIN pattern. Persisting here on
      // every layer-0 hit inflated cardsCount with repeat rejections during
      // the block window instead of genuine distinct BINs. The real alert
      // was already created/incremented at the moment the actual trigger
      // (layer 1/2/3) fired — skip persistence for layer 0.
      if (binSeq.layer !== 0 && (binSeq.blocked || binSeq.riskAddition > 0)) {
        persistBinSequenceAlert(req.tenant.id, bin, binSeq, req.storeId ?? null)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BinSequenceAlert persist failed'));
      }

      if (binSeq.blocked) {
        let binSeqCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) binSeqCardBin = b;
        }
        let binSeqCardType = null;
        if (req.body.cardType != null) {
          const ct = String(req.body.cardType).toLowerCase().trim();
          binSeqCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
        }
        const binSeqIpHash = ipAddress ? hashIp(ipAddress) : null;
        let binSeqAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) binSeqAmount = amt;
        }

 try {
          const binSeqIncrementQuota = shouldIncrementQuota(req.tenant.id, 'card_testing', binSeqCardBin || bin);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId:      req.tenant.id,
            storeId:         req.storeId ?? null,
            cardBin:         binSeqCardBin,
            cardType:        binSeqCardType,
            reason:          'card_testing',
            ipHash:          binSeqIpHash,
            amountAttempted: binSeqAmount,
            riskScore:       null,
            incrementQuota:  binSeqIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'bin_sequence', tenantId: req.tenant.id, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (BIN sequence path)'
          );
        }
        return res.status(403).json({
          error: 'Request blocked due to suspicious card testing pattern',
          reason: 'bin_sequence_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'bin_sequence_blocked' }]
        });
      }
    }

    // 1c. Device Fingerprint Trust & Rotation Detection
    // deviceSignal.trust classifies how much weight the device-anchored
    // signals in calculateRiskScore()/identityGraph.js should carry this
    // request — see deviceToken.js and the deviceTrustFactor logic in
    // riskScoring.js. rotationBlocked mirrors checkVelocity/checkBINSequence:
    // an attacker generating many fresh, forged fingerprints from one IP
    // is itself a detectable pattern, independent of whether any single
    // fingerprint can be verified.
    const deviceSignal = { trust: 'unsigned', ipMatches: null, rotationCount: 0 };

    if (deviceToken) {
      const verification = verifyDeviceToken(deviceToken, ipAddress);
      if (verification.valid) {
        deviceSignal.trust = verification.ipMatches ? 'signed' : 'signed_ip_mismatch';
        deviceSignal.ipMatches = verification.ipMatches;
      } else {
        deviceSignal.trust = 'invalid_token';
      }
    }

    if (ipAddress) {
      const ROTATION_WINDOW_MS = 60 * 60 * 1000; // 1 hour — matches deviceVelocityCount's own window elsewhere
      const ROTATION_BLOCK_THRESHOLD = 6; // 6+ distinct device fingerprints from one IP in 1h
      const rotationWindowStart = new Date(Date.now() - ROTATION_WINDOW_MS);

      // [Synthetic-ID pollution fix] راجع تعليق /woocommerce-webhook's قسم
      // 7c لنفس الفيكس بالحرف — أوردرات وصلت عبر الـ webhook من غير
      // fingerprint حقيقي مخزّنة بـ deviceFingerprint = `wc_<orderId>`
      // (فريدة لكل أوردر بالتصميم). Order table مشترك بين /evaluate
      // وwebhook، فأي IP جالها أوردر واحد بس عبر الـ webhook fallback كان
      // بيضيف "device مختلف" وهمي هنا في كل مرة.
      const recentDevicesForIp = await db.order.findMany({
        where: {
          merchantId, ...storeScope,
          ipAddress,
          createdAt: { gte: rotationWindowStart },
          deviceFingerprint: { not: null },
          NOT: { deviceFingerprint: { startsWith: WC_SYNTHETIC_DEVICE_PREFIX } },
        },
        select: { deviceFingerprint: true },
        distinct: ['deviceFingerprint'],
        take: 50,
      });
      const seenThisOne = deviceFingerprint && recentDevicesForIp.some(d => d.deviceFingerprint === deviceFingerprint);
      deviceSignal.rotationCount = recentDevicesForIp.length + (deviceFingerprint && !seenThisOne ? 1 : 0);

      if (deviceSignal.rotationCount >= ROTATION_BLOCK_THRESHOLD) {
        let rotCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) rotCardBin = b;
        }
        const rotIpHash = hashIp(ipAddress);
        let rotAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) rotAmount = amt;
        }

         try {
          // Keyed on ipAddress — this gate's own detection basis (distinct
          // fingerprints from one IP), so repeat blocks from the same IP
          // don't re-count, but a different IP rotating fingerprints still does.
          const rotIncrementQuota = shouldIncrementQuota(merchantId, 'device_rotation_ip', ipAddress);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         rotCardBin,
            cardType:        null,
            reason:          'velocity', // reuses the existing VALID_REASONS enum — conceptually a velocity pattern
            ipHash:          rotIpHash,
            amountAttempted: rotAmount,
            riskScore:       null,
            incrementQuota:  rotIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'device_rotation', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (device rotation path)'
          );
        }
               return res.status(403).json({
          error: 'Request blocked due to suspicious device fingerprint rotation',
          reason: 'device_rotation_ip_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_rotation_ip_blocked' }]
        });
      }
    }

    // 1c-ii. Global (Merchant-Scoped) Device Rotation Detection — complements
    // the per-IP check above rather than replacing it. Runs independently of
    // ipAddress: it tracks how fast entirely NEW fingerprints are appearing
    // for this merchant, so an attacker who rotates IP and fingerprint
    // together (defeating the per-IP check, which never sees more than 1
    // fingerprint per IP) still trips this one. In-memory, zero DB calls —
    // see lib/globalRotationDetector.js for the counter and its tradeoffs.
    if (deviceFingerprint) {
      const globalRotation = recordAndCheckGlobalRotation(merchantId, deviceFingerprint);

      if (globalRotation.blocked) {
        let globalRotCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) globalRotCardBin = b;
        }
        const globalRotIpHash = ipAddress ? hashIp(ipAddress) : null;
        let globalRotAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) globalRotAmount = amt;
        }

       try {
          const globalRotIncrementQuota = shouldIncrementQuota(merchantId, 'device_rotation_global', deviceFingerprint);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         globalRotCardBin,
            cardType:        null,
            reason:          'device_rotation_global',
            ipHash:          globalRotIpHash,
            amountAttempted: globalRotAmount,
            riskScore:       null,
            incrementQuota:  globalRotIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'device_rotation_global', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (global device rotation path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious device fingerprint rotation across the merchant',
          reason: 'device_rotation_global_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_rotation_global_blocked' }]
        });
      }
    }
    // End 1c. Device Fingerprint Trust & Rotation Detection

    // 1d. Raw (Unconditional) Device Velocity — يقفل الفجوة اللي سايبها
    // checkVelocity() فوق: ده بيشوف بس المحاولات اللي مش approve. بوت
    // بثابت الـ device fingerprint وبيلف على BIN prefixes مختلفة، وبياخد
    // سكور واطي كفاية إنه approve في أغلب المرات — مش هيظهر في
    // checkVelocity أبدًا مهما كان عدد محاولاته. راجع
    // lib/rawVelocityDetector.js للتفاصيل الكاملة عن ليه device بس (مش
    // IP) هو المفتاح الصح هنا.
    if (deviceFingerprint) {
      const rawDeviceVelocity = checkRawDeviceVelocity(merchantId, deviceFingerprint);
      if (rawDeviceVelocity.blocked) {
        let rawVelCardBin = null;
        if (bin != null) {
          const b = String(bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) rawVelCardBin = b;
        }
        const rawVelIpHash = ipAddress ? hashIp(ipAddress) : null;
        let rawVelAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) rawVelAmount = amt;
        }

        try {
          const rawVelIncrementQuota = shouldIncrementQuota(merchantId, 'raw_device_velocity', deviceFingerprint);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         rawVelCardBin,
            cardType:        null,
            reason:          'velocity',
            ipHash:          rawVelIpHash,
            amountAttempted: rawVelAmount,
            riskScore:       null,
            incrementQuota:  rawVelIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'raw_device_velocity', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (raw device velocity path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious request velocity',
          reason: 'device_velocity_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_velocity_blocked' }]
        });
      }
    } else if (ipAddress) {
      // Fallback — بس لما مفيش deviceFingerprint خالص. عتبة أعلى بكتير
      // عشان نتجنب false positives على شبكات NAT/مكاتب مشتركة.
      const rawIpHash = hashIp(ipAddress);
      const rawIpVelocity = checkRawIpVelocityFallback(merchantId, rawIpHash);
      if (rawIpVelocity.blocked) {
        let rawIpVelAmount = null;
        if (amount != null) {
          const amt = parseFloat(amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) rawIpVelAmount = amt;
        }

        try {
          const rawIpVelIncrementQuota = shouldIncrementQuota(merchantId, 'raw_ip_velocity', ipAddress);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         null,
            cardType:        null,
            reason:          'velocity',
            ipHash:          rawIpHash,
            amountAttempted: rawIpVelAmount,
            riskScore:       null,
            incrementQuota:  rawIpVelIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'evaluate', path: 'raw_ip_velocity_fallback', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (raw IP velocity fallback path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious request velocity',
          reason: 'ip_velocity_fallback_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'ip_velocity_fallback_blocked' }]
        });
      }
    }
    // End 1d. Raw (Unconditional) Device Velocity

    // 1. ���� ���� order
    const order = {
      id: orderId,
      email: email,
      ipAddress: ipAddress,
      deviceFingerprint: deviceFingerprint,
      deviceId: deviceFingerprint,
      amount: amount,
      billingAddress: billingCountry ? JSON.stringify({ country: billingCountry }) : null,
      shippingAddress: shippingCountry ? JSON.stringify({ country: shippingCountry }) : null,
      customerLoginId: req.body.customerLoginId || null,
      createdAt: new Date().toISOString(),
      eciCode: null,
      avsResponse: null,
      cvv2Response: null,
      payment_details: bin ? { card_bin: bin } : null,
      fingerprintVersion: 'v3',
      fingerprintConfig: null,
      fingerprintHardware: null,
      isNewCustomer: isNewCustomer || false,
    };

    // 2. ����� �������� ��������
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // ��� ������� ������� �� ����� ��������
    // ��� ��� 200 ��� ��� ����� ��������� (���� ����)
    const recentOrders = await db.order.findMany({
      where: { merchantId, ...storeScope, createdAt: { gte: last7days } },
      orderBy: { createdAt: 'desc' },
      take: 200
    });

    const formattedOrders = recentOrders.map(o => ({
      id: o.orderId,
      email: o.email,
      ipAddress: o.ipAddress,
      deviceFingerprint: o.deviceFingerprint,
      deviceId: o.deviceFingerprint,
      amount: o.amount,
      createdAt: o.createdAt,
      riskLevel: o.riskLevel,
      // [BIN Velocity fix] يدعم مسار الـ fallback في riskScoring.js
      // (لما externalVelocity مش شايل binVelocityCount*، زي enrichmentProcessor.js)
      cardBinPrefix: o.cardBinPrefix,
    }));

    // ���� ��� velocity counts �������� ��������� ������ (����)
    const last1h = new Date(Date.now() - 60 * 60 * 1000);
    const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const deviceVelocityCount = deviceFingerprint ? await db.order.count({
      where: { merchantId, ...storeScope, deviceFingerprint, createdAt: { gte: last1h } }
    }) : 0;

    const ipVelocityCount = ipAddress ? await db.order.count({
      where: { merchantId, ...storeScope, ipAddress, createdAt: { gte: last24h } }
    }) : 0;

    const emailVelocityCount = email ? await db.order.count({
      where: { merchantId, ...storeScope, email, createdAt: { gte: last6h } }
    }) : 0;

    // [BIN Velocity fix] cardBinPrefix للأوردر الحالي — نفس idiom الاستخراج
    // المستخدم بالفعل في كل مكان تاني في هذا الملف (blacklistCardBin،
    // emailBlockCardBin، إلخ) للاتساق. مفيش orderId يستثنى هنا لأن الأوردر
    // لسه معملوش upsert في الداتابيز في هذه المرحلة من الـ handler.
    let cardBinPrefixForVelocity = null;
    if (bin != null) {
      const b = String(bin).replace(/\D/g, '').slice(0, 6);
      if (b.length === 6) cardBinPrefixForVelocity = b;
    }

    // [BIN Velocity fix] 3 نوافذ زمنية دقيقة (DB-backed)، بنفس نمط
    // device/ip/email فوق بالظبط. Promise.all بدل sequential awaits —
    // تحسين أداء بسيط ومعزول، الاستعلامات مستقلة عن بعضها تمامًا.
    let binVelocityCount10min = 0;
    let binVelocityCount1h = 0;
    let binVelocityCount24h = 0;
    if (cardBinPrefixForVelocity) {
      const last10min = new Date(Date.now() - 10 * 60 * 1000);
      [binVelocityCount10min, binVelocityCount1h, binVelocityCount24h] = await Promise.all([
        db.order.count({ where: { merchantId, ...storeScope, cardBinPrefix: cardBinPrefixForVelocity, createdAt: { gte: last10min } } }),
        db.order.count({ where: { merchantId, ...storeScope, cardBinPrefix: cardBinPrefixForVelocity, createdAt: { gte: last1h } } }),
        db.order.count({ where: { merchantId, ...storeScope, cardBinPrefix: cardBinPrefixForVelocity, createdAt: { gte: last24h } } }),
      ]);
    }

    // ����� ��� ����� ��� computedSignals (���� ������� ��� riskScoring ������)
    // ����� ��������� ������ �� signalsSnapshot

    // ��� �������� ������� (��� 90 ���)
    // [Undefined-OR fix] Prisma بتتجاهل أي مفتاح قيمته undefined، فـ
    // deviceFingerprint (مفكوكة خام من req.body — undefined لو الـ
    // plugin مبعتش الحقل) أو normalizedEmailForMatch (undefined لو email
    // غايب) كانت بتحول فرعها جوه OR لشرط فاضي { order: {} } = صح دايمًا،
    // فترجّع أول 200 dispute لكل التاجر بدل المرتبطة بهذا الأوردر فقط.
    const disputeOrConditions = [];
    if (normalizedEmailForMatch) disputeOrConditions.push({ order: { normalizedEmail: normalizedEmailForMatch } });
    if (deviceFingerprint) disputeOrConditions.push({ order: { deviceFingerprint } });
    if (ipAddress) disputeOrConditions.push({ order: { ipAddress } });

    const disputes = disputeOrConditions.length > 0
      ? await db.disputeOutcome.findMany({
          where: {
            merchantId,
            resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) },
            OR: disputeOrConditions,
          },
          include: { order: true },
          take: 200,
        })
      : [];
    const blacklist = [];

    // 3. ���� ����� ������� ������ �����
    const orderForGraph = {
      deviceFingerprint: deviceFingerprint,
      deviceId: deviceFingerprint,
      email: email,
      ipAddress: ipAddress,
      shippingAddress: shippingCountry ? JSON.stringify({ country: shippingCountry }) : null,
      fingerprintVersion: 'v3',
    };

    try {
      await buildGraphFromOrder(orderForGraph, merchantId);
    } catch (err) {
      logger.error({ module: 'risk', action: 'buildGraphFromOrder', error: err.message }, 'Graph build error');
    }
        const evaluateStart = Date.now();

    // 4. ������� ���� ������� (�� ����� velocityCounts)
    const merchantConfig = {
      countryOverrides: req.tenant.countryOverrides || {},
      deviceSignal, // see riskScoring.js's deviceTrustFactor for how this is consumed
    };

    const riskResult = await calculateRiskScore(
      order,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      false,
      // [BIN Velocity fix] binVelocityCount10min/1h/24h مضافة — راجع
      // riskScoring.js لكيفية استهلاكها بدل allOrders.filter المكسورة.
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount, binVelocityCount10min, binVelocityCount1h, binVelocityCount24h },
      null,           // cardHashRecord — متاح فقط في /enrich
      merchantConfig,
      limitedScoring
    );

    // 5. ���� ���������
    const response = {
      orderId: orderId,
      score: riskResult.score,
      decision: riskResult.decision.includes('Approve') ? 'approve' :
                riskResult.decision.includes('Review') ? 'review' : 'block',
      flags: riskResult.flags,
      connectedRisk: 0,
      // `scored` is now always true — every request runs at least the
      // cheap, always-on detector set. `limitedScoring` is the new,
      // granular replacement for the old `scored:false`: it tells the
      // dashboard/plugin that external IP/email/BIN intelligence was
      // skipped for this request due to exhausted monthly quota, while
      // detection otherwise ran normally.
      scored: true,
      limitedScoring,
    };

    // ������� connectedRisk ������ �� ����� Identity Graph
  response.connectedRisk = riskResult.graphRisk || 0;
   // تسجيل المحاولة لتغذية checkVelocity() لاحقًا — على أي قرار مش approve
    // (يعني review أو block)، مش block بس. لو سجّلنا بس لما القرار يبقى
    // 'block'، أي نمط هجوم بيفضل عالق عند 'review' (بالظبط زي هجوم
    // الاختبار الحقيقي) مش هيغذي CardTestAttempt أبداً، وcheckVelocity()
    // تفضل عمياء عنه للأبد. التوسيع لـ 'review' يقفل الحلقة الدائرية من
    // غير ما نسجل كل أوردر approve عادي (الأغلبية الساحقة من الترافيك)،
    // فحجم الجدول يفضل متحكم فيه ومناسب لمدة الاحتفاظ 60 يوم.
    if (response.decision !== 'approve') {
      recordFailedAttempt({
        ip: ipAddress,
        deviceFingerprint,
        merchantId,
        storeId: storeScope.storeId ?? null,
        amount: amount || 0,
        wasBlocked: response.decision === 'block',
      });
    }

    // تسجيل الـ BlockedAttempt/quota — يفضل مربوط بـ block فقط عمدًا (مش
    // review)، لأنه عداد فوترة/تقرير فعلي لعدد "الهجمات المحجوبة"، ومش
    // المفروض يتوسع زي تسجيل الـ velocity فوق.
    if (response.decision === 'block') {
      // ── Quota Counter: coupled to the enforcement decision ─────────────
      // BlockedAttempt logging + monthlyBlockedCount increment happen here,
      // atomically, because this is the authoritative point where the block
      // decision is made — not in the separate, best-effort /blocked-attempt
      // call from the plugin, which can under-count under load (its own
      // 60/min rate limiter) or drop silently on network failure. The
      // counter must never depend on a less-trusted client's follow-up call
      // for a control that gates paid-tier revenue.
      let evalCardBin = null;
      if (bin != null) {
        const b = String(bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) evalCardBin = b;
      }

      let evalCardType = null;
      if (req.body.cardType != null) {
        const ct = String(req.body.cardType).toLowerCase().trim();
        evalCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
      }

      const evalIpHash = ipAddress ? hashIp(ipAddress) : null;

      let evalAmount = null;
      if (amount != null) {
        const amt = parseFloat(amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) evalAmount = amt;
      }

      let evalRiskScore = null;
      if (riskResult.score != null) {
        const rs = parseInt(riskResult.score, 10);
        if (!isNaN(rs) && rs >= 0 && rs <= 100) evalRiskScore = rs;
      }

       try {
        const patternIncrementQuota = shouldIncrementQuota(req.tenant.id, 'pattern', deviceFingerprint || ipAddress || email);

        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      req.tenant.id,
          storeId:         req.storeId ?? null,
          cardBin:         evalCardBin,
          cardType:        evalCardType,
          reason:          'pattern',
          ipHash:          evalIpHash,
          amountAttempted: evalAmount,
          riskScore:       evalRiskScore,
          incrementQuota:  patternIncrementQuota,
        }));
      } catch (counterErr) {
        // Logged, not fatal: a failed counter write shouldn't turn an
        // already-computed, correct block decision into a 500 for the
        // merchant. This is the one residual drift window in this design —
        // see write-up for the tradeoff.
        logger.error(
          { module: 'risk', endpoint: 'evaluate', tenantId: req.tenant.id, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter from /evaluate'
        );
      }
    }

    // 6. ��� ����� �� ����� ��������
    if (orderId) {
        const computed = riskResult.computedSignals || {};
      // ������� ����� �������� ������ �� externalVelocity (�������� �� ������)
      const deviceVelocityCountFinal = deviceVelocityCount;   // �� ���� ������
      const ipVelocityCountFinal = ipVelocityCount;           // �� ���� ������
      const emailVelocityCountFinal = emailVelocityCount;     // �� ���� ������
      const isNewCustomerComputed = computed.isNewCustomer || false;
      const amountAnomaly = (computed.orderMultiple || 0) >= 3;

      const shippingMismatchFlag = riskResult.flags.find(f => f.text === 'shipping_billing_mismatch');
      const shippingBillingMismatch = !!shippingMismatchFlag;

      const signalsSnapshot = {
        email,
        ipAddress,
        ipAnomaly,
        bin: bin || null,
        deviceFingerprint,
        amount,
        billingCountry,
        shippingCountry,
        isNewCustomer: isNewCustomerComputed,
        deviceVelocityCount: deviceVelocityCountFinal,
        ipVelocityCount: ipVelocityCountFinal,
        emailVelocityCount: emailVelocityCountFinal,
        // [BIN Velocity learning-loop fix] كانت غايبة تمامًا من الـ snapshot
        // رغم إنها بالفعل محسوبة فوق (binVelocityCount10min/1h/24h) ومُستخدمة
        // فعليًا في riskScoring.js لحساب العقوبة — يعني القرار كان بيتاخد
        // صح، لكن مفيش أي مسار للتعلّم منه لأن extractSignalsFromSnapshot()
        // (feedbackLoop.js) محتاجة الحقول دي هنا عشان تقدر تستخرجها.
        binVelocityCount10min,
        binVelocityCount1h,
        binVelocityCount24h,
        shippingBillingMismatch,
        binIssuerMismatch: riskResult.binIntel && riskResult.binIntel.issuerCountry !== billingCountry,
        amountAnomaly,
        ipIntel: riskResult.ipIntel || null,
        emailIntel: riskResult.emailIntel || null,
        binIntel: riskResult.binIntel || null,
        connectedRisk: response.connectedRisk,
        graphPath: riskResult.graphPath || [],
        flags: riskResult.flags,
        positives: riskResult.positives,
      };

      const savedOrder = await db.order.upsert({
        where: { merchantId_orderId: { merchantId, orderId } },
        create: {
          orderId,
          merchantId,
          // Unconditional attribution (mirrors BlockedAttempt.storeId) —
          // deliberately NOT storeScope.storeId, which only reflects
          // fraudIsolationMode==='per_store' and is for DETECTION-query
          // filtering only (see getStoreScope() in planAccess.js). Without
          // this fix, PayPal Shield and Monthly Report per-store breakdowns
          // (which read Order.storeId) would only ever populate for the
          // small subset of tenants who happened to also opt into fraud
          // isolation — an unrelated, unintended coupling.
          storeId: req.storeId ?? null,
          amount: amount || 0,
          currency: 'USD',
          email: email || null,
          // [Bug #7 fix] لمطابقة disputes/blacklist لاحقًا — email فوق
          // يفضل خام للعرض/الـ audit trail.
          normalizedEmail: email ? normalizeEmail(email) : null,
          // [BIN Velocity fix] راجع cardBinPrefixForVelocity فوق. عادةً
          // null هنا (BIN مبيوصلش قبل الدفع حسب ADR-0) — بس الكتابة
          // دايمًا صحيحة لو وصل مستقبلاً عبر تكامل مختلف.
          cardBinPrefix: cardBinPrefixForVelocity,
          ipAddress: ipAddress || null,
          deviceFingerprint: deviceFingerprint || null,
          riskScore: riskResult.score,
          riskLevel: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
          decision: response.decision,
          connectedRisk: response.connectedRisk,
          signalsSnapshot: JSON.stringify(signalsSnapshot),
        },
        update: {
          amount: amount || 0,
          email: email || null,
          normalizedEmail: email ? normalizeEmail(email) : null,
          cardBinPrefix: cardBinPrefixForVelocity,
          ipAddress: ipAddress || null,
          deviceFingerprint: deviceFingerprint || null,
          riskScore: riskResult.score,
          riskLevel: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
          decision: response.decision,
          connectedRisk: response.connectedRisk,
          fingerprintVersion: order.fingerprintVersion || null,
          fingerprintStatus: order.fingerprintStatus || null,
          signalsSnapshot: JSON.stringify(signalsSnapshot),
        },
      });

      // ��� RiskEvaluation ��� ��� ������ block �� review
      if (response.decision === 'block' || response.decision === 'review') {
        await db.riskEvaluation.upsert({
        where: { orderId: savedOrder.id },
        create: {
          orderId: savedOrder.id,
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            scoringVersion: riskResult.scoringVersion || 'v1.0',
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: response.decision === 'approve' ? 'low' : (response.decision === 'review' ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
        });
      }
    }

    prometheus.recordEvaluateDuration(Date.now() - evaluateStart);
    prometheus.recordEvaluateDecision(response.decision);
    res.json(response);
  } catch (error) {
    // Full detail stays server-side — the client response is generic in
    // production. /evaluate is the highest-traffic endpoint in this file
    // (hit on every checkout), so this was the highest-value leak to close.
    logger.error({ module: 'risk', endpoint: 'evaluate', error: error.message, stack: error.stack }, 'Evaluate error');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ���� ����� ������ �� ����� ����� (Feedback Loop)
// ������ orderId � isFraud (true = ����� ��� ������, false = ����� ��� ������)
const { processFeedback } = require('../lib/feedbackLoop');
/**
 * @swagger
 * /risk/feedback:
 *   post:
 *     summary: Provide feedback on a previous evaluation (for learning)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [orderId, isFraud]
 *             properties:
 *               orderId: { type: string }
 *               isFraud: { type: boolean }
 *     responses:
 *       200:
 *         description: Feedback recorded
 *       400:
 *         description: Missing orderId or isFraud
 *       500:
 *         description: Internal error
 */
router.post('/feedback', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { orderId, isFraud } = req.body;
    // CRITICAL FIX (C4): merchantId is derived from the authenticated tenant
    // (never trusted from the request body — CWE-639 / OWASP API1:2023),
    // and is now explicitly passed to processFeedback() so the lookup
    // inside feedbackLoop.js can be scoped to this tenant's own orders.
    // Previously this call passed no merchant context at all, meaning any
    // authenticated tenant could report fraud against any other tenant's
    // orderId and poison that tenant's MerchantProfile, SignalStat,
    // identity graph, and the shared cross-merchant pattern network.
    const merchantId = req.tenant.id;

    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (isFraud === undefined || isFraud === null) {
      return res.status(400).json({ error: 'isFraud is required (true/false)' });
    }

    // ������� ���� ������
    // ���� isFraud ������ (true = lost, false = won)
    await processFeedback(orderId, isFraud ? 'lost' : 'won', merchantId);

    res.json({ success: true, message: 'Feedback recorded successfully' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'feedback', error: error.message, stack: error.stack }, 'Feedback API error');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ========== POST /risk/reconcile ==========
// Links a temporary pre-order risk evaluation (Classic Checkout, created
// before the real WooCommerce order existed) to the real order ID once
// woocommerce_checkout_order_created fires. Without this, the Order row
// stays permanently keyed under the throwaway pre_xxxxx ID and the entire
// feedback loop (dispute recording, identity-graph fraud marking,
// pattern-sharing, SignalStat training) silently no-ops for every Classic
// Checkout order. See class-api-client.php reconcile_order() for the caller.
//
// Field names (preOrderId / orderId) match what reconcile_order() actually
// sends — not oldOrderId/newOrderId.
/**
 * @swagger
 * /risk/reconcile:
 *   post:
 *     summary: Re-key a pre-order Order row under the real WooCommerce order ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [preOrderId, orderId]
 *             properties:
 *               preOrderId: { type: string }
 *               orderId: { type: string }
 *     responses:
 *       200:
 *         description: Reconciled successfully
 *       400:
 *         description: Missing preOrderId or orderId
 *       404:
 *         description: No matching pre-order found for this tenant
 *       409:
 *         description: orderId already exists for this tenant (duplicate reconciliation)
 *       500:
 *         description: Internal error
 */
router.post('/reconcile', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { preOrderId, orderId } = req.body;
    // merchantId derived from the authenticated tenant only — never trust
    // a client-supplied merchant identifier (CWE-639 / OWASP API1:2023),
    // consistent with every other route in this file.
    const merchantId = req.tenant.id;

    if (!preOrderId || typeof preOrderId !== 'string' || !preOrderId.trim()) {
      return res.status(400).json({ error: 'preOrderId is required' });
    }
    if (!orderId || typeof orderId !== 'string' || !orderId.trim()) {
      return res.status(400).json({ error: 'orderId is required' });
    }

    // Scoped lookup via the compound key — this can structurally only
    // return a row belonging to the calling tenant, or no row at all
    // (same pattern as feedbackLoop.js's C4-guarded lookup).
    const existing = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId: preOrderId } },
      select: { id: true, merchantId: true },
    });

    // Generic 404 — deliberately does not distinguish "no such pre-order"
    // from "pre-order belongs to a different tenant", to avoid an
    // enumeration oracle (same rationale as processFeedbackSimplified's
    // order-not-found branch in feedbackLoop.js).
    if (!existing) {
      logger.warn({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId }, 'Reconcile: no matching pre-order found for this tenant');
      return res.status(404).json({ error: 'Order not found' });
    }

    try {
      await db.order.update({
        where: { id: existing.id },
        data: { orderId },
      });
    } catch (updateErr) {
      if (updateErr.code === 'P2002') {
        // newOrderId already exists for this tenant — most likely a
        // duplicate/retried reconciliation call. Not a server fault.
        logger.info({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId, orderId }, 'Reconcile: target orderId already exists for this tenant');
        return res.status(409).json({ error: 'An order with this orderId already exists for this merchant' });
      }
      throw updateErr;
    }

    logger.info({ module: 'risk', endpoint: 'reconcile', merchantId, preOrderId, orderId }, 'Pre-order reconciled to real order ID');
    res.json({ success: true });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'reconcile', error: error.message, stack: error.stack }, 'Reconcile error');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ���� ����� ����� ������� buildGraphFromOrder
/**
 * @swagger
 * /risk/test-graph:
 *   post:
 *     summary: Test identity graph building (for debugging)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [deviceFingerprint, merchantId]
 *             properties:
 *               deviceFingerprint: { type: string }
 *               email: { type: string }
 *               ipAddress: { type: string }
 *               merchantId: { type: string }
 *     responses:
 *       200:
 *         description: Graph built
 *       400:
 *         description: Missing deviceFingerprint or merchantId
 *       500:
 *         description: Internal error
 */
router.post('/test-graph', apiKeyAuth, async (req, res) => {
  // ��� ������ �� ���� �������
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Endpoint not available in production' });
  }
  try {
    const { deviceFingerprint, email, ipAddress } = req.body;
    if (!deviceFingerprint) {
      return res.status(400).json({ error: 'deviceFingerprint required' });
    }

    const { buildGraphFromOrder } = require('../lib/identityGraph');
    
    const mockOrder = {
      deviceFingerprint,
      deviceId: deviceFingerprint,
      email: email || 'test@test.com',
      ipAddress: ipAddress || '8.8.8.8',
      shippingAddress: JSON.stringify({ country: 'US' }),
      fingerprintVersion: 'v3',
    };

   const merchantId = req.tenant.id;
    await buildGraphFromOrder(mockOrder, merchantId);    
    res.json({ success: true, message: 'Graph built' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'test-graph', error: error.message, stack: error.stack }, 'test-graph error');
    res.status(500).json(safeErrorPayload(error));
  }
});
// ========== Blacklist Management Endpoints ==========
// ����� ���� ��� ������� �������
/**
 * @swagger
 * /risk/blacklist:
 *   post:
 *     summary: Add an entry to the blacklist
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [merchantId, type, value]
 *             properties:
 *               merchantId: { type: string }
 *               type: { type: string, enum: [EMAIL, IP, DEVICE_FINGERPRINT] }
 *               value: { type: string }
 *               reason: { type: string }
 *               expiresAt: { type: string, format: date-time }
 *               createdBy: { type: string }
 *     responses:
 *       200:
 *         description: Entry created
 *       400:
 *         description: Invalid input
 */
router.post('/blacklist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { type, value, reason, expiresAt, createdBy } = req.body;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)
    if (!type || !value) {
      return res.status(400).json({ error: 'type and value are required' });
    }
    // ������ �� ��� �����
    const validTypes = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
    }

    // [Bug #7 fix] normalizedValue هي اللي هتتقارن فعليًا في /evaluate
    // و /woocommerce-webhook — راجع computeNormalizedValue() فوق.
    const normalizedValue = computeNormalizedValue(type, value);

    const blacklistEntry = await db.blacklistEntry.create({
      data: {
        merchantId,
        type,
        value,
        normalizedValue,
        reason: reason || null,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: createdBy || null,
      },
    });
    prometheus.recordAccessControlAction('add', 'blacklist');
    res.json({ success: true, entry: blacklistEntry });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-add', error: error.message, stack: error.stack }, 'Error adding blacklist entry');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ��� ���� �� ������� �������
/**
 * @swagger
 * /risk/blacklist/{id}:
 *   delete:
 *     summary: Delete a blacklist entry
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [merchantId]
 *             properties:
 *               merchantId: { type: string }
 *     responses:
 *       200:
 *         description: Entry deleted
 *       404:
 *         description: Entry not found
 */
router.delete('/blacklist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ������ �� �� ������ ����� ��� ��� ������
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    await db.blacklistEntry.delete({ where: { id } });    prometheus.recordAccessControlAction('delete', 'blacklist');
    res.json({ success: true, message: 'Blacklist entry deleted' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-delete', error: error.message, stack: error.stack }, 'Error deleting blacklist entry');
    res.status(500).json(safeErrorPayload(error));
  }
});
// ========== GET Blacklist (Query) ==========
// ������� ������� ������� ������ ������
/**
 * @swagger
 * /risk/blacklist:
 *   get:
 *     summary: Get blacklist entries for a merchant
 *     parameters:
 *       - in: query
 *         name: merchantId
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: type
 *         schema: { type: string, enum: [EMAIL, IP, DEVICE_FINGERPRINT] }
 *       - in: query
 *         name: includeExpired
 *         schema: { type: boolean }
 *     responses:
 *       200:
 *         description: List of blacklist entries
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 entries: { type: array, items: { $ref: '#/components/schemas/BlacklistEntry' } }
 */
router.get('/whitelist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
   const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const { type, includeExpired } = req.query;
    const where = { merchantId };

    // ����� ��� ����� (�������)
    if (type) {
      const validTypes = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }

    // ����� ��������: ���� ������� ���� ��� ������� ������� (��� ������ �� expiresAt null)
    if (includeExpired !== 'true') {
      where.OR = [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } }
      ];
    }

    const blacklistEntries = await db.blacklistEntry.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json({ success: true, entries: blacklistEntries });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-get', error: error.message, stack: error.stack }, 'Error fetching blacklist');
    res.status(500).json(safeErrorPayload(error));
  }
});
// ========== UPDATE Blacklist Entry ==========
/**
 * @swagger
 * /risk/blacklist/{id}:
 *   put:
 *     summary: Update a blacklist entry (reason or expiresAt)
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               merchantId: { type: string }
 *               reason: { type: string }
 *               expiresAt: { type: string, format: date-time, nullable: true }
 *     responses:
 *       200:
 *         description: Entry updated
 *       400:
 *         description: Missing merchantId
 *       404:
 *         description: Entry not found or not owned by this merchant
 */
router.put('/blacklist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
     const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // ������ �� ����� ������
    const existing = await db.blacklistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Blacklist entry not found or not owned by this merchant' });
    }

    const { reason, expiresAt } = req.body;
    const updateData = {};
    if (reason !== undefined) updateData.reason = reason;
    if (expiresAt !== undefined) {
      updateData.expiresAt = expiresAt ? new Date(expiresAt) : null;
    }

    const updated = await db.blacklistEntry.update({
      where: { id },
      data: updateData,
    });

    res.json({ success: true, entry: updated });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'blacklist-update', error: error.message, stack: error.stack }, 'Error updating blacklist entry');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ========== Whitelist Management Endpoints ==========

router.post('/whitelist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { type, value, reason, expiresAt, createdBy } = req.body;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)
    if (!type || !value) {
      return res.status(400).json({ error: 'type and value are required' });
    }
    const validTypes = ['EMAIL', 'IP', 'BIN'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
    }

    // [Bug #7 fix] اتغيّر الاسم من normalizedValue لـ storedValue — الاسم
    // القديم بقى محجوز للعمود الجديد اللي بيُستخدم في المطابقة الأمنية
    // (تحت). storedValue هو اللي بيتكتب في عمود value نفسه: BIN بيتقلل
    // لـ 6 أرقام (زي ما كان بالظبط)، EMAIL/IP بيتخزنوا زي ما اتبعتوا.
    const storedValue = type === 'BIN'
      ? String(value).replace(/\D/g, '').slice(0, 6)
      : value;

    if (type === 'BIN' && storedValue.length !== 6) {
      return res.status(400).json({ error: 'BIN must be exactly 6 digits' });
    }

    // [Bug #7 fix] normalizedValue: عمود المطابقة الأمنية. بيتحسب من
    // storedValue (مش value الخام) عشان تقليل الـ BIN لـ 6 أرقام يفضل
    // متسق. ده بيقفل النص الخاص بالـ whitelist من نفس الثغرة — كانت
    // إيميلات الـ whitelist ماتتطبّقش خالص قبل كده.
    const normalizedValue = computeNormalizedValue(type, storedValue);

    const whitelistEntry = await db.whitelistEntry.create({
      data: {
        merchantId,
        type,
        value: storedValue,
        normalizedValue,
        reason: reason || null,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        createdBy: createdBy || null,
      },
    });
    prometheus.recordAccessControlAction('add', 'whitelist');
    res.json({ success: true, entry: whitelistEntry });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({ error: 'This entry already exists in the whitelist' });
    }
    logger.error({ module: 'risk', endpoint: 'whitelist-add', error: error.message, stack: error.stack }, 'Error adding whitelist entry');
    res.status(500).json(safeErrorPayload(error));
  }
});

router.get('/whitelist', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const { type, includeExpired } = req.query;
    const where = { merchantId };

    if (type) {
      const validTypes = ['EMAIL', 'IP', 'BIN'];
      if (!validTypes.includes(type)) {
        return res.status(400).json({ error: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }

    if (includeExpired !== 'true') {
      where.OR = [
        { expiresAt: null },
        { expiresAt: { gt: new Date() } }
      ];
    }

    const whitelistEntries = await db.whitelistEntry.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json({ success: true, entries: whitelistEntries });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'whitelist-get', error: error.message, stack: error.stack }, 'Error fetching whitelist');
    res.status(500).json(safeErrorPayload(error));
  }
});

router.delete('/whitelist/:id', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { id } = req.params;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    const existing = await db.whitelistEntry.findFirst({
      where: { id, merchantId },
    });
    if (!existing) {
      return res.status(404).json({ error: 'Whitelist entry not found or not owned by this merchant' });
    }

    await db.whitelistEntry.delete({ where: { id } });
    prometheus.recordAccessControlAction('delete', 'whitelist');
    res.json({ success: true, message: 'Whitelist entry deleted' });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'whitelist-delete', error: error.message, stack: error.stack }, 'Error deleting whitelist entry');
    res.status(500).json(safeErrorPayload(error));
  }
});

// WooCommerce webhook endpoint
router.post('/woocommerce-webhook', async (req, res) => {
  try {
    // 1. Get raw body for signature verification
    const rawBody = req.body; // express.raw puts Buffer in req.body
    
    if (!rawBody) {
      return res.status(400).json({ error: 'Raw body missing' });
    }

    // 2. Parse raw body to JSON (���� parsedBody �����)
    let parsedBody;
    try {
      parsedBody = JSON.parse(rawBody.toString());
    } catch (err) {
      logger.error({ module: 'risk', err: err.message }, 'Failed to parse webhook body');
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

      // merchantId is derived from the authenticated tenant via x-api-key, never from the
    // webhook payload (CWE-639 / OWASP API1:2023). The WooCommerce plugin is configured
    // with the tenant's API key and must send it on every webhook delivery.
    //
    // Tenant resolution now goes through the same centralized requireAuth()
    // middleware used by every other route in this file, instead of a manual
    // resolveTenantByApiKey/isActive/emailVerified copy (CWE-1059 drift fix —
    // see runAuthMiddleware/webhookAuth definitions above). This also gives
    // the webhook endpoint the same standardized 401/403 response shape and
    // uniform 200ms auth-failure timing delay as every other endpoint.
    const authOk = await runAuthMiddleware(req, res, webhookAuth);
    if (!authOk) return; // webhookAuth already sent the response (401/403/500)
    const merchantId = req.tenant.id;

    // Note: webhookAuth's select object must also include fraudIsolationMode
    // (see Change 3a-equivalent for webhookAuth definition) for this to be
    // anything other than {} — see next required edit below.

    // ── Best-effort store attribution (Agency multi-store) ───────────────
    // domainAuthMiddleware is NOT applied on this route (see historical
    // comments below on the two recordBlockedAttempt calls) — and cannot
    // be applied as-is, because it requires X-Store-Domain, which native
    // WooCommerce webhook delivery does not send. WooCommerce's own
    // delivery mechanism sends X-WC-Webhook-Source (the site's home URL)
    // instead; X-Store-Domain is kept as a fallback in case a future
    // plugin/proxy configuration ever adds it on this path. This call is
    // fail-open by design: on a missing header or no Store match,
    // req.storeId stays null, identical to pre-fix behavior — it never
    // rejects the request. See resolveStoreIdBestEffort() in domainAuth.js
    // for why this is a separate function from domainAuthMiddleware rather
    // than a relaxed mode of it.
    const webhookSourceDomain = req.headers['x-wc-webhook-source'] || req.headers['x-store-domain'];
    req.storeId = await resolveStoreIdBestEffort(merchantId, webhookSourceDomain);
    const storeScope = getStoreScope(req.tenant, req.storeId);

    // ── WooCommerce Signature Verification (mirrors /evaluate's ordering:
    // auth → signature → quota → business logic) ───────────────────────────
    // Moved ahead of the quota gate (Issue #3 fix). Previously this ran
    // AFTER checkQuotaGate, so an authenticated-but-unsigned/misconfigured
    // request from a near-quota tenant surfaced as "quota exceeded" instead
    // of "invalid signature" — masking the real root cause in logs and
    // alerts. No security change: requireAuth() already gated both checks
    // before and after this reorder.
    // Per-tenant secret — WooCommerce signs each merchant's webhook
    // deliveries with THAT merchant's own webhookSecret (generated at
    // /tenants/register and stored on Tenant.webhookSecret), not a
    // deployment-wide value. req.tenant is already resolved and scoped to
    // this request by webhookAuth above (see Edit 1 for the select fix
    // that makes webhookSecret actually present here).
    const wcSecret = req.tenant.webhookSecret;
    const signature = req.headers['x-wc-webhook-signature'];
    if (wcSecret && signature) {
      const expected = crypto.createHmac('sha256', wcSecret).update(rawBody).digest('base64');
      const expectedBuf = Buffer.from(expected);
      const signatureBuf = Buffer.from(signature);

      // crypto.timingSafeEqual throws on unequal-length buffers rather than
      // returning false — with a real per-tenant secret now in play, a
      // forged/garbled signature header is a live possibility, so guard the
      // length explicitly rather than let it fall into the outer catch as
      // a generic 500.
      const isValid = expectedBuf.length === signatureBuf.length &&
        crypto.timingSafeEqual(expectedBuf, signatureBuf);
      if (!isValid) {
        // [Bug #13 fix] التفاصيل التشخيصية (شاملة معاينة أول 50 حرف من
        // الـ raw body — بيانات أوردر حقيقية، PII محتمل) كانت بتتسجل
        // *دايمًا* في نداء logger.warn منفصل فوق، بغض النظر عن نجاح
        // التحقق من التوقيع من عدمه — يعني كل أوردر شرعي وصل بتوقيع صحيح
        // (الحالة الغالبة) كان بيسرّب جزء من بياناته في اللوجز من غير أي
        // داعي. دمجناه في نداء واحد هنا، ما بيتنفذش إلا وقت وجود مشكلة
        // فعلية (mismatch) تستاهل التشخيص — نفس فلسفة "I11 fix" الموثقة
        // في lib/woocommerce.js.
        logger.warn({
          module: 'risk',
          tenantId: merchantId,
          reason: 'mismatch',
          receivedSignatureLength: signature.length,
          expectedSignatureLength: expected.length,
          firstRawBodyChars: rawBody.toString('utf8').slice(0, 50),
          secretConfigured: !!wcSecret,
          signaturePresent: !!signature,
        }, 'Signature mismatch — rejecting forged webhook request');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    } else if (wcSecret && !signature) {
      // Secret configured but signature missing — reject
      return res.status(401).json({ error: 'Missing signature' });
    } else if (!wcSecret) {
      // Legacy tenant that predates webhookSecret provisioning — skip this
      // defense-in-depth layer gracefully rather than rejecting all
      // traffic. webhookAuth (X-Api-Key) has already authenticated this
      // request to a real, active, verified tenant; this only means that
      // one tenant is missing the extra WooCommerce-signature check, not
      // that the request is unauthenticated.
      logger.warn({ module: 'risk', tenantId: merchantId }, 'WooCommerce webhook signature check skipped — tenant has no webhookSecret configured');
    }

    // ── Quota Status (mirrors /evaluate's non-blocking behavior) ───────────
    // Both order-evaluation paths must agree on what "quota exhausted"
    // means: it now only gates expensive external intel calls inside
    // calculateRiskScore(), never the detection pipeline itself.
    const quotaStatus = await checkQuotaGate(req, 'woocommerce-webhook');
    const limitedScoring = quotaStatus.exceeded;
    // ── End Quota Status ──────────────────────────────────────────────────

   // 5. Extract order data
   const { extractOrderData, buildRiskEvaluationRequest } = require('../lib/woocommerce');
   let extracted;
   try {
     extracted = extractOrderData(parsedBody);
   } catch (err) {
     logger.error({ module: 'risk', err: err.message }, 'Failed to extract order data');
     return res.status(400).json({ error: 'Invalid payload structure' });
   }

   // Same defense-in-depth gate as /evaluate — see the comment there.
   // extractOrderData() has no way to know whether the plugin's
   // get_client_ip() resolved correctly; this backend re-validates
   // independently before extracted.ipAddress touches any IP-anchored
   // control below (whitelist/blacklist, velocity counts, identity graph).
   let webhookIpAnomaly = null;
   {
     const check = isPlausibleClientIp(extracted.ipAddress);
     if (!check.ok) {
       webhookIpAnomaly = check.reason;
       if (extracted.ipAddress) {
         logger.warn(
           { module: 'risk', endpoint: 'woocommerce-webhook', orderId: extracted.orderId, ipAnomaly: webhookIpAnomaly },
           'ipAddress failed plausibility check — excluding from IP-based detection for this request'
         );
       }
       extracted.ipAddress = null;
     } else {
       extracted.ipAddress = extracted.ipAddress.trim();
     }
   }

   // 6. Idempotency: check if order already processed
   const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } },
      select: { merchantId: true, decision: true, riskScore: true, signalsSnapshot: true, createdAt: true }
    });
    // Defense-in-depth (C3): mirrors the /evaluate guard above — should be
    // unreachable given the compound key, asserted anyway.
    if (existingOrder && existingOrder.merchantId !== merchantId) {
      logger.error({ module: 'risk', endpoint: 'woocommerce-webhook', merchantId, orderId: extracted.orderId }, 'C3 guard tripped — compound key returned a different merchant\'s row; should be unreachable');
      return res.status(403).json({ error: 'Merchant ID mismatch.' });
    }
    if (existingOrder) {
      // Return cached response (within reasonable time window, e.g., 24h)
      const ageHours = (Date.now() - new Date(existingOrder.createdAt).getTime()) / (1000 * 60 * 60);
      if (ageHours < 24) {
        logger.info({ module: 'risk', orderId: extracted.orderId }, 'Idempotent request � returning cached result');
        return res.json({
          orderId: extracted.orderId,
          score: existingOrder.riskScore,
          decision: existingOrder.decision,
          cached: true
        });
      }
    }

    // 7. Build request for risk scoring
    const riskRequest = buildRiskEvaluationRequest(extracted);
    riskRequest.merchantId = merchantId;

    // ������� ���� ������ �� Webhook (��� ����)
    let deviceFingerprint = parsedBody.device_fingerprint || null;
    if (!deviceFingerprint && parsedBody.meta_data) {
        const fpMeta = parsedBody.meta_data.find(m => m.key === '_chargeguard_device_fingerprint');
        if (fpMeta) deviceFingerprint = fpMeta.value;
    }
    riskRequest.deviceFingerprint = deviceFingerprint || `${WC_SYNTHETIC_DEVICE_PREFIX}${extracted.orderId}`; // fallback

    // Same treatment for the server-signed device token — mirrors the
    // fingerprint extraction immediately above. Sourced from order meta
    // (_chargeguard_device_token, persisted at checkout — see
    // class-dynamic-firewall.php) via the same meta_data field the
    // webhook payload already carries.
    let deviceToken = parsedBody.device_token || null;
    if (!deviceToken && parsedBody.meta_data) {
        const dtMeta = parsedBody.meta_data.find(m => m.key === '_chargeguard_device_token');
        if (dtMeta) deviceToken = dtMeta.value;
    }

    const webhookDeviceSignal = { trust: 'unsigned', ipMatches: null, rotationCount: 0 };
    if (deviceToken) {
      const webhookTokenVerification = verifyDeviceToken(deviceToken, extracted.ipAddress);
      if (webhookTokenVerification.valid) {
        webhookDeviceSignal.trust = webhookTokenVerification.ipMatches ? 'signed' : 'signed_ip_mismatch';
        webhookDeviceSignal.ipMatches = webhookTokenVerification.ipMatches;
      } else {
        webhookDeviceSignal.trust = 'invalid_token';
      }
    }
    const webhookMerchantConfig = { deviceSignal: webhookDeviceSignal };

    // [Bug #7 fix] نفس منطق normalizedEmailForMatch في /evaluate.
    const normalizedExtractedEmail = extracted.email ? normalizeEmail(extracted.email) : undefined;
    // [Discovery 2/3 fix] نفس منطق normalizedBinForMatch في /evaluate —
    // يُحسب مرة واحدة، يُستخدم في 7a (whitelist) و7a1 (blacklist) تحت.
    const normalizedExtractedBin = extracted.bin ? String(extracted.bin).replace(/\D/g, '').slice(0, 6) : undefined;

    // 7a. Whitelist Check
    // [Discovery 3 fix] BIN كانت غايبة من هذا الفحص تحديدًا — بالرغم من
    // وجودها في /evaluate's 0a (المرجع) وفي enrichmentProcessor.js's
    // whitelist check. نفس فئة Discovery 1/2 (حقل مدعوم بالكامل بس ناقص
    // من مسار واحد بعينه).
    const webhookWhitelistConditions = [];
    if (normalizedExtractedEmail) webhookWhitelistConditions.push({ type: 'EMAIL', normalizedValue: normalizedExtractedEmail });
    if (extracted.ipAddress)      webhookWhitelistConditions.push({ type: 'IP',   value: extracted.ipAddress });
    if (normalizedExtractedBin)   webhookWhitelistConditions.push({ type: 'BIN',  value: normalizedExtractedBin });

    if (webhookWhitelistConditions.length > 0) {
      const webhookWhitelistCheck = await db.whitelistEntry.findFirst({
        where: {
          merchantId,
          OR: webhookWhitelistConditions,
          AND: [{ OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } }
          ]}]
        }
      });

      if (webhookWhitelistCheck) {
        prometheus.recordWhitelistBypass(webhookWhitelistCheck.type);
        logger.info(
          { module: 'risk', merchantId, type: webhookWhitelistCheck.type, orderId: extracted.orderId },
          'Webhook request bypassed all checks — whitelisted'
        );
        return res.json({
          orderId: extracted.orderId,
          score: 0,
          decision: 'approve',
          flags: [],
          connectedRisk: 0,
          whitelisted: true
        });
      }
    }

    // 7a1. Blacklist Check — [Discovery 1 fix] كانت غايبة تمامًا من هذا
    // المسار. الفحص الداخلي جوه calculateRiskScore() (inBlacklist في
    // riskScoring.js) مش بديل كافٍ: هو soft -80 penalty بس (مش hard
    // block)، وكان أصلاً معطوبًا بنيويًا لحد فيكس منفصل (راجع
    // riskScoring.js). ده بيقفل التناقض الأمني بين /evaluate (عنده 0b
    // من الأول) و/woocommerce-webhook (كان من غيرها) — كيان اتحظر ممكن
    // كان يعدي بالكامل لو وصل عبر WooCommerce's native order webhook
    // بدل /evaluate.
    //
    // [قرار محسوم] storeScope مُضافة هنا — البلاك ليست hard block قاطع،
    // مش soft signal، فالاتساق الصحيح هو مع /evaluate's 0b (المرجع
    // الأمني، اللي بيستخدم storeScope من الأول)، مش مع عدّادات السرعة
    // التلاتة تحت (deviceVelocityCount/ipVelocityCount/emailVelocityCount)
    // اللي تجاهلها لـ storeScope مقبول لأنها soft signals بس بتأثر على
    // score. من غير الفيكس ده، بلاك ليست تاجر Agency مخصصة لـ Store A
    // كانت هتتفحص (وتُطبّق حظر) عبر كل متاجره بما فيهم Store B غير
    // المرتبط — عبر هذا المسار فقط — تناقض أمني من نفس فئة Discovery 1
    // الأصلية، بس على مستوى store بدل tenant.
    //
    // [Discovery 2 fix] bin مُضافة كمان — راجع blacklistGate.js's
    // findBlacklistMatch. extracted.bin نادرًا ما يتوفر عبر هذا المسار في
    // الإنتاج (راجع ADR-0)، لكن الفحص دلوقتي صحيح لو وصل مستقبلًا.
    const webhookBlacklistCheck = await findBlacklistMatch(db, {
      merchantId,
      storeScope,
      normalizedEmail: normalizedExtractedEmail,
      ip: extracted.ipAddress,
      deviceFingerprint: riskRequest.deviceFingerprint,
      bin: normalizedExtractedBin,
    });
    if (webhookBlacklistCheck) {
      prometheus.recordBlacklistHit(webhookBlacklistCheck.type);

      let webhookBlCardBin = null;
      if (extracted.bin != null) {
        const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) webhookBlCardBin = b;
      }
      const webhookBlIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
      let webhookBlAmount = null;
      if (extracted.amount != null) {
        const amt = parseFloat(extracted.amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookBlAmount = amt;
      }

      try {
        const webhookBlIncrementQuota = shouldIncrementQuota(merchantId, 'blacklist', webhookBlacklistCheck.value);

        await db.$transaction(recordBlockedAttempt(db, {
          merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         webhookBlCardBin,
          cardType:        null, // not captured by extractOrderData()
          reason:          'blacklist',
          ipHash:          webhookBlIpHash,
          amountAttempted: webhookBlAmount,
          riskScore:       null,
          incrementQuota:  webhookBlIncrementQuota,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'woocommerce-webhook', path: 'blacklist', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (webhook blacklist path)'
        );
      }

      return res.status(403).json({
        error: 'Request blocked: entity is blacklisted',
        reason: webhookBlacklistCheck.reason || 'Blacklisted',
        decision: 'block'
      });
    }

    // 7a2. Email Hard-Block — disposable domain / no-MX. [Bug #6 fix]
    // كانت غايبة تمامًا من هذا المسار. تعمل بشكل مطابق لقسم 0c في
    // /evaluate — وبشكل متعمد بدون أي شرط على limitedScoring، لأن وقت
    // نفاد الكوتا calculateRiskScore() بيقفل getEmailIntelligence() تمامًا
    // (راجع الـ Promise.allSettled جوه calculateRiskScore) — يعني أوردر
    // الـ webhook وقتها كان بيوصل لـ decision نهائي بدون أي إشارة إيميل
    // خالص، حاد ولا ناعم. اتحطت بعد whitelist (أرخص بوابة، bypass الأول)
    // وقبل BIN-sequence، بنفس منطق "الأرخص والأكثر حسمًا الأول" المستخدم
    // في /evaluate.
    if (extracted.email) {
      const webhookEmailHardBlock = await checkEmailHardBlock(extracted.email);
      if (webhookEmailHardBlock.blocked) {
        let webhookEmailBlockCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookEmailBlockCardBin = b;
        }
        const webhookEmailBlockIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
        let webhookEmailBlockAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookEmailBlockAmount = amt;
        }

        try {
          const webhookEmailIncrementQuota = shouldIncrementQuota(merchantId, 'email', extracted.email);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         webhookEmailBlockCardBin,
            cardType:        null, // not captured by extractOrderData()
            reason:          'email',
            ipHash:          webhookEmailBlockIpHash,
            amountAttempted: webhookEmailBlockAmount,
            riskScore:       null,
            incrementQuota:  webhookEmailIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'email_hard_block', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook email hard-block path)'
          );
        }
        return res.status(403).json({
          error: 'Request blocked: email address failed validation',
          reason: 'email_hard_block',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'email_hard_block' }]
        });
      }
    }

    // 7a3. Velocity Hard-Block — [Discovery 4 fix] كانت غايبة تمامًا من
    // هذا المسار. checkVelocity() (نفس الفنكشن المستخدم في /evaluate's
    // قسم 1) بيفحص CardTestAttempt — محاولات محظورة سابقة لنفس IP/device
    // خلال 10 دقائق. قبل الفيكس، burst سريع عبر الـ webhook كان بيوصل
    // لـ calculateRiskScore() ياخد soft penalty بس (device_velocity_blocked
    // flag جوه الـ score) — فرق جوهري عن hard 403 فوري، لأن الـ soft
    // penalty ممكن يتوازن بـ positive signals (MAX_POSITIVE_BOOST) أو
    // يقع في Review مش Block. الترتيب هنا (بعد email hard-block، قبل
    // BIN-sequence) مطابق لـ /evaluate بالحرف (قسم 1 قبل قسم 1b).
    //
    // deviceFingerprint هنا هي القيمة الحقيقية (قبل fallback الـ
    // `wc_${orderId}` تحت في قسم استخراج riskRequest.deviceFingerprint) —
    // عمدًا، مش riskRequest.deviceFingerprint. تمرير القيمة الاصطناعية
    // هنا مش خطر أمني (كل قيمة فريدة، مستحيل توصل threshold التكرار) لكنها
    // تلوّث بيانات بلا فايدة في CardTestAttempt.
    const webhookVelocityCheck = await checkVelocity({
      ip: extracted.ipAddress,
      deviceFingerprint,
      merchantId,
      storeId: storeScope.storeId ?? null,
    });

    if (webhookVelocityCheck.dbError) {
      logger.warn(
        { module: 'risk', endpoint: 'woocommerce-webhook', merchantId, fallbackBlocked: webhookVelocityCheck.blocked },
        'Velocity check ran in degraded mode — CardTestAttempt query failed, local fallback used'
      );
      try {
        if (typeof prometheus.recordVelocityDbError === 'function') {
          prometheus.recordVelocityDbError();
        }
      } catch (metricErr) {
        // Metrics must never affect request handling.
      }
    }

    if (webhookVelocityCheck.blocked) {
      let webhookVelCardBin = null;
      if (extracted.bin != null) {
        const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) webhookVelCardBin = b;
      }
      const webhookVelIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
      let webhookVelAmount = null;
      if (extracted.amount != null) {
        const amt = parseFloat(extracted.amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookVelAmount = amt;
      }

      try {
        const webhookVelIncrementQuota = shouldIncrementQuota(merchantId, 'velocity', deviceFingerprint || extracted.ipAddress);

        await db.$transaction(recordBlockedAttempt(db, {
          merchantId,
          storeId:         req.storeId ?? null,
          cardBin:         webhookVelCardBin,
          cardType:        null,
          reason:          'velocity',
          ipHash:          webhookVelIpHash,
          amountAttempted: webhookVelAmount,
          riskScore:       null,
          incrementQuota:  webhookVelIncrementQuota,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'woocommerce-webhook', path: 'velocity', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter (webhook velocity path)'
        );
      }

      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        reason: 'velocity_blocked',
        decision: 'block'
      });
    }

     // 7b. BIN Sequence Detection
    if (extracted.bin) {
      // tenantId is required here for tenant-scoped storage in
      // binSequenceDetector.js (CWE-653 fix) — merchantId is already
      // resolved above from the authenticated tenant (req.tenant.id).
      const binSeq = await checkBINSequence({
        tenantId: merchantId,
        bin: extracted.bin,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint
      });
      // tenantId resolved from the authenticated tenant (merchantId, derived
      // from req.tenant.id via the webhook's requireAuth resolution above) —
      // previously hardcoded to null, which meant BinSequenceAlert rows from
      // this path had no tenant association and were invisible to the
      // dashboard and to notifyBINSequenceAlert's tenant lookup.
      // L-fix: same rationale as /evaluate above — layer 0 is a repeat
      // rejection from an existing active block, not a new BIN detection.
      // Skip persistence to avoid inflating cardsCount with block-window
      // traffic instead of genuine distinct BINs.
      if (binSeq.layer !== 0 && (binSeq.blocked || binSeq.riskAddition > 0)) {
        persistBinSequenceAlert(merchantId, extracted.bin, binSeq, req.storeId ?? null)
          .catch(err => logger.error({ module: 'risk', err: err.message }, 'BinSequenceAlert persist failed'));
      }

      if (binSeq.blocked) {
        let webhookBinSeqCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookBinSeqCardBin = b;
        }
        const webhookBinSeqIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
        let webhookBinSeqAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookBinSeqAmount = amt;
        }

        // storeId is now best-effort resolved above from X-WC-Webhook-Source
        // (see resolveStoreIdBestEffort call near the top of this handler) —
        // still null if the header was missing or unmatched, exactly as
        // before. cardType remains always null — extractOrderData() does not
        // capture a card-type field from the WooCommerce payload.
        try {
          await db.$transaction(recordBlockedAttempt(db, {
            merchantId:      merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         webhookBinSeqCardBin,
            cardType:        null,
            reason:          'card_testing',
            ipHash:          webhookBinSeqIpHash,
            amountAttempted: webhookBinSeqAmount,
            riskScore:       null,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'bin_sequence', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook BIN sequence path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious card testing pattern',
          reason: 'bin_sequence_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'bin_sequence_blocked' }]
        });
      }
    }

    // 7c. Device Fingerprint Trust & Rotation Detection — [Discovery 4
    // fix] كانت غايبة تمامًا من هذا المسار. webhookDeviceSignal اتعرّفت
    // فوق (وقت فحص deviceToken) لكن rotationCount فضلت 0 دايمًا — مفيش
    // كود كان بيحسبها أو يستخدمها للحظر. نفس منطقين مستقلين من /evaluate's
    // قسم 1c بالحرف: (أ) per-IP — عدد device fingerprints مختلفة من نفس
    // IP خلال ساعة، (ب) global — معدل ظهور fingerprints جديدة كليًا لهذا
    // التاجر بغض النظر عن IP.
    //
    // ⚠️ فرق جوهري عن /evaluate: deviceFingerprint هنا (المتغيّر الخام،
    // قبل fallback الـ `wc_${orderId}` المُستخدم في riskRequest.deviceFingerprint
    // تحت) هي المستخدمة عمدًا، مش riskRequest.deviceFingerprint — لأن
    // الـ fallback الاصطناعي فريد لكل أوردر بالتصميم، فاستخدامه في فحص
    // "distinct fingerprints" كان هيخلق false positive حقيقي: أي تاجر
    // بدون JS pixel حقيقي هيبقى عنده "fingerprint جديد" مع كل أوردر
    // شرعي، ويوصل لعتبة الحظر بسرعة على أي حجم ترافيك طبيعي. كمان: عمود
    // Order.deviceFingerprint بيتخزن فيه القيمة الاصطناعية دي بالفعل من
    // كل أوردر webhook سابق (راجع قسم 12 تحت) — يعني الاستعلام نفسه
    // لازم يستثنيها، مش بس منطق العدّ الحالي، لإن التلوّث موجود تاريخيًا
    // في الداتابيز مسبقًا.
    if (extracted.ipAddress) {
      const ROTATION_WINDOW_MS = 60 * 60 * 1000; // 1 hour — matches /evaluate's own window
      const ROTATION_BLOCK_THRESHOLD = 6; // 6+ distinct REAL device fingerprints from one IP in 1h
      const rotationWindowStart = new Date(Date.now() - ROTATION_WINDOW_MS);

      const webhookRecentDevicesForIp = await db.order.findMany({
        where: {
          merchantId, ...storeScope,
          ipAddress: extracted.ipAddress,
          createdAt: { gte: rotationWindowStart },
          deviceFingerprint: { not: null },
          // استثناء synthetic fallback IDs — راجع الشرح فوق.
          NOT: { deviceFingerprint: { startsWith: 'wc_' } },
        },
        select: { deviceFingerprint: true },
        distinct: ['deviceFingerprint'],
        take: 50,
      });
      const webhookSeenThisOne = deviceFingerprint && webhookRecentDevicesForIp.some(d => d.deviceFingerprint === deviceFingerprint);
      webhookDeviceSignal.rotationCount = webhookRecentDevicesForIp.length + (deviceFingerprint && !webhookSeenThisOne ? 1 : 0);

      if (webhookDeviceSignal.rotationCount >= ROTATION_BLOCK_THRESHOLD) {
        let webhookRotCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookRotCardBin = b;
        }
        const webhookRotIpHash = hashIp(extracted.ipAddress);
        let webhookRotAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookRotAmount = amt;
        }

        try {
          const webhookRotIncrementQuota = shouldIncrementQuota(merchantId, 'device_rotation_ip', extracted.ipAddress);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         webhookRotCardBin,
            cardType:        null,
            reason:          'velocity', // reuses the existing VALID_REASONS enum — same choice as /evaluate
            ipHash:          webhookRotIpHash,
            amountAttempted: webhookRotAmount,
            riskScore:       null,
            incrementQuota:  webhookRotIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'device_rotation', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook device rotation path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious device fingerprint rotation',
          reason: 'device_rotation_ip_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_rotation_ip_blocked' }]
        });
      }
    }

    // Global rotation — [Discovery 4 fix] مفيش تلوّث تاريخي هنا (in-memory
    // مش DB)، لكن لازم نتجنب تسجيل الـ synthetic fallback ID كـ "fingerprint
    // جديد" في كل مرة — بوابة `if (deviceFingerprint)` (القيمة الحقيقية)
    // بس كفاية هنا، عكس الفحص فوق اللي احتاج فيكس على مستوى الاستعلام كمان.
    if (deviceFingerprint) {
      const webhookGlobalRotation = recordAndCheckGlobalRotation(merchantId, deviceFingerprint);

      if (webhookGlobalRotation.blocked) {
        let webhookGlobalRotCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookGlobalRotCardBin = b;
        }
        const webhookGlobalRotIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
        let webhookGlobalRotAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookGlobalRotAmount = amt;
        }

        try {
          const webhookGlobalRotIncrementQuota = shouldIncrementQuota(merchantId, 'device_rotation_global', deviceFingerprint);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         webhookGlobalRotCardBin,
            cardType:        null,
            reason:          'device_rotation_global',
            ipHash:          webhookGlobalRotIpHash,
            amountAttempted: webhookGlobalRotAmount,
            riskScore:       null,
            incrementQuota:  webhookGlobalRotIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'device_rotation_global', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook global device rotation path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious device fingerprint rotation across the merchant',
          reason: 'device_rotation_global_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_rotation_global_blocked' }]
        });
      }
    }
    // End 7c. Device Fingerprint Trust & Rotation Detection

    // 7d. Raw (Unconditional) Device Velocity — نفس منطق /evaluate's
    // قسم 1d بالحرف. deviceFingerprint هنا الخام عمدًا (قبل fallback
    // wc_${orderId}) — نفس تحذير قسم 7c فوق: القيمة الاصطناعية فريدة لكل
    // أوردر بالتصميم، فاستخدامها هنا كان هيخلق false positive حقيقي.
    if (deviceFingerprint) {
      const webhookRawDeviceVelocity = checkRawDeviceVelocity(merchantId, deviceFingerprint);
      if (webhookRawDeviceVelocity.blocked) {
        let webhookRawVelCardBin = null;
        if (extracted.bin != null) {
          const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
          if (b.length === 6) webhookRawVelCardBin = b;
        }
        const webhookRawVelIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
        let webhookRawVelAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookRawVelAmount = amt;
        }

        try {
          const webhookRawVelIncrementQuota = shouldIncrementQuota(merchantId, 'raw_device_velocity', deviceFingerprint);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         webhookRawVelCardBin,
            cardType:        null,
            reason:          'velocity',
            ipHash:          webhookRawVelIpHash,
            amountAttempted: webhookRawVelAmount,
            riskScore:       null,
            incrementQuota:  webhookRawVelIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'raw_device_velocity', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook raw device velocity path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious request velocity',
          reason: 'device_velocity_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'device_velocity_blocked' }]
        });
      }
    } else if (extracted.ipAddress) {
      const webhookRawIpHash = hashIp(extracted.ipAddress);
      const webhookRawIpVelocity = checkRawIpVelocityFallback(merchantId, webhookRawIpHash);
      if (webhookRawIpVelocity.blocked) {
        let webhookRawIpVelAmount = null;
        if (extracted.amount != null) {
          const amt = parseFloat(extracted.amount);
          if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookRawIpVelAmount = amt;
        }

        try {
          const webhookRawIpVelIncrementQuota = shouldIncrementQuota(merchantId, 'raw_ip_velocity', extracted.ipAddress);

          await db.$transaction(recordBlockedAttempt(db, {
            merchantId,
            storeId:         req.storeId ?? null,
            cardBin:         null,
            cardType:        null,
            reason:          'velocity',
            ipHash:          webhookRawIpHash,
            amountAttempted: webhookRawIpVelAmount,
            riskScore:       null,
            incrementQuota:  webhookRawIpVelIncrementQuota,
          }));
        } catch (counterErr) {
          logger.error(
            { module: 'risk', endpoint: 'woocommerce-webhook', path: 'raw_ip_velocity_fallback', tenantId: merchantId, error: counterErr.message },
            'Failed to record BlockedAttempt / increment quota counter (webhook raw IP velocity fallback path)'
          );
        }

        return res.status(403).json({
          error: 'Request blocked due to suspicious request velocity',
          reason: 'ip_velocity_fallback_blocked',
          decision: 'block',
          flags: [{ severity: 'critical', text: 'ip_velocity_fallback_blocked' }]
        });
      }
    }
    // End 7d. Raw (Unconditional) Device Velocity

    // 8. Load recent orders, disputes, blacklist for this merchant
    const last7days = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentOrders = await db.order.findMany({
      where: { merchantId, ...storeScope, createdAt: { gte: last7days } },
      orderBy: { createdAt: 'desc' },
      take: 200
    });
    const formattedOrders = recentOrders.map(o => ({
      id: o.orderId,
      email: o.email,
      ipAddress: o.ipAddress,
      deviceFingerprint: o.deviceFingerprint,
      amount: o.amount,
      createdAt: o.createdAt,
      riskLevel: o.riskLevel,
      cardBinPrefix: o.cardBinPrefix,
    }));
    // [Undefined-OR fix] نفس فيكس /evaluate بالحرف — riskRequest.deviceFingerprint
    // دايمًا truthy (fallback wc_${orderId} مضمون) فمحتاجش حراسة، لكن
    // normalizedExtractedEmail وextracted.ipAddress ممكن يكونوا undefined/null.
    const webhookDisputeOrConditions = [];
    if (normalizedExtractedEmail) webhookDisputeOrConditions.push({ order: { normalizedEmail: normalizedExtractedEmail } });
    webhookDisputeOrConditions.push({ order: { deviceFingerprint: riskRequest.deviceFingerprint } });
    if (extracted.ipAddress) webhookDisputeOrConditions.push({ order: { ipAddress: extracted.ipAddress } });

    const disputes = await db.disputeOutcome.findMany({
      where: {
        merchantId,
        resolvedAt: { gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) },
        OR: webhookDisputeOrConditions,
      },
      include: { order: true },
      take: 200,
    });
    // [Discovery 1 fix] البوابة المبكرة (7a1) فوق بترفض أي تطابق فعلي بـ
    // 403 قبل ما نوصل هنا — يعني أي أوردر وصل للسطر ده مستحيل يكون
    // متطابق مع بلاك ليست بنفس الشروط. الاستعلام القديم هنا (blacklistOr +
    // findMany) كان DB call مكرر بلا فايدة — نفس منطق /evaluate's
    // `const blacklist = [];` بعد 0b بالحرف.
    const blacklist = [];

    // 9. Velocity counts
    const last1h = new Date(Date.now() - 60 * 60 * 1000);
    const last6h = new Date(Date.now() - 6 * 60 * 60 * 1000);
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const deviceVelocityCount = riskRequest.deviceFingerprint ? await db.order.count({
      where: { merchantId, deviceFingerprint: riskRequest.deviceFingerprint, createdAt: { gte: last1h } }
    }) : 0;
    const ipVelocityCount = extracted.ipAddress ? await db.order.count({
      where: { merchantId, ipAddress: extracted.ipAddress, createdAt: { gte: last24h } }
    }) : 0;
    const emailVelocityCount = extracted.email ? await db.order.count({
      where: { merchantId, email: extracted.email, createdAt: { gte: last6h } }
    }) : 0;

    // [BIN Velocity fix] نفس منطق /evaluate — بدون storeScope عمدًا، اتساقًا
    // مع باقي عدّادات السرعة الثلاثة في هذا الـ endpoint تحديدًا (تناقضهم
    // مع /evaluate بخصوص storeScope موجود بالفعل من قبل وخارج نطاق هذا الفيكس).
    let webhookCardBinPrefix = null;
    if (extracted.bin != null) {
      const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
      if (b.length === 6) webhookCardBinPrefix = b;
    }

    let binVelocityCount10min = 0;
    let binVelocityCount1h = 0;
    let binVelocityCount24h = 0;
    if (webhookCardBinPrefix) {
      const last10min = new Date(Date.now() - 10 * 60 * 1000);
      [binVelocityCount10min, binVelocityCount1h, binVelocityCount24h] = await Promise.all([
        db.order.count({ where: { merchantId, cardBinPrefix: webhookCardBinPrefix, createdAt: { gte: last10min } } }),
        db.order.count({ where: { merchantId, cardBinPrefix: webhookCardBinPrefix, createdAt: { gte: last1h } } }),
        db.order.count({ where: { merchantId, cardBinPrefix: webhookCardBinPrefix, createdAt: { gte: last24h } } }),
      ]);
    }

    // 10. Build order object for riskScoring (compatible with calculateRiskScore)
    const orderForScoring = {
      id: extracted.orderId,
      email: extracted.email,
      ipAddress: extracted.ipAddress,
      deviceFingerprint: riskRequest.deviceFingerprint,
      amount: extracted.amount,
      billingAddress: extracted.billingCountry ? JSON.stringify({ country: extracted.billingCountry }) : null,
      shippingAddress: extracted.shippingCountry ? JSON.stringify({ country: extracted.shippingCountry }) : null,
      customerLoginId: extracted.customerLoginId,
      createdAt: extracted.createdAt || new Date().toISOString(),
      eciCode: null,
      avsResponse: null,
      cvv2Response: null,
      payment_details: extracted.bin ? { card_bin: extracted.bin } : null,
      fingerprintVersion: 'v3',
      fingerprintConfig: null,
      fingerprintHardware: null,
      isNewCustomer: false, // will be computed inside riskScoring
    };

    const { calculateRiskScore } = require('../lib/riskScoring');
    const riskResult = await calculateRiskScore(
      orderForScoring,
      formattedOrders,
      disputes,
      blacklist,
      merchantId,
      true,  // saveEvaluation
      { deviceVelocityCount, ipVelocityCount, emailVelocityCount, binVelocityCount10min, binVelocityCount1h, binVelocityCount24h },
      null,            // cardHashRecord — not available on this path
      webhookMerchantConfig, // threads deviceSignal into deviceTrustFactor — see above
      limitedScoring
    );

    // 11. Build signals snapshot
    const signalsSnapshot = {
      email: extracted.email,
      ipAddress: extracted.ipAddress,
      ipAnomaly: webhookIpAnomaly,
      bin: extracted.bin,
      deviceFingerprint: riskRequest.deviceFingerprint,
      amount: extracted.amount,
      billingCountry: extracted.billingCountry,
      shippingCountry: extracted.shippingCountry,
      isNewCustomer: riskResult.computedSignals?.isNewCustomer || false,
      deviceVelocityCount,
      ipVelocityCount,
      emailVelocityCount,
      // [BIN Velocity learning-loop fix] راجع نفس التعليق في /evaluate فوق
      // — binVelocityCount10min/1h/24h محسوبة بالفعل فوق (قسم "BIN Velocity
      // fix") ومُمررة لـ calculateRiskScore عبر externalVelocity، لكن كانت
      // غايبة من هنا فمفيش أي بيانات تعلّم توصل SignalStat من مسار الـ webhook.
      binVelocityCount10min,
      binVelocityCount1h,
      binVelocityCount24h,
      shippingBillingMismatch: extracted.billingCountry !== extracted.shippingCountry,
      // [Bug #5 fix] كانت hardcoded false. عمليًا لسه low-impact (راجع
      // ADR-0 — bin مبيوصلش لـ webhook في الإنتاج أصلًا)، لكن لو bin وصل
      // مستقبلًا (custom integration، إلخ) الفحص دلوقتي صحيح.
      binIssuerMismatch: riskResult.binIntel && riskResult.binIntel.issuerCountry !== extracted.billingCountry,
      amountAnomaly: (riskResult.computedSignals?.orderMultiple || 0) >= 3,
      ipIntel: riskResult.ipIntel || null,
      emailIntel: riskResult.emailIntel || null,
      binIntel: riskResult.binIntel || null,
      connectedRisk: riskResult.graphRisk || 0,
      graphPath: riskResult.graphPath || [],
      flags: riskResult.flags,
      positives: riskResult.positives,
    };

    // 12. Save order and risk evaluation
    await db.order.upsert({
      where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } },
      create: {
        orderId: extracted.orderId,
        merchantId,
        // Same unconditional-attribution fix as /evaluate (Change 2a).
        // req.storeId here comes from resolveStoreIdBestEffort() via
        // X-WC-Webhook-Source, set earlier in this handler.
        storeId: req.storeId ?? null,
        amount: extracted.amount,
        currency: 'USD',
        email: extracted.email,
        // [Bug #7 fix] راجع تعليق /evaluate فوق — نفس المنطق بالظبط.
        normalizedEmail: extracted.email ? normalizeEmail(extracted.email) : null,
        // [BIN Velocity fix] راجع webhookCardBinPrefix فوق.
        cardBinPrefix: webhookCardBinPrefix,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint,
        riskScore: riskResult.score,
        riskLevel: riskResult.riskLevel,
        decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
        connectedRisk: riskResult.graphRisk || 0,
        signalsSnapshot: JSON.stringify(signalsSnapshot),
        fingerprintVersion: 'v3',
      },
      update: {
        amount: extracted.amount,
        email: extracted.email,
        normalizedEmail: extracted.email ? normalizeEmail(extracted.email) : null,
        cardBinPrefix: webhookCardBinPrefix,
        ipAddress: extracted.ipAddress,
        deviceFingerprint: riskRequest.deviceFingerprint,
        riskScore: riskResult.score,
        riskLevel: riskResult.riskLevel,
        decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
        connectedRisk: riskResult.graphRisk || 0,
        signalsSnapshot: JSON.stringify(signalsSnapshot),
      },
    });

    // Optionally save RiskEvaluation if decision is block or review
    if (riskResult.decision.includes('Block') || riskResult.decision.includes('Review')) {
      const savedOrder = await db.order.findUnique({ where: { merchantId_orderId: { merchantId, orderId: extracted.orderId } } });
      if (savedOrder) {
        await db.riskEvaluation.upsert({
          where: { orderId: savedOrder.id },
          create: {
            orderId: savedOrder.id,
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            scoringVersion: riskResult.scoringVersion || 'v1.0',
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
          update: {
            staticScore: riskResult.score,
            learningScore: riskResult.score,
            finalDecision: riskResult.decision.includes('Approve') ? 'low' : (riskResult.decision.includes('Review') ? 'medium' : 'high'),
            topSignals: JSON.stringify(riskResult.flags.slice(0, 5)),
            positiveSignals: JSON.stringify(riskResult.positives || []),
            fraudProb: riskResult.economicData?.fraudProb ?? null,
            expectedLoss: riskResult.economicData?.expectedLoss ?? null,
            thresholdUsed: riskResult.economicData?.baseThreshold ?? null,
            decisionBefore: riskResult.economicData?.decisionBefore ?? null,
            decisionAfter: riskResult.economicData?.decisionAfter ?? null,
          },
        });
      }
    }

    // ── Quota Counter: webhook risk-scoring block path ──────────────────
    // Second of two block-producing decision points on this route (the
    // first being the BIN-sequence early-return above). Without this,
    // blocks resolved via calculateRiskScore() through the webhook were
    // written to Order/RiskEvaluation but never counted in BlockedAttempt
    // or monthlyBlockedCount — this closes that gap.
    const webhookFinalDecision = riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block');

    // [Discovery 4 fix] كانت غايبة من هذا المسار — يعني أي هجوم كارد
    // تيستنج جه بالكامل عبر الـ webhook (مش /evaluate) مكانش بيغذّي
    // CardTestAttempt خالص، فـ checkVelocity() (المُضافة فوق في 7a3، وأي
    // نداء مستقبلي من /evaluate لنفس IP/device) كانت تفضل عمياء عن نشاط
    // حقيقي حصل هنا. نفس شرط /evaluate بالحرف — أي قرار غير approve
    // (يشمل review، لقفل نفس الفجوة الدائرية الموثقة في /evaluate).
    // deviceFingerprint (الحقيقية، لا الاصطناعية) عمدًا — راجع تعليق 7c فوق.
    if (webhookFinalDecision !== 'approve') {
      recordFailedAttempt({
        ip: extracted.ipAddress,
        deviceFingerprint: deviceFingerprint || null,
        merchantId,
        storeId: storeScope.storeId ?? null,
        amount: extracted.amount || 0,
        wasBlocked: webhookFinalDecision === 'block',
      });
    }

    if (webhookFinalDecision === 'block') {
      let webhookFinalCardBin = null;
      if (extracted.bin != null) {
        const b = String(extracted.bin).replace(/\D/g, '').slice(0, 6);
        if (b.length === 6) webhookFinalCardBin = b;
      }
      const webhookFinalIpHash = extracted.ipAddress ? hashIp(extracted.ipAddress) : null;
      let webhookFinalAmount = null;
      if (extracted.amount != null) {
        const amt = parseFloat(extracted.amount);
        if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) webhookFinalAmount = amt;
      }
      let webhookFinalRiskScore = null;
      if (riskResult.score != null) {
        const rs = parseInt(riskResult.score, 10);
        if (!isNaN(rs) && rs >= 0 && rs <= 100) webhookFinalRiskScore = rs;
      }

      try {
        await db.$transaction(recordBlockedAttempt(db, {
          merchantId:      merchantId,
          storeId:         req.storeId ?? null, // best-effort, resolved above from X-WC-Webhook-Source
          cardBin:         webhookFinalCardBin,
          cardType:        null, // not captured by extractOrderData()
          reason:          'pattern',
          ipHash:          webhookFinalIpHash,
          amountAttempted: webhookFinalAmount,
          riskScore:       webhookFinalRiskScore,
        }));
      } catch (counterErr) {
        logger.error(
          { module: 'risk', endpoint: 'woocommerce-webhook', tenantId: merchantId, error: counterErr.message },
          'Failed to record BlockedAttempt / increment quota counter from woocommerce-webhook'
        );
      }
    }

    // Return response
    res.json({
      orderId: extracted.orderId,
      score: riskResult.score,
      decision: riskResult.decision.includes('Approve') ? 'approve' : (riskResult.decision.includes('Review') ? 'review' : 'block'),
      flags: riskResult.flags,
      connectedRisk: riskResult.graphRisk || 0,
      scored: true,
      limitedScoring,
    });

  } catch (error) {
    // Status code (500) is unchanged — this is what the plugin's circuit
    // breaker (class-api-client.php) keys on. Only the response body is
    // sanitized.
    logger.error({ module: 'risk', endpoint: 'woocommerce-webhook', error: error.message, stack: error.stack }, 'Webhook error');
    res.status(500).json(safeErrorPayload(error));
  }
});
// ========== Check Device Endpoint ==========
// ������� ������ ���� ������� ���������� �� ������� �������
router.post('/check-device', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { fingerprint } = req.body;
    if (!fingerprint) {
      return res.status(400).json({ error: 'fingerprint is required' });
    }

  const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // 1. ����� �� ���� ������ �� Identity Graph    const { getConnectedRisk } = require('../lib/identityGraph');
    const mockOrder = {
      deviceFingerprint: fingerprint,
      fingerprintVersion: 'v3',
    };

    let blocked = false;
    let reason = null;

    try {
      const graphResult = await getConnectedRisk(mockOrder, merchantId);
      // ��� ��� connectedRisk >= 80 ������ ������� ������ ������
      if (graphResult.connectedRisk >= 45) {
        blocked = true;
        reason = 'Device fingerprint linked to high-risk network';
      }
    } catch (err) {
      logger.error({ module: 'risk', endpoint: 'check-device', err }, 'Graph lookup error');
      // ��� ���: �� ���� �������� ��� ��� �����
    }

    // 2. (�������) ����� �� ������� ������� ��������
    if (!blocked) {
      const blacklisted = await db.blacklistEntry.findFirst({
        where: {
          merchantId,
          type: 'DEVICE_FINGERPRINT',
          value: fingerprint,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      });
      if (blacklisted) {
        blocked = true;
        reason = 'Device is blacklisted';
      }
    }

    res.json({ blocked, reason });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'check-device', error: error.message, stack: error.stack }, 'Check-device error');
    // blocked: false preserved — the plugin reads this field on every
    // response shape from this endpoint, including error paths.
    res.status(500).json({ blocked: false, ...safeErrorPayload(error) });
  }
});

// ========== Enrich Endpoint ==========
// ������� ������ ����� ������� BIN �� ������ ����� �������� (��� Stripe)
router.post('/enrich', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { 
      orderId, 
      paymentIntentId, 
      bin, 
      cardBrand, 
      cardCountry, 
      funding, 
      issuer,
      last4,
      expMonth,
      expYear,
      brand,
      idempotencyKey,
      deviceToken
    } = req.body;

    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (!bin && !last4) {
      return res.status(400).json({ error: 'bin or last4 is required' });
    }

    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    // Tier-1 fraud-isolation scope (opt-in) — same call as /evaluate and
    // /woocommerce-webhook (CWE-1059 drift fix: this was previously
    // omitted here, causing a ReferenceError on every /enrich call).
    const storeScope = getStoreScope(req.tenant, req.storeId);

    // ── Quota Status (mirrors /evaluate and /woocommerce-webhook) ──────────
    // Previously missing entirely on this path — a tenant that exhausted
    // its monthly block quota still received full external IP/email/BIN
    // intelligence on every post-payment enrichment call, indefinitely.
    // Quota only gates the expensive external lookups inside
    // calculateRiskScore(); it never blocks or short-circuits this request.
    const quotaStatus = await checkQuotaGate(req, 'enrich');
    const limitedScoring = quotaStatus.exceeded;
    // ── End Quota Status ──────────────────────────────────────────────────

    // ??? CardHash generation (if last4+expiry+brand provided) ???rovided) ???
    let cardHashRecord = null;
    if (last4 && expMonth && expYear && brand && merchantId) {

      const secret = process.env.CARD_HASH_SECRET;
      if (!secret) throw new Error('CARD_HASH_SECRET missing');
      const raw = `${merchantId}:${last4}:${expMonth}:${expYear}:${brand}`;
      const cardHash = crypto.createHmac('sha256', secret).update(raw).digest('hex');
      
      cardHashRecord = await db.cardHash.upsert({
        where: { cardHash },
        create: {
          merchantId,
          cardHash,
          last4,
          expMonth,
          expYear,
          brand,
          attemptCount: 1,
        },
        update: {
          attemptCount: { increment: 1 },
          lastSeenAt: new Date(),
        },
      });
    }

    // 1. ����� �� ����� �������
    const existingOrder = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId } },
      select: { 
        id: true, 
        merchantId: true, 
        decision: true, 
        riskScore: true, 
        signalsSnapshot: true,
    
        amount: true,
        email: true,
        ipAddress: true,
        deviceFingerprint: true,
        createdAt: true,

        customerLoginId: true,
        fingerprintVersion: true,

        riskLevel: true,
      }
    });

    // 2. ��� �� ���� ����ȡ ���� pending enrichment
    if (!existingOrder) {
      await db.pendingEnrichment.create({
        data: {
          // merchantId is already resolved from the authenticated tenant
          // above (never trusted from the body) — this closes the
          // cross-tenant scoping gap described in the schema migration.
          merchantId,
          orderId,
          paymentIntentId: paymentIntentId || null,
          enrichData: JSON.stringify(req.body),
          status: 'pending'
        }
      });
      return res.status(202).json({ 
        success: true, 
        message: 'Order not found. Enrichment queued for processing.',
        orderId 
      });
    }
// 3. ������ �� ����� ������ + core enrichment logic — delegated to the
    // shared processor so the replay job (see jobs/replayPendingEnrichments.js)
    // can never drift out of sync with this route's behavior.
    const { processEnrichment } = require('../lib/enrichmentProcessor');
    const result = await processEnrichment({ merchantId, orderId, body: req.body, storeId: req.storeId ?? null, tenant: req.tenant, limitedScoring });
    return res.status(result.status).json(result.body);
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'enrich', error: error.message, stack: error.stack }, 'Enrich error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== Tenant Registration (Early Access) ==========

/**
 * @swagger
 * /tenants/register:
 *   post:
 *     summary: Register a new tenant and receive an API key
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string, format: email }
 *               storeUrl: { type: string }
 *     responses:
 *       201:
 *         description: Registration successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 apiKey: { type: string }
 *                 email: { type: string }
 *       400:
 *         description: Missing email or email already registered
 *       500:
 *         description: Internal server error
 */


router.post('/tenants/register', async (req, res) => {
      // ?? Rate Limiting (Persistent DB) ????????????????????????????????????????
  const ip = req.ip || req.connection.remoteAddress;
  const ipHash = hashIp(ip);
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const MAX_ATTEMPTS = 5;

  try {
    const [, recentCount] = await Promise.all([
      db.registrationAttempt.deleteMany({
        where: { createdAt: { lt: oneHourAgo } }
      }),
      db.registrationAttempt.count({
        where: { ipHash, createdAt: { gte: oneHourAgo } }
      })
    ]);

    if (recentCount >= MAX_ATTEMPTS) {
      const oldestAttempt = await db.registrationAttempt.findFirst({
        where: { ipHash, createdAt: { gte: oneHourAgo } },
        orderBy: { createdAt: 'asc' },
        select: { createdAt: true }
      });
      const resetAt = oldestAttempt
        ? new Date(oldestAttempt.createdAt).getTime() + 60 * 60 * 1000
        : Date.now() + 60 * 60 * 1000;
      const retryAfterSecs = Math.ceil((resetAt - Date.now()) / 1000);
      const retryAfterMins = Math.ceil(retryAfterSecs / 60);
      res.set('Retry-After', String(retryAfterSecs));
      return res.status(429).json({
        error: `Too many registration attempts. Please try again in ${retryAfterMins} minute(s).`,
        retryAfter: retryAfterSecs
      });
    }

    await db.registrationAttempt.create({ data: { ipHash } });

  } catch (rateLimitErr) {
    logger.error(
      { module: 'risk', endpoint: 'register', error: rateLimitErr.message },
      'Rate limiter DB error � failing open'
    );
  }
  // ?? End Rate Limiting ?????????????????????????????????????????????????????

  // ?? Turnstile verification ????????????????????????????????????????????
      const turnstileToken = req.body.turnstileToken || '';
      if (!turnstileToken) {
        return res.status(400).json({ error: 'Security check token missing.' });
      }
      try {
        const turnstileRes = await fetch(
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              secret:   process.env.TURNSTILE_SECRET_KEY,
              response: turnstileToken,
              remoteip: req.ip || req.connection.remoteAddress
            })
          }
        );
        const turnstileData = await turnstileRes.json();
        if (!turnstileData.success) {
          return res.status(403).json({ error: 'Security check failed. Please try again.' });
        }
      } catch (turnstileErr) {
        console.error('Turnstile verification error:', turnstileErr);
        return res.status(503).json({ error: 'Security check unavailable. Please try again.' });
      }
// ?? End Turnstile ?????????????????????????????????????????????????????

  // ?? Honeypot check ????????????????????????????????????????????????????
  // A hidden field (name="website") that only bots reliably fill in. Real
  // users never see or complete it (CSS-hidden in index.html). Any
  // non-empty value here is treated as a bot signal — respond with a
  // generic success-shaped message (not an error) to avoid teaching a bot
  // it tripped a filter, and skip tenant creation entirely.
  const honeypotValue = req.body.website || '';
  if (honeypotValue.trim() !== '') {
    logger.warn({ module: 'risk', endpoint: 'register' }, 'Honeypot field filled — likely bot submission, rejecting silently');
    return res.status(200).json({
      email: req.body.email || null,
      plan: 'early_access',
      verified: false,
      requiresVerification: true,
      message: 'Almost there! We sent a confirmation link to your email. Click it to activate your account and receive your API key.'
    });
  }
  // ?? End honeypot check ???????????????????????????????????????????????      


  try {
    const { email, storeUrl } = req.body;



    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    // Check if tenant already exists
    const existing = await db.tenant.findUnique({ where: { email } });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Generate a unique API key (256-bit CSPRNG — NIST SP 800-63B §5.1.1.2 entropy requirement)
    const apiKey = crypto.randomBytes(32).toString('base64');
    const apiKeyHash = hashApiKey(apiKey);

    // Generate email verification token
    const emailVerifyToken = crypto.randomBytes(32).toString('hex');
    const emailVerifyExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Normalize storeUrl domain — this becomes the tenant's only authorized
    // origin for API key use (CWE-636 fix: domain binding must be populated
    // at creation time so domainAuthMiddleware has real data to enforce
    // against rather than failing open on a missing/empty array).
    const allowedDomains = [];
    if (storeUrl) {
      const normalizedDomain = normalizeDomain(storeUrl);
      if (normalizedDomain) {
        allowedDomains.push(normalizedDomain);
      }
    }

    // In development mode, skip email verification
    const skipVerification = process.env.EMAIL_VERIFICATION_DISABLED === 'true';

    // Webhook signing secret — required by verifyHmacSignature on every mutating
    // route. Must be generated here at tenant-creation time (not deferred to a
    // later recovery flow), otherwise req.tenant.webhookSecret stays null forever
    // and /evaluate, /enrich, /blacklist, /whitelist, /blocked-attempt all 401.
    // Same pattern as /connect/confirm in src/routes/auth.js.
    const webhookSecret = crypto.randomBytes(32).toString('hex');

    // Early Access Pro Grant — evaluated once, at the moment of tenant
    // creation. If EARLY_ACCESS_END_DATE is unset or still in the future,
    // this registration is eligible for "3 months of Shield Pro at no
    // cost." Ineligible registrations (after the cutoff) fall back to the
    // pre-existing free early_access behavior — unchanged from today.
    const earlyAccessGrant = {
      plan:                'starter',
      subscriptionStatus:  'free',
      subscriptionEndDate: null,
      billingCycle:        null,
    };

   const tenant = await db.tenant.create({
      data: {
        email,
        storeUrl: storeUrl || null,
        allowedDomains, // Domain-binding allowlist (CWE-636 fix) — enforced by domainAuthMiddleware
        webhookSecret, // HMAC request-signing secret — provisioned at tenant creation, not deferred
        apiKeyHash, // Source of truth for authentication (OWASP ASVS V6.2.1)
        // Production path only: apiKey plaintext is held transiently so the post-verification
        // welcome email (sent from /verify-email, only after inbox ownership is proven) can
        // include it. It is purged in the same DB write that sets emailVerified = true (see
        // routes/auth.js), bounding the exposure window to "time until the merchant clicks the
        // confirmation link" — the same transient-then-deleted pattern already used for
        // emailVerifyToken (CWE-532 minimization; NIST SP 800-63B authenticator lifecycle).
        // The skipVerification (dev mode) path below never writes apiKey at all, since the key
        // is sent directly from this request's closure before this row is committed.
        apiKey: skipVerification ? null : apiKey,
        ...earlyAccessGrant,
        isActive: true,
        emailVerified: skipVerification,
        emailVerifyToken: skipVerification ? null : emailVerifyToken,
        emailVerifyExpiresAt: skipVerification ? null : emailVerifyExpiresAt,
      }
    });

    logger.info({ module: 'risk', newTenant: tenant.email }, 'New tenant registered');

    if (skipVerification) {
      // Dev mode — send API key immediately as before
      const { sendApiKeyEmail } = require('../lib/email');
      sendApiKeyEmail(tenant.email, apiKey).catch(err => {
        logger.error({ module: 'email', error: err.message }, 'Failed to send API key email (dev mode)');
      });

      return res.status(201).json({
        email: tenant.email,
        plan: tenant.plan,
        verified: true,
        message: 'Welcome to ChargeGuard Early Access! Check your email for your API key.'
      });
    }

    // Production — send confirmation email, withhold API key
    const baseUrl = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';
    const confirmUrl = `${baseUrl}/api/auth/verify-email?token=${emailVerifyToken}`;

    const { sendConfirmationEmail } = require('../lib/email');
    sendConfirmationEmail(tenant.email, confirmUrl).catch(err => {
      logger.error({ module: 'email', error: err.message }, 'Failed to send confirmation email');
    });

    res.status(201).json({
      email: tenant.email,
      plan: tenant.plan,
      verified: false,
      requiresVerification: true,
      message: 'Almost there! We sent a confirmation link to your email. Click it to activate your account and receive your API key.'
    });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'register', error: error.message }, 'Registration error');
    res.status(500).json({ error: 'Internal server error' });
  }
});


// ========== GET /risk/verify-key ==========
// ������� ������ �� "���� �� �������" �� ����� WooCommerce
// �� ������ domainAuthMiddleware ����� � ������ �� ����� ��� ����� ������
/**
 * @swagger
 * /risk/verify-key:
 *   get:
 *     summary: Verify if an API key is valid and active
 *     parameters:
 *       - in: header
 *         name: x-api-key
 *         required: true
 *         schema: { type: string }
 *       - in: header
 *         name: x-store-domain
 *         required: false
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: API key is valid and active
 *       400:
 *         description: Missing x-api-key header
 *       401:
 *         description: Invalid or inactive API key
 *       403:
 *         description: Domain not authorized for this key
 *       500:
 *         description: Internal server error
 */
// SANCTIONED EXCEPTION to the centralized requireAuth() pattern (CWE-1059
// drift-prevention documentation — same rationale as the /connect/confirm
// no-grace-period note in routes/auth.js). Do NOT "fix" this to use
// requireAuth() without re-reading this comment in full.
//
// This is a lightweight HEALTH-CHECK endpoint: the WooCommerce plugin calls
// it to ask "is my API key still valid?" before doing anything else,
// including before it has fetched webhookSecret. Three deliberate
// deviations from the standard pattern follow from that:
//
//   a) No requireAuth() AUTH_FAIL_DELAY_MS (200ms) on failure. That delay
//      exists to blunt key-enumeration timing attacks against mutating,
//      capability-granting endpoints (CWE-208). A pure validity probe is a
//      much lower-value timing oracle — knowing a key is "valid" grants no
//      capability an attacker couldn't get more directly by trying the key
//      against a real endpoint — and this route is polled frequently, so
//      artificial latency here has a real operational cost with no
//      proportionate security benefit (cf. Kubernetes liveness/readiness
//      probes, which are intentionally excluded from the full
//      auth/authz chain the live application enforces, for the same
//      cost/benefit reason).
//   b) No domainAuthMiddleware. The plugin calls this from the merchant's
//      own server process, not a browser subject to origin enforcement —
//      there is no "origin" to bind in the way there is for browser-facing
//      mutating calls.
//   c) No verifyHmacSignature. The plugin may not have fetched
//      webhookSecret yet — requiring an HMAC signature here would be
//      circular (the secret needed to sign isn't available until after a
//      successful authenticated call).
//
// What is NOT relaxed: this handler still manually enforces tenant.isActive
// and tenant.emailVerified (mirroring requireAuth's policy exactly), and
// returns no sensitive data — only plan/subscription metadata, never a
// secret. If those manual checks and requireAuth's checks ever diverge,
// that is the one thing to fix; the missing delay/domain/HMAC layers above
// are by design and should stay missing.
router.get('/verify-key', async (req, res) => {
  try {
    // 1. ������ �� ���� ��� header
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(400).json({
        valid: false,
        message: 'Missing x-api-key header'
      });
    }

    // 2. Find tenant by API key (hash-first with deprecated-plaintext fallback — zero-downtime migration)
    const { tenant } = await resolveTenantByApiKey(apiKey, {
      id: true,
      isActive: true,
      emailVerified: true,
    });

    // 2. Validate tenant
    if (!tenant || !tenant.isActive) {
      return res.status(401).json({
        valid: false,
        message: 'Invalid or inactive API key'
      });
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({
        valid: false,
        message: 'Email not verified. Please check your inbox and click the confirmation link.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // 4. ������ ��������� �� �������
    //    ������� ��� ��� ��� ������ ���� allowedDomains �����
    //    (������ ��� ������� �� ������ ������� ����� ��� ����� ����� ����)
    // TODO: ����� ������ �� ������� ��� ���� ��� allowedDomains

    // 5. إرجاع حالة الاشتراك مع الـ validation
    const tenantFull = await db.tenant.findUnique({
      where:  { id: tenant.id },
      select: {
        plan:               true,
        subscriptionStatus: true,
        subscriptionEndDate: true,
        billingCycle:       true,
        lastPaymentDate:    true,
      },
    });

    return res.status(200).json({
      valid:              true,
      message:            'API key is valid',
      plan:               tenantFull?.plan               || 'starter',
      subscriptionStatus: tenantFull?.subscriptionStatus || 'free',
      subscriptionEndDate: tenantFull?.subscriptionEndDate || null,
      billingCycle:       tenantFull?.billingCycle        || null,
      lastPaymentDate:    tenantFull?.lastPaymentDate     || null,
    });

  } catch (error) {
    logger.error(
      { module: 'risk', endpoint: 'verify-key', error: error.message },
      'Verify key error'
    );
    return res.status(500).json({
      valid: false,
      message: 'Internal server error'
    });
  }
});

// ========== POST /risk/blocked-attempt ==========
// Receives blocked card-testing events from the WooCommerce Plugin.
// Stores them in BlockedAttempt table for the user dashboard.
//
// Auth:     X-Api-Key header (same apiKeyAuth middleware)
// Privacy:  Only ipHash (SHA-256) is accepted — real IP is never stored
// Reliability: Fire-and-forget from plugin side; failures are silent

const BLOCKED_ATTEMPT_RATE = new Map(); // keyed on apiKey, not IP
const BA_MAX_REQ   = 60;
const BA_WINDOW_MS = 60 * 1000;

// L3 fix: independent periodic sweep, mirroring the CONNECT_STATUS_RATE
// fix in routes/auth.js — a key polled exactly once (or never re-polled)
// was previously never pruned, since pruning only happened on a re-poll
// of the SAME key after its window expired. This closes that regardless
// of whether the map is ever populated pre-auth or not; see the
// middleware-ordering fix below for the actual root-cause fix.
setInterval(() => {
  const now = Date.now();
  for (const [key, rec] of BLOCKED_ATTEMPT_RATE.entries()) {
    if (now - rec.firstAt > BA_WINDOW_MS) {
      BLOCKED_ATTEMPT_RATE.delete(key);
    }
  }
}, BA_WINDOW_MS).unref();

const blockedAttemptRateLimit = (req, res, next) => {
  // L3 fix: this middleware now runs AFTER apiKeyAuth in the route
  // definition below (see that change), so req.tenant is guaranteed to
  // exist here — key on the authenticated tenant's id, not the raw
  // x-api-key header value. Previously this ran before authentication,
  // meaning an unauthenticated caller could populate this map with
  // arbitrary/garbage x-api-key values (or fall back to req.ip) without
  // bound, and a rejected key would still consume a map slot for no
  // legitimate reason.
  const key = req.tenant?.id || req.ip || 'unknown';
  const now = Date.now();
  const rec = BLOCKED_ATTEMPT_RATE.get(key);
  if (rec) {
    if (now - rec.firstAt > BA_WINDOW_MS) {
      BLOCKED_ATTEMPT_RATE.delete(key);
    } else if (rec.count >= BA_MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    BLOCKED_ATTEMPT_RATE.set(key, { count: 1, firstAt: now });
  }
  next();
};

const VALID_REASONS    = new Set(['card_testing', 'velocity', 'blacklist', 'pattern', 'email', 'device_rotation_global']);const VALID_CARD_TYPES = new Set(['visa', 'mastercard', 'amex', 'discover', 'unknown']);

// L3 fix: blockedAttemptRateLimit now runs after apiKeyAuth rather than
// before it. Only a request that has already presented a real, valid
// API key reaches the rate limiter and can grow BLOCKED_ATTEMPT_RATE —
// an unauthenticated caller is rejected by apiKeyAuth first and never
// touches the map at all. This also means the rate-limit key (req.tenant.id,
// set inside the middleware above) is now trustworthy tenant identity
// rather than a client-supplied header value.
router.post('/blocked-attempt', apiKeyAuth, blockedAttemptRateLimit, domainAuthMiddlewareWithAutoRegister, verifyHmacSignature, autoRegisterStoreMiddleware, async (req, res) => {
  try {
    const { cardBin, cardType, reason, ipHash, amountAttempted } = req.body;

    if (!reason || !VALID_REASONS.has(reason)) {
      return res.status(400).json({
        error: `Invalid or missing 'reason'. Allowed: ${[...VALID_REASONS].join(', ')}`,
      });
    }

    // cardBin: accept only 6 numeric digits
    let safeBin = null;
    if (cardBin != null) {
      const b = String(cardBin).replace(/\D/g, '').slice(0, 6);
      if (b.length === 6) safeBin = b;
    }

    // cardType: normalise to lowercase, fallback to 'unknown'
    let safeCardType = null;
    if (cardType != null) {
      const ct = String(cardType).toLowerCase().trim();
      safeCardType = VALID_CARD_TYPES.has(ct) ? ct : 'unknown';
    }

    // ipHash: must be 64-char hex (SHA-256)
    let safeIpHash = null;
    if (ipHash != null) {
      const h = String(ipHash).toLowerCase().trim();
      if (/^[0-9a-f]{64}$/.test(h)) safeIpHash = h;
    }

    // amountAttempted: positive number, sanity-capped at $999,999
    let safeAmount = null;
    if (amountAttempted != null) {
      const amt = parseFloat(amountAttempted);
      if (!isNaN(amt) && amt >= 0 && amt < 1_000_000) safeAmount = amt;
    }

    // riskScore: integer 0-100, nullable for legacy data
    let safeRiskScore = null;
    if (req.body.riskScore != null) {
      const rs = parseInt(req.body.riskScore, 10);
      if (!isNaN(rs) && rs >= 0 && rs <= 100) safeRiskScore = rs;
    }

    // monthlyBlockedCount is NO LONGER incremented here. The quota counter
    // is now driven solely by the /evaluate block-decision path (see the
    // $transaction there), which is the authoritative enforcement point.
    // Incrementing it here too would double-count every attack that goes
    // through /evaluate → block → plugin calls /blocked-attempt. This
    // endpoint still creates BlockedAttempt rows for dashboard/reporting —
    // e.g. plugin-local firewall blocks that never reach /evaluate — just
    // without touching the counter.
    await db.blockedAttempt.create({
      data: {
        tenantId:        req.tenant.id,
        // Agency multi-store attribution — req.storeId is set by
        // domainAuthMiddleware only for store-managed tenants; null for
        // Starter/Pro (no Store rows exist for them), which is the correct
        // "no store to attribute to" value, not an error.
        storeId:         req.storeId ?? null,
        cardBin:         safeBin,
        cardType:        safeCardType,
        reason:          reason,
        ipHash:          safeIpHash,
        amountAttempted: safeAmount,
        riskScore:       safeRiskScore,
      },
    });

    return res.status(200).json({ success: true });

  } catch (err) {
    logger.error(
      { module: 'risk', endpoint: 'blocked-attempt', error: err.message },
      'Failed to record blocked attempt'
    );
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
// ========== POST /risk/dispute-evidence ==========
// نقطة تسجيل موحّدة لأي دليل post-purchase يتجمّع على مدار عمر الـ
// dispute. لا تُغيّر قرار الأوردر (خلاص اتنفذ) — الغرض الوحيد هو تجميع
// إشارات هتُقرأ لاحقًا في processFeedbackSimplified() (feedbackLoop.js)
// وقت إغلاق الـ dispute (won/lost)، فتغذّي SignalStat بدقة أعلى من
// signalsSnapshot وحدها.
//
// Idempotent by design: @@unique([orderId, evidenceType]) — استدعاء
// متكرر لنفس النوع بيحدّث القيمة (upsert)، مش يكرر الصف.
const VALID_EVIDENCE_TYPES = new Set([
  'TRACKING', 'DELIVERY_PROOF', 'LOGIN', 'CTA', 'PRE_CHARGE',
  'USAGE_LOGS', 'NO_CANCEL_REQUEST', 'CE30', 'REFUND',
]);
const VALID_EVIDENCE_SOURCES = new Set(['system_derived', 'processor_webhook', 'manual']);

router.post('/dispute-evidence', apiKeyAuth, domainAuthMiddleware, verifyHmacSignature, async (req, res) => {
  try {
    const { orderId, evidenceType, value, source, metadata } = req.body;
    const merchantId = req.tenant.id; // never trust client-supplied merchantId (CWE-639)

    if (!orderId || typeof orderId !== 'string') {
      return res.status(400).json({ error: 'orderId is required' });
    }
    if (!evidenceType || !VALID_EVIDENCE_TYPES.has(evidenceType)) {
      return res.status(400).json({ error: `evidenceType must be one of: ${[...VALID_EVIDENCE_TYPES].join(', ')}` });
    }
    if (!value || typeof value !== 'string') {
      return res.status(400).json({ error: 'value is required' });
    }
    const safeSource = VALID_EVIDENCE_SOURCES.has(source) ? source : 'manual';

    // Scoped lookup — نفس نمط C3/C4 المستخدم في باقي الملف: compound key
    // يضمن إن الأوردر ينتمي لنفس التاجر المُصادَق عليه، مستحيل يرجع صف
    // تاجر تاني.
    const order = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId, orderId } },
      select: { id: true },
    });
    if (!order) {
      logger.warn({ module: 'risk', endpoint: 'dispute-evidence', merchantId, orderId }, 'Order not found for this merchant');
      return res.status(404).json({ error: 'Order not found' });
    }

    const confidence = safeSource === 'manual' ? 0.7 : 1.0;

    const evidence = await db.disputeEvidence.upsert({
      where: { orderId_evidenceType: { orderId: order.id, evidenceType } },
      create: {
        merchantId,
        orderId: order.id,
        evidenceType,
        value,
        source: safeSource,
        confidence,
        metadata: metadata ?? undefined,
        submittedBy: safeSource === 'manual' ? (req.body.submittedBy || 'merchant') : 'system',
      },
      update: {
        value,
        source: safeSource,
        confidence,
        metadata: metadata ?? undefined,
        submittedAt: new Date(),
      },
    });

    res.json({ success: true, evidence: { id: evidence.id, evidenceType: evidence.evidenceType, value: evidence.value } });
  } catch (error) {
    logger.error({ module: 'risk', endpoint: 'dispute-evidence', error: error.message, stack: error.stack }, 'Error recording dispute evidence');
    res.status(500).json(safeErrorPayload(error));
  }
});

// ── TEMP DEBUG — احذف هذا البلوك بالكامل بعد الانتهاء من الاختبار ──
router.get('/debug-quota/:tenantId', async (req, res) => {
  if (req.query.secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const tenant = await db.tenant.findUnique({
    where: { id: req.params.tenantId },
    select: { email: true, monthlyBlockedCount: true, quotaResetDate: true },
  });
  res.json(tenant);
});

router.post('/debug-reset-quota/:tenantId', async (req, res) => {
  if (req.query.secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const updated = await db.tenant.update({
    where: { id: req.params.tenantId },
    data: { monthlyBlockedCount: 0 },
  });
  res.json(updated);
});
// ── END TEMP DEBUG ──

module.exports = router;

