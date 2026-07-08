// src/lib/domainAuth.js
'use strict';

const crypto = require('crypto');
const db     = require('./db');
const logger = require('./logger');

// ─── ثوابت بيئات التطوير ───────────────────────────────────────────────────

const DEV_EXACT = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '0.0.0.0',
]);

// Regex للشبكات الخاصة (IPv4)
const PRIVATE_NETWORK_RE = /^(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/;

// ─── normalizeDomain ────────────────────────────────────────────────────────

/**
 * تُنظّف أي إدخال وتُعيد hostname نقياً بدون بروتوكول أو www أو port.
 * مثال: "https://www.MyStore.com:8080/" → "mystore.com"
 * تُعيد null إذا كان الإدخال غير صالح.
 *
 * @param  {string|undefined} raw
 * @returns {string|null}
 */
function normalizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;

  let input = raw.trim();
  if (!input) return null;

  // إذا لم يحتوِ على بروتوكول، أضفه مؤقتاً حتى يعمل new URL()
  if (!/^https?:\/\//i.test(input)) {
    input = 'https://' + input;
  }

  let hostname;
  try {
    hostname = new URL(input).hostname;
  } catch {
    // إدخال لا يمكن تحليله — مثل نص عشوائي
    return null;
  }

  // تحويل لحروف صغيرة وإزالة www. من البداية فقط
  hostname = hostname.toLowerCase().replace(/^www\./, '');

  // إزالة أي port علق في الـ hostname (نادر لكن محتمل)
  hostname = hostname.replace(/:\d+$/, '');

  return hostname || null;
}

// ─── isDevDomain ────────────────────────────────────────────────────────────

/**
 * تُعيد true إذا كان الدومين ينتمي إلى بيئة تطوير محلية.
 *
 * @param  {string} domain  — hostname منقّح من normalizeDomain
 * @returns {boolean}
 */
function isDevDomain(domain) {
  if (!domain) return false;

  // تطابق حرفي (localhost, 127.0.0.1, ...)
  if (DEV_EXACT.has(domain)) return true;

  // امتدادات التطوير الشائعة
  if (domain.endsWith('.local'))  return true;
  if (domain.endsWith('.test'))   return true;
  if (domain.endsWith('.dev'))    return true;  // بعض المشاريع تستخدمها
  if (domain.endsWith('.localhost')) return true;

  // شبكات IPv4 الخاصة
  if (PRIVATE_NETWORK_RE.test(domain)) return true;

  return false;
}

// ─── domainAuthMiddleware ───────────────────────────────────────────────────

/**
 * Express middleware يتحقق من أن الدومين المُرسَل مع الطلب
 * موجود في قائمة allowedDomains الخاصة بالـ tenant.
 *
 * يجب تشغيله بعد apiKeyAuth حتى يكون req.tenant متاحاً.
 *
 * @type {import('express').RequestHandler}
 */
const domainAuthMiddleware = async (req, res, next) => {
  try {

    // ── ١. تجاوز الطلبات الداخلية ─────────────────────────────────────────
    const internalTokenRaw = req.headers['x-internal-token'];
    const internalTokenEnv = process.env.INTERNAL_TOKEN;

    if (internalTokenRaw && internalTokenEnv) {
      // نستخدم timingSafeEqual لمنع timing attacks
      const a = Buffer.from(internalTokenRaw);
      const b = Buffer.from(internalTokenEnv);

      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        logger.debug(
          { module: 'domainAuth', path: req.path },
          'Internal token matched — skipping domain check'
        );
        return next();
      }

      // Token موجود لكن خاطئ — نرفض صراحةً
      logger.warn(
        { module: 'domainAuth', ip: req.ip, path: req.path },
        'Invalid internal token provided'
      );
      return res.status(403).json({
        error: 'Invalid internal token',
        code:  'INVALID_INTERNAL_TOKEN',
      });
    }

    // ── ٢. استخراج الدومين من الـ Header ─────────────────────────────────
    const rawDomain = req.headers['x-store-domain'];
    const normalizedDomain = normalizeDomain(rawDomain);

    if (!normalizedDomain) {
      logger.warn(
        {
          module:    'domainAuth',
          tenantId:  req.tenant?.id,
          raw:       rawDomain ?? '(missing)',
          ip:        req.ip,
          path:      req.path,
        },
        'Missing or unparseable X-Store-Domain header'
      );
      return res.status(400).json({
        error: 'X-Store-Domain header is required and must be a valid domain',
        code:  'MISSING_DOMAIN',
      });
    }

    // ── ٣. السماح ببيئات التطوير ──────────────────────────────────────────
    if (isDevDomain(normalizedDomain)) {
      logger.debug(
        {
          module:   'domainAuth',
          domain:   normalizedDomain,
          tenantId: req.tenant?.id,
        },
        'Dev/local domain — skipping allowedDomains check'
      );
      req.storeDomain = normalizedDomain;
      return next();
    }

    // ── ٤. التحقق من req.tenant (يجب أن يكون موجوداً من apiKeyAuth) ───────
    if (!req.tenant?.id) {
      // هذا لا يجب أن يحدث في الترتيب الصحيح للـ middleware
      logger.error(
        { module: 'domainAuth', path: req.path },
        'req.tenant missing — domainAuth must run after apiKeyAuth'
      );
      return res.status(500).json({
        error: 'Server configuration error',
        code:  'MISSING_TENANT_CONTEXT',
      });
    }

    // ── ٥. استعلام Prisma للتحقق من allowedDomains ────────────────────────
    const tenantRecord = await db.tenant.findUnique({
      where:  { id: req.tenant.id },
      select: { allowedDomains: true },
    });

    const allowedDomains = tenantRecord?.allowedDomains ?? [];

    // Backward compatibility: إذا كان allowedDomains فارغًا، اسمح بالمرور
    if (allowedDomains.length === 0) {
      logger.debug(
        { module: 'domainAuth', tenantId: req.tenant.id },
        'Tenant has no allowedDomains configured — allowing request (backward compatibility)'
      );
      req.storeDomain = normalizedDomain;
      return next();
    }

    // ── ٦. قرار السماح أو الرفض ───────────────────────────────────────────
    if (!allowedDomains.includes(normalizedDomain)) {
      logger.warn(
        {
          module:         'domainAuth',
          tenantId:       req.tenant.id,
          requestDomain:  normalizedDomain,
          allowedDomains,
          ip:             req.ip,
          userAgent:      req.headers['user-agent'] ?? '(none)',
          path:           req.path,
        },
        'Domain mismatch — request rejected'
      );
      return res.status(403).json({
        error: 'Domain not authorized for this API key',
        code:  'DOMAIN_MISMATCH',
      });
    }

    // ── ٧. نجح التحقق ─────────────────────────────────────────────────────
    req.storeDomain = normalizedDomain;
    logger.debug(
      { module: 'domainAuth', domain: normalizedDomain, tenantId: req.tenant.id },
      'Domain verified'
    );
    next();

  } catch (err) {
    logger.error(
      { module: 'domainAuth', error: err.message, stack: err.stack },
      'Unexpected error in domainAuthMiddleware'
    );
    // Fail open: لا نحجب المستخدم بسبب خطأ داخلي
    // إذا أردت Fail closed، استبدل next() بـ res.status(503).json(...)
    next();
  }
};

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  domainAuthMiddleware,
  normalizeDomain,
  isDevDomain,
};