// @ts-nocheck
'use strict';

const express = require('express');
const router  = express.Router();
const db = require('../lib/db'); // replaces the local `new PrismaClient()`
const {
  suspendTenant,
  reactivateTenant,
  downgradeToStarter,
  extendGracePeriod,
  setPlan,
  resetQuota,
} = require('../lib/subscriptionActions');
const { PLAN_QUOTA_LIMITS, STARTER_FALLBACK_LIMIT } = require('../lib/quotaGate');
const { isAgency, FREE_PLANS } = require('../lib/planAccess');
const { fetchRemoteConfig, setRemoteConfigKey } = require('../lib/remoteConfig');
const emergencyPause = require('../lib/emergencyPause');
const crypto = require('crypto');
// ── دالة الحماية من XSS ──────────────────────────────────────
const escapeHtml = (str) =>
  String(str ?? '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');

// ── بصمة غير قابلة للعكس للمفتاح (مشتقة من apiKeyHash فقط) ──
// لا تستقبل ولا تتعامل مع أي قيمة نصية صريحة لمفتاح API إطلاقاً
const keyFingerprint = (apiKeyHash) => {
  if (!apiKeyHash) return null;
  return escapeHtml(apiKeyHash.slice(0, 8).toUpperCase());
};

// ── IP hashing for order↔BlockedAttempt correlation ──────────────────
// MUST match src/routes/risk.js's local hashIp() exactly (same
// SECRET_SALT + HMAC-SHA256) or the correlation below will never match
// anything. Duplicated here because risk.js does not export it — if a
// third consumer ever needs this, extract both to lib/ipHash.js.
const ADMIN_SECRET_SALT = process.env.SECRET_SALT;
const hashIpForCorrelation = (ip) => {
  if (!ADMIN_SECRET_SALT || !ip) return null;
  return crypto.createHmac('sha256', ADMIN_SECRET_SALT).update(ip).digest('hex');
};

// ── Display-time IP masking (Order.ipAddress is stored in the clear,
// unlike BlockedAttempt.ipHash — see schema comments) ──────────────────
const maskIp = (ip) => {
  if (!ip) return '—';
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.•`;
  }
  if (ip.includes(':')) {
    const parts = ip.split(':');
    if (parts.length > 2) return parts.slice(0, -2).join(':') + ':•:•';
  }
  return ip.slice(0, Math.max(0, ip.length - 4)) + '••••';
};
// ── Audit logging helper ────────────────────────────────────
const logAdminAction = async (tenantId, action, note, result, adminUserId = null) => {
  try {
    await db.adminAction.create({
      data: {
        tenantId,
        action,
        note: note || null,
        success: result.success,
        resultCode: result.code,
        adminUserId: adminUserId || null,
      },
    });
  } catch (err) {
    // Audit log failure must never block the actual admin action's response
    console.error('[Admin] Audit log write failed:', err.message);
  }
};

// ── Blacklist/Whitelist validation (mirrors src/routes/risk.js) ─────────
const BLACKLIST_TYPES = ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'];
const WHITELIST_TYPES = ['EMAIL', 'IP', 'BIN'];

const normalizeEntryValue = (type, value) =>
  type === 'BIN' ? String(value).replace(/\D/g, '').slice(0, 6) : value;

const validateEntryInput = (type, value, validTypes) => {
  if (!type || !value) {
    return { ok: false, code: 'MISSING_FIELDS', message: 'type and value are required' };
  }
  if (!validTypes.includes(type)) {
    return { ok: false, code: 'INVALID_TYPE', message: `type must be one of: ${validTypes.join(', ')}` };
  }
  if (type === 'BIN' && normalizeEntryValue(type, value).length !== 6) {
    return { ok: false, code: 'INVALID_BIN', message: 'BIN must be exactly 6 digits' };
  }
  return { ok: true };
};

const httpStatusFor = (code) => {
  if (code === 'NOT_FOUND' || code === 'TENANT_NOT_FOUND') return 404;
  if (['INVALID_DAYS', 'INVALID_PLAN', 'NOT_IN_GRACE_PERIOD', 'INVALID_KEY', 'NO_CONFIG_KEY', 'NO_STORE_URL', 'INVALID_STORE_URL'].includes(code)) return 400;
  if (['SITE_UNREACHABLE', 'TIMEOUT', 'DNS_RESOLUTION_FAILED', 'BLOCKED_TARGET', 'SITE_ERROR', 'AUTH_REJECTED'].includes(code)) return 502;
  return 200; // includes ALREADY_* idempotent successes
};

// ── Brute-force protection بسيط (in-memory) ─────────────────
// ملاحظة: يُعاد ضبطه عند إعادة تشغيل الخادم — كافٍ للاستخدام الشخصي
const attempts   = new Map(); // IP → { count, firstAttempt }
const MAX_TRIES  = 5;
const WINDOW_MS  = 15 * 60 * 1000; // 15 دقيقة

const rateLimitAdmin = (req, res, next) => {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  const rec = attempts.get(ip);

  if (rec) {
    // إعادة ضبط النافذة إذا انتهت
    if (now - rec.firstAttempt > WINDOW_MS) {
      attempts.delete(ip);
    } else if (rec.count >= MAX_TRIES) {
      const retryAfterSec = Math.ceil((WINDOW_MS - (now - rec.firstAttempt)) / 1000);
      res.set('Retry-After', String(retryAfterSec));
      return res.status(429).send('Too Many Requests');
    }
  }
  next();
};

// ── التحقق من مفتاح الـ Admin ────────────────────────────────
// Admin secret is accepted ONLY via the x-admin-key header. Query strings
// are logged by browsers (history), servers/proxies/CDNs (access logs),
// and forwarded via Referer headers on outbound requests — CWE-598 (Use of
// GET Request Method With Sensitive Query Strings). Header-only auth
// matches the pattern used by every other authenticated route in this
// codebase (x-api-key).
const ADMIN_KEY_HASH_SECRET = process.env.ADMIN_KEY_HASH_SECRET || process.env.SECRET_SALT;
const hashAdminKey = (key) => {
  if (!ADMIN_KEY_HASH_SECRET || !key) return null;
  return crypto.createHmac('sha256', ADMIN_KEY_HASH_SECRET).update(key).digest('hex');
};

const recordFailedAttempt = (ip) => {
  const rec = attempts.get(ip) || { count: 0, firstAttempt: Date.now() };
  rec.count++;
  attempts.set(ip, rec);
};

const authAdmin = (req, res, next) => {
  const ip       = req.ip || 'unknown';
  const secret   = req.headers['x-admin-key'];
  const expected = process.env.ADMIN_SECRET;

  if (!secret) {
    recordFailedAttempt(ip);
    return res.status(401).send('Unauthorized');
  }

  if (!expected) {
    console.error('[Admin] ADMIN_SECRET is not set in environment variables');
    return res.status(503).send('Service Unavailable');
  }

  const a = Buffer.from(secret, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!valid) {
    recordFailedAttempt(ip);
    const rec = attempts.get(ip);
    console.warn(`[Admin] failed access attempt from ${ip} (${rec.count}/${MAX_TRIES})`);
    return res.status(401).send('Unauthorized');
  }

  attempts.delete(ip);
  req.adminUser = null;
  next();
};

// ── بناء صفحة HTML ───────────────────────────────────────────
const statusBadge = (status, isActive) => {
  if (!isActive) return `<span class="badge-status" style="background:#374151;color:#d1d5db;">Suspended</span>`;
  const map = {
    active:       { bg: '#0e4429', text: '#4ade80', label: 'Active' },
    grace_period: { bg: '#451a03', text: '#fbbf24', label: 'Grace Period' },
    expired:      { bg: '#450a0a', text: '#f87171', label: 'Expired' },
    free:         { bg: '#1e293b', text: '#94a3b8', label: 'Free' },
  };
  const s = map[status] || map.free;
  return `<span class="badge-status" style="background:${s.bg};color:${s.text};">${s.label}</span>`;
};

const daysRemainingLabel = (endDate) => {
  if (!endDate) return '—';
  const days = Math.ceil((new Date(endDate) - Date.now()) / 86400000);
  if (days < 0) return `<span style="color:#f87171;">expired ${Math.abs(days)}d ago</span>`;
  return `${days}d left`;
};

const quotaLimitFor = (plan) =>
  PLAN_QUOTA_LIMITS[plan] !== undefined ? PLAN_QUOTA_LIMITS[plan] : STARTER_FALLBACK_LIMIT;

const quotaBadge = (t) => {
  if (isAgency(t.plan)) return '<span style="color:#475569">unlimited</span>';

  const limit = quotaLimitFor(t.plan);
  const isStale = t.quotaResetDate && new Date(t.quotaResetDate) <= Date.now();
  if (isStale) {
    // quotaResetDate has passed but the count only resets lazily on this
    // tenant's next live request (see checkQuotaGate) — the stored count
    // no longer reflects the current cycle, so showing a raw pct here
    // would be misleading rather than merely stale.
    return `<span style="color:#475569" title="Resets on tenant's next request">${t.monthlyBlockedCount}/${limit} <small>(pending reset)</small></span>`;
  }

  const pct = Math.round((t.monthlyBlockedCount / limit) * 100);
  const color = pct >= 100 ? '#f87171' : pct >= 80 ? '#fbbf24' : '#94a3b8';
  return `<span style="color:${color};font-weight:${pct >= 80 ? 600 : 400}">${t.monthlyBlockedCount}/${limit} <small>(${pct}%)</small></span>`;
};

const buildHtml = (tenants, total, summary, activityMap, pauseInfo = { global: null, tenantMap: new Map() }, { status = 'all', search = '', plan = 'all', nearQuota = false } = {}) => {
  const rows = tenants.map((t, i) => {
    const planLabel = t.plan || '—';
    const isDisabled = !t.isActive;

    const tenantPause = pauseInfo.tenantMap.get(t.id);
    return `
    <tr class="${i % 2 === 0 ? 'even' : 'odd'}${tenantPause ? ' row-paused' : ''}">
      <td>${i + 1}</td>
      <td>${escapeHtml(t.email)}</td>
      <td>${escapeHtml(t.storeUrl ?? '—')}</td>
      <td><span class="plan">${escapeHtml(planLabel)}</span></td>
      <td>${statusBadge(t.subscriptionStatus, t.isActive)}</td>
       <td>${daysRemainingLabel(t.subscriptionEndDate)}</td>
      <td>${t.plan === 'agency' ? (t._count?.stores ?? 0) : '—'}</td>
      <td>${quotaBadge(t)}</td>
      <td>${(() => {
        const last = activityMap.get(t.id);
        if (!last) return '<span style="color:#475569">no activity</span>';
        const days = Math.floor((Date.now() - new Date(last).getTime()) / 86400000);
        return days === 0 ? 'today' : `${days}d ago`;
      })()}</td>
      <td class="key">${
        t.apiKeyHash
          ? `<span title="بصمة غير قابلة للعكس، مشتقة من HMAC-SHA256">${keyFingerprint(t.apiKeyHash)}</span>`
          : `<span class="badge-legacy">Legacy</span>`
      }</td>
      <td>${escapeHtml(t.createdAt?.toISOString().replace('T', ' ').slice(0, 19))} <small>(UTC)</small></td>
      <td class="actions">
        <button data-action="suspend" data-id="${t.id}" ${!t.isActive ? 'disabled' : ''}>Suspend</button>
        <button data-action="reactivate" data-id="${t.id}" ${t.isActive ? 'disabled' : ''}>Reactivate</button>
        <button data-action="downgrade" data-id="${t.id}" ${t.plan === 'starter' ? 'disabled' : ''}>Downgrade</button>
        <button data-action="extend-grace" data-id="${t.id}" ${t.subscriptionStatus !== 'grace_period' ? 'disabled' : ''}>+Grace</button>
        <button data-action="set-plan" data-id="${t.id}">Set Plan</button>
        <button data-action="reset-quota" data-id="${t.id}" ${isAgency(t.plan) ? 'disabled' : ''}>Reset Quota</button>
        <button class="view-orders-btn" data-id="${t.id}" data-email="${escapeHtml(t.email)}">View Orders</button>
        <button class="view-config-btn" data-id="${t.id}" data-email="${escapeHtml(t.email)}">View Config</button>
        <button class="view-blacklist-btn" data-id="${t.id}" data-email="${escapeHtml(t.email)}">Blacklist</button>
        <button class="view-whitelist-btn" data-id="${t.id}" data-email="${escapeHtml(t.email)}">Whitelist</button>
        ${tenantPause
          ? `<button data-action="unpause" data-id="${t.id}" title="Paused until ${escapeHtml(tenantPause.expiresAt.toISOString())}">▶ Resume (paused)</button>`
          : `<button data-action="pause" data-id="${t.id}">⏸ Pause Blocking</button>`}
      </td>
    </tr>`;
  }).join('');

  const generatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19);

  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>ChargeGuard — Admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body   { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }
    h1     { font-size: 1.4rem; margin-bottom: 1.5rem; color: #7dd3fc; letter-spacing: .05em; }
    .stats { display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
    .card  { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
             padding: .9rem 1.4rem; min-width: 160px; }
    .card .label { font-size: .7rem; text-transform: uppercase; color: #94a3b8; }
    .card .value { font-size: 1.6rem; font-weight: 700; color: #38bdf8; margin-top: .2rem; }

    .filter-form { display: flex; gap: .75rem; margin-bottom: 1.5rem; flex-wrap: wrap; align-items: center; }
    .filter-form select, .filter-form input, .filter-form button {
      padding: .5rem .8rem; border-radius: 6px; border: 1px solid #334155;
      background: #1e293b; color: #e2e8f0; font-size: .85rem; outline: none;
    }
    .filter-form button { background: #0e4429; color: #4ade80; cursor: pointer; border-color: #4ade80; }
    .filter-form button:hover { background: #166534; }

    table  { width: 100%; border-collapse: collapse; font-size: .8rem; }
    th     { background: #1e293b; color: #94a3b8; font-weight: 600; text-align: right;
             padding: .5rem .6rem; border-bottom: 2px solid #334155; white-space: nowrap; }
    td     { padding: .4rem .6rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }
    tr.even td { background: #0f1117; }
    tr.odd  td { background: #131920; }
    tr:hover td { background: #1e3a5f; transition: background .15s; }

    .plan  { background: #0e4429; color: #4ade80; border-radius: 4px;
             padding: .1rem .4rem; font-size: .7rem; font-weight: 600; }
    .badge-status { border-radius: 4px; padding: .1rem .5rem; font-size: .7rem; font-weight: 600; }
    .key   { font-family: monospace; color: #fbbf24; font-size: .75rem; }
    .badge-legacy { background:#4a1d1d; color:#f87171; border-radius:4px; padding:.1rem .4rem; font-size:.65rem; }

    .actions { display: flex; gap: .3rem; flex-wrap: wrap; }
    .actions button { background: #1e293b; color: #94a3b8; border: 1px solid #334155;
                      border-radius: 4px; padding: .15rem .5rem; font-size: .65rem;
                      cursor: pointer; transition: all .15s; white-space: nowrap; }
    .actions button:hover:not(:disabled) { background: #334155; color: #e2e8f0; }
    .actions button:disabled { opacity: .3; cursor: not-allowed; }

 small  { color: #64748b; font-size: .65rem; }
    footer { margin-top: 1.5rem; font-size: .7rem; color: #475569; }

    .section-title { font-size: 1.1rem; margin: 2rem 0 1rem; color: #7dd3fc; }
    .audit-pagination { display: flex; gap: .75rem; align-items: center; margin-top: .75rem; }
    .audit-pagination button { padding: .35rem .8rem; border-radius: 6px; border: 1px solid #334155;
      background: #1e293b; color: #e2e8f0; font-size: .8rem; cursor: pointer; }
    .audit-pagination button:disabled { opacity: .3; cursor: not-allowed; }
    .success-yes { color: #4ade80; font-weight: 600; }
    .success-no  { color: #f87171; font-weight: 600; }

    .modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.6); z-index:1000; align-items:flex-start; justify-content:center; padding:3rem 1rem; overflow-y:auto; }
    .modal-overlay.open { display:flex; }
    .modal-box { background:#131920; border:1px solid #334155; border-radius:10px; padding:1.5rem; width:100%; max-width:1100px; }
    .modal-box h3 { color:#7dd3fc; margin-bottom:1rem; font-size:1.1rem; }
    .modal-close { float:left; background:#1e293b; color:#e2e8f0; border:1px solid #334155; border-radius:6px; padding:.3rem .7rem; cursor:pointer; }
    .order-row { cursor:pointer; }
    .order-detail-row td { background:#0b0e14; padding:1rem; }
    .flag-critical { color:#f87171; }
    .flag-warning  { color:#fbbf24; }
    .flag-info     { color:#94a3b8; }
    .decision-approve { color:#4ade80; font-weight:600; }
    .decision-review  { color:#fbbf24; font-weight:600; }
    .decision-block   { color:#f87171; font-weight:600; }

    .pause-banner { background:#450a0a; border:2px solid #f87171; color:#fecaca; border-radius:8px;
                    padding:.9rem 1.2rem; margin-bottom:1.5rem; display:flex; align-items:center;
                    justify-content:space-between; gap:1rem; font-weight:600; }
    .pause-banner button { background:#7f1d1d; color:#fecaca; border:1px solid #f87171; border-radius:6px;
                            padding:.4rem .9rem; cursor:pointer; font-weight:700; }
    .pause-all-btn { background:#450a0a !important; color:#fca5a5 !important; border-color:#f87171 !important; font-weight:700; }
    .pause-all-btn:hover { background:#7f1d1d !important; }
    .actions button[data-action="pause"] { background:#450a0a; color:#fca5a5; border-color:#7f1d1d; }
    .actions button[data-action="unpause"] { background:#0e4429; color:#4ade80; border-color:#166534; }
    .row-paused td { background:#2a0f0f !important; }
  </style></head><body>
  <h1>⚡ ChargeGuard — لوحة التحكم الداخلية</h1>

  ${pauseInfo.global ? `<div class="pause-banner">
    <span>🚨 EMERGENCY PAUSE ACTIVE — ALL tenants are being auto-approved right now. Expires ${escapeHtml(pauseInfo.global.expiresAt.toISOString())} UTC${pauseInfo.global.activatedByName ? ` · activated by ${escapeHtml(pauseInfo.global.activatedByName)}` : ''}</span>
    <button type="button" id="unpauseAllBannerBtn">Resume Blocking Now</button>
  </div>` : ''}

  <div style="margin-bottom:1.5rem;">
    <button type="button" id="pauseAllBtn" class="pause-all-btn" style="padding:.6rem 1.1rem;border-radius:6px;border:1px solid;cursor:pointer;">
      🚨 Pause ALL Blocking (Emergency)
    </button>
  </div>

   <div class="stats">
    <div class="card">
      <div class="label">إجمالي المسجلين</div>
      <div class="value">${summary.totalAll}</div>
    </div>
    <div class="card">
      <div class="label">Active</div>
      <div class="value" style="color:#4ade80">${summary.byStatus.active || 0}</div>
    </div>
    <div class="card">
      <div class="label">Grace Period</div>
      <div class="value" style="color:#fbbf24">${summary.byStatus.grace_period || 0}</div>
    </div>
    <div class="card">
      <div class="label">Expired</div>
      <div class="value" style="color:#f87171">${summary.byStatus.expired || 0}</div>
    </div>
    <div class="card">
      <div class="label">Suspended</div>
      <div class="value" style="color:#94a3b8">${summary.suspended}</div>
    </div>
    <div class="card">
      <div class="label">Plan Mix</div>
      <div class="value" style="font-size:.8rem;margin-top:.4rem">
        ${Object.entries(summary.byPlan).map(([p,c]) => `${escapeHtml(p)}: <b>${c}</b>`).join(' &nbsp;·&nbsp; ')}
      </div>
    </div>
  </div>

  <form method="GET" class="filter-form">
    <select name="status">
      <option value="all" ${status === 'all' ? 'selected' : ''}>All statuses</option>
      <option value="active" ${status === 'active' ? 'selected' : ''}>Active</option>
      <option value="grace_period" ${status === 'grace_period' ? 'selected' : ''}>Grace Period</option>
      <option value="expired" ${status === 'expired' ? 'selected' : ''}>Expired</option>
      <option value="free" ${status === 'free' ? 'selected' : ''}>Free</option>
    </select>
    <select name="plan">
      <option value="all" ${plan === 'all' ? 'selected' : ''}>All plans</option>
      <option value="starter" ${plan === 'starter' ? 'selected' : ''}>Starter</option>
      <option value="pro" ${plan === 'pro' ? 'selected' : ''}>Pro</option>
      <option value="agency" ${plan === 'agency' ? 'selected' : ''}>Agency</option>
    </select>
     <input type="text" name="search" placeholder="Search by email..." value="${escapeHtml(search)}"/>
    <label style="display:flex;align-items:center;gap:.35rem;font-size:.8rem;color:#94a3b8;">
      <input type="checkbox" name="nearQuota" value="1" ${nearQuota ? 'checked' : ''}/> Near quota (≥80%)
    </label>
    <button type="submit">Filter</button>
  </form>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>البريد الإلكتروني</th>
        <th>رابط المتجر</th>
        <th>الخطة</th>
        <th>الحالة</th>
        <th>المتبقي</th>
        <th>Key Fingerprint</th>
        <th>تاريخ التسجيل</th>
        <th>الإجراءات</th>
      </tr>
    </thead>
    <tbody>
      ${rows || '<tr><td colspan="9" style="text-align:center;padding:2rem;color:#64748b">لا يوجد مسجلون بعد</td></tr>'}
    </tbody>
  </table>

  <h2 class="section-title">📋 Admin Action Log <small>(read-only)</small></h2>

  <form id="auditFilterForm" class="filter-form" onsubmit="return false;">
    <select id="auditAction">
      <option value="">All actions</option>
      <option value="suspend">Suspend</option>
      <option value="reactivate">Reactivate</option>
      <option value="downgrade">Downgrade</option>
      <option value="extend-grace">Extend Grace</option>
      <option value="set-plan">Set Plan</option>
      <option value="reset-quota">Reset Quota</option>
      <option value="view-orders">View Orders</option>
      <option value="view-config">View Config</option>
      <option value="set-config-key">Set Config Key</option>
      <option value="add-blacklist">Add Blacklist</option>
      <option value="remove-blacklist">Remove Blacklist</option>
      <option value="add-whitelist">Add Whitelist</option>
      <option value="remove-whitelist">Remove Whitelist</option>
      <option value="override-order">Override Order</option>
    </select>
    <input type="text" id="auditTenantId" placeholder="Tenant ID (optional)"/>
    <select id="auditRange">
      <option value="7">Last 7 days</option>
      <option value="30">Last 30 days</option>
      <option value="90" selected>Last 90 days</option>
      <option value="all">All time</option>
    </select>
    <button type="button" id="auditFilterBtn">Filter</button>
  </form>

  <table id="auditTable">
    <thead>
      <tr>
        <th>Timestamp (UTC)</th>
        <th>Tenant</th>
        <th>Action</th>
        <th>Result</th>
        <th>Note</th>
      </tr>
    </thead>
    <tbody id="auditRows">
      <tr><td colspan="5" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr>
    </tbody>
  </table>

  <div class="audit-pagination">
    <button type="button" id="auditPrev" disabled>&larr; Prev</button>
    <span id="auditPageInfo" style="color:#64748b;font-size:.75rem;"></span>
    <button type="button" id="auditNext" disabled>Next &rarr;</button>
  </div>

<footer>ChargeGuard Admin Panel &mdash; ${generatedAt} UTC &mdash; للاستخدام الداخلي فقط</footer>

  <div class="modal-overlay" id="configModal">
    <div class="modal-box" style="max-width:640px;">
      <button class="modal-close" id="configModalClose">✕ Close</button>
      <h3 id="configModalTitle">Plugin Config</h3>
      <div id="configBody" style="font-size:.82rem;"></div>
    </div>
  </div>

  <div class="modal-overlay" id="ordersModal">
    <div class="modal-box">
      <button class="modal-close" id="ordersModalClose">✕ Close</button>
      <h3 id="ordersModalTitle">Orders</h3>
      <form id="ordersFilterForm" class="filter-form" onsubmit="return false;" style="margin-bottom:1rem;">
        <input type="text" id="ordersFilterOrderId" placeholder="Order ID"/>
        <input type="text" id="ordersFilterEmail" placeholder="Email"/>
        <select id="ordersFilterDecision">
          <option value="">All decisions</option>
          <option value="approve">Approve</option>
          <option value="review">Review</option>
          <option value="block">Block</option>
        </select>
        <button type="button" id="ordersFilterBtn">Filter</button>
      </form>
      <table id="ordersTable">
        <thead>
          <tr>
            <th>Order ID</th><th>Email</th><th>IP</th><th>Amount</th>
            <th>Decision</th><th>Risk</th><th>Blocks (approx.)</th>
            <th>Dispute</th><th>Created</th>
          </tr>
        </thead>
        <tbody id="ordersRows">
          <tr><td colspan="9" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr>
        </tbody>
      </table>
      <div class="audit-pagination">
        <button type="button" id="ordersPrev" disabled>&larr; Prev</button>
        <span id="ordersPageInfo" style="color:#64748b;font-size:.75rem;"></span>
        <button type="button" id="ordersNext" disabled>Next &rarr;</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="blacklistModal">
    <div class="modal-box" style="max-width:760px;">
      <button class="modal-close" id="blacklistModalClose">✕ Close</button>
      <h3 id="blacklistModalTitle">Blacklist</h3>
      <form id="blacklistAddForm" class="filter-form" onsubmit="return false;" style="margin-bottom:1rem;">
        <select id="blacklistType">
          <option value="EMAIL">EMAIL</option>
          <option value="IP">IP</option>
          <option value="DEVICE_FINGERPRINT">DEVICE_FINGERPRINT</option>
        </select>
        <input type="text" id="blacklistValue" placeholder="Value"/>
        <input type="text" id="blacklistReason" placeholder="Reason (optional)"/>
        <button type="button" id="blacklistAddBtn">Add Entry</button>
      </form>
      <table id="blacklistTable">
        <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Added</th><th>Expires</th><th></th></tr></thead>
        <tbody id="blacklistRows"><tr><td colspan="6" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="modal-overlay" id="whitelistModal">
    <div class="modal-box" style="max-width:760px;">
      <button class="modal-close" id="whitelistModalClose">✕ Close</button>
      <h3 id="whitelistModalTitle">Whitelist</h3>
      <form id="whitelistAddForm" class="filter-form" onsubmit="return false;" style="margin-bottom:1rem;">
        <select id="whitelistType">
          <option value="EMAIL">EMAIL</option>
          <option value="IP">IP</option>
          <option value="BIN">BIN</option>
        </select>
        <input type="text" id="whitelistValue" placeholder="Value"/>
        <input type="text" id="whitelistReason" placeholder="Reason (optional)"/>
        <button type="button" id="whitelistAddBtn">Add Entry</button>
      </form>
      <table id="whitelistTable">
        <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Added</th><th>Expires</th><th></th></tr></thead>
        <tbody id="whitelistRows"><tr><td colspan="6" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

  <script>
    document.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const action = btn.dataset.action;
        const id = btn.dataset.id;

        let body = {};
        if (action === 'extend-grace') {
          const days = prompt('Extend grace period by how many days?', '3');
          if (!days) return;
          body = { days: parseInt(days, 10) };
        } else if (action === 'set-plan') {
          const plan = prompt('Set plan to (starter / pro / agency):');
          if (!plan) return;
          body = { plan: plan.trim().toLowerCase() };
        }
        const note = prompt('Optional note for audit log:') || '';
        body.note = note;

        const adminKey = prompt('Re-enter admin key to confirm:');
        if (!adminKey) return;

        btn.disabled = true;
        try {
          const res = await fetch(\`/admin/tenants/\${id}/\${action}\`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
            body: JSON.stringify(body),
          });
          const data = await res.json();
          if (data.success) {
            alert('✅ ' + data.message);
            location.reload();
          } else {
            alert('❌ ' + data.message);
            btn.disabled = false;
          }
          } catch (e) {
          alert('❌ Network error');
          btn.disabled = false;
        }
      });
    });

    

    // ── Emergency Pause (Global) ────────────────────────────────────────
    const pauseAllBtn = document.getElementById('pauseAllBtn');
    if (pauseAllBtn) {
      pauseAllBtn.addEventListener('click', async () => {
        const warning = '🚨 THIS WILL APPROVE EVERY ORDER FOR EVERY TENANT, RIGHT NOW.\\n\\n' +
          'No fraud detection will run on /evaluate until this expires or you resume it manually.\\n\\n' +
          'Type PAUSE ALL (exactly, all caps) to confirm:';
        const confirmText = prompt(warning);
        if (confirmText !== 'PAUSE ALL') { if (confirmText !== null) alert('Confirmation text did not match — nothing was paused.'); return; }

        const minutesInput = prompt('Duration in minutes (default 30, max 1440):', '30');
        const minutes = minutesInput ? parseInt(minutesInput, 10) : 30;
        const note = prompt('Optional note for audit log:') || '';
        const adminKey = prompt('Re-enter admin key to confirm:');
        if (!adminKey) return;

        pauseAllBtn.disabled = true;
        try {
          const res = await fetch('/admin/pause-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
            body: JSON.stringify({ confirm: 'PAUSE ALL', minutes, note }),
          });
          const data = await res.json();
          if (data.success) { alert('🚨 ' + data.message); location.reload(); }
          else { alert('❌ ' + data.message); pauseAllBtn.disabled = false; }
        } catch (e) {
          alert('❌ Network error');
          pauseAllBtn.disabled = false;
        }
      });
    }

    const unpauseAllBannerBtn = document.getElementById('unpauseAllBannerBtn');
    if (unpauseAllBannerBtn) {
      unpauseAllBannerBtn.addEventListener('click', async () => {
        const note = prompt('Optional note for audit log:') || '';
        const adminKey = prompt('Re-enter admin key to confirm resuming blocking for ALL tenants:');
        if (!adminKey) return;

        unpauseAllBannerBtn.disabled = true;
        try {
          const res = await fetch('/admin/unpause-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
            body: JSON.stringify({ note }),
          });
          const data = await res.json();
          if (data.success) { alert('✅ ' + data.message); location.reload(); }
          else { alert('❌ ' + data.message); unpauseAllBannerBtn.disabled = false; }
        } catch (e) {
          alert('❌ Network error');
          unpauseAllBannerBtn.disabled = false;
        }
      });
    }

    // ── Read-only Remote Config Viewer ──────────────────────────────────
    const SETTING_LABELS = {
      chargeguard_enable_firewall: 'Firewall Enabled',
      chargeguard_firewall_block_duration: 'Block Duration (hrs)',
      chargeguard_trust_proxy_headers: 'Legacy Trust-Proxy Toggle',
      chargeguard_proxy_trust_mode: 'Proxy Trust Mode',
      chargeguard_trusted_proxy_cidrs: 'Trusted Proxy CIDRs',
      chargeguard_auto_block: 'Auto-Block',
      chargeguard_auto_refund: 'Auto-Refund',
      chargeguard_api_down_behavior: 'API-Down Behavior',
      chargeguard_api_down_rate_limit: 'API-Down Rate Limit',
      chargeguard_block_min_amount: 'Auto-Block Min Amount',
    };

    document.querySelectorAll('.view-config-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        document.getElementById('configModalTitle').textContent = \`Plugin Config — \${btn.dataset.email}\`;
        const body = document.getElementById('configBody');
        body.innerHTML = '<div style="padding:1rem;color:#64748b;">Loading…</div>';
        document.getElementById('configModal').classList.add('open');

        const adminKey = prompt('Re-enter admin key to fetch config:');
        if (!adminKey) { document.getElementById('configModal').classList.remove('open'); return; }

        try {
          const res = await fetch('/admin/tenants/' + btn.dataset.id + '/config', { headers: { 'x-admin-key': adminKey } });
          const data = await res.json();

          if (!data.success) {
            body.innerHTML = '<div style="padding:1rem;color:#f87171;">' +
              escapeHtmlClient(data.message || 'Could not fetch config') +
              (data.code === 'NO_CONFIG_KEY' ? '<br/><br/><button id="setKeyBtn" style="padding:.4rem .8rem;background:#0e4429;color:#4ade80;border:1px solid #4ade80;border-radius:6px;cursor:pointer;">Set Config Key</button>' : '') +
              '</div>';
            const setKeyBtn = document.getElementById('setKeyBtn');
            if (setKeyBtn) {
              setKeyBtn.addEventListener('click', async () => {
                const key = prompt('Paste the Remote Config Key from the merchant\'s ChargeGuard settings page:');
                if (!key) return;
                const res2 = await fetch('/admin/tenants/' + btn.dataset.id + '/config-key', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
                  body: JSON.stringify({ key }),
                });
                const data2 = await res2.json();
                alert(data2.success ? '✅ Key saved — click View Config again' : '❌ ' + data2.message);
              });
            }
            return;
          }

          const rows = Object.entries(data.settings).map(function(entry) {
            var k = entry[0], v = entry[1];
            return '<tr>' +
              '<td style="padding:.4rem .6rem;color:#94a3b8;">' + escapeHtmlClient(SETTING_LABELS[k] || k) + '</td>' +
              '<td style="padding:.4rem .6rem;font-family:monospace;color:#e2e8f0;">' + escapeHtmlClient(JSON.stringify(v)) + '</td>' +
              '</tr>';
          }).join('');

          body.innerHTML = '<div style="font-size:.7rem;color:#64748b;margin-bottom:.5rem;">' +
            'Fetched live just now · Plugin v' + escapeHtmlClient(data.pluginVersion || '\u2014') +
            '</div>' +
            '<table style="width:100%;border-collapse:collapse;">' + rows + '</table>';
        } catch (e) {
          body.innerHTML = '<div style="padding:1rem;color:#f87171;">Network error</div>';
        }
      });
    });

    document.getElementById('configModalClose').addEventListener('click', () => {
      document.getElementById('configModal').classList.remove('open');
    });

    // ── Read-only Order Viewer ─────────────────────────────────────────
    let cachedAdminKey = null; // in-memory only for this page load — never persisted to storage
    let ordersState = { tenantId: null, offset: 0, limit: 25 };

    const escapeHtmlClient = (str) => String(str ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

    const decisionClass = (d) => d === 'approve' ? 'decision-approve' : d === 'block' ? 'decision-block' : 'decision-review';

    function getAdminKey() {
      if (!cachedAdminKey) {
        cachedAdminKey = prompt('Re-enter admin key to view orders:');
      }
      return cachedAdminKey;
    }

    async function loadOrders() {
      const key = getAdminKey();
      if (!key) return;

      const params = new URLSearchParams({
        limit: String(ordersState.limit),
        offset: String(ordersState.offset),
      });
      const orderId = document.getElementById('ordersFilterOrderId').value.trim();
      const email = document.getElementById('ordersFilterEmail').value.trim();
      const decision = document.getElementById('ordersFilterDecision').value;
      if (orderId) params.set('orderId', orderId);
      if (email) params.set('email', email);
      if (decision) params.set('decision', decision);

      const rowsEl = document.getElementById('ordersRows');
      rowsEl.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr>';

      try {
        const res = await fetch(\`/admin/tenants/\${ordersState.tenantId}/orders?\${params.toString()}\`, {
          headers: { 'x-admin-key': key },
        });
        if (res.status === 401) {
          cachedAdminKey = null;
          rowsEl.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:1rem;color:#f87171">Invalid admin key — click Filter to retry</td></tr>';
          return;
        }
        const data = await res.json();
        if (!data.success) {
          rowsEl.innerHTML = \`<tr><td colspan="9" style="text-align:center;padding:1rem;color:#f87171">\${escapeHtmlClient(data.message || 'Error')}</td></tr>\`;
          return;
        }

        if (!data.orders.length) {
          rowsEl.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:1rem;color:#64748b">No matching orders</td></tr>';
        } else {
          rowsEl.innerHTML = data.orders.map((o, i) => {
            const detailId = \`order-detail-\${i}\`;
            const dispute = o.disputeOutcome
              ? \`\${escapeHtmlClient(o.disputeOutcome.result)} (\${new Date(o.disputeOutcome.resolvedAt).toISOString().slice(0,10)})\`
              : '—';
            return \`
            <tr class="order-row" data-target="\${detailId}">
              <td>\${escapeHtmlClient(o.orderId)}</td>
              <td>\${escapeHtmlClient(o.email || '—')}</td>
              <td>\${escapeHtmlClient(o.ipAddress)}</td>
              <td>$\${Number(o.amount).toFixed(2)}</td>
              <td class="\${decisionClass(o.decision)}">\${escapeHtmlClient(o.decision || '—')}</td>
              <td>\${o.riskScore ?? '—'} (\${escapeHtmlClient(o.riskLevel || '—')})</td>
              <td>\${o.blockedAttemptsApprox}</td>
              <td>\${dispute}</td>
              <td>\${new Date(o.createdAt).toISOString().replace('T',' ').slice(0,19)}</td>
            </tr>
            <tr class="order-detail-row" id="\${detailId}" style="display:none;">
              <td colspan="9">
                <strong>Flags:</strong>
                \${o.flags.length ? '<ul>' + o.flags.map(f => \`<li class="flag-\${escapeHtmlClient(f.severity || 'info')}">\${escapeHtmlClient(f.text || JSON.stringify(f))}</li>\`).join('') + '</ul>' : '<span style="color:#64748b">none</span>'}
                <br/><strong>Signals summary:</strong> <code>\${escapeHtmlClient(JSON.stringify(o.signalsSummary))}</code>
                <br/><strong>Enrichment source:</strong> \${escapeHtmlClient(o.enrichmentSource || '—')}
                &nbsp;|&nbsp; <strong>Feedback processed:</strong> \${o.feedbackProcessedAt ? new Date(o.feedbackProcessedAt).toISOString() : 'not yet'}
                <br/><br/>
                <button class="override-order-btn" data-orderid="\${escapeHtmlClient(o.orderId)}" data-current="\${escapeHtmlClient(o.decision || '')}">Override Decision</button>
              </td>
            </tr>\`;
          }).join('');

          rowsEl.querySelectorAll('.order-row').forEach(row => {
            row.addEventListener('click', () => {
              const target = document.getElementById(row.dataset.target);
              target.style.display = target.style.display === 'none' ? 'table-row' : 'none';
            });
          });

          rowsEl.querySelectorAll('.override-order-btn').forEach(btn => {
            btn.addEventListener('click', (ev) => {
              ev.stopPropagation();
              overrideOrder(btn.dataset.orderid, btn.dataset.current);
            });
          });
        }

        document.getElementById('ordersPageInfo').textContent =
          \`\${ordersState.offset + 1}–\${ordersState.offset + data.orders.length} of \${data.total}\`;
        document.getElementById('ordersPrev').disabled = ordersState.offset === 0;
        document.getElementById('ordersNext').disabled = ordersState.offset + data.orders.length >= data.total;

      } catch (e) {
        rowsEl.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:1rem;color:#f87171">Network error</td></tr>';
      }
    }

    document.querySelectorAll('.view-orders-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        ordersState = { tenantId: btn.dataset.id, offset: 0, limit: 25 };
        document.getElementById('ordersModalTitle').textContent = \`Orders — \${btn.dataset.email}\`;
        document.getElementById('ordersFilterOrderId').value = '';
        document.getElementById('ordersFilterEmail').value = '';
        document.getElementById('ordersFilterDecision').value = '';
        document.getElementById('ordersModal').classList.add('open');
        loadOrders();
      });
    });

    document.getElementById('ordersModalClose').addEventListener('click', () => {
      document.getElementById('ordersModal').classList.remove('open');
    });
    document.getElementById('ordersFilterBtn').addEventListener('click', () => {
      ordersState.offset = 0;
      loadOrders();
    });
    document.getElementById('ordersPrev').addEventListener('click', () => {
      ordersState.offset = Math.max(0, ordersState.offset - ordersState.limit);
      loadOrders();
    });
    document.getElementById('ordersNext').addEventListener('click', () => {
      ordersState.offset += ordersState.limit;
      loadOrders();
    });

    // ── Order Override ────────────────────────────────────────────────
    async function overrideOrder(orderId, currentDecision) {
      const decision = prompt('New decision for order ' + orderId + ' (approve / review / block). Current: ' + (currentDecision || '\u2014'));
      if (!decision) return;
      const normalized = decision.trim().toLowerCase();
      if (!['approve', 'review', 'block'].includes(normalized)) {
        alert('Decision must be approve, review, or block');
        return;
      }
      const reason = prompt('Reason for this override (required):');
      if (!reason || !reason.trim()) { alert('Reason is required'); return; }

      const key = getAdminKey();
      if (!key) return;

      try {
        const res = await fetch('/admin/tenants/' + ordersState.tenantId + '/orders/' + encodeURIComponent(orderId) + '/override', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-admin-key': key },
          body: JSON.stringify({ decision: normalized, reason: reason.trim() }),
        });
        const data = await res.json();
        if (data.success) {
          alert('✅ ' + data.message);
          loadOrders();
        } else {
          alert('❌ ' + data.message);
        }
      } catch (e) {
        alert('❌ Network error');
      }
    }

    // ── Blacklist / Whitelist management ────────────────────────────────
    function renderListRows(tbodyId, entries, listName, tenantId) {
      const tbody = document.getElementById(tbodyId);
      if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:#64748b">No entries</td></tr>';
        return;
      }
      tbody.innerHTML = entries.map(function(e) {
        return '<tr>' +
          '<td>' + escapeHtmlClient(e.type) + '</td>' +
          '<td style="font-family:monospace;">' + escapeHtmlClient(e.value) + '</td>' +
          '<td>' + escapeHtmlClient(e.reason || '\u2014') + '</td>' +
          '<td>' + new Date(e.createdAt).toISOString().replace('T',' ').slice(0,19) + '</td>' +
          '<td>' + (e.expiresAt ? new Date(e.expiresAt).toISOString().replace('T',' ').slice(0,19) : '\u2014') + '</td>' +
          '<td><button class="list-delete-btn" data-list="' + listName + '" data-tenant="' + tenantId + '" data-entry="' + e.id + '">Delete</button></td>' +
          '</tr>';
      }).join('');

      tbody.querySelectorAll('.list-delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteListEntry(btn.dataset.list, btn.dataset.tenant, btn.dataset.entry));
      });
    }

    async function loadListEntries(listName, tenantId) {
      const key = getAdminKey();
      if (!key) return;
      const tbodyId = listName + 'Rows';
      const tbody = document.getElementById(tbodyId);
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:#64748b">Loading…</td></tr>';
      try {
        const res = await fetch('/admin/tenants/' + tenantId + '/' + listName, { headers: { 'x-admin-key': key } });
        if (res.status === 401) {
          cachedAdminKey = null;
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:#f87171">Invalid admin key — reopen to retry</td></tr>';
          return;
        }
        const data = await res.json();
        if (!data.success) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:#f87171">' + escapeHtmlClient(data.message || 'Error') + '</td></tr>';
          return;
        }
        renderListRows(tbodyId, data.entries, listName, tenantId);
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:1rem;color:#f87171">Network error</td></tr>';
      }
    }

    async function addListEntry(listName, tenantId) {
      const key = getAdminKey();
      if (!key) return;
      const type = document.getElementById(listName + 'Type').value;
      const value = document.getElementById(listName + 'Value').value.trim();
      const reason = document.getElementById(listName + 'Reason').value.trim();
      if (!value) { alert('Value is required'); return; }

      try {
        const res = await fetch('/admin/tenants/' + tenantId + '/' + listName, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-admin-key': key },
          body: JSON.stringify({ type, value, reason: reason || undefined }),
        });
        const data = await res.json();
        if (data.success) {
          document.getElementById(listName + 'Value').value = '';
          document.getElementById(listName + 'Reason').value = '';
          loadListEntries(listName, tenantId);
        } else {
          alert('❌ ' + data.message);
        }
      } catch (e) {
        alert('❌ Network error');
      }
    }

    async function deleteListEntry(listName, tenantId, entryId) {
      if (!confirm('Delete this ' + listName + ' entry?')) return;
      const key = getAdminKey();
      if (!key) return;
      try {
        const res = await fetch('/admin/tenants/' + tenantId + '/' + listName + '/' + entryId, {
          method: 'DELETE',
          headers: { 'x-admin-key': key },
        });
        const data = await res.json();
        if (data.success) {
          loadListEntries(listName, tenantId);
        } else {
          alert('❌ ' + data.message);
        }
      } catch (e) {
        alert('❌ Network error');
      }
    }

    document.querySelectorAll('.view-blacklist-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('blacklistModalTitle').textContent = 'Blacklist \u2014 ' + btn.dataset.email;
        document.getElementById('blacklistAddBtn').dataset.tenant = btn.dataset.id;
        document.getElementById('blacklistModal').classList.add('open');
        loadListEntries('blacklist', btn.dataset.id);
      });
    });
    document.getElementById('blacklistModalClose').addEventListener('click', () => {
      document.getElementById('blacklistModal').classList.remove('open');
    });
    document.getElementById('blacklistAddBtn').addEventListener('click', (e) => {
      addListEntry('blacklist', e.target.dataset.tenant);
    });

    document.querySelectorAll('.view-whitelist-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.getElementById('whitelistModalTitle').textContent = 'Whitelist \u2014 ' + btn.dataset.email;
        document.getElementById('whitelistAddBtn').dataset.tenant = btn.dataset.id;
        document.getElementById('whitelistModal').classList.add('open');
        loadListEntries('whitelist', btn.dataset.id);
      });
    });
    document.getElementById('whitelistModalClose').addEventListener('click', () => {
      document.getElementById('whitelistModal').classList.remove('open');
    });
    document.getElementById('whitelistAddBtn').addEventListener('click', (e) => {
      addListEntry('whitelist', e.target.dataset.tenant);
    });
  </script>
</body>
</html>`;
};

// ── الـ Route الرئيسي ─────────────────────────────────────────
router.get('/', rateLimitAdmin, authAdmin, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 50, 200);
  const status = req.query.status; // 'active' | 'grace_period' | 'expired' | 'all' | undefined
  const plan   = req.query.plan;   // 'starter' | 'pro' | 'agency' | 'all' | undefined
  const search = req.query.search?.trim();

 const nearQuota = req.query.nearQuota === '1';
  const now = new Date();

  const where = {};
  if (status && status !== 'all') where.subscriptionStatus = status;
  if (plan && plan !== 'all') where.plan = plan;
  if (search) where.email = { contains: search, mode: 'insensitive' };
  if (nearQuota) {
    // Agency is intentionally excluded — checkQuotaGate() never enforces a
    // limit for Agency tenants (isAgency short-circuits before any lookup
    // in quotaGate.js), so there is no ceiling to be "near" of.
    // quotaResetDate: { gt: now } excludes stale counts that haven't been
    // lazily reset yet — see the isStale check in quotaBadge() above; a
    // count from a prior cycle showing "480/500" here would be a false
    // positive, not a real at-risk tenant.
    where.AND = [
      ...(where.AND || []),
      {
        OR: [
          { plan: { in: FREE_PLANS }, monthlyBlockedCount: { gte: Math.ceil(STARTER_FALLBACK_LIMIT * 0.8) }, quotaResetDate: { gt: now } },
          { plan: 'pro', monthlyBlockedCount: { gte: Math.ceil(PLAN_QUOTA_LIMITS.pro * 0.8) }, quotaResetDate: { gt: now } },
        ],
      },
    ];
  }

  try {
    const [tenants, total, statusGroups, planGroups, suspended] = await Promise.all([
      db.tenant.findMany({
        where,
        orderBy: { subscriptionEndDate: 'asc' },
        take: limit,
        select: {
          id: true, email: true, storeUrl: true, plan: true, apiKeyHash: true, createdAt: true,
          isActive: true, subscriptionStatus: true, subscriptionEndDate: true,
          billingCycle: true, lastPaymentDate: true, monthlyBlockedCount: true,
          quotaResetDate: true,
          _count: { select: { stores: true } },
        },

      }),
      db.tenant.count({ where }),
      // Global health snapshot — intentionally NOT scoped to `where`,
      // matching dashboard.js's existing pattern of tenant-wide vs.
      // filtered numbers living side by side (see totalTenants there).
      db.tenant.groupBy({ by: ['subscriptionStatus'], _count: { _all: true } }),
      db.tenant.groupBy({ by: ['plan'], _count: { _all: true } }),
      db.tenant.count({ where: { isActive: false } }),
    ]);

    const tenantIds = tenants.map(t => t.id);
    const lastActivityRows = tenantIds.length
      ? await db.blockedAttempt.groupBy({
          by: ['tenantId'],
          where: { tenantId: { in: tenantIds } },
          _max: { blockedAt: true },
        })
      : [];
    const activityMap = new Map(lastActivityRows.map(r => [r.tenantId, r._max.blockedAt]));

    const summary = {
      totalAll: statusGroups.reduce((s, g) => s + g._count._all, 0),
      byStatus: Object.fromEntries(statusGroups.map(g => [g.subscriptionStatus, g._count._all])),
      byPlan:   Object.fromEntries(planGroups.map(g => [g.plan, g._count._all])),
      suspended,
    };

    // ── Emergency pause status (in-memory, no DB hit) ───────────────────
    const globalPauseRaw = emergencyPause.getStatus(null).global;
    const activeTenantPauses = emergencyPause.getAllActiveTenantPauses();
    const activatorIds = [...new Set([
      globalPauseRaw?.activatedById,
      ...[...activeTenantPauses.values()].map(p => p.activatedById),
    ].filter(Boolean))];
    const activators = activatorIds.length
      ? await db.adminUser.findMany({ where: { id: { in: activatorIds } }, select: { id: true, name: true } })
      : [];
    const activatorNameById = Object.fromEntries(activators.map(a => [a.id, a.name]));

    const pauseInfo = {
      global: globalPauseRaw
        ? { expiresAt: globalPauseRaw.expiresAt, activatedByName: activatorNameById[globalPauseRaw.activatedById] || null }
        : null,
      tenantMap: new Map(
        [...activeTenantPauses.entries()].map(([tid, p]) => [tid, { expiresAt: p.expiresAt, activatedByName: activatorNameById[p.activatedById] || null }])
      ),
    };

    res.setHeader('Content-Type',  'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag',  'noindex');
    res.send(buildHtml(tenants, total, summary, activityMap, pauseInfo,
      { status: status || 'all', search: search || '', plan: plan || 'all', nearQuota }));

  } catch (err) {
    console.error('[Admin] خطأ في جلب البيانات:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// ── GET /admin/actions — read-only audit log viewer ──────────────
const VALID_AUDIT_ACTIONS = ['suspend', 'reactivate', 'downgrade', 'extend-grace', 'set-plan', 'reset-quota', 'view-orders', 'view-config', 'set-config-key', 'add-blacklist', 'remove-blacklist', 'add-whitelist', 'remove-whitelist', 'override-order', 'pause-blocking', 'unpause-blocking', 'pause-all', 'unpause-all'];
router.get('/actions', rateLimitAdmin, authAdmin, async (req, res) => {
  const action   = req.query.action;
  const tenantId = req.query.tenantId?.trim();
  const range    = req.query.range || '90'; // '7' | '30' | '90' | 'all'
  const limit    = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const offset   = Math.max(parseInt(req.query.offset, 10) || 0, 0);

  const where = {};
  if (action && VALID_AUDIT_ACTIONS.includes(action)) where.action = action;
  if (tenantId) where.tenantId = tenantId;
  if (['7', '30', '90'].includes(range)) {
    where.createdAt = { gte: new Date(Date.now() - parseInt(range, 10) * 24 * 60 * 60 * 1000) };
  }

  try {
    const [actions, total] = await Promise.all([
      db.adminAction.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true, action: true, note: true, success: true, resultCode: true, createdAt: true,
          tenantId: true,
          tenant: { select: { email: true } },
        },
      }),
      db.adminAction.count({ where }),
    ]);

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      success: true,
      total,
      limit,
      offset,
      actions: actions.map((a) => ({
        id:          a.id,
        createdAt:   a.createdAt,
        action:      a.action,
        note:        a.note,
        success:     a.success,
        resultCode:  a.resultCode,
        tenantId:    a.tenantId,
        tenantEmail: a.tenantId ? (a.tenant?.email ?? '(deleted tenant)') : 'GLOBAL (all tenants)',
      })),
    });
  } catch (err) {
    console.error('[Admin] audit log fetch error:', err.message);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// ── GET /admin/tenants/:id/orders — read-only per-tenant order viewer ──
router.get('/tenants/:id/orders', rateLimitAdmin, authAdmin, async (req, res) => {
  const { id: tenantId } = req.params;
  const orderIdFilter = req.query.orderId?.trim();
  const emailFilter    = req.query.email?.trim();
  const decisionFilter = req.query.decision;
  const limit  = Math.min(parseInt(req.query.limit, 10) || 25, 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

  const where = { merchantId: tenantId };
  if (orderIdFilter) where.orderId = { contains: orderIdFilter, mode: 'insensitive' };
  if (emailFilter)   where.email   = { contains: emailFilter, mode: 'insensitive' };
  if (decisionFilter && ['approve', 'review', 'block'].includes(decisionFilter)) {
    where.decision = decisionFilter;
  }

  const logNote = `orderId=${orderIdFilter || '-'} email=${emailFilter || '-'} decision=${decisionFilter || 'all'} limit=${limit} offset=${offset}`;

  try {
    const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true } });
    if (!tenant) {
      await logAdminAction(tenantId, 'view-orders', logNote, { success: false, code: 'NOT_FOUND' });
      return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Tenant not found' });
    }

    const [orders, total] = await Promise.all([
      db.order.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        select: {
          id: true, orderId: true, email: true, ipAddress: true, amount: true,
          decision: true, riskScore: true, riskLevel: true, signalsSnapshot: true,
          createdAt: true, enrichmentSource: true, feedbackProcessedAt: true,
          disputeOutcomes: {
            select: { result: true, resolvedAt: true, caseScore: true },
            orderBy: { resolvedAt: 'desc' },
            take: 1,
          },
        },
      }),
      db.order.count({ where }),
    ]);

    // Best-effort correlated BlockedAttempt count per order — see the
    // caveat above the route: BlockedAttempt has no orderId, so this is a
    // tenant+ipHash+time-window heuristic, not an authoritative join.
    const ONE_HOUR_MS = 60 * 60 * 1000;
    const withCorrelation = await Promise.all(orders.map(async (o) => {
      const ipHash = hashIpForCorrelation(o.ipAddress);
      let blockedAttemptsApprox = 0;
      if (ipHash) {
        blockedAttemptsApprox = await db.blockedAttempt.count({
          where: {
            tenantId,
            ipHash,
            blockedAt: {
              gte: new Date(o.createdAt.getTime() - ONE_HOUR_MS),
              lte: new Date(o.createdAt.getTime() + ONE_HOUR_MS),
            },
          },
        });
      }

      let flags = [];
      let signalsSummary = null;
      if (o.signalsSnapshot) {
        try {
          const parsed = JSON.parse(o.signalsSnapshot);
          flags = Array.isArray(parsed.flags) ? parsed.flags : [];
          signalsSummary = {
            deviceVelocityCount:     parsed.deviceVelocityCount ?? null,
            ipVelocityCount:         parsed.ipVelocityCount ?? null,
            emailVelocityCount:      parsed.emailVelocityCount ?? null,
            shippingBillingMismatch: parsed.shippingBillingMismatch ?? null,
            amountAnomaly:           parsed.amountAnomaly ?? null,
            connectedRisk:           parsed.connectedRisk ?? null,
            ipAnomaly:               parsed.ipAnomaly ?? null,
          };
        } catch (parseErr) {
          // Malformed/legacy snapshot — degrade gracefully, don't 500 the
          // whole viewer over one bad row.
        }
      }

      const latestDispute = o.disputeOutcomes[0] || null;

      return {
        orderId:             o.orderId,
        email:               o.email,
        ipAddress:           maskIp(o.ipAddress),
        amount:              o.amount,
        decision:            o.decision,
        riskScore:           o.riskScore,
        riskLevel:           o.riskLevel,
        flags,
        signalsSummary,
        createdAt:           o.createdAt,
        enrichmentSource:    o.enrichmentSource,
        feedbackProcessedAt: o.feedbackProcessedAt,
        blockedAttemptsApprox,
        disputeOutcome: latestDispute && {
          result:     latestDispute.result,
          resolvedAt: latestDispute.resolvedAt,
          caseScore:  latestDispute.caseScore,
        },
      };
    }));

    await logAdminAction(tenantId, 'view-orders', logNote, { success: true, code: 'VIEWED' });

    res.setHeader('Cache-Control', 'no-store');
    res.json({ success: true, total, limit, offset, orders: withCorrelation });

  } catch (err) {
    console.error('[Admin] orders fetch error:', err.message);
    logAdminAction(tenantId, 'view-orders', logNote, { success: false, code: 'INTERNAL_ERROR' }).catch(() => {});
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/orders/:orderId/override ─────────────
// Pure administrative decision flip. Deliberately does NOT touch
// riskScore/riskLevel/signalsSnapshot/connectedRisk, and does NOT invoke
// recordBlockedAttempt, calculateRiskScore, checkBINSequence, or any other
// part of the detection pipeline — the operator is asserting the correct
// outcome directly, not re-triggering evaluation.
const VALID_ORDER_DECISIONS = ['approve', 'review', 'block'];

router.post('/tenants/:id/orders/:orderId/override', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id: tenantId, orderId } = req.params;
  const { decision, reason, createdBy } = req.body || {};

  if (!decision || !VALID_ORDER_DECISIONS.includes(decision)) {
    const result = { success: false, code: 'INVALID_DECISION' };
    await logAdminAction(tenantId, 'override-order', `orderId=${orderId} attemptedDecision=${decision || '-'}`, result);
    return res.status(400).json({ success: false, code: 'INVALID_DECISION', message: `decision must be one of: ${VALID_ORDER_DECISIONS.join(', ')}` });
  }

  if (!reason || !String(reason).trim()) {
    const result = { success: false, code: 'MISSING_REASON' };
    await logAdminAction(tenantId, 'override-order', `orderId=${orderId}`, result);
    return res.status(400).json({ success: false, code: 'MISSING_REASON', message: 'reason is required' });
  }

  try {
    // Compound-key lookup — structurally scoped to this tenant, same
    // pattern as risk.js's idempotency check and /reconcile above.
    const existing = await db.order.findUnique({
      where: { merchantId_orderId: { merchantId: tenantId, orderId } },
      select: { id: true, orderId: true, merchantId: true, decision: true },
    });

    if (!existing) {
      const result = { success: false, code: 'NOT_FOUND' };
      await logAdminAction(tenantId, 'override-order', `orderId=${orderId}`, result);
      return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Order not found for this tenant' });
    }

    const oldDecision = existing.decision;
    const isNoChange = oldDecision === decision;

    // Note deliberately encodes old → new + reason + (optional) agent —
    // this is the full "who changed what and why" audit trail, since
    // AdminAction has no dedicated createdBy column.
    const note = `orderId=${orderId} decision: ${oldDecision || '(none)'} → ${decision}` +
      (createdBy ? ` | by: ${createdBy}` : '') +
      ` | reason: ${String(reason).trim()}`;

    if (!isNoChange) {
      // Only `decision` is written — riskScore, riskLevel, signalsSnapshot,
      // connectedRisk, and every other field are left exactly as the
      // original evaluation set them.
      await db.order.update({
        where: { id: existing.id },
        data: { decision },
      });
    }

    const result = { success: true, code: isNoChange ? 'NO_CHANGE' : 'OVERRIDDEN' };
    await logAdminAction(tenantId, 'override-order', note, result);

    res.json({
      success: true,
      code: result.code,
      message: isNoChange
        ? `Order ${orderId} was already set to '${decision}' — no change made`
        : `Order ${orderId} decision overridden: ${oldDecision || '(none)'} → ${decision}`,
      order: { orderId, merchantId: tenantId, previousDecision: oldDecision, decision },
    });
  } catch (err) {
    console.error('[Admin] override-order error:', err.message);
    await logAdminAction(tenantId, 'override-order', `orderId=${orderId}`, { success: false, code: 'INTERNAL_ERROR' });
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/suspend ─────────────────────────────
router.post('/tenants/:id/suspend', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {  const { id } = req.params;
  const { note } = req.body || {};
  try {
    const result = await suspendTenant(id, { note });
    await logAdminAction(id, 'suspend', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] suspend error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/reactivate ──────────────────────────
router.post('/tenants/:id/reactivate', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { note } = req.body || {};
  try {
    const result = await reactivateTenant(id, { note });
    await logAdminAction(id, 'reactivate', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] reactivate error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/downgrade ────────────────────────────
router.post('/tenants/:id/downgrade', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { note } = req.body || {};
  try {
    const result = await downgradeToStarter(id, { note });
    await logAdminAction(id, 'downgrade', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] downgrade error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/extend-grace ──────────────────────────
router.post('/tenants/:id/extend-grace', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { days, note } = req.body || {};
  try {
    const result = await extendGracePeriod(id, { days: parseInt(days, 10), note });
    await logAdminAction(id, 'extend-grace', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] extend-grace error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/set-plan ─────────────────────────────
router.post('/tenants/:id/set-plan', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { plan, note } = req.body || {};
  try {
    const result = await setPlan(id, { plan, note });
    await logAdminAction(id, 'set-plan', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] set-plan error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/reset-quota ───────────────────────────
// Forces an immediate quota reset with NO plan change — the missing lever
// for a Starter merchant hit early by a card-testing wave.
router.post('/tenants/:id/reset-quota', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { note } = req.body || {};
  try {
    const result = await resetQuota(id, { note });
    await logAdminAction(id, 'reset-quota', note, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] reset-quota error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/pause — tenant-scoped emergency pause ────────
router.post('/tenants/:id/pause', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id: tenantId } = req.params;
  const { minutes, note } = req.body || {};
  try {
    const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true } });
    if (!tenant) {
      await logAdminAction(tenantId, 'pause-blocking', note, { success: false, code: 'NOT_FOUND' }, req.adminUser?.id);
      return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Tenant not found' });
    }

    const row = await emergencyPause.activatePause({
      tenantId,
      durationMinutes: minutes,
      activatedById: req.adminUser?.id || null,
    });

    await logAdminAction(tenantId, 'pause-blocking', `expiresAt=${row.expiresAt.toISOString()}${note ? ` | note: ${note}` : ''}`, { success: true, code: 'PAUSED' }, req.adminUser?.id);
    res.json({ success: true, code: 'PAUSED', message: `Blocking paused for this tenant until ${row.expiresAt.toISOString()}`, expiresAt: row.expiresAt });
  } catch (err) {
    console.error('[Admin] pause error:', err.message);
    await logAdminAction(tenantId, 'pause-blocking', note, { success: false, code: 'INTERNAL_ERROR' }, req.adminUser?.id);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/unpause ───────────────────────────────────────
router.post('/tenants/:id/unpause', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id: tenantId } = req.params;
  const { note } = req.body || {};
  try {
    const wasActive = await emergencyPause.deactivatePause({ tenantId, deactivatedById: req.adminUser?.id || null, reason: 'manual' });
    const code = wasActive ? 'UNPAUSED' : 'ALREADY_INACTIVE';
    await logAdminAction(tenantId, 'unpause-blocking', note, { success: true, code }, req.adminUser?.id);
    res.json({ success: true, code, message: wasActive ? 'Blocking resumed for this tenant' : 'No active pause was found for this tenant' });
  } catch (err) {
    console.error('[Admin] unpause error:', err.message);
    await logAdminAction(tenantId, 'unpause-blocking', note, { success: false, code: 'INTERNAL_ERROR' }, req.adminUser?.id);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/pause-all — global emergency pause (ALL tenants) ─────────
// Its own top-level route, not nested under /tenants/:id — no tenant
// scope at all. logAdminAction is called with tenantId: null (see the
// AdminAction.tenantId nullability change in schema.prisma).
router.post('/pause-all', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { minutes, note, confirm } = req.body || {};
  if (confirm !== 'PAUSE ALL') {
    return res.status(400).json({ success: false, code: 'CONFIRMATION_REQUIRED', message: 'Send { confirm: "PAUSE ALL" } to activate a global pause' });
  }
  try {
    const row = await emergencyPause.activatePause({
      tenantId: null,
      durationMinutes: minutes,
      activatedById: req.adminUser?.id || null,
    });
    await logAdminAction(null, 'pause-all', `expiresAt=${row.expiresAt.toISOString()}${note ? ` | note: ${note}` : ''}`, { success: true, code: 'PAUSED_ALL' }, req.adminUser?.id);
    res.json({ success: true, code: 'PAUSED_ALL', message: `ALL tenants paused until ${row.expiresAt.toISOString()}`, expiresAt: row.expiresAt });
  } catch (err) {
    console.error('[Admin] pause-all error:', err.message);
    await logAdminAction(null, 'pause-all', note, { success: false, code: 'INTERNAL_ERROR' }, req.adminUser?.id);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/unpause-all ────────────────────────────────────────────────
router.post('/unpause-all', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { note } = req.body || {};
  try {
    const wasActive = await emergencyPause.deactivatePause({ tenantId: null, deactivatedById: req.adminUser?.id || null, reason: 'manual' });
    const code = wasActive ? 'UNPAUSED_ALL' : 'ALREADY_INACTIVE';
    await logAdminAction(null, 'unpause-all', note, { success: true, code }, req.adminUser?.id);
    res.json({ success: true, code, message: wasActive ? 'Global pause lifted' : 'No active global pause was found' });
  } catch (err) {
    console.error('[Admin] unpause-all error:', err.message);
    await logAdminAction(null, 'unpause-all', note, { success: false, code: 'INTERNAL_ERROR' }, req.adminUser?.id);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── GET /admin/tenants/:id/config — read-only remote plugin config viewer ──
router.get('/tenants/:id/config', rateLimitAdmin, authAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await fetchRemoteConfig(id);
    await logAdminAction(id, 'view-config', null, { success: result.success, code: result.code });
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] view-config error:', err.message);
    await logAdminAction(id, 'view-config', null, { success: false, code: 'INTERNAL_ERROR' });
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});

// ── POST /admin/tenants/:id/config-key — store the merchant-provided key ──
router.post('/tenants/:id/config-key', rateLimitAdmin, authAdmin, express.json(), async (req, res) => {
  const { id } = req.params;
  const { key } = req.body || {};
  try {
    const result = await setRemoteConfigKey(id, key);
    // Never log the key value itself — same redaction pattern used for
    // blacklist/whitelist entry values elsewhere in this file.
    await logAdminAction(id, 'set-config-key', null, result);
    res.status(httpStatusFor(result.code)).json(result);
  } catch (err) {
    console.error('[Admin] set-config-key error:', err.message);
    res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
  }
});
// ══════════════════════════════════════════════════════════════════════
// Admin-side Blacklist / Whitelist management
// Tenant-wide only (storeId: null) — admin acts at the tenant level,
// independent of any per-store fraud-isolation config on the tenant.
// ══════════════════════════════════════════════════════════════════════

// ── shared implementation, parameterized by list type ───────────────────
const buildAddEntryHandler = (listName, model, validTypes, action) =>
  async (req, res) => {
    const { id: tenantId } = req.params;
    const { type, value, reason, expiresAt, createdBy } = req.body || {};
    const logNote = `type=${type || '-'}`; // never log raw value — PII/secret-bearing (email, IP, device fp)

    const validation = validateEntryInput(type, value, validTypes);
    if (!validation.ok) {
      await logAdminAction(tenantId, action, logNote, { success: false, code: validation.code });
      return res.status(400).json({ success: false, code: validation.code, message: validation.message });
    }

    try {
      const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true } });
      if (!tenant) {
        await logAdminAction(tenantId, action, logNote, { success: false, code: 'NOT_FOUND' });
        return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Tenant not found' });
      }

      const normalizedValue = normalizeEntryValue(type, value);

      const existing = await db[model].findFirst({
        where: { merchantId: tenantId, storeId: null, type, value: normalizedValue },
      });
      if (existing) {
        await logAdminAction(tenantId, action, logNote, { success: false, code: 'DUPLICATE_ENTRY' });
        return res.status(409).json({ success: false, code: 'DUPLICATE_ENTRY', message: `This entry already exists in the ${listName}` });
      }

      const entry = await db[model].create({
        data: {
          merchantId: tenantId,
          storeId: null,
          type,
          value: normalizedValue,
          reason: reason || null,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
          createdBy: createdBy || 'admin',
        },
      });

      await logAdminAction(tenantId, action, `Added ${type} entry to ${listName}`, { success: true, code: 'ADDED' });
      res.status(201).json({ success: true, code: 'ADDED', entry });
    } catch (err) {
      if (err.code === 'P2002') {
        // Race with a concurrent write past the findFirst check above.
        await logAdminAction(tenantId, action, logNote, { success: false, code: 'DUPLICATE_ENTRY' });
        return res.status(409).json({ success: false, code: 'DUPLICATE_ENTRY', message: `This entry already exists in the ${listName}` });
      }
      console.error(`[Admin] ${action} error:`, err.message);
      await logAdminAction(tenantId, action, logNote, { success: false, code: 'INTERNAL_ERROR' });
      res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
    }
  };

const buildRemoveEntryHandler = (listName, model, action) =>
  async (req, res) => {
    const { id: tenantId, entryId } = req.params;
    const logNote = `entryId=${entryId}`;
    try {
      const existing = await db[model].findFirst({ where: { id: entryId, merchantId: tenantId } });
      if (!existing) {
        await logAdminAction(tenantId, action, logNote, { success: false, code: 'NOT_FOUND' });
        return res.status(404).json({ success: false, code: 'NOT_FOUND', message: `${listName} entry not found for this tenant` });
      }

      await db[model].delete({ where: { id: entryId } });
      await logAdminAction(tenantId, action, `Removed ${existing.type} entry from ${listName}`, { success: true, code: 'REMOVED' });
      res.json({ success: true, code: 'REMOVED', message: `${listName} entry deleted` });
    } catch (err) {
      console.error(`[Admin] ${action} error:`, err.message);
      await logAdminAction(tenantId, action, logNote, { success: false, code: 'INTERNAL_ERROR' });
      res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
    }
  };

const buildListEntriesHandler = (model, validTypes) =>
  async (req, res) => {
    const { id: tenantId } = req.params;
    const { type, includeExpired } = req.query;
    const where = { merchantId: tenantId };

    if (type) {
      if (!validTypes.includes(type)) {
        return res.status(400).json({ success: false, code: 'INVALID_TYPE', message: `type must be one of: ${validTypes.join(', ')}` });
      }
      where.type = type;
    }
    if (includeExpired !== 'true') {
      where.OR = [{ expiresAt: null }, { expiresAt: { gt: new Date() } }];
    }

    try {
      const entries = await db[model].findMany({ where, orderBy: { createdAt: 'desc' } });
      res.setHeader('Cache-Control', 'no-store');
      res.json({ success: true, entries });
    } catch (err) {
      console.error('[Admin] list entries error:', err.message);
      res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Internal Server Error' });
    }
  };

// ── Blacklist ─────────────────────────────────────────────────────────
router.post('/tenants/:id/blacklist', rateLimitAdmin, authAdmin, express.json(),
  buildAddEntryHandler('blacklist', 'blacklistEntry', BLACKLIST_TYPES, 'add-blacklist'));

router.delete('/tenants/:id/blacklist/:entryId', rateLimitAdmin, authAdmin,
  buildRemoveEntryHandler('blacklist', 'blacklistEntry', 'remove-blacklist'));

router.get('/tenants/:id/blacklist', rateLimitAdmin, authAdmin,
  buildListEntriesHandler('blacklistEntry', BLACKLIST_TYPES));

// ── Whitelist ─────────────────────────────────────────────────────────
router.post('/tenants/:id/whitelist', rateLimitAdmin, authAdmin, express.json(),
  buildAddEntryHandler('whitelist', 'whitelistEntry', WHITELIST_TYPES, 'add-whitelist'));

router.delete('/tenants/:id/whitelist/:entryId', rateLimitAdmin, authAdmin,
  buildRemoveEntryHandler('whitelist', 'whitelistEntry', 'remove-whitelist'));

router.get('/tenants/:id/whitelist', rateLimitAdmin, authAdmin,
  buildListEntriesHandler('whitelistEntry', WHITELIST_TYPES));

module.exports = router;