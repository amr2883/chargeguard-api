'use strict';

const express = require('express');
const router  = express.Router();
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// ── دالة الحماية من XSS ──────────────────────────────────────
const escapeHtml = (str) =>
  String(str ?? '')
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#x27;');

// ── إخفاء API Key (أول 12 حرف فقط) ─────────────────────────
const maskKey = (key) => {
  if (!key || key.length < 12) return '••••••••••••';
  return escapeHtml(key.slice(0, 12)) + '••••••••••••';
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
const authAdmin = (req, res, next) => {
  const ip        = req.ip || 'unknown';
  const secret    = req.headers['x-admin-key'] || req.query.secret;
  const expected  = process.env.ADMIN_SECRET;

  if (!expected) {
    console.error('[Admin] ADMIN_SECRET غير مضبوط في متغيرات البيئة');
    return res.status(503).send('Service Unavailable');
  }

  // مقارنة ثابتة الوقت (تمنع timing attacks)
  const crypto = require('crypto');
  const a = Buffer.from(secret  ?? '', 'utf8');
  const b = Buffer.from(expected,      'utf8');
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!valid) {
    // تسجيل المحاولة الفاشلة
    const rec = attempts.get(ip) || { count: 0, firstAttempt: Date.now() };
    rec.count++;
    attempts.set(ip, rec);
    console.warn(`[Admin] محاولة وصول فاشلة من ${ip} (${rec.count}/${MAX_TRIES})`);
    // تأخير 200ms لمنع timing enumeration
    return setTimeout(() => res.status(401).send('Unauthorized'), 200);
  }

  // مسح سجل المحاولات عند النجاح
  attempts.delete(ip);
  next();
};

// ── بناء صفحة HTML ───────────────────────────────────────────
const buildHtml = (tenants, total) => {
  const rows = tenants.map((t, i) => `
    <tr class="${i % 2 === 0 ? 'even' : 'odd'}">
      <td>${i + 1}</td>
      <td>${escapeHtml(t.email)}</td>
      <td>${escapeHtml(t.storeUrl ?? '—')}</td>
      <td><span class="plan">${escapeHtml(t.plan ?? '—')}</span></td>
      <td class="key">${maskKey(t.apiKey)}</td>
      <td>${escapeHtml(t.createdAt?.toISOString().replace('T', ' ').slice(0, 19))} <small>(UTC)</small></td>
    </tr>`).join('');

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
    table  { width: 100%; border-collapse: collapse; font-size: .85rem; }
    th     { background: #1e293b; color: #94a3b8; font-weight: 600; text-align: right;
             padding: .65rem 1rem; border-bottom: 2px solid #334155; white-space: nowrap; }
    td     { padding: .6rem 1rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }
    tr.even td { background: #0f1117; }
    tr.odd  td { background: #131920; }
    tr:hover td { background: #1e3a5f; transition: background .15s; }
    .plan  { background: #0e4429; color: #4ade80; border-radius: 4px;
             padding: .15rem .5rem; font-size: .75rem; font-weight: 600; }
    .key   { font-family: monospace; color: #fbbf24; font-size: .8rem; }
    small  { color: #64748b; font-size: .7rem; }
    footer { margin-top: 1.5rem; font-size: .75rem; color: #475569; }
  </style>
</head>
<body>
  <h1>⚡ ChargeGuard — لوحة التحكم الداخلية</h1>

  <div class="stats">
    <div class="card">
      <div class="label">إجمالي المسجلين</div>
      <div class="value">${total}</div>
    </div>
    <div class="card">
      <div class="label">يُعرض حالياً</div>
      <div class="value">${tenants.length}</div>
    </div>
    <div class="card">
      <div class="label">آخر تحديث</div>
      <div class="value" style="font-size:.85rem;margin-top:.4rem">${generatedAt} <small>(UTC)</small></div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>البريد الإلكتروني</th>
        <th>رابط المتجر</th>
        <th>الخطة</th>
        <th>API Key</th>
        <th>تاريخ التسجيل</th>
      </tr>
    </thead>
    <tbody>
      ${rows || '<tr><td colspan="6" style="text-align:center;padding:2rem;color:#64748b">لا يوجد مسجلون بعد</td></tr>'}
    </tbody>
  </table>

  <footer>ChargeGuard Admin Panel &mdash; ${generatedAt} UTC &mdash; للاستخدام الداخلي فقط</footer>
</body>
</html>`;
};

// ── الـ Route الرئيسي ─────────────────────────────────────────
router.get('/', rateLimitAdmin, authAdmin, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);

  try {
    const [tenants, total] = await Promise.all([
      prisma.tenant.findMany({
        orderBy: { createdAt: 'desc' },
        take:    limit,
        select:  { id: true, email: true, storeUrl: true, plan: true, apiKey: true, createdAt: true },
      }),
      prisma.tenant.count(),
    ]);

    res.setHeader('Content-Type',  'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag',  'noindex');
    res.send(buildHtml(tenants, total));

  } catch (err) {
    console.error('[Admin] خطأ في جلب البيانات:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

module.exports = router;