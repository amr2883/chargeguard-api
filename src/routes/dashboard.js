'use strict';

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// ── ثوابت ────────────────────────────────────────────────────
const FEES_PER_ATTEMPT = 0.30; // تقدير رسوم البوابة لكل محاولة محظورة
const DASHBOARD_RATE   = new Map(); // IP → { count, firstAt }
const MAX_REQ          = 30;
const WINDOW_MS        = 60 * 1000; // 30 طلب / دقيقة

// ── Rate Limiter خاص بالـ Dashboard ─────────────────────────
const rateLimit = (req, res, next) => {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  const rec = DASHBOARD_RATE.get(ip);

  if (rec) {
    if (now - rec.firstAt > WINDOW_MS) {
      DASHBOARD_RATE.delete(ip);
    } else if (rec.count >= MAX_REQ) {
      return res.status(429).json({ error: 'Too Many Requests' });
    } else {
      rec.count++;
    }
  } else {
    DASHBOARD_RATE.set(ip, { count: 1, firstAt: now });
  }
  next();
};

// ── التحقق من API Key ─────────────────────────────────────────
const authByApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'Missing X-Api-Key header' });
  }

  try {
    const tenant = await prisma.tenant.findUnique({
      where:  { apiKey },
      select: { id: true, email: true, plan: true, isActive: true, createdAt: true },
    });

    if (!tenant || !tenant.isActive) {
      return setTimeout(() => res.status(401).json({ error: 'Unauthorized' }), 200);
    }

    req.tenant = tenant;
    next();
  } catch (err) {
    console.error('[Dashboard] Auth error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// ── حساب حالة الاتصال بناءً على آخر نشاط ────────────────────
const getConnectionStatus = (lastActivityAt) => {
  if (!lastActivityAt) return { label: 'لم يُسجَّل نشاط بعد', color: 'gray',   minutes: null };
  const diffMs  = Date.now() - new Date(lastActivityAt).getTime();
  const minutes = Math.floor(diffMs / 60000);

  if (minutes < 10)  return { label: `منذ ${minutes} دقيقة`,  color: 'green',  minutes };
  if (minutes < 60)  return { label: `منذ ${minutes} دقيقة`,  color: 'yellow', minutes };
  if (minutes < 1440)return { label: `منذ ${Math.floor(minutes/60)} ساعة`, color: 'gray', minutes };
  return               { label: `منذ ${Math.floor(minutes/1440)} يوم`,    color: 'red',  minutes };
};

// ── استعلامات الداشبورد ───────────────────────────────────────
const getDashboardData = async (tenantId) => {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

  const [totalBlocked, recentAttempts, lastFive, lastActivity] = await Promise.all([

    // إجمالي الهجمات المحظورة
    prisma.blockedAttempt.count({
      where: { tenantId },
    }),

    // هجمات آخر 7 أيام (للرسم البياني)
    prisma.blockedAttempt.findMany({
      where:   { tenantId, blockedAt: { gte: sevenDaysAgo } },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'asc' },
    }),

    // آخر 5 هجمات
    prisma.blockedAttempt.findMany({
      where:   { tenantId },
      select:  { blockedAt: true, cardType: true, reason: true, cardBin: true },
      orderBy: { blockedAt: 'desc' },
      take:    5,
    }),

    // آخر نشاط (أحدث سجل)
    prisma.blockedAttempt.findFirst({
      where:   { tenantId },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'desc' },
    }),

  ]);

  // تجميع هجمات آخر 7 أيام حسب اليوم
  const dayMap = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    dayMap[key] = 0;
  }
  for (const a of recentAttempts) {
    const key = new Date(a.blockedAt).toISOString().slice(0, 10);
    if (key in dayMap) dayMap[key]++;
  }

  return {
    totalBlocked,
    feesSaved:     (totalBlocked * FEES_PER_ATTEMPT).toFixed(2),
    chartData:     Object.entries(dayMap).map(([date, count]) => ({ date, count })),
    recentFive:    lastFive,
    connectionStatus: getConnectionStatus(lastActivity?.blockedAt ?? null),
  };
};

// ── Endpoint: GET /api/dashboard (JSON) ──────────────────────
router.get('/', rateLimit, authByApiKey, async (req, res) => {
  try {
    const data = await getDashboardData(req.tenant.id);
    res.json({
      tenant: {
        email:     req.tenant.email,
        plan:      req.tenant.plan,
        memberSince: req.tenant.createdAt,
      },
      ...data,
    });
  } catch (err) {
    console.error('[Dashboard] Data error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ── Endpoint: GET /api/dashboard/page (HTML) ─────────────────
router.get('/page', rateLimit, authByApiKey, async (req, res) => {
  try {
    const data = await getDashboardData(req.tenant.id);
    res.setHeader('Content-Type',  'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag',  'noindex');
    res.send(buildDashboardHtml(req.tenant, data));
  } catch (err) {
    console.error('[Dashboard] Page error:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// ── بناء صفحة HTML ────────────────────────────────────────────
const escapeHtml = (str) =>
  String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');

const reasonLabel = (r) => ({
  card_testing: 'اختبار بطاقة',
  velocity:     'سرعة مشبوهة',
  blacklist:    'قائمة سوداء',
  pattern:      'نمط احتيال',
}[r] || escapeHtml(r));

const statusColor = { green: '#4ade80', yellow: '#facc15', gray: '#94a3b8', red: '#f87171' };

const buildDashboardHtml = (tenant, data) => {
  const { totalBlocked, feesSaved, chartData, recentFive, connectionStatus } = data;
  const maxChart = Math.max(...chartData.map(d => d.count), 1);
  const isNew    = totalBlocked === 0;

  const chartBars = chartData.map(({ date, count }) => {
    const pct   = Math.round((count / maxChart) * 100);
    const label = new Date(date).toLocaleDateString('ar-EG', { weekday: 'short' });
    return `
      <div class="bar-wrap">
        <div class="bar-val">${count || ''}</div>
        <div class="bar" style="height:${pct}%"></div>
        <div class="bar-label">${label}</div>
      </div>`;
  }).join('');

  const recentRows = recentFive.length === 0
    ? '<tr><td colspan="4" class="empty">لا يوجد نشاط بعد</td></tr>'
    : recentFive.map(a => `
      <tr>
        <td>${new Date(a.blockedAt).toLocaleString('ar-EG', { timeZone: 'UTC' })}</td>
        <td>${escapeHtml(a.cardType || '—')}</td>
        <td>${escapeHtml(a.cardBin  || '—')}••••••</td>
        <td><span class="badge">${reasonLabel(a.reason)}</span></td>
      </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>ChargeGuard — لوحتك</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e2e8f0;padding:1.5rem;min-height:100vh}
    h1{font-size:1.2rem;color:#7dd3fc;margin-bottom:1.5rem}
    /* Status Bar */
    .status{display:flex;align-items:center;gap:.6rem;background:#1e293b;border-radius:10px;
            padding:.8rem 1.2rem;margin-bottom:1.5rem;border:1px solid #334155}
    .dot{width:14px;height:14px;border-radius:50%;flex-shrink:0}
    .status-text{font-size:.9rem;font-weight:600}
    .status-sub{font-size:.75rem;color:#94a3b8;margin-right:auto}
    /* Cards */
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1.5rem}
    .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1rem 1.2rem}
    .card .lbl{font-size:.7rem;text-transform:uppercase;color:#94a3b8;letter-spacing:.05em}
    .card .val{font-size:1.8rem;font-weight:700;color:#38bdf8;margin-top:.25rem}
    .card .sub{font-size:.7rem;color:#64748b;margin-top:.2rem}
    /* Chart */
    .chart-wrap{background:#1e293b;border:1px solid #334155;border-radius:10px;
                padding:1rem 1.2rem;margin-bottom:1.5rem}
    .chart-title{font-size:.8rem;color:#94a3b8;margin-bottom:.8rem}
    .chart{display:flex;align-items:flex-end;gap:.5rem;height:80px}
    .bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:.2rem;height:100%}
    .bar{width:100%;background:#3b82f6;border-radius:3px 3px 0 0;min-height:2px;transition:height .3s}
    .bar-val{font-size:.65rem;color:#94a3b8;height:14px}
    .bar-label{font-size:.65rem;color:#64748b}
    /* Table */
    .tbl-wrap{background:#1e293b;border:1px solid #334155;border-radius:10px;overflow:hidden;margin-bottom:1.5rem}
    .tbl-title{font-size:.8rem;color:#94a3b8;padding:.8rem 1.2rem;border-bottom:1px solid #334155}
    table{width:100%;border-collapse:collapse;font-size:.8rem}
    th{background:#0f1117;color:#64748b;padding:.5rem .8rem;text-align:right;font-weight:500}
    td{padding:.55rem .8rem;border-bottom:1px solid #1a2535}
    tr:last-child td{border-bottom:none}
    .empty{text-align:center;padding:1.5rem;color:#475569}
    .badge{background:#1e3a5f;color:#60a5fa;border-radius:4px;padding:.15rem .5rem;font-size:.72rem}
    /* Onboarding */
    .onboard{background:#0d2137;border:1px solid #1e4976;border-radius:10px;
             padding:1.5rem;text-align:center;margin-bottom:1.5rem}
    .onboard p{color:#93c5fd;line-height:1.7;font-size:.9rem}
    /* Responsive */
    @media(max-width:480px){
      .cards{grid-template-columns:1fr 1fr}
      .card .val{font-size:1.4rem}
      th:nth-child(3),td:nth-child(3){display:none}
    }
    footer{font-size:.72rem;color:#334155;text-align:center;margin-top:1rem}
  </style>
</head>
<body>
  <h1>⚡ ChargeGuard — لوحة الحماية</h1>

  <!-- حالة الاتصال -->
  <div class="status">
    <div class="dot" style="background:${statusColor[connectionStatus.color]}"></div>
    <span class="status-text" style="color:${statusColor[connectionStatus.color]}">
      ${connectionStatus.color === 'green' ? 'محمي ✓' :
        connectionStatus.color === 'red'   ? 'تحقق من الـ Plugin ⚠️' : 'في المراقبة'}
    </span>
    <span class="status-sub">آخر نشاط: ${escapeHtml(connectionStatus.label)}</span>
    <span style="font-size:.72rem;color:#334155">${escapeHtml(tenant.email)}</span>
  </div>

  ${isNew ? `
  <!-- Onboarding -->
  <div class="onboard">
    <p>🛡️ لوحتك جاهزة والـ Plugin متصل.<br>
    الهجمات المحظورة ستظهر هنا فور اكتشافها.<br>
    <strong style="color:#7dd3fc">متجرك تحت الحماية الآن.</strong></p>
  </div>` : ''}

  <!-- البطاقات الإحصائية -->
  <div class="cards">
    <div class="card">
      <div class="lbl">هجمات محظورة</div>
      <div class="val">${totalBlocked.toLocaleString()}</div>
      <div class="sub">منذ بداية الحماية</div>
    </div>
    <div class="card">
      <div class="lbl">رسوم موفرة</div>
      <div class="val" style="color:#4ade80">$${escapeHtml(feesSaved)}</div>
      <div class="sub">تقريباً ($0.30 / محاولة)</div>
    </div>
    <div class="card">
      <div class="lbl">هجمات الأسبوع</div>
      <div class="val">${chartData.reduce((s,d)=>s+d.count,0)}</div>
      <div class="sub">آخر 7 أيام</div>
    </div>
    <div class="card">
      <div class="lbl">خطتك</div>
      <div class="val" style="font-size:1rem;padding-top:.4rem">${escapeHtml(tenant.plan)}</div>
      <div class="sub">عضو منذ ${new Date(tenant.memberSince).toLocaleDateString('ar-EG')}</div>
    </div>
  </div>

  <!-- الرسم البياني -->
  <div class="chart-wrap">
    <div class="chart-title">نشاط الأسبوع الماضي</div>
    <div class="chart">${chartBars}</div>
  </div>

  <!-- آخر الهجمات -->
  <div class="tbl-wrap">
    <div class="tbl-title">آخر الهجمات المحظورة</div>
    <table>
      <thead>
        <tr>
          <th>الوقت (UTC)</th>
          <th>النوع</th>
          <th>BIN</th>
          <th>السبب</th>
        </tr>
      </thead>
      <tbody>${recentRows}</tbody>
    </table>
  </div>

  <footer>ChargeGuard &mdash; للاستخدام الداخلي &mdash; ${new Date().toISOString().slice(0,10)} UTC</footer>
</body>
</html>`;
};

module.exports = router;