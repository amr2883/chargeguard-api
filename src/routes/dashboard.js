'use strict';

const express = require('express');
const router  = express.Router();
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// ── Constants ─────────────────────────────────────────────────
const FEES_PER_ATTEMPT = 0.30;
const DASHBOARD_RATE   = new Map();
const MAX_REQ          = 30;
const WINDOW_MS        = 60 * 1000;

// ── US English formatters ─────────────────────────────────────
const fmtDate = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: 'long', day: 'numeric',
});
const fmtDateTime = new Intl.DateTimeFormat('en-US', {
  year: 'numeric', month: 'short', day: 'numeric',
  hour: 'numeric', minute: '2-digit', hour12: true,
  timeZone: 'UTC', timeZoneName: 'short',
});
const fmtCurrency = new Intl.NumberFormat('en-US', {
  style: 'currency', currency: 'USD',
});

// ── Rate Limiter ──────────────────────────────────────────────
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

// ── API Key Auth ──────────────────────────────────────────────
const authByApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing X-Api-Key header' });
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

// ── Connection status ─────────────────────────────────────────
const getConnectionStatus = (lastActivityAt) => {
  if (!lastActivityAt) return { label: 'No activity recorded yet', color: 'gray', minutes: null };
  const diffMs  = Date.now() - new Date(lastActivityAt).getTime();
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 10)   return { label: `${minutes}m ago`,                  color: 'green',  minutes };
  if (minutes < 60)   return { label: `${minutes}m ago`,                  color: 'yellow', minutes };
  if (minutes < 1440) return { label: `${Math.floor(minutes / 60)}h ago`, color: 'gray',   minutes };
  return                     { label: `${Math.floor(minutes / 1440)}d ago`, color: 'red',  minutes };
};

// ── Dashboard queries ─────────────────────────────────────────
const getDashboardData = async (tenantId) => {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [totalBlocked, recentAttempts, lastFive, lastActivity] = await Promise.all([
    prisma.blockedAttempt.count({ where: { tenantId } }),
    prisma.blockedAttempt.findMany({
      where:   { tenantId, blockedAt: { gte: sevenDaysAgo } },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'asc' },
    }),
    prisma.blockedAttempt.findMany({
      where:   { tenantId },
      select:  { blockedAt: true, cardType: true, reason: true, cardBin: true, amountAttempted: true },
      orderBy: { blockedAt: 'desc' },
      take:    5,
    }),
    prisma.blockedAttempt.findFirst({
      where:   { tenantId },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'desc' },
    }),
  ]);

  const dayMap = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    dayMap[d.toISOString().slice(0, 10)] = 0;
  }
  for (const a of recentAttempts) {
    const key = new Date(a.blockedAt).toISOString().slice(0, 10);
    if (key in dayMap) dayMap[key]++;
  }

  return {
    totalBlocked,
    feesSaved:        (totalBlocked * FEES_PER_ATTEMPT).toFixed(2),
    chartData:        Object.entries(dayMap).map(([date, count]) => ({ date, count })),
    recentFive:       lastFive,
    connectionStatus: getConnectionStatus(lastActivity?.blockedAt ?? null),
  };
};

// ── GET /api/dashboard  (JSON) ───────────────────────────────
router.get('/', rateLimit, authByApiKey, async (req, res) => {
  try {
    const data = await getDashboardData(req.tenant.id);
    res.json({
      tenant: {
        email:       req.tenant.email,
        plan:        req.tenant.plan,
        memberSince: req.tenant.createdAt instanceof Date
          ? req.tenant.createdAt.toISOString()
          : String(req.tenant.createdAt),
      },
      ...data,
    });
  } catch (err) {
    console.error('[Dashboard] Data error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ── GET /api/dashboard/page  (HTML) ─────────────────────────
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

// ── HTML helpers ─────────────────────────────────────────────
const escapeHtml = (str) =>
  String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');

const reasonLabel = (r) => ({
  card_testing: 'Card Testing',
  velocity:     'Velocity Abuse',
  blacklist:    'Blacklisted',
  pattern:      'Fraud Pattern',
}[r] ?? escapeHtml(r));

const reasonColor = (r) => ({
  card_testing: { bg: '#2d1b69', text: '#a78bfa', dot: '#7c3aed' },
  velocity:     { bg: '#1c1917', text: '#fb923c', dot: '#ea580c' },
  blacklist:    { bg: '#1c0a0a', text: '#f87171', dot: '#dc2626' },
  pattern:      { bg: '#0c1a2e', text: '#38bdf8', dot: '#0284c7' },
}[r] ?? { bg: '#1e293b', text: '#94a3b8', dot: '#475569' });

const statusColor = { green: '#22c55e', yellow: '#f59e0b', gray: '#64748b', red: '#ef4444' };
const statusBg    = { green: '#052e16', yellow: '#1c1202', gray: '#0f172a', red: '#1c0202' };
const statusBorder= { green: '#166534', yellow: '#713f12', gray: '#1e293b', red: '#7f1d1d' };

// ── Build HTML ────────────────────────────────────────────────
const buildDashboardHtml = (tenant, data) => {
  const { totalBlocked, feesSaved, chartData, recentFive, connectionStatus } = data;
  const maxChart  = Math.max(...chartData.map(d => d.count), 1);
  const isNew     = totalBlocked === 0;
  const weekTotal = chartData.reduce((s, d) => s + d.count, 0);

  // ── Safe date parsing (fixes Invalid Date) ─────────────────
  // tenant.createdAt from Prisma is a Date object — always safe with new Date()
  const memberSinceDate = new Date(tenant.createdAt);
  const memberSinceStr  = isNaN(memberSinceDate.getTime())
    ? 'N/A'
    : fmtDate.format(memberSinceDate);

  const feesFormatted = fmtCurrency.format(parseFloat(feesSaved));

  // ── Chart bars ─────────────────────────────────────────────
  const chartBars = chartData.map(({ date, count }) => {
    const pct   = Math.round((count / maxChart) * 100);
    const label = new Intl.DateTimeFormat('en-US', {
      weekday: 'short', timeZone: 'UTC',
    }).format(new Date(date));
    const isToday = date === new Date().toISOString().slice(0, 10);
    return `
      <div class="bar-wrap">
        <div class="bar-val">${count > 0 ? count : ''}</div>
        <div class="bar${isToday ? ' bar-today' : ''}" style="height:${Math.max(pct, count > 0 ? 4 : 0)}%"></div>
        <div class="bar-label${isToday ? ' bar-label-today' : ''}">${label}</div>
      </div>`;
  }).join('');

  // ── Table rows ─────────────────────────────────────────────
  const recentRows = recentFive.length === 0
    ? `<tr><td colspan="5" class="empty-row">
        <div class="empty-icon">🔍</div>
        <div class="empty-msg">No blocked attempts recorded yet</div>
        <div class="empty-sub">Attacks will appear here in real time</div>
       </td></tr>`
    : recentFive.map(a => {
        const rc      = reasonColor(a.reason);
        const dateStr = a.blockedAt
          ? fmtDateTime.format(new Date(a.blockedAt))
          : '—';
        const amount  = a.amountAttempted != null
          ? fmtCurrency.format(a.amountAttempted)
          : '—';
        return `
      <tr>
        <td class="td-time">${escapeHtml(dateStr)}</td>
        <td>${escapeHtml(a.cardType ? a.cardType.charAt(0).toUpperCase() + a.cardType.slice(1) : '—')}</td>
        <td class="td-mono">${escapeHtml(a.cardBin || '—')}••••••</td>
        <td><span class="badge" style="background:${rc.bg};color:${rc.text}">
          <span class="badge-dot" style="background:${rc.dot}"></span>${reasonLabel(a.reason)}
        </span></td>
        <td class="td-amount">${escapeHtml(amount)}</td>
      </tr>`;
      }).join('');

  // ── Status copy ────────────────────────────────────────────
  const statusCopy = {
    green:  { title: 'Protected',       sub: 'Plugin active · Attacks being blocked' },
    yellow: { title: 'Active',          sub: 'Plugin active · No recent attacks'     },
    gray:   { title: 'Monitoring',      sub: 'Awaiting first blocked attempt'        },
    red:    { title: 'Needs Attention', sub: 'No recent activity — check plugin'     },
  }[connectionStatus.color];

  // ── Plan badge ─────────────────────────────────────────────
  const planDisplay = tenant.plan === 'early_access' ? 'Early Access' : escapeHtml(tenant.plan);

  const todayStr = fmtDate.format(new Date());

  return `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>ChargeGuard — Protection Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    /* ── CSS Variables ───────────────────────────────────────── */
    :root {
      --bg:        #080c14;
      --surface:   #0d1220;
      --surface2:  #111827;
      --border:    #1e2d45;
      --border2:   #162236;
      --text:      #e2e8f0;
      --text-sub:  #64748b;
      --text-dim:  #334155;
      --accent:    #3b82f6;
      --accent-dim:#1e3a5f;
      --green:     #22c55e;
      --yellow:    #f59e0b;
      --red:       #ef4444;
      --radius:    12px;
      --radius-sm: 7px;
    }

    /* ── Reset ───────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── Base ────────────────────────────────────────────────── */
    body {
      font-family: 'DM Sans', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 1.75rem 1.5rem;
      min-height: 100vh;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* ── Subtle grid texture on background ──────────────────── */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(var(--border2) 1px, transparent 1px),
        linear-gradient(90deg, var(--border2) 1px, transparent 1px);
      background-size: 40px 40px;
      opacity: .35;
      pointer-events: none;
      z-index: 0;
    }

    /* All content above texture */
    .wrap { position: relative; z-index: 1; max-width: 860px; margin: 0 auto; }

    /* ── Header ──────────────────────────────────────────────── */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.75rem;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: .6rem;
    }
    .brand-icon {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, #1d4ed8, #7c3aed);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 16px;
      flex-shrink: 0;
      box-shadow: 0 0 16px rgba(59,130,246,.35);
    }
    .brand-name {
      font-size: 1rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -.02em;
    }
    .brand-name span { color: #60a5fa; }
    .header-meta {
      display: flex;
      align-items: center;
      gap: .75rem;
    }
    .header-email {
      font-size: .75rem;
      color: var(--text-sub);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: .25rem .75rem;
    }
    .plan-badge {
      font-size: .68rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .06em;
      background: linear-gradient(135deg, #1e3a5f, #1e1b4b);
      color: #93c5fd;
      border: 1px solid #1e3a8a;
      border-radius: 20px;
      padding: .25rem .7rem;
    }

    /* ── Status bar ──────────────────────────────────────────── */
    .status {
      display: flex;
      align-items: center;
      gap: 1rem;
      background: ${statusBg[connectionStatus.color]};
      border: 1px solid ${statusBorder[connectionStatus.color]};
      border-radius: var(--radius);
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }
    .status-left {
      display: flex;
      align-items: center;
      gap: .75rem;
      flex: 1;
      min-width: 200px;
    }
    .status-dot-wrap {
      position: relative;
      width: 18px; height: 18px; flex-shrink: 0;
    }
    .status-dot {
      width: 18px; height: 18px;
      border-radius: 50%;
      background: ${statusColor[connectionStatus.color]};
    }
    .status-dot-pulse {
      position: absolute;
      inset: 0;
      border-radius: 50%;
      background: ${statusColor[connectionStatus.color]};
      opacity: .4;
      animation: ${connectionStatus.color === 'green' ? 'pulse 2s ease-in-out infinite' : 'none'};
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1);   opacity: .4; }
      50%       { transform: scale(1.8); opacity: 0;  }
    }
    .status-text {
      font-size: .95rem;
      font-weight: 700;
      color: ${statusColor[connectionStatus.color]};
      letter-spacing: -.01em;
    }
    .status-sub-text {
      font-size: .78rem;
      color: var(--text-sub);
    }
    .status-right {
      font-size: .75rem;
      color: var(--text-dim);
      white-space: nowrap;
    }

    /* ── Stat cards ──────────────────────────────────────────── */
    .cards {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.1rem 1.25rem;
      position: relative;
      overflow: hidden;
      transition: border-color .2s;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: var(--card-accent, transparent);
      border-radius: var(--radius) var(--radius) 0 0;
    }
    .card-blocked::before { --card-accent: linear-gradient(90deg, #3b82f6, #6366f1); }
    .card-fees::before    { --card-accent: linear-gradient(90deg, #22c55e, #16a34a); }
    .card-week::before    { --card-accent: linear-gradient(90deg, #f59e0b, #d97706); }
    .card-plan::before    { --card-accent: linear-gradient(90deg, #8b5cf6, #6d28d9); }

    .card-icon {
      font-size: 1.1rem;
      margin-bottom: .5rem;
      opacity: .7;
    }
    .card .lbl {
      font-size: .68rem;
      text-transform: uppercase;
      color: var(--text-sub);
      letter-spacing: .07em;
      font-weight: 600;
      margin-bottom: .3rem;
    }
    .card .val {
      font-size: 1.9rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -.03em;
      line-height: 1.1;
      font-variant-numeric: tabular-nums;
    }
    .card .val-sm {
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--text);
      padding-top: .2rem;
      line-height: 1.3;
    }
    .card .sub {
      font-size: .68rem;
      color: var(--text-dim);
      margin-top: .35rem;
      line-height: 1.4;
    }
    .val-green { color: #4ade80 !important; }
    .val-blue  { color: #60a5fa !important; }

    /* ── Chart ───────────────────────────────────────────────── */
    .chart-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
    }
    .section-title {
      font-size: .75rem;
      color: var(--text-sub);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .07em;
    }
    .section-badge {
      font-size: .68rem;
      color: var(--text-dim);
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: .2rem .6rem;
    }
    .chart {
      display: flex;
      align-items: flex-end;
      gap: .4rem;
      height: 88px;
    }
    .bar-wrap {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: .25rem;
      height: 100%;
    }
    .bar {
      width: 100%;
      background: linear-gradient(180deg, #3b82f6 0%, #1d4ed8 100%);
      border-radius: 4px 4px 0 0;
      min-height: 2px;
      transition: height .4s cubic-bezier(.4,0,.2,1);
      position: relative;
    }
    .bar-today {
      background: linear-gradient(180deg, #60a5fa 0%, #3b82f6 100%);
      box-shadow: 0 -2px 8px rgba(96,165,250,.4);
    }
    .bar-val {
      font-size: .62rem;
      color: var(--text-sub);
      height: 14px;
      font-family: 'DM Mono', monospace;
    }
    .bar-label {
      font-size: .6rem;
      color: var(--text-dim);
      font-weight: 500;
    }
    .bar-label-today {
      color: #60a5fa;
      font-weight: 700;
    }

    /* ── Table ───────────────────────────────────────────────── */
    .tbl-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .tbl-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: .9rem 1.25rem;
      border-bottom: 1px solid var(--border);
    }
    .tbl-title {
      font-size: .75rem;
      color: var(--text-sub);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .07em;
    }
    .tbl-count {
      font-size: .68rem;
      color: var(--text-dim);
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: .15rem .55rem;
      font-family: 'DM Mono', monospace;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: .8rem;
    }
    th {
      background: var(--surface2);
      color: var(--text-dim);
      padding: .55rem 1rem;
      text-align: left;
      font-weight: 600;
      font-size: .65rem;
      text-transform: uppercase;
      letter-spacing: .07em;
    }
    td {
      padding: .65rem 1rem;
      border-bottom: 1px solid var(--border2);
      color: #94a3b8;
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,.018); }
    .td-time   { color: var(--text-sub); font-size: .75rem; white-space: nowrap; }
    .td-mono   { font-family: 'DM Mono', monospace; font-size: .75rem; color: var(--text-sub); }
    .td-amount { font-family: 'DM Mono', monospace; font-size: .78rem; color: #4ade80; font-weight: 500; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      border-radius: var(--radius-sm);
      padding: .2rem .6rem;
      font-size: .7rem;
      font-weight: 600;
      white-space: nowrap;
    }
    .badge-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      flex-shrink: 0;
    }

    /* ── Empty state ─────────────────────────────────────────── */
    .empty-row td {
      text-align: center;
      padding: 2.5rem 1rem;
    }
    .empty-icon { font-size: 1.75rem; margin-bottom: .5rem; opacity: .5; }
    .empty-msg  { font-size: .85rem; color: var(--text-sub); font-weight: 600; }
    .empty-sub  { font-size: .75rem; color: var(--text-dim); margin-top: .25rem; }

    /* ── Onboarding banner ───────────────────────────────────── */
    .onboard {
      background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 50%, #0a1628 100%);
      border: 1px solid #1e3a5f;
      border-radius: var(--radius);
      padding: 1.75rem 1.5rem;
      margin-bottom: 1.5rem;
      position: relative;
      overflow: hidden;
      text-align: center;
    }
    .onboard::before {
      content: '';
      position: absolute;
      top: -40px; left: 50%;
      transform: translateX(-50%);
      width: 200px; height: 200px;
      background: radial-gradient(circle, rgba(59,130,246,.12) 0%, transparent 70%);
      pointer-events: none;
    }
    .onboard-icon { font-size: 2rem; margin-bottom: .75rem; }
    .onboard h2 {
      font-size: 1rem;
      font-weight: 700;
      color: #93c5fd;
      margin-bottom: .5rem;
      letter-spacing: -.01em;
    }
    .onboard p {
      color: #60a5fa;
      line-height: 1.7;
      font-size: .85rem;
      max-width: 400px;
      margin: 0 auto;
      opacity: .85;
    }
    .onboard-steps {
      display: flex;
      justify-content: center;
      gap: 1.5rem;
      margin-top: 1.1rem;
      flex-wrap: wrap;
    }
    .onboard-step {
      display: flex;
      align-items: center;
      gap: .4rem;
      font-size: .75rem;
      color: #38bdf8;
      font-weight: 500;
    }
    .onboard-step-num {
      width: 20px; height: 20px;
      border-radius: 50%;
      background: rgba(56,189,248,.15);
      border: 1px solid rgba(56,189,248,.3);
      display: flex; align-items: center; justify-content: center;
      font-size: .65rem;
      font-weight: 700;
    }

    /* ── Footer ──────────────────────────────────────────────── */
    footer {
      font-size: .68rem;
      color: var(--text-dim);
      text-align: center;
      margin-top: .5rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border2);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: .5rem;
    }
    footer span { opacity: .4; }

    /* ── Responsive ──────────────────────────────────────────── */
    @media (max-width: 700px) {
      body { padding: 1rem; }
      .cards { grid-template-columns: 1fr 1fr; }
      .card .val { font-size: 1.5rem; }
      th:nth-child(3), td:nth-child(3),
      th:nth-child(5), td:nth-child(5) { display: none; }
      .header-meta { gap: .4rem; }
    }
    @media (max-width: 420px) {
      .cards { grid-template-columns: 1fr 1fr; }
      .plan-badge { display: none; }
      th:nth-child(2), td:nth-child(2) { display: none; }
    }
  </style>
</head>
<body>
<div class="wrap">

  <!-- ── Header ── -->
  <div class="header">
    <div class="brand">
      <div class="brand-icon">⚡</div>
      <span class="brand-name">Charge<span>Guard</span></span>
    </div>
    <div class="header-meta">
      <span class="header-email">${escapeHtml(tenant.email)}</span>
      <span class="plan-badge">${escapeHtml(planDisplay)}</span>
    </div>
  </div>

  <!-- ── Status bar ── -->
  <div class="status">
    <div class="status-left">
      <div class="status-dot-wrap">
        <div class="status-dot"></div>
        <div class="status-dot-pulse"></div>
      </div>
      <div>
        <div class="status-text">${escapeHtml(statusCopy.title)}</div>
        <div class="status-sub-text">${escapeHtml(statusCopy.sub)}</div>
      </div>
    </div>
    <div class="status-right">Last activity: ${escapeHtml(connectionStatus.label)}</div>
  </div>

  ${isNew ? `
  <!-- ── Onboarding ── -->
  <div class="onboard">
    <div class="onboard-icon">🛡️</div>
    <h2>Your store is protected</h2>
    <p>ChargeGuard is active and monitoring checkout events.
       Blocked card-testing attempts will appear here in real time.</p>
    <div class="onboard-steps">
      <div class="onboard-step">
        <div class="onboard-step-num">1</div>
        Plugin connected
      </div>
      <div class="onboard-step">
        <div class="onboard-step-num">2</div>
        Monitoring active
      </div>
      <div class="onboard-step">
        <div class="onboard-step-num">3</div>
        Waiting for first attack
      </div>
    </div>
  </div>` : ''}

  <!-- ── Stat cards ── -->
  <div class="cards">
    <div class="card card-blocked">
      <div class="card-icon">🛡️</div>
      <div class="lbl">Attacks Blocked</div>
      <div class="val val-blue">${totalBlocked.toLocaleString('en-US')}</div>
      <div class="sub">Since protection started</div>
    </div>
    <div class="card card-fees">
      <div class="card-icon">💰</div>
      <div class="lbl">Fees Saved</div>
      <div class="val val-green">${escapeHtml(feesFormatted)}</div>
      <div class="sub">Gateway fees you didn't pay</div>
    </div>
    <div class="card card-week">
      <div class="card-icon">📊</div>
      <div class="lbl">This Week</div>
      <div class="val">${weekTotal.toLocaleString('en-US')}</div>
      <div class="sub">Attacks in last 7 days</div>
    </div>
    <div class="card card-plan">
      <div class="card-icon">✦</div>
      <div class="lbl">Your Plan</div>
      <div class="val-sm">${escapeHtml(planDisplay)}</div>
      <div class="sub">Member since<br>${escapeHtml(memberSinceStr)}</div>
    </div>
  </div>

  <!-- ── Weekly chart ── -->
  <div class="chart-wrap">
    <div class="section-header">
      <span class="section-title">7-Day Attack Activity</span>
      <span class="section-badge">${weekTotal} this week</span>
    </div>
    <div class="chart">${chartBars}</div>
  </div>

  <!-- ── Recent attempts table ── -->
  <div class="tbl-wrap">
    <div class="tbl-header">
      <span class="tbl-title">Recent Blocked Attempts</span>
      <span class="tbl-count">Last ${recentFive.length}</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Time (UTC)</th>
          <th>Card</th>
          <th>BIN</th>
          <th>Reason</th>
          <th>Amount</th>
        </tr>
      </thead>
      <tbody>${recentRows}</tbody>
    </table>
  </div>

  <footer>
    ChargeGuard
    <span>·</span>
    Internal Use Only
    <span>·</span>
    ${escapeHtml(todayStr)}
  </footer>

</div><!-- /.wrap -->
</body>
</html>`;
};

module.exports = router;