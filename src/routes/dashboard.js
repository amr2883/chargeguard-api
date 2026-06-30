'use strict';

const express = require('express');
const router  = express.Router();
const { PrismaClient } = require('@prisma/client');
const { getBINStats, THRESHOLDS } = require('../lib/binSequenceDetector');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');
const { hashApiKey } = require('../lib/apiKeyHash');

const prisma = new PrismaClient();

// ── Constants ─────────────────────────────────────────────────
const { SAVINGS_PER_ATTACK: FEES_PER_ATTEMPT } = require('../lib/constants');
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
    const { tenant, usedPreviousKey } = await resolveTenantByApiKey(apiKey, {
      id: true, email: true, plan: true, isActive: true, createdAt: true, keyRotatedAt: true,
    });

    if (!tenant || !tenant.isActive) {
      return setTimeout(() => res.status(401).json({ error: 'Unauthorized' }), 200);
    }

    if (usedPreviousKey) {
      res.set('X-ChargeGuard-Key-Deprecated', 'true');
      console.warn(`[Dashboard] Request authenticated using previous (grace-period) API key — tenant ${tenant.id}`);
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

// ── Security Score Calculator ─────────────────────────────────
const calculateSecurityScore = (attacks24h, weekTotal, uniqueReasonCount, daysSinceJoined) => {
  const base         = 100;
  const intensity    = Math.min(attacks24h  * 0.8, 30);
  const weekPressure = Math.min(weekTotal   * 0.15, 15);
  const diversity    = uniqueReasonCount >= 3 ? 8 : uniqueReasonCount >= 2 ? 4 : 0;
  const longevity    = Math.min(daysSinceJoined * 0.04, 8);
  const raw          = base - intensity - weekPressure - diversity + longevity;
  return Math.max(52, Math.min(100, Math.round(raw)));
};

// ── Dashboard queries ─────────────────────────────────────────
const getDashboardData = async (tenantId, tenantCreatedAt) => {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const oneHourAgo         = new Date(Date.now() - 60 * 60 * 1000);

  const [totalBlocked, recentAttempts, lastEight, lastActivity, amountData, reasonData, attacks24h, binAttackData, topBinsForOrigin, totalTenants] = await Promise.all([
    prisma.blockedAttempt.count({ where: { tenantId } }),
    prisma.blockedAttempt.findMany({
      where:   { tenantId, blockedAt: { gte: sevenDaysAgo } },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'asc' },
    }),
    prisma.blockedAttempt.findMany({
      where:   { tenantId },
      select:  { blockedAt: true, cardType: true, reason: true, cardBin: true, amountAttempted: true, riskScore: true },
      orderBy: { blockedAt: 'desc' },
      take:    8,
    }),
    prisma.blockedAttempt.findFirst({
      where:   { tenantId },
      select:  { blockedAt: true },
      orderBy: { blockedAt: 'desc' },
    }),
    prisma.blockedAttempt.aggregate({
      where:  { tenantId },
      _sum:   { amountAttempted: true },
    }),
    prisma.blockedAttempt.groupBy({
      by:     ['reason'],
      where:  { tenantId },
      _count: { reason: true },
    }),
    prisma.blockedAttempt.count({
      where: { tenantId, blockedAt: { gte: twentyFourHoursAgo } },
    }),
    prisma.blockedAttempt.groupBy({
      by:      ['cardBin'],
      where:   { tenantId, blockedAt: { gte: oneHourAgo }, cardBin: { not: null } },
      _count:  { cardBin: true },
      orderBy: { _count: { cardBin: 'desc' } },
      take:    3,
    }),
    prisma.blockedAttempt.groupBy({
      by:      ['cardBin'],
      where:   { tenantId, cardBin: { not: null } },
      _count:  { cardBin: true },
      orderBy: { _count: { cardBin: 'desc' } },
      take:    10,
    }),
    prisma.tenant.count({ where: { isActive: true } }),
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
  const weekTotal = Object.values(dayMap).reduce((s, c) => s + c, 0);

  const amountProtected = amountData._sum.amountAttempted ?? 0;
  const reasonBreakdown = Object.fromEntries(
    reasonData.map(r => [r.reason, r._count.reason])
  );
  const uniqueReasonCount = reasonData.length;

  const daysSinceJoined = tenantCreatedAt
    ? Math.floor((Date.now() - new Date(tenantCreatedAt).getTime()) / 86400000)
    : 0;
  const securityScore = calculateSecurityScore(attacks24h, weekTotal, uniqueReasonCount, daysSinceJoined);

  // ── BIN Activity Analysis ──────────────────────────────────
  const activeBinAttack = binAttackData.find(b => b._count.cardBin >= 3) ?? null;
  const binActivity = {
    hasActiveAttack:  !!activeBinAttack,
    topBin:           activeBinAttack?.cardBin ?? null,
    topBinCount:      activeBinAttack?._count?.cardBin ?? 0,
    totalBinPatterns: binAttackData.filter(b => b._count.cardBin >= 2).length,
  };

  // ── Threat Origins — BIN → Country lookup ─────────────────
  const topBinValues = topBinsForOrigin.map(b => b.cardBin).filter(Boolean);
  const binRecords = topBinValues.length > 0
    ? await prisma.binRecord.findMany({
        where:  { bin: { in: topBinValues } },
        select: { bin: true, issuerCountry: true, brand: true },
      })
    : [];

  const binCountryMap = Object.fromEntries(binRecords.map(r => [r.bin, r]));

  const threatOrigins = topBinsForOrigin
    .map(b => ({
      bin:     b.cardBin,
      count:   b._count.cardBin,
      country: binCountryMap[b.cardBin]?.issuerCountry ?? null,
      brand:   binCountryMap[b.cardBin]?.brand ?? null,
    }))
    .filter(o => o.country)
    .reduce((acc, o) => {
      const existing = acc.find(a => a.country === o.country);
      if (existing) { existing.count += o.count; }
      else acc.push({ country: o.country, count: o.count, brand: o.brand });
      return acc;
    }, [])
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const binSequenceStats = getBINStats();

  // ── PayPal Shield Stats (from AlertLog) ───────────────────────────────
  const sevenDaysAgoPaypal = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [paypalWeeklyLogs, paypalAllTimeLogs, tenantPaypalMeta] = await Promise.all([

    // آخر 7 أيام من تنبيهات PayPal
    prisma.alertLog.findMany({
      where: {
        tenantId:  tenantId,
        alertType: 'paypal_weekly_shield',
        sentAt:    { gte: sevenDaysAgoPaypal },
      },
      select: { attackCount: true, savedAmount: true, sentAt: true },
      orderBy: { sentAt: 'desc' },
    }),

    // إجمالي كل الوقت
    prisma.alertLog.aggregate({
      where:   { tenantId: tenantId, alertType: 'paypal_weekly_shield' },
      _sum:    { attackCount: true, savedAmount: true },
      _count:  { id: true },
    }),

    // آخر تنبيه PayPal فوري (من lastPaypalAlertAt)
    prisma.tenant.findUnique({
      where:  { id: tenantId },
      select: { lastPaypalAlertAt: true },
    }),

  ]);

  const paypalWeekSuspicious  = paypalWeeklyLogs.reduce((s, l) => s + (l.attackCount || 0), 0);
  const paypalWeekSaved       = paypalWeeklyLogs.reduce((s, l) => s + (l.savedAmount  || 0), 0);
  const paypalAllTimeSuspicious = paypalAllTimeLogs._sum.attackCount || 0;
  const paypalAllTimeSaved      = paypalAllTimeLogs._sum.savedAmount  || 0;
  const paypalReportCount       = paypalAllTimeLogs._count.id         || 0;
  const paypalIsActive          = paypalReportCount > 0;
  const lastPaypalAlertAt       = tenantPaypalMeta?.lastPaypalAlertAt ?? null;

  const paypalStats = {
    isActive:            paypalIsActive,
    weekSuspicious:      paypalWeekSuspicious,
    weekSaved:           paypalWeekSaved,
    allTimeSuspicious:   paypalAllTimeSuspicious,
    allTimeSaved:        paypalAllTimeSaved,
    reportCount:         paypalReportCount,
    lastAlertAt:         lastPaypalAlertAt,
  };

  return {
    totalBlocked,
    feesSaved:        (totalBlocked * FEES_PER_ATTEMPT).toFixed(2),
    amountProtected:  amountProtected.toFixed(2),
    reasonBreakdown,
    attacks24h,
    securityScore,
    binActivity,
    binSequenceStats,
    threatOrigins,
    totalTenants,
    chartData:        Object.entries(dayMap).map(([date, count]) => ({ date, count })),
    recentEight:      lastEight,
    connectionStatus: getConnectionStatus(lastActivity?.blockedAt ?? null),
    paypalStats,
  };
};

// ── GET /api/dashboard  (JSON) ───────────────────────────────
router.get('/', rateLimit, authByApiKey, async (req, res) => {
  try {
    const data = await getDashboardData(req.tenant.id, req.tenant.createdAt);
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
    const data = await getDashboardData(req.tenant.id, req.tenant.createdAt);
    res.setHeader('Content-Type',  'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag',  'noindex');
    res.send(await buildDashboardHtml(req.tenant, data));
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
  card_testing: 'Stolen Card Probe',
  velocity:     'Rapid-Fire Attack',
  blacklist:    'Known Threat Actor',
  pattern:      'Network Fraud Pattern',
}[r] ?? escapeHtml(r));

const reasonColor = (r) => ({
  card_testing: { bg: '#2d1b69', text: '#a78bfa', dot: '#7c3aed' },
  velocity:     { bg: '#1c1917', text: '#fb923c', dot: '#ea580c' },
  blacklist:    { bg: '#1c0a0a', text: '#f87171', dot: '#dc2626' },
  pattern:      { bg: '#0c1a2e', text: '#38bdf8', dot: '#0284c7' },
}[r] ?? { bg: '#1e293b', text: '#94a3b8', dot: '#475569' });

// ── Risk Score Badge ───────────────────────────────────────────
const riskBadge = (score) => {
  if (score === null || score === undefined) {
    return '<span style="color:#334155;font-size:.7rem;">—</span>';
  }
  const color = score >= 75 ? '#f87171'
              : score >= 60 ? '#fb923c'
              : score >= 40 ? '#fbbf24'
              :               '#4ade80';
  const label = score >= 75 ? 'Critical'
              : score >= 60 ? 'High'
              : score >= 40 ? 'Medium'
              :               'Low';
  return `<span style="background:${color}18;color:${color};border:1px solid ${color}44;border-radius:6px;padding:.2rem .55rem;font-size:.7rem;font-weight:600;font-family:'DM Mono',monospace;white-space:nowrap;" title="Risk Score: ${score}/100 — ${label}">${score} · ${label}</span>`;
};

const statusColor = { green: '#22c55e', yellow: '#f59e0b', gray: '#64748b', red: '#ef4444' };
const statusBg    = { green: '#052e16', yellow: '#1c1202', gray: '#0f172a', red: '#1c0202' };
const statusBorder= { green: '#166534', yellow: '#713f12', gray: '#1e293b', red: '#7f1d1d' };

// ── Build HTML ────────────────────────────────────────────────
const buildDashboardHtml = async (tenant, data) => {
  const { totalBlocked, feesSaved, chartData, recentEight, connectionStatus } = data;
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
  const recentRows = recentEight.length === 0
    ? `<tr><td colspan="5" class="empty-row">
        <div class="empty-icon">🔍</div>
        <div class="empty-msg">No blocked attempts recorded yet</div>
        <div class="empty-sub">Attacks will appear here in real time</div>
       </td></tr>`
    : recentEight.map(a => {
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
        <td class="td-risk">${riskBadge(a.riskScore)}</td>
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

    /* ── Hero Section ────────────────────────────────────────── */
    .hero {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.75rem 1.5rem 1.5rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 2rem;
      position: relative;
      overflow: hidden;
    }
    .hero::before {
      content: '';
      position: absolute;
      top: -60px; right: -60px;
      width: 200px; height: 200px;
      background: radial-gradient(circle, rgba(59,130,246,.07) 0%, transparent 70%);
      pointer-events: none;
    }
    .gauge-wrap {
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: .5rem;
    }
    .gauge-svg { overflow: visible; }
    .gauge-score {
      font-size: 2rem;
      font-weight: 700;
      letter-spacing: -.04em;
      font-variant-numeric: tabular-nums;
      line-height: 1;
    }
    .gauge-label {
      font-size: .7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .08em;
      opacity: .7;
    }
    .hero-right {
      flex: 1;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .hero-title {
      font-size: 1.1rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -.02em;
      line-height: 1.3;
    }
    .hero-title span {
      display: block;
      font-size: .8rem;
      font-weight: 400;
      color: var(--text-sub);
      margin-top: .2rem;
    }
    .hero-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: .75rem;
    }
    .hero-stat {
      background: var(--bg);
      border: 1px solid var(--border2);
      border-radius: var(--radius-sm);
      padding: .6rem .75rem;
    }
    .hero-stat-label {
      font-size: .6rem;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: var(--text-dim);
      font-weight: 600;
      margin-bottom: .2rem;
    }
    .hero-stat-val {
      font-size: .88rem;
      font-weight: 700;
      color: var(--text);
      font-family: 'DM Mono', monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* ── Value Card ──────────────────────────────────────────── */
    .value-card-inner {
      display: flex;
      flex-direction: column;
      gap: .5rem;
    }
    .value-primary {
      font-size: 1.75rem;
      font-weight: 700;
      color: #4ade80;
      letter-spacing: -.03em;
      line-height: 1;
      font-variant-numeric: tabular-nums;
    }
    .value-primary-label {
      font-size: .65rem;
      color: #4ade80;
      opacity: .7;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: .06em;
      margin-top: .15rem;
    }
    .value-divider {
      border: none;
      border-top: 1px solid var(--border2);
      margin: .25rem 0;
    }
    .value-secondaries {
      display: flex;
      flex-direction: column;
      gap: .3rem;
    }
    .value-secondary {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: .5rem;
    }
    .value-secondary-label {
      font-size: .65rem;
      color: var(--text-dim);
      font-weight: 500;
    }
    .value-secondary-val {
      font-size: .72rem;
      font-weight: 600;
      color: var(--text-sub);
      font-family: 'DM Mono', monospace;
    }

    /* ── Intelligence Feed ───────────────────────────────────── */
    .feed-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .feed-list {
      padding: .5rem 0;
    }
    .feed-item {
      display: flex;
      align-items: flex-start;
      gap: .875rem;
      padding: .65rem 1.25rem;
      border-bottom: 1px solid var(--border2);
      transition: background .15s;
    }
    .feed-item:last-child { border-bottom: none; }
    .feed-item:hover { background: rgba(255,255,255,.015); }
    .feed-dot-col {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0;
      padding-top: .3rem;
      flex-shrink: 0;
    }
    .feed-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .feed-line {
      width: 1px;
      flex: 1;
      background: var(--border2);
      min-height: 16px;
      margin-top: 3px;
    }
    .feed-item:last-child .feed-line { display: none; }
    .feed-body { flex: 1; min-width: 0; }
    .feed-text {
      font-size: .78rem;
      color: var(--text-sub);
      line-height: 1.4;
      overflow: hidden;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
    }
    .feed-text strong { color: var(--text); font-weight: 600; }
    .feed-text .feed-check { color: #4ade80; font-weight: 700; }
    .feed-meta {
      font-size: .65rem;
      color: var(--text-dim);
      margin-top: .15rem;
      font-family: 'DM Mono', monospace;
    }

    /* ── BIN Panel ───────────────────────────────────────────── */
    .bin-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .bin-panel-inner {
      padding: 1.25rem 1.5rem;
    }
    .bin-alert {
      display: flex;
      align-items: flex-start;
      gap: 1rem;
    }
    .bin-alert-icon {
      font-size: 1.4rem;
      flex-shrink: 0;
      margin-top: .1rem;
    }
    .bin-alert-body { flex: 1; }
    .bin-alert-title {
      font-size: .9rem;
      font-weight: 700;
      color: var(--text);
      letter-spacing: -.01em;
      margin-bottom: .25rem;
    }
    .bin-alert-sub {
      font-size: .78rem;
      color: var(--text-sub);
      line-height: 1.5;
    }
    .bin-alert-sub strong { color: var(--text); }
    .bin-confirmed {
      display: inline-flex;
      align-items: center;
      gap: .3rem;
      margin-top: .5rem;
      font-size: .7rem;
      font-weight: 600;
      color: #4ade80;
      background: rgba(74,222,128,.08);
      border: 1px solid rgba(74,222,128,.2);
      border-radius: 20px;
      padding: .2rem .7rem;
    }

    /* ── Soft Lock (Pro Teaser) ──────────────────────────────── */
    .pro-lock {
      position: relative;
      overflow: hidden;
    }
    .pro-lock-overlay {
      position: absolute;
      inset: 0;
      background: linear-gradient(180deg, transparent 0%, var(--surface) 55%);
      display: flex;
      align-items: flex-end;
      justify-content: center;
      padding-bottom: 1.25rem;
      pointer-events: none;
    }
    .pro-lock-cta {
      pointer-events: all;
      display: inline-flex;
      align-items: center;
      gap: .5rem;
      background: linear-gradient(135deg, #1d4ed8, #7c3aed);
      color: #fff;
      font-size: .78rem;
      font-weight: 600;
      padding: .55rem 1.25rem;
      border-radius: 20px;
      border: none;
      cursor: pointer;
      box-shadow: 0 4px 16px rgba(59,130,246,.3);
      letter-spacing: -.01em;
      text-decoration: none;
    }

    /* ── Weekly Digest ───────────────────────────────────────── */
    .digest-wrap {
      background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
      border: 1px solid #1e3a5f;
      border-radius: var(--radius);
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.5rem;
    }
    .digest-narrative {
      font-size: .85rem;
      color: #93c5fd;
      line-height: 1.7;
      margin-bottom: 1rem;
      font-style: italic;
    }
    .digest-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: .75rem;
    }
    .digest-stat {
      background: rgba(255,255,255,.04);
      border: 1px solid rgba(59,130,246,.15);
      border-radius: var(--radius-sm);
      padding: .65rem .875rem;
      text-align: center;
    }
    .digest-stat-val {
      font-size: 1.3rem;
      font-weight: 700;
      color: #60a5fa;
      letter-spacing: -.02em;
      font-variant-numeric: tabular-nums;
      line-height: 1;
    }
    .digest-stat-label {
      font-size: .62rem;
      color: #3b82f6;
      opacity: .7;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: .06em;
      margin-top: .3rem;
    }

    /* ── Threat Origins ──────────────────────────────────────── */
    .origins-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      margin-bottom: 1.5rem;
    }
    .origins-list {
      padding: .75rem 1.25rem 1rem;
      display: flex;
      flex-direction: column;
      gap: .6rem;
    }
    .origin-row {
      display: flex;
      align-items: center;
      gap: .75rem;
    }
    .origin-flag {
      font-size: 1rem;
      flex-shrink: 0;
      width: 20px;
      text-align: center;
    }
    .origin-country {
      font-size: .78rem;
      font-weight: 600;
      color: var(--text);
      flex: 1;
      min-width: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .origin-bar-wrap {
      flex: 2;
      height: 6px;
      background: var(--border2);
      border-radius: 3px;
      overflow: hidden;
    }
    .origin-bar {
      height: 100%;
      border-radius: 3px;
      background: linear-gradient(90deg, #3b82f6, #6366f1);
    }
    .origin-count {
      font-size: .7rem;
      font-family: 'DM Mono', monospace;
      color: var(--text-dim);
      flex-shrink: 0;
      width: 28px;
      text-align: right;
    }

    /* ── Social Proof ────────────────────────────────────────── */
    .social-proof {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.5rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .social-proof-icon {
      font-size: 1.5rem;
      flex-shrink: 0;
    }
    .social-proof-text {
      flex: 1;
      font-size: .82rem;
      color: var(--text-sub);
      line-height: 1.5;
    }
    .social-proof-text strong {
      color: #60a5fa;
      font-weight: 700;
    }
    .social-proof-badge {
      flex-shrink: 0;
      font-size: .68rem;
      font-weight: 600;
      color: #22c55e;
      background: rgba(34,197,94,.08);
      border: 1px solid rgba(34,197,94,.2);
      border-radius: 20px;
      padding: .3rem .8rem;
      white-space: nowrap;
    }

    /* ── Responsive ──────────────────────────────────────────── */
    @media (max-width: 700px) {
      body { padding: 1rem; }
      .cards { grid-template-columns: 1fr 1fr; }
      .card .val { font-size: 1.5rem; }
      th:nth-child(3), td:nth-child(3),
      th:nth-child(5), td:nth-child(5) { display: none; }
      .header-meta { gap: .4rem; }
      .hero { flex-direction: column; gap: 1.25rem; padding: 1.25rem 1rem; }
      .gauge-wrap { flex-direction: row; gap: 1rem; align-items: center; width: 100%; }
      .gauge-svg { width: 90px; height: 70px; }
      .hero-stats { grid-template-columns: repeat(3, 1fr); gap: .5rem; }
      .hero-stat-val { font-size: .78rem; }
    }
    @media (max-width: 420px) {
      .cards { grid-template-columns: 1fr 1fr; }
      .plan-badge { display: none; }
      th:nth-child(2), td:nth-child(2) { display: none; }
      .hero-stats { grid-template-columns: 1fr 1fr; }
      .hero-stat:last-child { grid-column: 1 / -1; }
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

  <!-- ── Hero Section ── -->
  ${(() => {
    const score = data.securityScore;
    const a24   = data.attacks24h || 0;

    const isFirstDay  = data.totalBlocked === 0;
    const scoreColor  = isFirstDay    ? '#3b82f6'
                      : score >= 85   ? '#22c55e'
                      : score >= 70   ? '#3b82f6'
                      :                 '#f59e0b';
    const scoreLabel  = isFirstDay   ? 'Ready'
                      : score >= 85  ? 'Secure'
                      : score >= 70  ? 'Protected'
                      :                'Active Defense';
    const heroTitle   = isFirstDay
      ? 'Protection is active — scanning every checkout'
      : score >= 85
      ? 'Your store is fully protected'
      : score >= 70
      ? 'Active protection in place'
      : 'Defense systems engaged';
    const heroSub     = isFirstDay
      ? 'ChargeGuard is live and learning your store\'s patterns · First attack report will appear here'
      : score >= 85
      ? 'All systems operational · No active threats detected'
      : score >= 70
      ? 'Monitoring elevated activity · All threats contained'
      : 'High threat volume · Every attempt blocked';

    // Gauge arc math (270° sweep, starts at 135°)
    const R       = 54;
    const CX      = 64, CY = 72;
    const totalArc = 270;
    const filledArc = (score / 100) * totalArc;
    const toRad    = (deg) => (deg - 90) * Math.PI / 180;
    const startDeg = 135, endDeg = 135 + totalArc;
    const filledEnd = 135 + filledArc;

    const arcPath = (fromDeg, toDeg, r) => {
      const x1 = CX + r * Math.cos(toRad(fromDeg));
      const y1 = CY + r * Math.sin(toRad(fromDeg));
      const x2 = CX + r * Math.cos(toRad(toDeg));
      const y2 = CY + r * Math.sin(toRad(toDeg));
      const large = (toDeg - fromDeg) > 180 ? 1 : 0;
      return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
    };

    const daysSince = Math.floor((Date.now() - new Date(tenant.createdAt).getTime()) / 86400000);
    const streakLabel = daysSince >= 1 ? `${daysSince}d` : 'Today';
    const lastStopLabel = connectionStatus.label;
    const threatsTodayLabel = a24 === 0 ? 'None' : `${a24}`;

    return `<div class="hero">
      <div class="gauge-wrap">
        <svg class="gauge-svg" width="128" height="100" viewBox="0 0 128 100">
          <path d="${arcPath(startDeg, endDeg, R)}"
            fill="none" stroke="${scoreColor}18" stroke-width="10" stroke-linecap="round"/>
          <path d="${arcPath(startDeg, filledEnd, R)}"
            fill="none" stroke="${scoreColor}" stroke-width="10" stroke-linecap="round"
            filter="url(#glow)"/>
          <defs>
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2.5" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>
          <text x="${CX}" y="${CY - 4}" text-anchor="middle"
            fill="${scoreColor}" font-family="DM Sans, sans-serif"
            font-size="22" font-weight="700" letter-spacing="-1">${score}</text>
          <text x="${CX}" y="${CY + 13}" text-anchor="middle"
            fill="${scoreColor}" font-family="DM Sans, sans-serif"
            font-size="8" font-weight="600" opacity=".75"
            letter-spacing="1.5" text-transform="uppercase">${scoreLabel.toUpperCase()}</text>
        </svg>
        <div style="font-size:.6rem;color:var(--text-dim);font-weight:500;letter-spacing:.05em;margin-top:-.25rem;">SECURITY SCORE</div>
      </div>
      <div class="hero-right">
        <div class="hero-title">
          ${escapeHtml(heroTitle)}
          <span>${escapeHtml(heroSub)}</span>
        </div>
        <div class="hero-stats">
          <div class="hero-stat">
            <div class="hero-stat-label">Last Stopped</div>
            <div class="hero-stat-val" style="color:${scoreColor};">${escapeHtml(lastStopLabel)}</div>
          </div>
          <div class="hero-stat">
            <div class="hero-stat-label">Protected Since</div>
            <div class="hero-stat-val">${escapeHtml(streakLabel)}</div>
          </div>
          <div class="hero-stat">
            <div class="hero-stat-label">Threats Today</div>
            <div class="hero-stat-val" style="color:${a24 > 0 ? '#fb923c' : 'var(--text-sub)'};">${escapeHtml(threatsTodayLabel)}</div>
          </div>
        </div>
      </div>
    </div>`;
  })()}

  <!-- ── PayPal Shield Section ── -->
  ${(() => {
    const pp = data.paypalStats;

    // إذا لم يكن التاجر يستخدم PayPal بعد
    if (!pp.isActive) {
      return `
      <div style="
        background:linear-gradient(135deg,#0a0f1e,#0d1529);
        border:1px solid #1e2d45;
        border-radius:var(--radius);
        padding:1.1rem 1.5rem;
        margin-bottom:1.5rem;
        display:flex;
        align-items:center;
        gap:1rem;
      ">
        <div style="
          width:36px;height:36px;flex-shrink:0;
          background:rgba(59,130,246,.08);
          border:1px solid rgba(59,130,246,.15);
          border-radius:9px;
          display:flex;align-items:center;justify-content:center;
          font-size:1rem;
        ">🅿️</div>
        <div style="flex:1;">
          <div style="font-size:.8rem;font-weight:700;color:#475569;letter-spacing:-.01em;">
            PayPal Shield — Ready
          </div>
          <div style="font-size:.72rem;color:#334155;margin-top:.15rem;line-height:1.4;">
            Connect your PayPal webhook to activate transaction-level monitoring
          </div>
        </div>
        <div style="
          flex-shrink:0;
          font-size:.65rem;font-weight:600;
          color:#334155;
          background:rgba(255,255,255,.03);
          border:1px solid #1e2d45;
          border-radius:20px;
          padding:.25rem .7rem;
          white-space:nowrap;
        ">Not connected</div>
      </div>`;
    }

    // PayPal نشط — عرض الـ Shield Section كاملة
    const savedFmt = fmtCurrency.format(pp.weekSaved);
    const allTimeSavedFmt = fmtCurrency.format(pp.allTimeSaved);

    const relTime = (date) => {
      if (!date) return 'No alerts yet';
      const diff = Date.now() - new Date(date).getTime();
      const m = Math.floor(diff / 60000);
      const h = Math.floor(diff / 3600000);
      const d = Math.floor(diff / 86400000);
      if (m < 1)  return 'just now';
      if (m < 60) return `${m}m ago`;
      if (h < 24) return `${h}h ago`;
      return `${d}d ago`;
    };

    const lastAlertStr = relTime(pp.lastAlertAt);
    const hasWeekActivity = pp.weekSuspicious > 0;

    return `
    <div style="
      background:linear-gradient(135deg,#080f1f,#0c1a38);
      border:1px solid #1a3159;
      border-radius:var(--radius);
      margin-bottom:1.5rem;
      overflow:hidden;
      position:relative;
    ">
      <!-- Glow top border -->
      <div style="
        position:absolute;top:0;left:0;right:0;height:2px;
        background:linear-gradient(90deg,#1d4ed8,#3b82f6,#1d4ed8);
        opacity:.7;
      "></div>

      <!-- Header Row -->
      <div style="
        display:flex;align-items:center;justify-content:space-between;
        padding:.875rem 1.25rem;
        border-bottom:1px solid rgba(59,130,246,.1);
      ">
        <div style="display:flex;align-items:center;gap:.6rem;">
          <div style="
            width:28px;height:28px;
            background:linear-gradient(135deg,#1d4ed8,#3b82f6);
            border-radius:7px;
            display:flex;align-items:center;justify-content:center;
            font-size:.85rem;
            box-shadow:0 0 12px rgba(59,130,246,.3);
          ">🅿️</div>
          <span style="
            font-size:.75rem;font-weight:700;
            text-transform:uppercase;letter-spacing:.07em;
            color:#60a5fa;
          ">PayPal Shield</span>
          <span style="
            font-size:.62rem;font-weight:600;
            color:#22c55e;
            background:rgba(34,197,94,.08);
            border:1px solid rgba(34,197,94,.2);
            border-radius:20px;
            padding:.15rem .55rem;
          ">● Active</span>
        </div>
        <div style="
          font-size:.65rem;color:#334155;
          background:rgba(255,255,255,.03);
          border:1px solid #1e2d45;
          border-radius:20px;
          padding:.2rem .65rem;
          font-family:'DM Mono',monospace;
        ">Last alert: ${escapeHtml(lastAlertStr)}</div>
      </div>

      <!-- Stats Row -->
      <div style="
        display:grid;
        grid-template-columns:repeat(3,1fr);
        gap:0;
        border-bottom:1px solid rgba(59,130,246,.08);
      ">

        <!-- Stat 1: This Week Intercepted -->
        <div style="
          padding:1rem 1.25rem;
          border-right:1px solid rgba(59,130,246,.08);
          position:relative;
        ">
          <div style="
            font-size:.6rem;font-weight:600;
            text-transform:uppercase;letter-spacing:.08em;
            color:#334155;margin-bottom:.35rem;
          ">This Week</div>
          <div style="
            font-size:1.75rem;font-weight:700;
            color:${hasWeekActivity ? '#f87171' : '#475569'};
            letter-spacing:-.03em;line-height:1;
            font-variant-numeric:tabular-nums;
          ">${pp.weekSuspicious}</div>
          <div style="font-size:.65rem;color:#334155;margin-top:.25rem;">
            suspicious transactions
          </div>
          ${hasWeekActivity ? `
          <div style="
            position:absolute;top:.75rem;right:.75rem;
            width:6px;height:6px;
            border-radius:50%;
            background:#ef4444;
            box-shadow:0 0 6px #ef4444;
            animation:pulse 2s ease-in-out infinite;
          "></div>` : ''}
        </div>

        <!-- Stat 2: Savings This Week -->
        <div style="
          padding:1rem 1.25rem;
          border-right:1px solid rgba(59,130,246,.08);
        ">
          <div style="
            font-size:.6rem;font-weight:600;
            text-transform:uppercase;letter-spacing:.08em;
            color:#334155;margin-bottom:.35rem;
          ">Saved This Week</div>
          <div style="
            font-size:1.75rem;font-weight:700;
            color:${pp.weekSaved > 0 ? '#4ade80' : '#475569'};
            letter-spacing:-.03em;line-height:1;
            font-variant-numeric:tabular-nums;
          ">${pp.weekSaved > 0 ? savedFmt : '—'}</div>
          <div style="font-size:.65rem;color:#334155;margin-top:.25rem;">
            in dispute fees avoided
          </div>
        </div>

        <!-- Stat 3: All Time -->
        <div style="padding:1rem 1.25rem;">
          <div style="
            font-size:.6rem;font-weight:600;
            text-transform:uppercase;letter-spacing:.08em;
            color:#334155;margin-bottom:.35rem;
          ">All Time</div>
          <div style="
            font-size:1.75rem;font-weight:700;
            color:#3b82f6;
            letter-spacing:-.03em;line-height:1;
            font-variant-numeric:tabular-nums;
          ">${pp.allTimeSuspicious}</div>
          <div style="font-size:.65rem;color:#334155;margin-top:.25rem;">
            total intercepted · ${allTimeSavedFmt} saved
          </div>
        </div>

      </div>

      <!-- End Rule — Peak-End Psychology -->
      <div style="
        padding:.7rem 1.25rem;
        display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:.5rem;
      ">
        <span style="
          font-size:.72rem;font-weight:600;
          color:#1e40af;
          display:flex;align-items:center;gap:.4rem;
        ">
          <span style="color:#22c55e;">✓</span>
          PayPal transactions monitored with the same precision as Stripe
        </span>
        <span style="
          font-size:.65rem;color:#1e3a5f;
          font-family:'DM Mono',monospace;
        ">${pp.reportCount} weekly report${pp.reportCount !== 1 ? 's' : ''} generated</span>
      </div>

    </div>`;
  })()}

  ${isNew ? `
  <!-- ── Onboarding ── -->
  <div class="onboard">
    <div class="onboard-icon">🔬</div>
    <h2>What happens next</h2>
    <p>ChargeGuard is now building a behavioral baseline for your store.
       Here's what the first 48 hours look like:</p>
    <div class="onboard-steps">
      <div class="onboard-step">
        <div class="onboard-step-num">1</div>
        Learning normal checkout patterns
      </div>
      <div class="onboard-step">
        <div class="onboard-step-num">2</div>
        First threat blocked → appears in feed
      </div>
      <div class="onboard-step">
        <div class="onboard-step-num">3</div>
        Intelligence grows with every order
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
      <div class="lbl">Value Protected</div>
      ${(() => {
        const amt = parseFloat(data.amountProtected || '0');
        const fees = parseFloat(feesSaved);
        if (amt <= 0 && fees <= 0) {
          return `<div class="val-sm" style="color:var(--text-sub);padding-top:.4rem;">Monitoring active</div>
                  <div class="sub">Protection value accrues as threats are blocked</div>`;
        }
        const roiRaw = fees > 0 ? fees / 29 : 0;
        const roiX = roiRaw >= 2 ? roiRaw.toFixed(1) : null;
        return `<div class="value-card-inner">
          <div>
            <div class="value-primary">${fmtCurrency.format(amt > 0 ? amt : fees)}</div>
            <div class="value-primary-label">${amt > 0 ? 'fraud value blocked' : 'gateway fees saved'}</div>
          </div>
          <hr class="value-divider"/>
          <div class="value-secondaries">
            ${amt > 0 ? `<div class="value-secondary">
              <span class="value-secondary-label">Gateway fees saved</span>
              <span class="value-secondary-val">${fmtCurrency.format(fees)}</span>
            </div>` : ''}
            ${roiX ? `<div class="value-secondary">
              <span class="value-secondary-label">Est. ROI on plan</span>
              <span class="value-secondary-val" style="color:#4ade80;">${roiX}x</span>
            </div>` : ''}
          </div>
        </div>`;
      })()}
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

  <!-- ── Intelligence Feed ── -->
  ${(() => {
    const events = recentEight;
    if (events.length === 0) return '';

    const relTime = (dateStr) => {
      const diff = Date.now() - new Date(dateStr).getTime();
      const m = Math.floor(diff / 60000);
      const h = Math.floor(diff / 3600000);
      const d = Math.floor(diff / 86400000);
      if (m < 1)  return 'just now';
      if (m < 60) return `${m}m ago`;
      if (h < 24) return `${h}h ago`;
      return `${d}d ago`;
    };

    const feedMsg = (a) => {
      const bin     = a.cardBin ? `BIN ${a.cardBin.slice(0,4)}••` : 'Unknown BIN';
      const card    = a.cardType ? a.cardType.charAt(0).toUpperCase() + a.cardType.slice(1) : 'Card';
      const amt     = a.amountAttempted != null ? ` · ${fmtCurrency.format(a.amountAttempted)} protected` : '';
      const labels  = {
        card_testing: 'Stolen Card Probe',
        velocity:     'Rapid-Fire Attack',
        blacklist:    'Known Threat Actor',
        pattern:      'Network Fraud Pattern',
      };
      const label = labels[a.reason] ?? a.reason;
      return `<strong>${card} ${bin}</strong> blocked · ${label}${amt} <span class="feed-check">✓</span>`;
    };

    const dotColor = (r) => ({
      card_testing: '#7c3aed',
      velocity:     '#ea580c',
      blacklist:    '#dc2626',
      pattern:      '#0284c7',
    }[r] ?? '#475569');

    const rows = events.map(a => `
      <div class="feed-item">
        <div class="feed-dot-col">
          <div class="feed-dot" style="background:${dotColor(a.reason)};box-shadow:0 0 6px ${dotColor(a.reason)}66;"></div>
          <div class="feed-line"></div>
        </div>
        <div class="feed-body">
          <div class="feed-text">${feedMsg(a)}</div>
          <div class="feed-meta">${relTime(a.blockedAt)}</div>
        </div>
      </div>`).join('');

    return `<div class="feed-wrap">
      <div class="tbl-header">
        <span class="tbl-title">Live Threat Feed</span>
        <span class="tbl-count">${events.length} recent events</span>
      </div>
      <div class="feed-list">${rows}</div>
    </div>`;
  })()}

  <!-- ── BIN Sequence Alert Panel ── -->
  <div id="cg-bin-seq-panel" style="margin-bottom:1.5rem;">
    ${(() => {
      const stats = data.binSequenceStats || { activePrefixes: 0, blockedPrefixes: 0, totalActiveBINs: 0 };
      if (stats.blockedPrefixes > 0 || stats.activePrefixes > 0) {
        const threshold    = 8;
        const pct          = Math.min(Math.round((stats.totalActiveBINs / threshold) * 100), 100);
        const barColor     = pct < 50 ? '#3b82f6' : pct < 75 ? '#f59e0b' : '#ef4444';
        const borderColor  = pct < 50 ? '#1e3a5f' : pct < 75 ? '#713f12' : '#7f1d1d';
        const bgColor      = pct < 50 ? '#0a1628' : pct < 75 ? '#1c1202' : '#1c0202';
        return `<div style="background:${bgColor};border:1px solid ${borderColor};border-radius:var(--radius);padding:1.25rem 1.5rem;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;">
            <span style="font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:${barColor};">
              ⚠️ BIN Sequence — Under Watch
            </span>
            <span style="font-size:.68rem;color:var(--text-dim);background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:.2rem .6rem;">
              ${stats.activePrefixes} active prefix${stats.activePrefixes !== 1 ? 'es' : ''}
            </span>
          </div>
          <div style="background:var(--border2);border-radius:4px;height:6px;overflow:hidden;margin-bottom:.5rem;">
            <div style="height:100%;width:${pct}%;background:${barColor};border-radius:4px;transition:width .4s;"></div>
          </div>
          <div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--text-dim);">
            <span>${stats.totalActiveBINs} / ${threshold} BINs to alert threshold</span>
            <span style="color:${barColor};font-weight:600;">${pct}%</span>
          </div>
        </div>`;
      }
      return '';
    })()}
  </div>

  <!-- ── BIN Intelligence Panel ── -->
  ${(() => {
    const bin   = data.binActivity;
    const isPro = tenant.plan !== 'early_access' && tenant.plan !== 'free';

    // Soft Lock للـ early_access — يُظهر رقم الأنماط، يحجب التفاصيل
    if (!isPro) {
      const patternCount = bin.totalBinPatterns || (data.attacks24h > 0 ? 1 : 0);
      const hasActivity  = data.totalBlocked > 0;
      return `<div class="bin-panel pro-lock">
        <div class="tbl-header">
          <span class="tbl-title">🔬 BIN Intelligence</span>
          <span class="tbl-count" style="color:#8b5cf6;border-color:#4c1d95;background:#1e1b4b;">Pro Feature</span>
        </div>
        <div class="bin-panel-inner" style="filter:blur(1.5px);pointer-events:none;user-select:none;">
          <div class="bin-alert">
            <div class="bin-alert-icon">⚠️</div>
            <div class="bin-alert-body">
              <div class="bin-alert-title">${hasActivity ? `${patternCount} BIN pattern${patternCount !== 1 ? 's' : ''} in analysis` : 'BIN Intelligence Active'}</div>
              <div class="bin-alert-sub">${hasActivity ? 'Card prefix patterns detected · ' : 'Monitoring card prefixes · '}<strong>Upgrade to Pro for full details</strong></div>
            </div>
          </div>
        </div>
        <div class="pro-lock-overlay">
          <a class="pro-lock-cta" href="mailto:support@chargeguard.io?subject=Upgrade to Pro">
            🔓 Unlock BIN Intelligence — Upgrade to Pro
          </a>
        </div>
      </div>`;
    }

    if (bin.hasActiveAttack) {
      const maskedBin = bin.topBin ? bin.topBin.slice(0,4) + '••' : '????••';
      return `<div class="bin-panel" style="border-color:#92400e;">
        <div class="tbl-header" style="background:rgba(251,146,60,.04);">
          <span class="tbl-title" style="color:#fb923c;">⚠️ BIN Intelligence — Active Alert</span>
          <span class="tbl-count" style="color:#fb923c;border-color:#92400e;">Live</span>
        </div>
        <div class="bin-panel-inner">
          <div class="bin-alert">
            <div class="bin-alert-icon">🎯</div>
            <div class="bin-alert-body">
              <div class="bin-alert-title">Active BIN Sequence Attack Detected</div>
              <div class="bin-alert-sub">
                BIN prefix <strong>${escapeHtml(maskedBin)}</strong> — 
                <strong>${bin.topBinCount} cards</strong> attempted in the last hour.<br>
                This pattern indicates an organized card-testing operation.
              </div>
              <div class="bin-confirmed">✓ All attempts blocked by ChargeGuard</div>
            </div>
          </div>
        </div>
      </div>`;
    }

    // حالة هادئة
    return `<div class="bin-panel">
      <div class="tbl-header">
        <span class="tbl-title">🔬 BIN Intelligence</span>
        <span class="tbl-count" style="color:#22c55e;border-color:#166534;background:#052e16;">All Clear</span>
      </div>
      <div class="bin-panel-inner">
        <div class="bin-alert">
          <div class="bin-alert-icon">🛡️</div>
          <div class="bin-alert-body">
            <div class="bin-alert-title">No Active BIN Attacks</div>
            <div class="bin-alert-sub">
              No coordinated card-prefix attacks detected in the last hour.<br>
              ChargeGuard is actively monitoring all BIN sequences on your store.
            </div>
            <div class="bin-confirmed">✓ BIN sequence monitoring active</div>
          </div>
        </div>
      </div>
    </div>`;
  })()}

  <!-- ── Weekly Intelligence Digest ── -->
  ${(() => {
    const dominant = Object.entries(data.reasonBreakdown || {})
      .sort((a, b) => b[1] - a[1])[0];

    const dominantLabel = dominant ? ({
      card_testing: 'stolen card probes',
      velocity:     'rapid-fire attacks',
      blacklist:    'known threat actors',
      pattern:      'network fraud patterns',
    }[dominant[0]] ?? dominant[0]) : null;

    const todayIso = new Date().toISOString().slice(0, 10);
    const peakDay  = data.chartData
      .filter(d => d.date !== todayIso)
      .reduce((max, d) => d.count > max.count ? d : max, { date: '', count: 0 });

    const peakLabel = peakDay.count > 0
      ? new Intl.DateTimeFormat('en-US', { weekday: 'long', timeZone: 'UTC' })
          .format(new Date(peakDay.date))
      : null;

    const narrative = weekTotal === 0
      ? 'This week was completely quiet — no threats reached your checkout. ChargeGuard remained on standby, monitoring every transaction.'
      : weekTotal <= 5
      ? `A calm week with ${weekTotal} isolated attempt${weekTotal > 1 ? 's' : ''}, all blocked instantly. No patterns of concern detected.`
      : dominantLabel && peakLabel
      ? `This week saw ${weekTotal} blocked attempts, with peak activity on ${peakLabel}. The dominant threat type was ${dominantLabel}. Every attempt was stopped before reaching your payment gateway.`
      : `ChargeGuard blocked ${weekTotal} threats this week across ${Object.keys(data.reasonBreakdown || {}).length} distinct attack types. All attempts contained.`;

    const amtNum = parseFloat(data.amountProtected || '0');

    return `<div class="digest-wrap" style="padding:0;">
      <div class="tbl-header" style="background:transparent;border-bottom:1px solid rgba(59,130,246,.15);">
        <span class="tbl-title" style="color:#60a5fa;">📋 Weekly Intelligence Digest</span>
        <span class="tbl-count" style="color:#3b82f6;border-color:#1e3a5f;background:rgba(59,130,246,.08);">This Week</span>
      </div>
      <div style="padding:1rem 1.5rem 1.25rem;">
      <div class="digest-narrative">"${escapeHtml(narrative)}"</div>
      <div class="digest-stats">
        <div class="digest-stat">
          <div class="digest-stat-val">${weekTotal}</div>
          <div class="digest-stat-label">Threats Blocked</div>
        </div>
        <div class="digest-stat">
          <div class="digest-stat-val">${Object.keys(data.reasonBreakdown || {}).length}</div>
          <div class="digest-stat-label">Attack Types</div>
        </div>
        <div class="digest-stat">
          <div class="digest-stat-val">${amtNum > 0 ? fmtCurrency.format(amtNum) : '—'}</div>
          <div class="digest-stat-label">Total Protected</div>
        </div>
      </div>
      </div>
    </div>`;
  })()}

  <!-- ── Threat Origins ── -->
  ${(() => {
    const origins = data.threatOrigins || [];
    if (origins.length === 0) {
      if (data.totalBlocked === 0) return '';
      return `<div class="origins-wrap">
        <div class="tbl-header">
          <span class="tbl-title">🌍 Card Issuer Origins</span>
          <span class="tbl-count" style="color:var(--text-dim);">Building data</span>
        </div>
        <div style="padding:1.25rem 1.5rem;text-align:center;">
          <div style="font-size:.78rem;color:var(--text-dim);line-height:1.6;">
            Origin intelligence builds as more card BINs are analyzed.<br>
            <span style="color:var(--text-dim);font-size:.7rem;">Data appears after first BIN-linked attempt.</span>
          </div>
        </div>
      </div>`;
    }

    const maxCount = origins[0]?.count || 1;

    const countryNames = {
      US: 'United States', GB: 'United Kingdom', CN: 'China',
      RU: 'Russia', NG: 'Nigeria', BR: 'Brazil', IN: 'India',
      DE: 'Germany', FR: 'France', CA: 'Canada', AU: 'Australia',
      PK: 'Pakistan', ID: 'Indonesia', UA: 'Ukraine', TR: 'Turkey',
      MX: 'Mexico', IT: 'Italy', ES: 'Spain', NL: 'Netherlands',
      PL: 'Poland', RO: 'Romania', VN: 'Vietnam', PH: 'Philippines',
    };

    const countryFlag = (code) => {
      if (!code || code.length !== 2) return '🌐';
      try {
        return code.toUpperCase().replace(/./g,
          c => String.fromCodePoint(c.charCodeAt(0) + 127397));
      } catch { return '🌐'; }
    };

    const rows = origins.map(o => {
      const pct  = Math.round((o.count / maxCount) * 100);
      const name = countryNames[o.country] ?? o.country;
      const flag = countryFlag(o.country);
      return `
        <div class="origin-row">
          <div class="origin-flag">${flag}</div>
          <div class="origin-country">${escapeHtml(name)}</div>
          <div class="origin-bar-wrap">
            <div class="origin-bar" style="width:${pct}%"></div>
          </div>
          <div class="origin-count">${o.count}</div>
        </div>`;
    }).join('');

    return `<div class="origins-wrap">
      <div class="tbl-header">
        <span class="tbl-title">🌍 Card Issuer Origins</span>
        <span class="tbl-count">Top ${origins.length} sources</span>
      </div>
      <div class="origins-list">${rows}</div>
    </div>`;
  })()}

  <!-- ── Social Proof ── -->
  ${(() => {
    const total = data.totalTenants || 1;
    const blockedNet = data.totalBlocked || 0;
    const networkBadge = total >= 100
      ? `${total.toLocaleString('en-US')} merchants protected`
      : total >= 10
      ? `${total} merchants in network`
      : 'Growing merchant network';
    const socialText = blockedNet > 0
      ? `Your store is part of the <strong>ChargeGuard protection network</strong>.
         Every threat blocked on your store —
         <strong>${blockedNet.toLocaleString('en-US')} and counting</strong> —
         strengthens intelligence for all ${total.toLocaleString('en-US')} merchants in the network.`
      : `Your store just joined the <strong>ChargeGuard protection network</strong>
         alongside <strong>${total.toLocaleString('en-US')} active merchants</strong>.
         Threats detected across the network now protect your store automatically.`;
    return `<div class="social-proof">
      <div class="social-proof-icon">🌐</div>
      <div class="social-proof-text">${socialText}</div>
      <div class="social-proof-badge">✓ ${networkBadge}</div>
    </div>`;
  })()}

  <!-- ── Recent attempts table ── -->
  <div class="tbl-wrap">
    <div class="tbl-header">
      <span class="tbl-title">Recent Blocked Attempts</span>
      <span class="tbl-count">Last ${recentEight.length}</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Time (UTC)</th>
          <th>Card</th>
          <th>BIN</th>
          <th>Risk Score</th>
          <th>Reason</th>
          <th>Amount</th>
        </tr>
      </thead>
      <tbody>${recentRows}</tbody>
    </table>
  </div>
  <!-- ── Monthly Reports Archive ── -->
  ${await buildReportsArchiveSection(tenant.id, tenant.plan)}

  <!-- ── API Key Section ── -->
  <div class="tbl-wrap" style="margin-top:1.5rem;">
    <div class="tbl-header">
      <span class="tbl-title">🔑 API Key</span>
      <span class="tbl-count">Keep this secret</span>
    </div>
    <div style="padding:1.25rem 1.5rem;">
      <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:1rem;">
        <code id="apiKeyDisplay" style="font-family:'DM Mono',monospace;font-size:.8rem;color:var(--text-sub);background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:.5rem .875rem;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
          ••••••••••••••••••••••••••••••••••••••••••••
        </code>
        <button onclick="toggleKey()" id="toggleBtn" style="padding:.45rem .9rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text-sub);font-size:.75rem;cursor:pointer;">Show</button>
        <button onclick="copyKey()" style="padding:.45rem .9rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text-sub);font-size:.75rem;cursor:pointer;">Copy</button>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;">
        <span style="font-size:.72rem;color:var(--text-dim);">
          Last rotated: <strong style="color:var(--text-sub);">${tenant.keyRotatedAt ? new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(new Date(tenant.keyRotatedAt)) : 'Never'}</strong>
        </span>
        <button onclick="rotateKey()" id="rotateBtn" style="padding:.5rem 1.1rem;background:#dc2626;border:none;border-radius:6px;color:#fff;font-size:.78rem;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:.4rem;">
          ⟳ Rotate Key
        </button>
      </div>
      <div id="rotateMsg" style="display:none;margin-top:.75rem;padding:.6rem .9rem;border-radius:6px;font-size:.78rem;"></div>
    </div>
  </div>

  <script>
    // Plaintext API keys are never persisted after initial delivery — only apiKeyHash is stored
    // (OWASP ASVS V6.2.1 / NIST SP 800-63B §5.1.3). tenant.apiKey is intentionally not selected
    // or embedded here. _key only becomes populated client-side, in-memory, immediately after a
    // successful rotation response below, and is discarded on page reload.
    let _key = null;
    let _visible = false;

    // ── BIN Sequence Polling ──────────────────────────────────────────
    let _binPollingId   = null;
    let _binActiveTimer = null;
    let _binActiveSeconds = 0;

    const LAYER_NAMES = {
      0: 'Active Attack Wave',
      1: 'Rapid BIN Velocity Attack',
      2: 'Sequential Card Scan — Brute Force',
      3: 'Distributed Multi-Source Attack',
    };

    function updateBINPanel(data) {
      const panel = document.getElementById('cg-bin-seq-panel');
      if (!panel) return;

      const active = data.activeAlert;
      const stats  = data.liveStats || {};
      const pct    = stats.progressPercent || 0;
      const color  = stats.progressColor === 'red'    ? '#ef4444'
                   : stats.progressColor === 'yellow' ? '#f59e0b'
                   :                                    '#3b82f6';
      const border = stats.progressColor === 'red'    ? '#7f1d1d'
                   : stats.progressColor === 'yellow' ? '#713f12'
                   :                                    '#1e3a5f';
      const bg     = stats.progressColor === 'red'    ? '#1c0202'
                   : stats.progressColor === 'yellow' ? '#1c1202'
                   :                                    '#0a1628';

      // حالة: هجوم نشط
      if (active) {
        _binActiveSeconds = active.activeForSeconds || 0;
        clearInterval(_binActiveTimer);
        _binActiveTimer = setInterval(function() { _binActiveSeconds++; }, 1000);

        panel.innerHTML =
          '<div style="background:#1c0202;border:1px solid #ef4444;border-radius:var(--radius);padding:1.25rem 1.5rem;">' +
          '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.875rem;">' +
          '<span style="font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#ef4444;">🚨 BIN Sequence Attack — Active</span>' +
          '<span id="cg-bin-timer" style="font-size:.7rem;font-family:\'DM Mono\',monospace;color:#ef4444;background:#7f1d1d22;border:1px solid #7f1d1d;border-radius:20px;padding:.2rem .6rem;"></span>' +
          '</div>' +
          '<div style="font-size:.82rem;color:#fca5a5;line-height:1.6;margin-bottom:.875rem;">' +
          '<strong style="color:#fff;">BIN Prefix ' + escHtml(active.binPrefix) + 'xx</strong> — ' +
          (LAYER_NAMES[active.layer] || 'Unknown Attack') + '<br>' +
          '<strong>' + active.cardsCount + ' cards</strong> detected · ' +
          '+' + active.riskAddition + ' risk pts applied' +
          '</div>' +
          '<div style="display:inline-flex;align-items:center;gap:.3rem;font-size:.7rem;font-weight:600;color:#4ade80;background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.2);border-radius:20px;padding:.2rem .7rem;">✓ All attempts automatically blocked</div>' +
          '</div>';

        // تحديث الـ timer كل ثانية
        (function tickTimer() {
          const el = document.getElementById('cg-bin-timer');
          if (!el) return;
          const h = Math.floor(_binActiveSeconds / 3600);
          const m = Math.floor((_binActiveSeconds % 3600) / 60);
          const s = _binActiveSeconds % 60;
          el.textContent = (h > 0 ? h + 'h ' : '') +
            String(m).padStart(2,'0') + 'm ' +
            String(s).padStart(2,'0') + 's';
        })();
        return;
      }

      // حالة: تحت المراقبة
      if (stats.activePrefixes > 0) {
        clearInterval(_binActiveTimer);
        panel.innerHTML =
          '<div style="background:' + bg + ';border:1px solid ' + border + ';border-radius:var(--radius);padding:1.25rem 1.5rem;">' +
          '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem;">' +
          '<span style="font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:' + color + ';">⚠️ BIN Sequence — Under Watch</span>' +
          '<span style="font-size:.68rem;color:var(--text-dim);background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:.2rem .6rem;">' +
          stats.activePrefixes + ' active prefix' + (stats.activePrefixes !== 1 ? 'es' : '') + '</span>' +
          '</div>' +
          '<div style="background:var(--border2);border-radius:4px;height:6px;overflow:hidden;margin-bottom:.5rem;">' +
          '<div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:4px;transition:width .6s;"></div>' +
          '</div>' +
          '<div style="display:flex;justify-content:space-between;font-size:.65rem;color:var(--text-dim);">' +
          '<span>' + stats.totalActiveBINs + ' / ' + (stats.thresholdForAlert || 8) + ' BINs to alert threshold</span>' +
          '<span style="color:' + color + ';font-weight:600;">' + pct + '%</span>' +
          '</div></div>';
        return;
      }

      // حالة: هادئ — لا نُظهر شيئًا
      clearInterval(_binActiveTimer);
      panel.innerHTML = '';
    }

    function escHtml(str) {
      return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    async function fetchBINAlerts() {
      try {
        const res  = await fetch('/api/dashboard/bin-sequence-alerts', {
          headers: { 'X-Api-Key': _key }
        });
        const data = await res.json();
        if (data.success) {
          updateBINPanel(data);
          // Adaptive interval
          clearInterval(_binPollingId);
          const nextMs = (data.metadata?.nextRefreshSeconds || 30) * 1000;
          _binPollingId = setInterval(fetchBINAlerts, nextMs);
        }
      } catch(e) { /* silent fail — panel يبقى كما هو */ }
    }

    // Visibility API — إيقاف عند إخفاء التبويب
    document.addEventListener('visibilitychange', function() {
      if (document.hidden) {
        clearInterval(_binPollingId);
        clearInterval(_binActiveTimer);
      } else {
        fetchBINAlerts();
      }
    });

    // Cleanup عند مغادرة الصفحة
    window.addEventListener('beforeunload', function() {
      clearInterval(_binPollingId);
      clearInterval(_binActiveTimer);
    });

    // بدء الـ polling فورًا
    fetchBINAlerts();
    _binPollingId = setInterval(fetchBINAlerts, 30000);

    function toggleKey() {
      if (!_key) {
        showMsg('⚠️ For your security, keys are never stored in plaintext after delivery. Click "Rotate Key" to issue a new one.', '#f59e0b');
        return;
      }
      _visible = !_visible;
      document.getElementById('apiKeyDisplay').textContent = _visible ? _key : '••••••••••••••••••••••••••••••••••••••••••••';
      document.getElementById('toggleBtn').textContent = _visible ? 'Hide' : 'Show';
    }

    function copyKey() {
      if (!_key) {
        showMsg('⚠️ No key available to copy in this session. Click "Rotate Key" to issue a new one.', '#f59e0b');
        return;
      }
      navigator.clipboard.writeText(_key).then(() => showMsg('✅ Copied to clipboard!', '#16a34a'));
    }
    async function rotateKey() {
      if (!confirm('⚠️ Your current API key will be invalidated immediately.\\n\\nYou must update your plugin settings after rotation.\\n\\nContinue?')) return;
      const btn = document.getElementById('rotateBtn');
      btn.disabled = true;
      btn.textContent = 'Rotating...';
      try {
        const res = await fetch('/api/dashboard/rotate-key', {
          method: 'POST',
          headers: { 'X-Api-Key': _key }
        });
        const data = await res.json();
        if (res.ok) {
          showMsg('✅ ' + data.message, '#16a34a');
          _key = data.newApiKey;
          document.getElementById('apiKeyDisplay').textContent = data.newApiKey;
          _visible = true;
          document.getElementById('toggleBtn').textContent = 'Hide';
          btn.textContent = '⟳ Rotate Key';
          btn.disabled = false;
        } else {
          showMsg('❌ ' + (data.error || 'Failed'), '#dc2626');
          btn.textContent = '⟳ Rotate Key';
          btn.disabled = false;
        }
      } catch (e) {
        showMsg('❌ Network error', '#dc2626');
        btn.textContent = '⟳ Rotate Key';
        btn.disabled = false;
      }
    }

    function showMsg(text, color) {
      const el = document.getElementById('rotateMsg');
      el.textContent = text;
      el.style.background = color + '18';
      el.style.border = '1px solid ' + color + '44';
      el.style.color = color;
      el.style.display = 'block';
      setTimeout(() => el.style.display = 'none', 5000);
    }
  </script>


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

// ── monthly reports archive section ──────────────────────────────────────
async function buildReportsArchiveSection(tenantId, plan) {
  const isPro = plan !== 'early_access' && plan !== 'free';

  const reports = await prisma.monthlyReport.findMany({
    where:   { tenantId, status: 'ready' },
    orderBy: [{ reportYear: 'desc' }, { reportMonth: 'desc' }],
    take:    isPro ? 24 : 3,
    select: {
      id: true, reportMonth: true, reportYear: true,
      totalAttacks: true, totalProtected: true, totalFeesSaved: true,
    },
  });

  if (reports.length === 0) {
    return '';
  }

  const monthNames = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const fmtUsd = (n) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 0 });

  const rows = reports.map((r, i) => {
    const isLocked   = !isPro && i > 0;
    const monthLabel = `${monthNames[r.reportMonth]} ${r.reportYear}`;
    const isLatest   = i === 0;

    return `
      <div style="display:flex;align-items:center;gap:1rem;padding:.75rem 1.25rem;
                  border-bottom:1px solid var(--border2);
                  ${isLocked ? 'filter:blur(2px);pointer-events:none;user-select:none;' : ''}
                  transition:background .15s;"
           ${!isLocked ? 'onmouseover="this.style.background=\'rgba(255,255,255,.018)\'"' : ''}
           ${!isLocked ? 'onmouseout="this.style.background=\'transparent\'"' : ''}>

        <div style="width:80px;flex-shrink:0;">
          <div style="font-size:.82rem;font-weight:700;color:var(--text);">${monthLabel}</div>
          ${isLatest ? '<div style="font-size:.62rem;color:#60a5fa;font-weight:600;margin-top:.1rem;">latest</div>' : ''}
        </div>

        <div style="flex:1;display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;">
          <div>
            <div style="font-size:.6rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;">Attacks</div>
            <div style="font-size:.85rem;font-weight:700;color:var(--text);font-family:'DM Mono',monospace;">${r.totalAttacks.toLocaleString('en-US')}</div>
          </div>
          <div>
            <div style="font-size:.6rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;">Protected</div>
            <div style="font-size:.85rem;font-weight:700;color:#4ade80;font-family:'DM Mono',monospace;">${fmtUsd(r.totalProtected)}</div>
          </div>
          <div>
            <div style="font-size:.6rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em;">Fees Saved</div>
            <div style="font-size:.85rem;font-weight:700;color:#60a5fa;font-family:'DM Mono',monospace;">${fmtUsd(r.totalFeesSaved)}</div>
          </div>
        </div>

        ${!isLocked ? `
        <a href="/api/reports/monthly?month=${r.reportMonth}&year=${r.reportYear}"
           style="flex-shrink:0;display:inline-flex;align-items:center;gap:.35rem;
                  background:var(--surface2);border:1px solid var(--border);
                  color:var(--text-sub);font-size:.72rem;font-weight:600;
                  padding:.4rem .85rem;border-radius:6px;text-decoration:none;
                  transition:border-color .15s;"
           onmouseover="this.style.borderColor='#3b82f6'"
           onmouseout="this.style.borderColor='var(--border)'">
          ↓ PDF
        </a>` : ''}
      </div>`;
  });

  const upgradeOverlay = !isPro && reports.length > 1 ? `
    <div style="position:absolute;bottom:0;left:0;right:0;height:60%;
                background:linear-gradient(180deg,transparent,var(--surface) 60%);
                display:flex;align-items:flex-end;justify-content:center;
                padding-bottom:1rem;pointer-events:none;">
      <a href="mailto:support@chargeguard.io?subject=Upgrade to Pro"
         style="pointer-events:all;display:inline-flex;align-items:center;gap:.5rem;
                background:linear-gradient(135deg,#1d4ed8,#7c3aed);color:#fff;
                font-size:.78rem;font-weight:600;padding:.55rem 1.25rem;
                border-radius:20px;text-decoration:none;
                box-shadow:0 4px 16px rgba(59,130,246,.3);">
        🔓 Access full archive — Upgrade to Pro
      </a>
    </div>` : '';

  const totalHistoricalProtected = reports.reduce((s, r) => s + r.totalProtected, 0);
  const summaryBadge = totalHistoricalProtected > 0 ? `
    <div style="font-size:.72rem;color:#4ade80;font-weight:600;
                background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.2);
                border-radius:20px;padding:.2rem .7rem;">
      ${fmtUsd(totalHistoricalProtected)} protected total
    </div>` : '';

  return `
    <div class="tbl-wrap" style="margin-bottom:1.5rem;position:relative;">
      <div class="tbl-header">
        <span class="tbl-title">📋 Monthly Security Reports</span>
        <div style="display:flex;align-items:center;gap:.5rem;">
          ${summaryBadge}
          <span class="tbl-count">${reports.length} report${reports.length !== 1 ? 's' : ''}</span>
        </div>
      </div>
      ${rows.join('')}
      ${upgradeOverlay}
    </div>`;
}

// ── POST /api/dashboard/rotate-key ──────────────────────────────────────
// ── GET /api/dashboard/monthly-report-preview ──────────────────────────
router.get('/monthly-report-preview', rateLimit, authByApiKey, async (req, res) => {
  try {
    const latest = await prisma.monthlyReport.findFirst({
      where:   { tenantId: req.tenant.id, status: 'ready' },
      orderBy: [{ reportYear: 'desc' }, { reportMonth: 'desc' }],
      select: {
        reportMonth: true, reportYear: true,
        totalAttacks: true, totalProtected: true,
        totalFeesSaved: true, securityScore: true,
        topCountry: true, topReason: true,
        prevMonthAttacks: true,
      },
    });

    if (!latest) {
      return res.json({ available: false, message: 'First report generates on the 1st of next month.' });
    }

    const monthOverMonthPct = latest.prevMonthAttacks
      ? Math.round(((latest.totalAttacks - latest.prevMonthAttacks) / latest.prevMonthAttacks) * 100)
      : null;

    res.json({
      available: true,
      ...latest,
      monthOverMonthPct,
      downloadUrl: `/api/reports/monthly?month=${latest.reportMonth}&year=${latest.reportYear}`,
    });

  } catch (err) {
    console.error('[Dashboard] monthly-report-preview error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.post('/rotate-key', rateLimit, authByApiKey, async (req, res) => {
  try {
    const tenant = req.tenant;

    const RECENCY_WINDOW_MS = 15 * 60 * 1000;
    const tenantFull = await prisma.tenant.findUnique({
      where:  { id: tenant.id },
      select: { lastConnectVerifiedAt: true },
    });

    const lastVerified = tenantFull?.lastConnectVerifiedAt;
    if (!lastVerified || (Date.now() - new Date(lastVerified).getTime()) > RECENCY_WINDOW_MS) {
      return res.status(403).json({
        error: 'Recent verification required. Please use the "Connect" flow (check your email for a confirm link) within the last 15 minutes before rotating your key.',
        code: 'RECENT_VERIFICATION_REQUIRED'
      });
    }

    // منع التدوير المتكرر: 5 دقائق بين كل rotation
    if (tenant.keyRotatedAt) {
      const msSinceLastRotation = Date.now() - new Date(tenant.keyRotatedAt).getTime();
      const cooldownMs = 5 * 60 * 1000; // 5 دقائق
      if (msSinceLastRotation < cooldownMs) {
        const waitSecs = Math.ceil((cooldownMs - msSinceLastRotation) / 1000);
        return res.status(429).json({
          error: `Please wait ${Math.ceil(waitSecs / 60)} minute(s) before rotating again.`,
          retryAfter: waitSecs
        });
      }
    }

    // توليد مفتاح جديد آمن (256-bit CSPRNG)
    const crypto = require('crypto');
    const newApiKey = crypto.randomBytes(32).toString('base64url');
    const newApiKeyHash = hashApiKey(newApiKey);

    // Fetch current key identifiers to carry into previousApiKey/previousApiKeyHash for the
    // grace period — fetched narrowly, only at the moment it's needed (CWE-532 minimization)
    const currentTenant = await prisma.tenant.findUnique({
      where:  { id: tenant.id },
      select: { apiKeyHash: true, apiKey: true },
    });

    // Grace period — both old and new keys remain valid for this window,
    // matching Stripe/GitHub/Twilio rotation patterns (NIST SP 800-63B
    // authenticator lifecycle guidance: credential replacement should not
    // require an atomic, unbuffered swap). Configurable via env var,
    // defaults to 24 hours.
    const GRACE_PERIOD_HOURS = parseInt(process.env.KEY_ROTATION_GRACE_HOURS || '24', 10);
    const GRACE_PERIOD_MS = GRACE_PERIOD_HOURS * 60 * 60 * 1000;
    const previousApiKeyExpiresAt = new Date(Date.now() + GRACE_PERIOD_MS);

    // Atomic update في DB — only the new key's hash is persisted going forward (OWASP ASVS V6.2.1).
    // previousApiKey/previousApiKeyHash are both carried forward for the grace period to support
    // any not-yet-migrated lookup path; previousApiKey will be dropped once backfill is confirmed complete.
    await prisma.tenant.update({
      where: { id: tenant.id },
      data: {
        previousApiKey: currentTenant.apiKey,
        previousApiKeyHash: currentTenant.apiKeyHash,
        previousApiKeyExpiresAt,
        apiKey: null,
        apiKeyHash: newApiKeyHash,
        keyRotatedAt: new Date()
      }
    });

    // إرسال إيميل (fire-and-forget)
    const { sendRotatedKeyEmail } = require('../lib/email');
    sendRotatedKeyEmail(tenant.email, newApiKey).catch(err => {
      console.error('[rotate-key] Email failed:', err.message);
    });

    return res.json({
      success: true,
      newApiKey,
      graceExpiresAt: previousApiKeyExpiresAt.toISOString(),
      message: `API key rotated successfully. Your old key remains valid until ${previousApiKeyExpiresAt.toUTCString()} — update your plugin settings before then to avoid a protection gap.`
    });

  } catch (err) {
    console.error('[rotate-key] Error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
// ────────────────────────────────────────────────────────────────────────

// ── GET /api/dashboard/bin-sequence-alerts ────────────────────────────────
router.get('/bin-sequence-alerts', rateLimit, authByApiKey, async (req, res) => {
  try {
    const tenantId = req.tenant.id;
    const now      = Date.now();

    // ── جلب البيانات بالتوازي ─────────────────────────────────────────────
    const [activeAlert, recentAlerts, liveStats] = await Promise.all([

      // التنبيه النشط — آخر سجل active في الساعة الأخيرة
      prisma.binSequenceAlert.findFirst({
        where: {
          tenantId,
          status:     'active',
          detectedAt: { gte: new Date(now - 60 * 60 * 1000) },
        },
        orderBy: { detectedAt: 'desc' },
      }),

      // آخر 10 تنبيهات بغض النظر عن الحالة
      prisma.binSequenceAlert.findMany({
        where:   { tenantId },
        orderBy: { detectedAt: 'desc' },
        take:    10,
        select: {
          id:          true,
          binPrefix:   true,
          layer:       true,
          reason:      true,
          cardsCount:  true,
          status:      true,
          riskAddition: true,
          detectedAt:  true,
          resolvedAt:  true,
        },
      }),

      // إحصائيات حية من الـ in-memory store
      Promise.resolve(getBINStats()),
    ]);

    // ── حساب activeForSeconds ─────────────────────────────────────────────
    const activeAlertFormatted = activeAlert ? {
      id:            activeAlert.id,
      binPrefix:     activeAlert.binPrefix,
      layer:         activeAlert.layer,
      layerName:     LAYER_NAMES[activeAlert.layer] ?? 'Unknown Attack',
      cardsCount:    activeAlert.cardsCount,
      entitiesCount: activeAlert.entitiesCount,
      riskAddition:  activeAlert.riskAddition,
      status:        activeAlert.status,
      detectedAt:    activeAlert.detectedAt,
      activeForSeconds: Math.floor((now - new Date(activeAlert.detectedAt).getTime()) / 1000),
      isBlocked:     true,
    } : null;

    // ── حساب Progress ─────────────────────────────────────────────────────
    const threshold       = THRESHOLDS.UNIQUE_BINS_PER_PREFIX;
    const progressPercent = Math.min(
      Math.round((liveStats.totalActiveBINs / threshold) * 100),
      100
    );
    const progressColor   = progressPercent < 50 ? 'blue'
                          : progressPercent < 75 ? 'yellow'
                          : 'red';

    res.json({
      success: true,
      activeAlert: activeAlertFormatted,
      liveStats: {
        activePrefixes:   liveStats.activePrefixes,
        blockedPrefixes:  liveStats.blockedPrefixes,
        totalActiveBINs:  liveStats.totalActiveBINs,
        thresholdForAlert: threshold,
        progressPercent,
        progressColor,
      },
      recentAlerts,
      metadata: {
        lastCheckedAt:      new Date().toISOString(),
        nextRefreshSeconds: activeAlertFormatted ? 15 : 30,
      },
    });

  } catch (err) {
    console.error('[Dashboard] bin-sequence-alerts error:', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ── Layer Names ───────────────────────────────────────────────────────────
const LAYER_NAMES = {
  0: 'Active Attack Wave — Blocked Prefix',
  1: 'Rapid BIN Velocity Attack',
  2: 'Sequential Card Scan — Brute Force',
  3: 'Distributed Multi-Source Attack',
};

module.exports = router;
