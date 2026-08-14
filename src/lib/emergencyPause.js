'use strict';

const db = require('./db');
const logger = require('./logger');

const DEFAULT_DURATION_MINUTES = parseInt(process.env.EMERGENCY_PAUSE_DEFAULT_MINUTES, 10) || 30;
const MAX_DURATION_MINUTES = 24 * 60; // hard ceiling — a typo like "3000" minutes shouldn't pause for two days

// ── In-memory cache ──────────────────────────────────────────────────────
// This is the ONLY thing /evaluate reads on its hot path — no DB round
// trip. The DB row is the durable source of truth (survives restarts), but
// this Map is what makes the check work "even if the database is under
// heavy load," per the requirement.
let globalPause = null; // { id, expiresAt, activatedById } | null
const tenantPauses = new Map(); // tenantId -> { id, expiresAt, activatedById }
const timers = new Map(); // pause id -> Timeout

const scheduleAutoExpiry = (pauseId, tenantId, expiresAt) => {
  const ms = expiresAt.getTime() - Date.now();
  // Best-effort — the lazy expiresAt check in isPaused() is the real
  // guarantee (covers restarts, clock drift, missed timers). MAX_DURATION
  // caps us well under setTimeout's ~24.8-day overflow limit.
  const timer = setTimeout(async () => {
    timers.delete(pauseId);
    if (tenantId) {
      if (tenantPauses.get(tenantId)?.id === pauseId) tenantPauses.delete(tenantId);
    } else if (globalPause?.id === pauseId) {
      globalPause = null;
    }
    try {
      await db.emergencyPause.updateMany({
        where: { id: pauseId, isActive: true },
        data: { isActive: false, deactivatedAt: new Date(), deactivatedReason: 'auto_expired' },
      });
      logger.warn({ module: 'emergencyPause', pauseId, tenantId: tenantId || 'GLOBAL' }, 'Emergency pause auto-expired');
    } catch (err) {
      logger.error({ module: 'emergencyPause', pauseId, error: err.message }, 'Failed to persist auto-expiry');
    }
  }, Math.max(ms, 0));
  timer.unref();
  timers.set(pauseId, timer);
};

// ── Startup hydration ────────────────────────────────────────────────────
// Call once at process boot. Restores any still-active, unexpired pause
// rows from the DB into memory — this is what makes the pause durable
// across restarts/deploys.
async function loadActivePauses() {
  try {
    const rows = await db.emergencyPause.findMany({
      where: { isActive: true, expiresAt: { gt: new Date() } },
    });
    for (const row of rows) {
      const entry = { id: row.id, expiresAt: row.expiresAt, activatedById: row.activatedById };
      if (row.tenantId) tenantPauses.set(row.tenantId, entry);
      else globalPause = entry;
      scheduleAutoExpiry(row.id, row.tenantId, row.expiresAt);
    }
    if (rows.length) {
      logger.warn({ module: 'emergencyPause', count: rows.length }, 'Restored active emergency pause(s) from DB on startup');
    }
  } catch (err) {
    logger.error({ module: 'emergencyPause', error: err.message }, 'Failed to load active pauses on startup — starting with no pause active');
  }
}

// ── Hot-path check — used by /evaluate ───────────────────────────────────
// Pure in-memory, O(1), no DB access. Lazy-expires so an already-expired
// entry (missed timer, restart, clock skew) never keeps approving orders
// past its window.
function isPaused(tenantId) {
  const now = Date.now();
  if (globalPause && globalPause.expiresAt.getTime() > now) {
    return { paused: true, scope: 'global', expiresAt: globalPause.expiresAt };
  }
  const tenantEntry = tenantId ? tenantPauses.get(tenantId) : null;
  if (tenantEntry && tenantEntry.expiresAt.getTime() > now) {
    return { paused: true, scope: 'tenant', expiresAt: tenantEntry.expiresAt };
  }
  return { paused: false };
}

// ── Activation / deactivation ─────────────────────────────────────────────
async function activatePause({ tenantId = null, durationMinutes, activatedById = null }) {
  let minutes = parseInt(durationMinutes, 10);
  if (!Number.isFinite(minutes) || minutes <= 0) minutes = DEFAULT_DURATION_MINUTES;
  if (minutes > MAX_DURATION_MINUTES) minutes = MAX_DURATION_MINUTES;

  const expiresAt = new Date(Date.now() + minutes * 60 * 1000);

  // Supersede any existing active pause at this same scope first, so we
  // never accumulate overlapping "active" rows or leak their timers.
  await deactivatePause({ tenantId, deactivatedById: activatedById, reason: 'superseded', silent: true });

  const row = await db.emergencyPause.create({
    data: { tenantId, isActive: true, expiresAt, activatedById },
  });

  const entry = { id: row.id, expiresAt, activatedById };
  if (tenantId) tenantPauses.set(tenantId, entry);
  else globalPause = entry;

  scheduleAutoExpiry(row.id, tenantId, expiresAt);

  logger.warn({ module: 'emergencyPause', tenantId: tenantId || 'GLOBAL', minutes, activatedById }, 'Emergency pause ACTIVATED');
  return row;
}

async function deactivatePause({ tenantId = null, deactivatedById = null, reason = 'manual', silent = false } = {}) {
  // [Memory/DB divergence fix] الـ DB write بقى الأول دلوقتي — لو فشل، الدالة
  // بترمي exception قبل ما تلمس الذاكرة خالص، فمفيش أي لحظة الذاكرة بتقول
  // "مفيش pause" والـ DB لسه بيقول "فيه pause فعّال". قبل الفيكس، الترتيب
  // كان معكوس: الذاكرة بتتفضّى الأول، فلو الـ updateMany فشل، الصف في الـ
  // DB يفضل isActive:true بينما الذاكرة بتفتكر إنه اتشال — وده كان بيرجع
  // يظهر تاني بعد أي restart عن طريق loadActivePauses() (اللي بتحمّل أي صف
  // isActive:true ولسه مش منتهي). activatePause() بينادي الدالة دي (silent)
  // قبل ما يعمل create لصف جديد بدون try/catch — فلو فشلت هنا، الفيكس ده
  // بيضمن إن activatePause كمان تفشل بنظافة بدل ما تسيب حالة متضاربة.
  const result = await db.emergencyPause.updateMany({
    where: { tenantId: tenantId ?? null, isActive: true },
    data: { isActive: false, deactivatedAt: new Date(), deactivatedReason: reason },
  });

  const timerId = tenantId ? tenantPauses.get(tenantId)?.id : globalPause?.id;
  if (timerId && timers.has(timerId)) {
    clearTimeout(timers.get(timerId));
    timers.delete(timerId);
  }
  if (tenantId) tenantPauses.delete(tenantId);
  else globalPause = null;

  if (!silent) {
    logger.warn({ module: 'emergencyPause', tenantId: tenantId || 'GLOBAL', deactivatedById, reason }, 'Emergency pause DEACTIVATED');
  }
  return result.count > 0;
}

// ── Dashboard status ──────────────────────────────────────────────────────
function getStatus(tenantId = null) {
  const now = Date.now();
  const global = globalPause && globalPause.expiresAt.getTime() > now ? globalPause : null;
  const tenantEntry = tenantId ? tenantPauses.get(tenantId) : null;
  const tenant = tenantEntry && tenantEntry.expiresAt.getTime() > now ? tenantEntry : null;
  return { global, tenant };
}

function getAllActiveTenantPauses() {
  const now = Date.now();
  const out = new Map();
  for (const [tenantId, entry] of tenantPauses.entries()) {
    if (entry.expiresAt.getTime() > now) out.set(tenantId, entry);
  }
  return out;
}

module.exports = {
  loadActivePauses,
  isPaused,
  activatePause,
  deactivatePause,
  getStatus,
  getAllActiveTenantPauses,
  DEFAULT_DURATION_MINUTES,
  MAX_DURATION_MINUTES,
};