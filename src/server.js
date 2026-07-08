require('dotenv').config();

const app = require('./app');
const { PrismaClient } = require('@prisma/client');

const { runFastCleanup, runDailyRetention } = require('./lib/retention');
const { startAttackAlertScheduler } = require('./lib/attackAlertScheduler');
const { startWeeklySummaryScheduler } = require('./jobs/weeklySummaryScheduler');
const { startMonthlyReportScheduler } = require('./jobs/monthlyReportScheduler');
const { startPaypalWeeklyReportScheduler } = require('./jobs/paypalWeeklyReportScheduler');
const { startSubscriptionScheduler } = require('./jobs/subscriptionScheduler');

const PORT = process.env.PORT || 3000;
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const DAILY_RETENTION_MS = 24 * 60 * 60 * 1000;

const prismaForCleanup = new PrismaClient();
app.listen(PORT, () => {
  console.log(`?? Server running on http://localhost:${PORT}`);

  // ?? 1) Fast cleanup (every 10 min) ? blocked orders, expired blacklist, stale pending
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] ?? Fast cleanup scheduler started (every 10 min)`);
    setInterval(() => runFastCleanup(prismaForCleanup), CLEANUP_INTERVAL_MS);
  }, 30 * 1000);

  // ?? 2) Daily retention (every 24h) ? full data retention policy
  setTimeout(() => {
    const { RETENTION } = require('./lib/retention');
    console.log(`[${new Date().toISOString()}] ???  Daily retention scheduler started (every 24h)`);
    console.log(`[${new Date().toISOString()}] ?? Retention config (days):`, RETENTION);
    runDailyRetention();
    setInterval(runDailyRetention, DAILY_RETENTION_MS);
  }, 5 * 60 * 1000); // ??? 5 ????? ?? ??? ?????? (???? ?????? ??? ???????????)

  // ?? 3) Keep-alive self-ping (every 14 min) ????????????????????
  const KEEP_ALIVE_MS = 14 * 60 * 1000;
  const RENDER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

  setTimeout(() => {
    const httpModule = RENDER_URL.startsWith('https') ? require('https') : require('http');

    const selfPing = () => {
      const targetUrl = `${RENDER_URL}/health`;
      const req = httpModule.get(targetUrl, (res) => {
        console.log(`[${new Date().toISOString()}] ?? Keep-alive ping ? ${res.statusCode} OK`);
        res.resume();
      });
      req.on('error', (err) => {
        console.warn(`[${new Date().toISOString()}] ?? Keep-alive ping failed: ${err.message}`);
      });
      req.setTimeout(10000, () => {
        console.warn(`[${new Date().toISOString()}] ?? Keep-alive ping timeout ? destroying request`);
        req.destroy();
      });
    };

    setInterval(selfPing, KEEP_ALIVE_MS);
    console.log(`[${new Date().toISOString()}] ?? Keep-alive started ? pinging ${RENDER_URL}/health every 14 min`);
  }, 60 * 1000);

  // ?? 4) Attack Alert Scheduler (every 2 min)
  startAttackAlertScheduler(prismaForCleanup);

  // ?? 5) Weekly Summary Scheduler (checks hourly, sends Sundays 09:xx UTC)
  startWeeklySummaryScheduler(prismaForCleanup);

  // ?? 6) Monthly Report Scheduler (checks hourly, runs on 1st of month 10:xx UTC)
  startMonthlyReportScheduler(prismaForCleanup);

  // ??? 7) PayPal Weekly Shield Scheduler (checks hourly, sends Sundays 09:30 UTC)
  startPaypalWeeklyReportScheduler(prismaForCleanup);

  // ?? 8) Subscription Lifecycle Scheduler (hourly)
  startSubscriptionScheduler(prismaForCleanup);
});