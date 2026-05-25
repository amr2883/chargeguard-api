require('dotenv').config();
const { runFastCleanup, runDailyRetention } = require('./lib/retention');
const { startAttackAlertScheduler } = require('./lib/attackAlertScheduler');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const prometheus = require('./lib/prometheus');

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(helmet());
app.use(cors());
app.use(prometheus.httpMetricsMiddleware);
let swaggerUi, swaggerSpec;
try {
  swaggerUi = require('swagger-ui-express');
  swaggerSpec = require('./swagger');
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });
} catch (e) {
  console.warn('?? Swagger UI not available:', e.message);
}
app.use('/api/risk/woocommerce-webhook', express.raw({ type: '*/*' }));
app.use('/api/risk/blocked-attempt', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(morgan('dev', {
  skip: (req) => req.skipMorgan === true,
}));

const riskRoutes      = require('./routes/risk');
const authRoutes      = require('./routes/auth');
const adminRoutes     = require('./routes/admin');
const dashboardRoutes = require('./routes/dashboard');
app.use('/api/risk',  riskRoutes);
app.use('/api/auth',  authRoutes);
app.use('/api/dashboard', dashboardRoutes);
// Morgan ����� �� /admin ���� ����� ��� secret �� �����
app.use('/admin', (req, res, next) => {
  req.skipMorgan = true;
  next();
}, adminRoutes);

// ?? Global error handler � MUST be after all routes ??????????
app.use((err, req, res, next) => {
  if (req.originalUrl === '/api/risk/woocommerce-webhook') {
    return next(err);
  }
  console.error('?? Global error handler caught:', err.stack || err.message || err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ChargeGuard WooCommerce Backend' });
});
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.registry.contentType);
  res.end(await prometheus.registry.metrics());
});

// ============================================================
//  ���� GET ������ ������� �������� ������ ������ ��������
// ============================================================
app.get('/api/retention-config', (req, res) => {
  const { RETENTION } = require('./lib/retention');
  res.json({ success: true, retention: RETENTION });
});

app.get('/api/cleanup-now', async (req, res) => {
  console.log(`[${new Date().toISOString()}] ? External ping � running fast cleanup...`);
  try {
    await runFastCleanup(prismaForCleanup);
    res.json({ success: true });
  } catch (err) {
    console.error(`[${new Date().toISOString()}] ? Cleanup failed:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  Cleanup Intervals
// ============================================================
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const DAILY_RETENTION_MS  = 24 * 60 * 60 * 1000;

// prisma ����� �� FastCleanup ��� (���� ������� ��� ��� ������)
const { PrismaClient } = require('@prisma/client');
const prismaForCleanup = new PrismaClient();

app.listen(PORT, () => {
  console.log(`?? Server running on http://localhost:${PORT}`);

  // ?? 1) Fast cleanup (every 10 min) � blocked orders, expired blacklist, stale pending
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] ?? Fast cleanup scheduler started (every 10 min)`);
    setInterval(() => runFastCleanup(prismaForCleanup), CLEANUP_INTERVAL_MS);
  }, 30 * 1000);

  // ?? 2) Daily retention (every 24h) � full data retention policy
  setTimeout(() => {
    const { RETENTION } = require('./lib/retention');
    console.log(`[${new Date().toISOString()}] ???  Daily retention scheduler started (every 24h)`);
    console.log(`[${new Date().toISOString()}] ?? Retention config (days):`, RETENTION);
    runDailyRetention();
    setInterval(runDailyRetention, DAILY_RETENTION_MS);
  }, 5 * 60 * 1000); // ��� 5 ����� �� ��� ������ (���� ������ ��� ���������)

  // ?? 3) Keep-alive self-ping (every 14 min) ????????????????????
  // Render Free tier ���� ��� 15 ����� �� ���� HTTP requests ������.
  // ��� ��� ping ���� request ����� �� ������ ����� ��� ������
  // ��� ������ Render �� activity ����� ��� cold start.
  // �� ������ �� ����� ������ � http/https ������� ���.
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
        console.warn(`[${new Date().toISOString()}] ?? Keep-alive ping timeout � destroying request`);
        req.destroy();
      });
    };

    setInterval(selfPing, KEEP_ALIVE_MS);
    console.log(`[${new Date().toISOString()}] ?? Keep-alive started � pinging ${RENDER_URL}/health every 14 min`);
  }, 60 * 1000);
    // 🚨 4) Attack Alert Scheduler (every 2 min)
  startAttackAlertScheduler(prismaForCleanup);
});
