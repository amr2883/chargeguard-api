require('dotenv').config();
const { runFastCleanup } = require('./lib/retention');
const db = require('./lib/db');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const prometheus = require('./lib/prometheus');
const logger = require('./lib/logger');
const { safeErrorPayload } = require('./lib/errorResponse');

const app = express();
app.set('trust proxy', true);

// TEMPORARY — remove after test
app.get('/ping', (req, res) => res.send('pong'));

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
app.use('/api/payments/paypal-webhook', express.raw({ type: 'application/json' }));
app.use('/api/risk/evaluate', express.raw({ type: 'application/json' }));
app.use('/api/risk/feedback', express.raw({ type: 'application/json' }));
app.use('/api/risk/blacklist', express.raw({ type: 'application/json' }));
app.use('/api/risk/blacklist/:id', express.raw({ type: 'application/json' }));
app.use('/api/risk/whitelist', express.raw({ type: 'application/json' }));
app.use('/api/risk/whitelist/:id', express.raw({ type: 'application/json' }));
app.use('/api/risk/check-device', express.raw({ type: 'application/json' }));
app.use('/api/risk/enrich', express.raw({ type: 'application/json' }));
app.use('/api/risk/device-token', express.raw({ type: 'application/json' }));
app.use('/api/risk/cloudflare-ranges', express.raw({ type: 'application/json' }));
app.use('/api/settings/webhook', express.raw({ type: 'application/json' }));
app.use('/api/settings/webhook/test', express.raw({ type: 'application/json' }));
app.use('/api/risk/reconcile', express.raw({ type: 'application/json' }));
app.use('/api/settings/country-overrides', express.raw({ type: 'application/json' }));
app.use('/api/stores', express.raw({ type: 'application/json' }));
app.use('/api/stores/:id', express.raw({ type: 'application/json' }));
app.use('/api/auth/self-test', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(morgan('dev', {
  skip: (req) => req.skipMorgan === true,
}));

const path = require('path');
const riskRoutes      = require('./routes/risk');
const authRoutes      = require('./routes/auth');
const adminRoutes     = require('./routes/admin');
const dashboardRoutes = require('./routes/dashboard');
const settingsRoutes  = require('./routes/settings');
const paymentsRoutes  = require('./routes/payments');
// const updatesRoutes   = require('./routes/updates');
app.use('/api/risk',      riskRoutes);
app.use('/api/auth',      authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/settings',  settingsRoutes);
app.use('/api/payments',  paymentsRoutes);
app.use('/api/stores',    require('./routes/stores'));
// app.use('/api/updates',   updatesRoutes);
// Morgan ����� �� /admin ���� ����� ��� secret �� �����
app.use('/admin', (req, res, next) => {
  req.skipMorgan = true;
  next();
}, adminRoutes);

app.use(express.static(path.join(__dirname, 'public')));
// ?? Global error handler ? MUST be after all routes ??????????
app.use((err, req, res, next) => {
  if (req.originalUrl === '/api/risk/woocommerce-webhook') {
    // Unchanged: forwarded to Express's built-in final handler. This path
    // only fires for errors thrown before that route's own try/catch could
    // run (e.g. a raw-body-parsing failure upstream) — Express's default
    // handler still responds with a 5xx status, which is all the plugin's
    // circuit breaker (class-api-client.php) actually inspects.
    return next(err);
  }
  // Full detail (message + stack) goes to the structured logger only —
  // never to the client. safeErrorPayload() returns a generic
  // { error: 'Internal server error' } in production, and only reveals
  // err.message/err.stack when NODE_ENV === 'development' or
  // DEBUG_ERRORS=true (see lib/errorResponse.js).
  logger.error({ module: 'app', path: req.originalUrl, error: err.message, stack: err.stack }, 'Global error handler caught an unhandled error');
  res.status(500).json(safeErrorPayload(err));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ChargeGuard WooCommerce Backend' });
});
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.registry.contentType);
  res.end(await prometheus.registry.metrics());
});

// ============================================================
//  ???? GET ?????? ??????? ???????? ?????? ?????? ????????
// ============================================================
app.get('/api/retention-config', (req, res) => {
  const { RETENTION } = require('./lib/retention');
  res.json({ success: true, retention: RETENTION });
});

app.get('/api/cleanup-now', async (req, res) => {
  console.log(`[${new Date().toISOString()}] ? External ping ? running fast cleanup...`);
  try {
    await runFastCleanup(db);
    res.json({ success: true });
  } catch (err) {
    console.error(`[${new Date().toISOString()}] ? Cleanup failed:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

module.exports = app;
