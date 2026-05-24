require('dotenv').config();
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
  console.warn('⚠️ Swagger UI not available:', e.message);
}
app.use('/api/risk/woocommerce-webhook', express.raw({ type: '*/*' }));
app.use(express.json());
app.use(morgan('dev'));
app.use((err, req, res, next) => {
  if (req.originalUrl === '/api/risk/woocommerce-webhook') {
    return next(err);
  }
  console.error('🚨 Global error handler caught:', err.stack || err.message || err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

const riskRoutes = require('./routes/risk');
const authRoutes = require('./routes/auth');
app.use('/api/risk', riskRoutes);
app.use('/api/auth', authRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ChargeGuard WooCommerce Backend' });
});
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.registry.contentType);
  res.end(await prometheus.registry.metrics());
});

// ============================================================
//  نقطة GET لتنظيف الطلبات المحظورة وإبقاء الخادم مستيقظًا
// ============================================================
app.get('/api/cleanup-now', async (req, res) => {
  console.log(`[${new Date().toISOString()}] ⏰ External ping — running cleanup...`);
  try {
    const { PrismaClient } = require('@prisma/client');
    const prisma = new PrismaClient();
    const deleted = await prisma.order.deleteMany({ where: { decision: 'block' } });
    await prisma.$disconnect();
    console.log(`[${new Date().toISOString()}] ✅ Cleanup completed — cleanedCount: ${deleted.count}`);
    res.json({ success: true, cleanedCount: deleted.count });
  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Cleanup failed:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  Auto-Cleanup Cron Job (Internal)
// ============================================================
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

async function runAutoCleanup() {
  const startedAt = new Date().toISOString();
  console.log(`[${startedAt}] ⏰ Auto-cleanup started...`);
  try {
    const { PrismaClient } = require('@prisma/client');
    const prisma = new PrismaClient();
    const deleted = await prisma.order.deleteMany({ where: { decision: 'block' } });
    await prisma.$disconnect();
    console.log(`[${new Date().toISOString()}] ✅ Auto-cleanup completed — cleanedCount: ${deleted.count}`);
  } catch (err) {
    console.error(`[${new Date().toISOString()}] ❌ Auto-cleanup failed:`, err.message);
  }
}

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  setTimeout(() => {
    console.log(`[${new Date().toISOString()}] 🔄 Internal cleanup scheduler started (every 10 min)`);
    setInterval(runAutoCleanup, CLEANUP_INTERVAL_MS);
  }, 30 * 1000);
});
