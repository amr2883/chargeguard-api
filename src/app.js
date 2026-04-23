require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const prometheus = require('./lib/prometheus');

const app = express();
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
// Custom middleware: capture raw body and skip JSON parsing for webhook
app.use((req, res, next) => {
  let chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    req.rawBody = Buffer.concat(chunks);
    // Skip JSON parsing for WooCommerce webhook endpoint
    if (req.originalUrl === '/api/risk/woocommerce-webhook') {
      req.body = null;
      return next();
    }
    try {
      req.body = JSON.parse(req.rawBody.toString());
    } catch (e) {
      req.body = null;
    }
    next();
  });
});
app.use(morgan('dev'));
// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Global error handler caught:', err.stack || err.message || err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});


// Routes
const riskRoutes = require('./routes/risk');
app.use('/api/risk', riskRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ChargeGuard WooCommerce Backend' });
});
// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.registry.contentType);
  res.end(await prometheus.registry.metrics());
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
