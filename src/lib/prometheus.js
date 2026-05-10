// src/lib/prometheus.js
const client = require('prom-client');
const logger = require('./logger');

// Enable default metrics (Node.js performance)
client.collectDefaultMetrics({ timeout: 5000 });

// Custom metrics
const httpRequestDuration = new client.Histogram({
  name: 'chargeguard_http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
});

const httpRequestsTotal = new client.Counter({
  name: 'chargeguard_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

const evaluateDecisions = new client.Counter({
  name: 'chargeguard_evaluate_decisions_total',
  help: 'Total number of evaluate decisions',
  labelNames: ['decision'] // approve, review, block
});

const evaluateDuration = new client.Histogram({
  name: 'chargeguard_evaluate_duration_ms',
  help: 'Duration of evaluate endpoint in ms',
  buckets: [10, 25, 50, 100, 250, 500, 1000, 2000, 5000]
});

const blacklistHits = new client.Counter({
  name: 'chargeguard_blacklist_hits_total',
  help: 'Total number of blacklist hits',
  labelNames: ['type'] // EMAIL, IP, DEVICE_FINGERPRINT
});

const idempotencyHits = new client.Counter({
  name: 'chargeguard_idempotency_hits_total',
  help: 'Total number of idempotent requests (cached responses)'
});

// External API metrics
const ipIntelRequests = new client.Counter({
  name: 'chargeguard_ip_intel_requests_total',
  help: 'Total IP intelligence requests',
  labelNames: ['source', 'status'] // source: cache, api, timeout, skipped; status: success, failure
});

const emailIntelRequests = new client.Counter({
  name: 'chargeguard_email_intel_requests_total',
  help: 'Total email intelligence requests',
  labelNames: ['source', 'status']
});

const binIntelRequests = new client.Counter({
  name: 'chargeguard_bin_intel_requests_total',
  help: 'Total BIN intelligence requests',
  labelNames: ['source', 'status']
});

// Function to record evaluate decision
function recordEvaluateDecision(decision) {
  evaluateDecisions.labels(decision).inc();
}

// Function to record evaluate duration
function recordEvaluateDuration(durationMs) {
  evaluateDuration.observe(durationMs);
}

// Function to record idempotency hit
function recordIdempotencyHit() {
  idempotencyHits.inc();
}

// Function to record blacklist hit
function recordBlacklistHit(type) {
  blacklistHits.labels(type).inc();
}

// Function to record IP intel request
function recordIPIntel(source, status = 'success') {
  ipIntelRequests.labels(source, status).inc();
}

// Function to record Email intel request
function recordEmailIntel(source, status = 'success') {
  emailIntelRequests.labels(source, status).inc();
}

// Function to record BIN intel request
function recordBINIntel(source, status = 'success') {
  binIntelRequests.labels(source, status).inc();
}

// Middleware to record HTTP metrics (to be used in app.js)
const httpMetricsMiddleware = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const route = req.route ? req.route.path : req.path;
    httpRequestDuration.labels(req.method, route, res.statusCode).observe(duration);
    httpRequestsTotal.labels(req.method, route, res.statusCode).inc();
  });
  next();
};

module.exports = {
  httpMetricsMiddleware,
  recordEvaluateDecision,
  recordEvaluateDuration,
  recordIdempotencyHit,
  recordBlacklistHit,
  recordIPIntel,
  recordEmailIntel,
  recordBINIntel,
  // Export metrics for health check or manual inspection if needed
  registry: client.register,
};