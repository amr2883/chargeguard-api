module.exports = {
  testEnvironment: 'node',
  // Turnstile siteverify is answered locally (tests/setup/mockTurnstile.js);
  // set TURNSTILE_REAL=1 to hit Cloudflare for real.
  setupFiles: ['<rootDir>/tests/setup/loadEnv.js', '<rootDir>/tests/setup/mockTurnstile.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup/resetRateLimits.js'],
  // DB-backed suites assume exclusive use of one test database (deleteMany in
  // beforeEach, shared limiters). Parallel workers made results non-deterministic.
  maxWorkers: 1,
  testTimeout: 15000,
};