module.exports = {
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/tests/setup/loadEnv.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup/resetRateLimits.js'],
  // DB-backed suites assume exclusive use of one test database (deleteMany in
  // beforeEach, shared limiters). Parallel workers made results non-deterministic.
  maxWorkers: 1,
  testTimeout: 15000,
};