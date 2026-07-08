module.exports = {
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/tests/setup/loadEnv.js'],
  setupFilesAfterEnv: ['<rootDir>/tests/setup/resetRateLimits.js'],
  testTimeout: 15000,
};