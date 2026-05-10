module.exports = {
  testMatch: ['<rootDir>/src/__tests__/**/*.test.js'],
  testPathIgnorePatterns: ['/node_modules/', '/grafana/'],
  modulePathIgnorePatterns: ['/grafana/'], // تجاهل مجلد grafana بالكامل
  collectCoverageFrom: [
    'src/lib/**/*.js',
    '!src/lib/db.mock.js',
    '!src/lib/logger.js',
    '!src/lib/metrics.js'
  ]
};