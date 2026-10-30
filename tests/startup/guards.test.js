/**
 * MOCK1: production startup guard tests.
 *
 * The guard prevents the server from booting in production when
 * MOCK_IP_INTEL=true, which would silently replace real IP intelligence
 * with mock data (see src/lib/ipIntelligence.js:128).
 *
 * Mutation coverage: T1 fails if the throw is removed from the guard.
 * T2-T5 are coverage (they verify the no-throw paths).
 */
const { enforceProductionGuards } = require('../../src/lib/startupGuards');

describe('startupGuards: enforceProductionGuards', () => {
  let savedNodeEnv;
  let savedMockIp;

  beforeEach(() => {
    savedNodeEnv = process.env.NODE_ENV;
    savedMockIp = process.env.MOCK_IP_INTEL;
  });

  afterEach(() => {
    if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNodeEnv;
    if (savedMockIp === undefined) delete process.env.MOCK_IP_INTEL;
    else process.env.MOCK_IP_INTEL = savedMockIp;
  });

  // T1: the actual fix (mutation coverage). Must fail if the throw is removed.
  it('T1: throws when NODE_ENV=production and MOCK_IP_INTEL=true', () => {
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).toThrow(/MOCK_IP_INTEL/);
  });

  // T2: safe value in production (no throw)
  it('T2: does not throw when NODE_ENV=production and MOCK_IP_INTEL=false', () => {
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  // T3: unset in production (default-safe)
  it('T3: does not throw when NODE_ENV=production and MOCK_IP_INTEL is unset', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.MOCK_IP_INTEL;
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  // T4: dev allows mock (no throw) - developers need mocks locally
  it('T4: does not throw when NODE_ENV=development and MOCK_IP_INTEL=true', () => {
    process.env.NODE_ENV = 'development';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  // T5: test allows mock (no throw) - jest itself sets NODE_ENV=test
  it('T5: does not throw when NODE_ENV=test and MOCK_IP_INTEL=true', () => {
    process.env.NODE_ENV = 'test';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });
});