/**
 * MOCK1 + REQUIRED_ENV: production startup guard tests.
 *
 * The guard:
 * - Refuses to boot when MOCK_IP_INTEL=true (silent mock data risk).
 * - Refuses to boot when any of the 10 required env vars is missing
 *   (turns silent degradation from `?? null` and `?? IDENTITY_GRAPH_SECRET`
 *   fallbacks into a loud failure).
 *
 * Mutation coverage:
 * - T1 fails if the MOCK_IP_INTEL throw is removed.
 * - T7, T8, T9 fail if the REQUIRED_ENV check is disabled.
 */
const { enforceProductionGuards, REQUIRED_ENV_VARS } = require('../../src/lib/startupGuards');

const ALL_KEYS = ['NODE_ENV', 'MOCK_IP_INTEL'].concat(REQUIRED_ENV_VARS);

function setAllRequired(values) {
  for (const k of REQUIRED_ENV_VARS) {
    const v = (values && k in values) ? values[k] : ('x-test-' + k);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

describe('startupGuards: enforceProductionGuards', () => {
  const saved = {};

  beforeEach(() => {
    for (const k of ALL_KEYS) {
      saved[k] = process.env[k];
    }
  });

  afterEach(() => {
    for (const k of ALL_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  // --- MOCK1 (T1-T5) ---

  it('T1: throws when NODE_ENV=production and MOCK_IP_INTEL=true', () => {
    setAllRequired();
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).toThrow(/MOCK_IP_INTEL/);
  });

  it('T2: does not throw when NODE_ENV=production and MOCK_IP_INTEL=false', () => {
    setAllRequired();
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  it('T3: does not throw when NODE_ENV=production and MOCK_IP_INTEL is unset', () => {
    setAllRequired();
    process.env.NODE_ENV = 'production';
    delete process.env.MOCK_IP_INTEL;
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  it('T4: does not throw when NODE_ENV=development and MOCK_IP_INTEL=true', () => {
    setAllRequired();
    process.env.NODE_ENV = 'development';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  it('T5: does not throw when NODE_ENV=test and MOCK_IP_INTEL=true', () => {
    setAllRequired();
    process.env.NODE_ENV = 'test';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  // --- REQUIRED_ENV (T6-T11) ---

  it('T6: does not throw when all 10 required env vars are present (production)', () => {
    setAllRequired();
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  it('T7: throws when DATABASE_URL is missing in production', () => {
    setAllRequired({ DATABASE_URL: undefined });
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).toThrow(/DATABASE_URL/);
  });

  it('T8: throws when CARD_HASH_SECRET is missing in production', () => {
    setAllRequired({ CARD_HASH_SECRET: undefined });
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).toThrow(/CARD_HASH_SECRET/);
  });

  it('T9: throws and lists all missing vars when 3 are absent', () => {
    setAllRequired({
      DATABASE_URL: undefined,
      ADMIN_SECRET: undefined,
      PATTERN_SHARING_SECRET: undefined,
    });
    process.env.NODE_ENV = 'production';
    process.env.MOCK_IP_INTEL = 'false';
    expect(() => enforceProductionGuards()).toThrow(/DATABASE_URL.*ADMIN_SECRET.*PATTERN_SHARING_SECRET/);
  });

  it('T10: development mode does not enforce REQUIRED_ENV', () => {
    const empty = {};
    REQUIRED_ENV_VARS.forEach(k => { empty[k] = undefined; });
    setAllRequired(empty);
    process.env.NODE_ENV = 'development';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });

  it('T11: test mode does not enforce REQUIRED_ENV', () => {
    const empty = {};
    REQUIRED_ENV_VARS.forEach(k => { empty[k] = undefined; });
    setAllRequired(empty);
    process.env.NODE_ENV = 'test';
    process.env.MOCK_IP_INTEL = 'true';
    expect(() => enforceProductionGuards()).not.toThrow();
  });
});