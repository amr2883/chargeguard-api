'use strict';

// ─── T3d-1: Tier 1/2/3 Static + Velocity Scoring ───────────────────────────
//
// SCOPE — read before touching these tests.
//
// This file covers the Tier 1 (critical), Tier 2 (strong/contextual), and
// Tier 3 (positive) signal blocks inside calculateRiskScore in
// riskScoring.js, EXCLUDING:
//   - The risk-floor clamp + decision assignment    → risk-floor.test.js (T3d-2)
//   - The economic engine override layer             → economic-engine.test.js (T3d-3)
//   - getMerchantAdjustment() correctness             → merchant-adjustment.test.js (T3d-4)
// Those subsystems still RUN inside calculateRiskScore here (they can't be
// disabled), so several assertions below account for risk-floor clamping
// explicitly rather than pretending it doesn't exist.
//
// MOCKING STRATEGY — this deliberately DIVERGES from T3d-2/T3d-3 in one
// important way, explained below.
//
//   - ipIntelligence    → jest.mock'd. calculateIPPenalty's return value is
//     our "penalty dial" (severity always 'medium' unless a test says
//     otherwise), used in several tests to shift the pre-floor score by a
//     known amount so a specific Tier 2 penalty's exact magnitude is
//     recoverable from the final `score` even though the function also
//     clamps score to [0,100] and (later) applies the risk floor.
//   - patternSharing    → jest.mock'd (no DB dependency; checkPatternRisk/
//     recordPattern are called unconditionally regardless of flag count).
//   - prom-client       → jest.mock'd defensively, matching economic-engine
//     .test.js — avoids "metric already registered" errors if some
//     unmocked dependency in the require graph pulls prom-client in.
//
//   - emailIntelligence, binIntelligence, identityGraph → jest.mock'd HERE,
//     UNLIKE T3d-2/T3d-3. Those files left these three real and simply
//     never exercised them, by never setting order.email/deviceId/bin.
//     T3d-1 cannot do that: email disputes, email velocity, returning-
//     customer, device disputes, device velocity, trusted-device, and BIN
//     velocity ALL require real email/deviceId/bin values on the order.
//     Leaving the real modules in place would mean live DNS resolution
//     (emailIntelligence's checkDomainDNS) and live Prisma calls
//     (identityGraph's getConnectedRisk) firing during a unit test run.
//     getConnectedRisk happens to fail-safe to {connectedRisk:0} when the
//     DB is unavailable (it has its own internal try/catch), so it would
//     probably not have crashed the suite — but it would be a live,
//     non-deterministic dependency, so it is mocked out entirely instead.
//     getEmailIntelligence/getBINIntelligence are mocked to resolve a
//     neutral object, and calculateEmailPenalty/calculateBINPenalty are
//     mocked to always return {penalty:0, flags:[]} — this keeps those
//     two intelligence layers fully inert so that email/BIN VELOCITY
//     (computed directly in riskScoring.js from allOrders, NOT from these
//     modules) can be tested in isolation.
//   - similarity.js (findSimilarDisputes et al.) → left REAL. It is pure
//     JS with no network/DB dependency, so it's safe to exercise as-is;
//     several tests below pass real disputes/addresses through it and
//     assert it does NOT interfere with the signal being tested.
//   - db (Prisma) → left REAL, never invoked: merchantId is null in every
//     test (getWeightsForMerchant and the merchant-profile lookup are both
//     gated on `if (merchantId)`), so no DB call-site is ever reached.
//
// THE "IP PENALTY DIAL" TECHNIQUE (borrowed from T3d-2/T3d-3):
//   Any single Tier 2 flag with severity "high" will, on its own, push a
//   raw score above 70 back down to exactly 70 via the risk floor (see
//   T3d-2). To let the *exact* magnitude of the penalty under test surface
//   in `result.score`, most Tier 2 tests below supply a same-severity
//   ('medium', so it doesn't add to highCount) ipPenalty dial large enough
//   to keep the composite raw score at or below 70 (and, where 2 high
//   flags are already present, at or below 55). Each such test states the
//   arithmetic inline.
//
// KNOWN, DELIBERATELY DOCUMENTED (NOT FIXED) BEHAVIORS — see the dedicated
// "documented behaviors" describe blocks near the bottom of this file:
//   1. IP velocity is double-penalized: an unconditional early block
//      (based on `sameIPOrders`) and a later fallback block (based on
//      `ipVelocityCount`, only skipped if `externalVelocity` supplies a
//      DIFFERENT count) both apply the identical log-scaled penalty when
//      externalVelocity is not supplied.
//   2. Email velocity is double-penalized the same way (`sameEmailOrders`
//      then `emailVelocityCount`).
//   3. Device velocity is NOT double-penalized — there is only ONE block
//      for it (no unconditional early pass), so it is asymmetric with
//      IP/email velocity.
//   4. pixelBotScore/pixelSuspicious are hardcoded to 0/false — the entire
//      Tier 1 "Bot Detection Penalty" block is permanently dead code.
//   5. The second high-value-order check (guarded by
//      `!highValuePenaltyApplied`, near "Behavioral Deviation") is
//      unreachable: its own trigger condition (`avgOrderValue > 0 &&
//      orderMultiple >= 3`) is identical to the first block's, and the
//      first block always sets `highValuePenaltyApplied = true` whenever
//      that condition holds.
//   6. utils.js's normalizeEmail (used by riskScoring.js) has NO homoglyph
//      mapping, unlike similarity.js's normalizeEmail. A Cyrillic-spoofed
//      email variant is therefore NOT recognized as a duplicate for
//      velocity/dispute/returning-customer purposes inside
//      calculateRiskScore.

jest.mock('prom-client', () => ({
  Counter: jest.fn().mockImplementation(() => ({
    inc: jest.fn(),
    labels: jest.fn().mockReturnThis(),
  })),
  Histogram: jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    labels: jest.fn().mockReturnThis(),
    startTimer: jest.fn().mockReturnValue(jest.fn()),
  })),
  collectDefaultMetrics: jest.fn(),
  register: {
    metrics: jest.fn().mockResolvedValue(''),
    contentType: 'text/plain; version=0.0.4',
    registerMetric: jest.fn(),
    clear: jest.fn(),
  },
}));

jest.mock('../../src/lib/ipIntelligence', () => ({
  getIPIntelligence: jest.fn(),
  calculateIPPenalty: jest.fn(),
  invalidateIPCache: jest.fn(),
  normalizeIP: jest.fn((ip) => ip),
}));

jest.mock('../../src/lib/patternSharing', () => ({
  checkPatternRisk: jest.fn().mockResolvedValue({ penalty: 0, flags: [] }),
  recordPattern: jest.fn().mockResolvedValue(null),
  buildPattern: jest.fn(),
  markPatternAsFraud: jest.fn().mockResolvedValue(null),
}));

jest.mock('../../src/lib/emailIntelligence', () => ({
  getEmailIntelligence: jest.fn(),
  calculateEmailPenalty: jest.fn(),
  invalidateEmailCache: jest.fn(),
}));

jest.mock('../../src/lib/binIntelligence', () => ({
  getBINIntelligence: jest.fn(),
  calculateBINPenalty: jest.fn(),
  normalizeBin: jest.fn((raw) => {
    if (!raw) return null;
    const cleaned = String(raw).replace(/\D/g, '').slice(0, 8);
    return cleaned.length >= 6 ? cleaned : null;
  }),
  extractBIN: jest.fn(),
}));

jest.mock('../../src/lib/identityGraph', () => ({
  getConnectedRisk: jest.fn().mockResolvedValue({ connectedRisk: 0, hasConnections: false, graphPath: [] }),
  buildGraphFromOrder: jest.fn(),
  markOrderAsFraud: jest.fn(),
  markOrderAsClean: jest.fn(),
}));

const { calculateRiskScore } = require('../../src/lib/riskScoring');

const { getIPIntelligence, calculateIPPenalty } = require('../../src/lib/ipIntelligence');
const { getEmailIntelligence, calculateEmailPenalty } = require('../../src/lib/emailIntelligence');
const { getBINIntelligence, calculateBINPenalty } = require('../../src/lib/binIntelligence');

// ─── Test Helpers ───────────────────────────────────────────────────────────

function minutesAgo(m) {
  return new Date(Date.now() - m * 60 * 1000);
}

function hoursAgo(h) {
  return new Date(Date.now() - h * 60 * 60 * 1000);
}

// Fixed local-noon timestamp by default — avoids the 2-5am "unusual hour"
// penalty regardless of the machine's timezone (same convention as
// risk-floor.test.js / economic-engine.test.js). Tests targeting the
// unusual-hour check override createdAt explicitly.
function makeOrder(overrides = {}) {
  return {
    id: 'order-1',
    amount: 50,
    ipAddress: '203.0.113.10',
    createdAt: new Date(2025, 5, 15, 12, 0, 0),
    ...overrides,
  };
}

// Drives the real calculateRiskScore with every non-static-scoring
// dependency neutralized. `ipPenalty`/`ipSeverity` is the one deliberate
// "dial" used to control the pre-floor score in several tests (see file
// header). emailIntelligence/binIntelligence are always inert (penalty 0,
// no flags) so email/BIN VELOCITY (computed independently inside
// riskScoring.js from allOrders) can be isolated.
async function runScoring({
  order,
  allOrders = [],
  disputes = [],
  blacklist = [],
  cardHashRecord = null,
  externalVelocity = null,
  ipPenalty = 0,
  ipSeverity = 'medium',
  binIntel = {},
  merchantId = null,
} = {}) {
  getIPIntelligence.mockResolvedValue({});
  calculateIPPenalty.mockReturnValue({
    penalty: ipPenalty,
    flags: ipPenalty > 0
      ? [{ severity: ipSeverity, text: 'IP risk dial (test fixture)' }]
      : [],
  });

  getEmailIntelligence.mockResolvedValue({});
  calculateEmailPenalty.mockReturnValue({ penalty: 0, flags: [] });

  getBINIntelligence.mockResolvedValue(binIntel);
  calculateBINPenalty.mockReturnValue({ penalty: 0, flags: [] });

  return calculateRiskScore(
    order,
    allOrders,
    disputes,
    blacklist,
    merchantId,
    false, // saveEvaluation
    externalVelocity,
    cardHashRecord,
    null,  // merchantConfig
  );
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ─── Tier 1 — Definitive (Critical) ─────────────────────────────────────────

describe('Tier 1 — blacklist', () => {
  test('email match on blacklist → -80, critical, floor clamps raw score of 20 unchanged (already below 40)', async () => {
    const order = makeOrder({ email: 'blocked@example.com' });
    const result = await runScoring({
      order,
      blacklist: [{ email: 'blocked@example.com' }],
    });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('fraud blacklist'))).toBe(true);
    expect(result.score).toBe(20);
  });

  test('ip match on blacklist → -80, critical', async () => {
    const order = makeOrder({ ipAddress: '198.51.100.9' });
    const result = await runScoring({
      order,
      blacklist: [{ ip: '198.51.100.9' }],
    });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('fraud blacklist'))).toBe(true);
    expect(result.score).toBe(20);
  });

  test('deviceId match on blacklist → -80, critical', async () => {
    const order = makeOrder({ deviceFingerprint: 'device-abc-123' });
    const result = await runScoring({
      order,
      blacklist: [{ deviceId: 'device-abc-123' }],
    });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('fraud blacklist'))).toBe(true);
    expect(result.score).toBe(20);
  });

  test('no field matches → no blacklist flag', async () => {
    const order = makeOrder({ email: 'clean@example.com', ipAddress: '203.0.113.10' });
    const result = await runScoring({
      order,
      blacklist: [{ email: 'someoneelse@example.com', ip: '9.9.9.9', deviceId: 'other-device' }],
    });
    expect(result.flags.some((f) => f.text.includes('fraud blacklist'))).toBe(false);
  });
});

describe('Tier 1 — device disputes', () => {
  test('1 lost dispute on this device fingerprint → -60, critical, raw=40 unchanged by floor (min(40,40))', async () => {
    const order = makeOrder({ deviceFingerprint: 'device-xyz' });
    const disputes = [
      { id: 'd1', result: 'lost', order: { deviceFingerprint: 'device-xyz' } },
    ];
    const result = await runScoring({ order, disputes });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Device fingerprint linked to 1 lost dispute'))).toBe(true);
    expect(result.score).toBe(40);
  });

  test('2+ lost disputes pluralizes the flag text but the penalty is still a flat -60 (no per-dispute scaling)', async () => {
    const order = makeOrder({ deviceFingerprint: 'device-xyz' });
    const disputes = [
      { id: 'd1', result: 'lost', order: { deviceFingerprint: 'device-xyz' } },
      { id: 'd2', result: 'lost', order: { deviceFingerprint: 'device-xyz' } },
    ];
    const result = await runScoring({ order, disputes });
    expect(result.flags.some((f) => f.text.includes('Device fingerprint linked to 2 lost disputes'))).toBe(true);
    expect(result.score).toBe(40); // same as the single-dispute case — flat penalty
  });

  test('a "won" dispute on the same device does NOT count', async () => {
    const order = makeOrder({ deviceFingerprint: 'device-xyz' });
    const disputes = [
      { id: 'd1', result: 'won', order: { deviceFingerprint: 'device-xyz' } },
    ];
    const result = await runScoring({ order, disputes });
    expect(result.flags.some((f) => f.text.includes('Device fingerprint linked to'))).toBe(false);
  });
});

describe('Tier 1 — IP disputes (>= 3 lost required)', () => {
  test('exactly 2 lost disputes on this IP → NO penalty (threshold is >= 3)', async () => {
    const order = makeOrder({ ipAddress: '198.51.100.20' });
    const disputes = [
      { id: 'd1', result: 'lost', order: { ipAddress: '198.51.100.20' } },
      { id: 'd2', result: 'lost', order: { ipAddress: '198.51.100.20' } },
    ];
    const result = await runScoring({ order, disputes });
    expect(result.flags.some((f) => f.text.includes('disputes across network'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('exactly 3 lost disputes on this IP → -50, critical, raw=50 clamped down to 40 by the floor', async () => {
    const order = makeOrder({ ipAddress: '198.51.100.20' });
    const disputes = [
      { id: 'd1', result: 'lost', order: { ipAddress: '198.51.100.20' } },
      { id: 'd2', result: 'lost', order: { ipAddress: '198.51.100.20' } },
      { id: 'd3', result: 'lost', order: { ipAddress: '198.51.100.20' } },
    ];
    const result = await runScoring({ order, disputes });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('IP address linked to 3 disputes'))).toBe(true);
    expect(result.score).toBe(40);
  });
});

describe('Tier 1 — stacking', () => {
  test('blacklist + device disputes + IP disputes all firing together sum additively before the floor/global clamp', async () => {
    // raw = 100 - 80 (blacklist) - 60 (device) - 50 (ip) = -90 → Math.max(0,...) = 0
    // Floor (hasCriticalSignal) → min(0,40) = 0. No change.
    const order = makeOrder({
      email: 'blocked@example.com',
      ipAddress: '198.51.100.20',
      deviceFingerprint: 'device-xyz',
    });
    const disputes = [
      { id: 'd1', result: 'lost', order: { deviceFingerprint: 'device-xyz' } },
      { id: 'd2', result: 'lost', order: { ipAddress: '198.51.100.20' } },
      { id: 'd3', result: 'lost', order: { ipAddress: '198.51.100.20' } },
      { id: 'd4', result: 'lost', order: { ipAddress: '198.51.100.20' } },
    ];
    const result = await runScoring({
      order,
      disputes,
      blacklist: [{ email: 'blocked@example.com' }],
    });
    const criticalFlags = result.flags.filter((f) => f.severity === 'critical');
    expect(criticalFlags.length).toBeGreaterThanOrEqual(3);
    expect(result.score).toBe(0);
  });
});

// ─── Tier 1 — documented dead code: pixel bot detection ────────────────────

describe('documented dead code — pixelBotScore / pixelSuspicious', () => {
  test('pixelBotScore/pixelSuspicious are hardcoded to 0/false — no bot flag can ever be produced', async () => {
    const order = makeOrder({});
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.text.toLowerCase().includes('bot'))).toBe(false);
    expect(result.score).toBe(100);
  });
});

// ─── Tier 2 — Shipping/Billing Mismatch ────────────────────────────────────

describe('Tier 2 — shipping/billing country mismatch', () => {
  test('different countries → -15, high; dial(-20, medium) keeps raw at 65 so the -15 is exactly recoverable', async () => {
    const order = makeOrder({
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
    });
    const result = await runScoring({ order, ipPenalty: 20 });
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('Shipping country differs from billing country'))).toBe(true);
    expect(result.score).toBe(65); // 100 - 15 - 20
  });

  test('same country on both sides → no mismatch penalty', async () => {
    const order = makeOrder({
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'US' }),
    });
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.text.includes('Shipping country differs'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('malformed shipping/billing JSON is silently swallowed (parsed to {}) — no throw, no penalty', async () => {
    const order = makeOrder({
      shippingAddress: 'not-json',
      billingAddress: 'also-not-json',
    });
    await expect(runScoring({ order })).resolves.toBeDefined();
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.text.includes('Shipping country differs'))).toBe(false);
  });
});

// ─── Tier 2 — IP Velocity (and documented double-penalty) ──────────────────

describe('Tier 2 — IP velocity', () => {
  test('exactly 1 other order from same IP in 24h → below threshold (>=2 required) → no penalty', async () => {
    const order = makeOrder({ ipAddress: '198.51.100.50', email: 'orderemail@example.com' });
    const allOrders = [
      { id: 'ip-hist-1', amount: 50, ipAddress: '198.51.100.50', email: 'hist1@example.com', createdAt: minutesAgo(30) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('same IP in last 24 hours'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('DOCUMENTED DOUBLE-PENALTY: 2 other orders from same IP in 24h are penalized TWICE — once by the unconditional early block, once by the fallback recompute block — because the early block never checks externalVelocity', async () => {
    // penalty per occurrence = min(round(15*log2(3)),35) = 24 (verified: 15*log2(3)=23.77→round=24)
    // total = 24 + 24 = 48. raw = 100 - 48 = 52.
    // highCount = 2 (two identical "high" flags) but score(52) is not > 55,
    // so the "2+ high flags" floor rule does NOT clamp it — the true
    // double-counted value is directly observable.
    const order = makeOrder({ amount: 50, ipAddress: '198.51.100.50', email: 'orderemail@example.com' });
    const allOrders = [
      { id: 'ip-hist-1', amount: 50, ipAddress: '198.51.100.50', email: 'hist1@example.com', createdAt: minutesAgo(30) },
      { id: 'ip-hist-2', amount: 50, ipAddress: '198.51.100.50', email: 'hist2@example.com', createdAt: minutesAgo(45) },
    ];
    const result = await runScoring({ order, allOrders });

    const ipVelocityFlags = result.flags.filter((f) => f.text.includes('3 orders from same IP in last 24 hours'));
    expect(ipVelocityFlags.length).toBe(2); // duplicated flag — the tell-tale sign of the double-count
    expect(ipVelocityFlags.every((f) => f.severity === 'high')).toBe(true);
    expect(result.score).toBe(52); // 100 - 24 - 24, NOT 100 - 24
  });

  test('when externalVelocity supplies ipVelocityCount=0, the SECOND (fallback) block is suppressed, but the FIRST (unconditional, allOrders-based) block still fires regardless — proving the early block genuinely ignores externalVelocity', async () => {
    // Early block: sameIPOrders.length=2 → penalty 24, flag fires.
    // Fallback block: externalVelocity truthy → ipVelocityCount = 0 (from
    // externalVelocity.ipVelocityCount) → `if (ipVelocityCount >= 2)` is
    // false → second penalty does NOT fire.
    // raw = 100 - 24 = 76 → single high flag, score>70 → floor caps to 70.
    const order = makeOrder({ amount: 50, ipAddress: '198.51.100.60', email: 'orderemail2@example.com' });
    const allOrders = [
      { id: 'ip-hist-3', amount: 50, ipAddress: '198.51.100.60', email: 'hist3@example.com', createdAt: minutesAgo(10) },
      { id: 'ip-hist-4', amount: 50, ipAddress: '198.51.100.60', email: 'hist4@example.com', createdAt: minutesAgo(20) },
    ];
    const result = await runScoring({
      order,
      allOrders,
      externalVelocity: { deviceVelocityCount: 0, ipVelocityCount: 0, emailVelocityCount: 0 },
    });
    const ipVelocityFlags = result.flags.filter((f) => f.text.includes('same IP in last 24 hours'));
    expect(ipVelocityFlags.length).toBe(1); // only the early block fired
    expect(result.score).toBe(70); // 100-24=76, floor-capped to 70
  });
});

// ─── Tier 2 — Email Velocity (and documented double-penalty) ──────────────

describe('Tier 2 — email velocity', () => {
  test('exactly 2 other orders from same email in 6h → below threshold (>=3 required) → no penalty', async () => {
    const order = makeOrder({ email: 'buyer@example.com', ipAddress: 'unique-ip-a' });
    const allOrders = [
      { id: 'email-hist-1', amount: 50, email: 'buyer@example.com', ipAddress: 'ip-a', createdAt: minutesAgo(30) },
      { id: 'email-hist-2', amount: 50, email: 'buyer@example.com', ipAddress: 'ip-b', createdAt: minutesAgo(45) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('same email in last 6 hours'))).toBe(false);
  });

  test('DOCUMENTED DOUBLE-PENALTY: 3 other orders from same email in 6h are penalized TWICE, same structural bug as IP velocity', async () => {
    // penalty per occurrence = min(round(12*log2(4)),30) = 24 (12*2=24)
    // total = 24 + 24 = 48. raw = 100 - 48 = 52 (highCount=2, not >55 → no clamp).
    // disputes below reference each history order's id purely to exclude
    // them from `prevGoodOrders` (returning-customer credit) — otherwise
    // the same 3 matching-email orders would ALSO trigger the returning-
    // customer positive bonus and (since they're all recent) the "rapid
    // order history" -10 flag, contaminating this test's arithmetic. The
    // disputes carry no `order` field, so they don't touch any other
    // dispute-based penalty (deviceDisputes/ipDisputes/emailDisputes all
    // read from `d.order`, which is undefined here).
    const order = makeOrder({ amount: 50, email: 'buyer@example.com', ipAddress: 'unique-ip-x' });
    const allOrders = [
      { id: 'email-hist-1', amount: 50, email: 'buyer@example.com', ipAddress: 'ip-1', createdAt: minutesAgo(30) },
      { id: 'email-hist-2', amount: 50, email: 'buyer@example.com', ipAddress: 'ip-2', createdAt: minutesAgo(45) },
      { id: 'email-hist-3', amount: 50, email: 'buyer@example.com', ipAddress: 'ip-3', createdAt: minutesAgo(60) },
    ];
    const disputes = [
      { id: 'suppress-1', orderId: 'email-hist-1' },
      { id: 'suppress-2', orderId: 'email-hist-2' },
      { id: 'suppress-3', orderId: 'email-hist-3' },
    ];
    const result = await runScoring({ order, allOrders, disputes });

    const emailVelocityFlags = result.flags.filter((f) => f.text.includes('4 orders from same email in last 6 hours'));
    expect(emailVelocityFlags.length).toBe(2);
    expect(result.score).toBe(52);
  });
});

// ─── Tier 2 — Device Velocity (NOT double-penalized — asymmetric) ─────────

describe('Tier 2 — device velocity (single-count, unlike IP/email)', () => {
  test('1 other order from same device in last hour → -15, medium (no floor interference — medium severity)', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'device-v1', email: 'a@example.com' });
    const allOrders = [
      { id: 'dev-hist-1', amount: 50, deviceFingerprint: 'device-v1', email: 'b@example.com', createdAt: minutesAgo(10) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('Device fingerprint linked to 2 orders in last hour'))).toBe(true);
    expect(result.score).toBe(85); // 100 - 15, single medium flag never floors
  });

  test('2 other orders from same device in last hour → -25, high', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'device-v2', email: 'a@example.com' });
    const allOrders = [
      { id: 'dev-hist-1', amount: 50, deviceFingerprint: 'device-v2', email: 'b@example.com', createdAt: minutesAgo(10) },
      { id: 'dev-hist-2', amount: 50, deviceFingerprint: 'device-v2', email: 'c@example.com', createdAt: minutesAgo(20) },
    ];
    // disputes below suppress the incidental sameDeviceGood ("trusted
    // device") +15 bonus, which would otherwise fire unconditionally
    // (it has no time-window filter) whenever 2+ matching-device history
    // orders exist with no disputes referencing them — contaminating the
    // pure velocity-penalty arithmetic this test is isolating.
    const result = await runScoring({
      order,
      allOrders,
      disputes: [{ id: 'sup-dv-1', orderId: 'dev-hist-1' }, { id: 'sup-dv-2', orderId: 'dev-hist-2' }],
      ipPenalty: 15, // dial: 100-25-15=60, avoids the >70 single-high floor
    });
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('Device fingerprint linked to 3 orders in last hour'))).toBe(true);
    expect(result.score).toBe(60);
  });

  test('3+ other orders from same device in last hour → -40, critical (floor forces score <= 40 regardless)', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'device-v3', email: 'a@example.com' });
    const allOrders = [
      { id: 'dev-hist-1', amount: 50, deviceFingerprint: 'device-v3', email: 'b@example.com', createdAt: minutesAgo(5) },
      { id: 'dev-hist-2', amount: 50, deviceFingerprint: 'device-v3', email: 'c@example.com', createdAt: minutesAgo(10) },
      { id: 'dev-hist-3', amount: 50, deviceFingerprint: 'device-v3', email: 'd@example.com', createdAt: minutesAgo(15) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Device fingerprint linked to 4 orders in last hour'))).toBe(true);
    expect(result.score).toBe(40); // 100-40=60, critical floor clamps to 40
  });

  test('CONTRAST WITH IP/EMAIL: device velocity is penalized exactly ONCE even with no externalVelocity supplied — only a single matching flag appears', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'device-v4', email: 'a@example.com' });
    const allOrders = [
      { id: 'dev-hist-1', amount: 50, deviceFingerprint: 'device-v4', email: 'b@example.com', createdAt: minutesAgo(10) },
    ];
    const result = await runScoring({ order, allOrders, externalVelocity: null });
    const deviceFlags = result.flags.filter((f) => f.text.includes('Device fingerprint linked to') && f.text.includes('last hour'));
    expect(deviceFlags.length).toBe(1); // exactly one — no structural duplicate block exists for device
  });
});

// ─── Tier 2 — BIN Velocity ──────────────────────────────────────────────────

describe('Tier 2 — BIN velocity (tiered, first-match-wins: 10min > 1h > 24h)', () => {
  test('2 other orders with same BIN prefix in 10 minutes → -10 (non-prepaid); dial keeps score exact', async () => {
    const order = makeOrder({
      amount: 50,
      email: 'bin1@example.com',
      ipAddress: 'ip-bin-1',
      payment_details: { card_bin: '411111' },
    });
    const allOrders = [
      { id: 'bin-hist-1', amount: 50, email: 'binh1@example.com', ipAddress: 'ip-h1', payment_details: { card_bin: '411111' }, createdAt: minutesAgo(2) },
      { id: 'bin-hist-2', amount: 50, email: 'binh2@example.com', ipAddress: 'ip-h2', payment_details: { card_bin: '411111' }, createdAt: minutesAgo(5) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 20 }); // 100-10-20=70
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('3 orders from same BIN prefix in 10 minutes'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('prepaid card'))).toBe(false);
    expect(result.score).toBe(70);
  });

  test('prepaid multiplier (2.5x) applies to the 10-minute tier: penalty becomes round(10*2.5)=25', async () => {
    const order = makeOrder({
      amount: 50,
      email: 'bin2@example.com',
      ipAddress: 'ip-bin-2',
      payment_details: { card_bin: '511111' },
    });
    const allOrders = [
      { id: 'bin-hist-3', amount: 50, email: 'binh3@example.com', ipAddress: 'ip-h3', payment_details: { card_bin: '511111' }, createdAt: minutesAgo(2) },
      { id: 'bin-hist-4', amount: 50, email: 'binh4@example.com', ipAddress: 'ip-h4', payment_details: { card_bin: '511111' }, createdAt: minutesAgo(5) },
    ];
    const result = await runScoring({
      order,
      allOrders,
      binIntel: { isPrepaid: true },
      ipPenalty: 15, // 100-25-15=60
    });
    expect(result.flags.some((f) => f.text.includes('BIN attack pattern detected (prepaid card)'))).toBe(true);
    expect(result.score).toBe(60);
  });

  test('satisfying the 1h (>=3) and 24h (>=5) tiers simultaneously with the 10min tier ALSO satisfied → only the 10-minute tier fires (first-match-wins, not cumulative)', async () => {
    const order = makeOrder({
      amount: 50,
      email: 'bin3@example.com',
      ipAddress: 'ip-bin-3',
      payment_details: { card_bin: '611111' },
    });
    // 2 orders inside 10 minutes (satisfies 10min>=2) AND inside 1h and 24h
    // windows too (since 24h > 1h > 10min supersets). Even though 1h count
    // would be >=2 (not >=3, so 1h tier alone wouldn't fire on its own —
    // but this test's real point is: whichever earlier tier matches wins).
    const allOrders = [
      { id: 'bin-hist-5', amount: 50, email: 'binh5@example.com', ipAddress: 'ip-h5', payment_details: { card_bin: '611111' }, createdAt: minutesAgo(2) },
      { id: 'bin-hist-6', amount: 50, email: 'binh6@example.com', ipAddress: 'ip-h6', payment_details: { card_bin: '611111' }, createdAt: minutesAgo(3) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 20 });
    const binFlags = result.flags.filter((f) => f.text.includes('BIN prefix'));
    expect(binFlags.length).toBe(1);
    expect(binFlags[0].text).toContain('10 minutes');
    expect(result.score).toBe(70); // 100-10-20
  });

  test('no bin on the order → BIN velocity block is skipped entirely (guarded by `if (binPrefix)`)', async () => {
    const order = makeOrder({ amount: 50, email: 'nobin@example.com' });
    const allOrders = [
      { id: 'irrelevant-1', amount: 50, email: 'x@example.com', payment_details: { card_bin: '411111' }, createdAt: minutesAgo(2) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('BIN prefix'))).toBe(false);
    expect(result.score).toBe(100);
  });
});

// ─── Tier 2 — CardHash Penalty ──────────────────────────────────────────────

describe('Tier 2 — CardHash repeated-use penalty', () => {
  test('attemptCount=0, blockCount=0 → cardPenalty=0 → no flag at all (guarded by `if (cardPenalty > 0)`)', async () => {
    const order = makeOrder({});
    const result = await runScoring({ order, cardHashRecord: { attemptCount: 0, blockCount: 0 } });
    expect(result.flags.some((f) => f.text.includes('Same card used'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('attemptCount=1, blockCount=0 → attemptBonus=5, cardPenalty=5, severity "high" (not >30)', async () => {
    // NOTE: cardPenalty=5 still gets severity "high" (the ternary is
    // `cardPenalty > 30 ? 'critical' : 'high'` — there is no "medium"
    // tier at all for this signal). That makes this a single high-severity
    // flag, so the dial must keep the composite raw score at or below 70
    // (not just "some offset") or the risk floor will clamp it.
    const order = makeOrder({ amount: 50 });
    const result = await runScoring({ order, cardHashRecord: { attemptCount: 1, blockCount: 0 }, ipPenalty: 30 });
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('Same card used 1 times (blocked 0 times)'))).toBe(true);
    expect(result.score).toBe(65); // 100-5-30
  });

  test('attemptCount=6, blockCount=0 → attemptBonus=min(30,25)=25 (cap engages at 5 attempts, not 6) — cardPenalty=25, still "high"', async () => {
    const order = makeOrder({ amount: 50 });
    const result = await runScoring({ order, cardHashRecord: { attemptCount: 6, blockCount: 0 }, ipPenalty: 15 });
    expect(result.flags.some((f) => f.text.includes('Same card used 6 times (blocked 0 times)'))).toBe(true);
    expect(result.score).toBe(60); // 100-25-15
  });

  test('attemptCount=3, blockCount=1 → attemptBonus=15 + blockBonus=20 = 35 (>30) → severity "critical"; floor forces score <= 40', async () => {
    const order = makeOrder({ amount: 50 });
    const result = await runScoring({ order, cardHashRecord: { attemptCount: 3, blockCount: 1 } });
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Same card used 3 times (blocked 1 times)'))).toBe(true);
    expect(result.score).toBe(40); // 100-35=65, critical floor clamps to 40
  });
});

// ─── Tier 2 — High-Value Order Tiers ────────────────────────────────────────

describe('Tier 2 — high-value order (3x / 5x average order value, new vs returning customer)', () => {
  test('exactly 3.0x average, new customer → -20, high, text says "New customer"', async () => {
    const order = makeOrder({ amount: 300 }); // no email/deviceId set → isNewCustomer=true
    const allOrders = [
      { id: 'hv-hist-1', amount: 100, email: 'hist1@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-2', amount: 100, email: 'hist2@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 10 }); // 100-20-10=70
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('New customer with order 3x above store average'))).toBe(true);
    expect(result.score).toBe(70);
  });

  test('exactly 3.0x average, RETURNING customer (matching email in history) → -10, medium, text has no "New customer" wording', async () => {
    const order = makeOrder({ amount: 300, email: 'returning@example.com' });
    const allOrders = [
      { id: 'hv-hist-3', amount: 100, email: 'returning@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-4', amount: 100, email: 'other@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders, disputes: [{ id: 'sup-1', orderId: 'hv-hist-3' }, { id: 'sup-2', orderId: 'hv-hist-4' }] });
    // disputes suppress returning-customer bonus contamination (see email-velocity test comment)
    const flag = result.flags.find((f) => f.text.includes('Order value 3x above store average'));
    expect(flag).toBeDefined();
    expect(flag.severity).toBe('medium');
    expect(flag.text).not.toContain('New customer');
    expect(result.score).toBe(90); // 100-10
  });

  test('exactly 5.0x average, new customer → -30 (high-value) PLUS an un-suppressed -10 (first-order penalty) — DISCOVERED QUIRK: the alreadyFlagged suppression only matches capitalized "New customer", but the 5x tier\'s own flag text uses lowercase "new customer", so the case-sensitive `includes("New customer")` check fails to catch it', async () => {
    // This is a genuine, previously undocumented behavior difference from
    // the 3x tier (whose flag text IS "New customer with order..." —
    // capitalized — which DOES successfully suppress the -10). At the 5x
    // tier the suppression silently does not fire, so both penalties land:
    // raw = 100 - 30 (high-value) - 10 (first-order, NOT suppressed) - 10 (dial) = 50.
    const order = makeOrder({ amount: 500 });
    const allOrders = [
      { id: 'hv-hist-5', amount: 100, email: 'hist5@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-6', amount: 100, email: 'hist6@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 10 });
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('extreme anomaly from new customer'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('First order from this email'))).toBe(true); // NOT suppressed, unlike the 3x-tier case
    expect(result.score).toBe(50); // NOT 60 — the second -10 is real
  });

  test('exactly 5.0x average, RETURNING customer → -25, still "high" severity (extreme tier is high regardless), no "new customer" suffix', async () => {
    const order = makeOrder({ amount: 500, email: 'returning2@example.com' });
    const allOrders = [
      { id: 'hv-hist-7', amount: 100, email: 'returning2@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-8', amount: 100, email: 'other2@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({
      order,
      allOrders,
      disputes: [{ id: 'sup-3', orderId: 'hv-hist-7' }, { id: 'sup-4', orderId: 'hv-hist-8' }],
      ipPenalty: 10, // 100-25-10=65
    });
    const flag = result.flags.find((f) => f.text.includes('extreme anomaly'));
    expect(flag).toBeDefined();
    expect(flag.severity).toBe('high');
    expect(flag.text).not.toContain('new customer');
    expect(result.score).toBe(65);
  });

  test('2.9x average (just below the 3x boundary) → no high-value penalty at all', async () => {
    const order = makeOrder({ amount: 290 });
    const allOrders = [
      { id: 'hv-hist-9', amount: 100, email: 'h9@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-10', amount: 100, email: 'h10@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('above store average'))).toBe(false);
  });

  test('DOCUMENTED DEAD CODE: the second high-value check (guarded by !highValuePenaltyApplied) never fires when the first already did — only ONE high-value flag ever appears', async () => {
    const order = makeOrder({ amount: 300 });
    const allOrders = [
      { id: 'hv-hist-11', amount: 100, email: 'h11@example.com', createdAt: hoursAgo(48) },
      { id: 'hv-hist-12', amount: 100, email: 'h12@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders });
    const highValueFlags = result.flags.filter((f) => f.text.includes('above store average'));
    expect(highValueFlags.length).toBe(1); // never 2, proving the second block is unreachable here
  });
});

// ─── Tier 2 — "First order from this email" penalty and its suppression ───

describe('Tier 2 — new-customer first-order penalty (-10) and its suppression by an existing "New customer" flag', () => {
  test('new customer, amount >= 150, NO high-value trigger (no order history at all) → -10 fires standalone, medium', async () => {
    const order = makeOrder({ amount: 150 }); // avgOrderValue=0 (no allOrders) → high-value block skipped entirely
    const result = await runScoring({ order, allOrders: [] });
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('First order from this email with value $150'))).toBe(true);
    expect(result.score).toBe(90); // 100-10, single medium flag, no floor
  });

  test('new customer, amount < 150 → penalty does not apply at all', async () => {
    const order = makeOrder({ amount: 149 });
    const result = await runScoring({ order, allOrders: [] });
    expect(result.flags.some((f) => f.text.includes('First order from this email'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('SUPPRESSION: when the high-value block already produced a "New customer..." flag, the -10 "first order" penalty is NOT additionally applied', async () => {
    // Same fixture as the 3x/new-customer high-value test: -20 fires with
    // text containing "New customer". amount=300 >= 150, so the -10 check
    // would normally also fire — but `alreadyFlagged` suppresses it.
    const order = makeOrder({ amount: 300 });
    const allOrders = [
      { id: 'sup-hv-1', amount: 100, email: 'sh1@example.com', createdAt: hoursAgo(48) },
      { id: 'sup-hv-2', amount: 100, email: 'sh2@example.com', createdAt: hoursAgo(50) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('New customer with order 3x above store average'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('First order from this email'))).toBe(false);
    // raw = 100-20=80 (single high) → floor caps to 70
    expect(result.score).toBe(70);
  });
});

// ─── Tier 2 — First-Seen Device Penalty ────────────────────────────────────

describe('Tier 2 — first-seen device / cold-start device penalty', () => {
  test('brand-new device (no prior orders) + amount >= 100 → -15, medium', async () => {
    const order = makeOrder({ amount: 100, deviceFingerprint: 'brand-new-device' });
    const result = await runScoring({ order, allOrders: [] });
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('First-time device with order $100'))).toBe(true);
    expect(result.score).toBe(85); // 100-15
  });

  test('brand-new device + amount < 100 → no penalty', async () => {
    const order = makeOrder({ amount: 99, deviceFingerprint: 'brand-new-device-2' });
    const result = await runScoring({ order, allOrders: [] });
    expect(result.flags.some((f) => f.text.includes('First-time device'))).toBe(false);
  });

  test('device seen < 24h ago + amount >= 200 → -10, medium (distinct from the first-time tier)', async () => {
    // history amount is deliberately 100 (not 50) to keep orderMultiple
    // (200/100=2.0) below the 3x high-value threshold — an earlier
    // version of this fixture used amount:50, which produced an
    // unintended 4x high-value trigger contaminating the score.
    const order = makeOrder({ amount: 200, deviceFingerprint: 'seen-recently-device' });
    const allOrders = [
      { id: 'dev-seen-1', amount: 100, deviceFingerprint: 'seen-recently-device', email: 'x@example.com', createdAt: hoursAgo(2) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('New device') && f.text.includes('high-value order'))).toBe(true);
    expect(result.score).toBe(90); // 100-10
  });

  test('device seen < 24h ago + amount < 200 → no penalty (neither tier applies)', async () => {
    // history amount kept at 100 (not 50) for the same reason as the
    // sibling test above — avoids an incidental high-value trigger
    // (199/50=3.98x would cross the 3x threshold; 199/100=1.99x does not).
    const order = makeOrder({ amount: 199, deviceFingerprint: 'seen-recently-device-2' });
    const allOrders = [
      { id: 'dev-seen-2', amount: 100, deviceFingerprint: 'seen-recently-device-2', email: 'x@example.com', createdAt: hoursAgo(2) },
    ];
    const result = await runScoring({ order, allOrders });
    expect(result.flags.some((f) => f.text.includes('First-time device') || f.text.includes('New device'))).toBe(false);
    expect(result.flags.some((f) => f.text.includes('above store average'))).toBe(false); // confirms no incidental high-value contamination either
  });
});

// ─── Tier 2 — Unusual Hour ──────────────────────────────────────────────────

describe('Tier 2 — unusual hour (2AM-5AM inclusive)', () => {
  test.each([
    [1, false],
    [2, true],
    [3, true],
    [4, true],
    [5, true],
    [6, false],
  ])('hour=%i → unusual-hour flag present: %s', async (hour, shouldFlag) => {
    const order = makeOrder({ amount: 50, createdAt: new Date(2025, 5, 15, hour, 0, 0) });
    const result = await runScoring({ order });
    const hasFlag = result.flags.some((f) => f.text.includes('unusual hour'));
    expect(hasFlag).toBe(shouldFlag);
    expect(result.score).toBe(shouldFlag ? 90 : 100);
  });
});

// ─── Tier 2 — Large Line Items ──────────────────────────────────────────────

describe('Tier 2 — unusually large order (line items)', () => {
  test('exactly 10 items → no penalty (threshold is > 10, not >=)', async () => {
    const order = makeOrder({ amount: 50, lineItems: JSON.stringify(Array(10).fill({ sku: 'x' })) });
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.text.includes('different items'))).toBe(false);
    expect(result.score).toBe(100);
  });

  test('11 items → -10, medium', async () => {
    const order = makeOrder({ amount: 50, lineItems: JSON.stringify(Array(11).fill({ sku: 'x' })) });
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('11 different items'))).toBe(true);
    expect(result.score).toBe(90);
  });

  test('malformed lineItems JSON is silently swallowed — no throw, no penalty', async () => {
    const order = makeOrder({ amount: 50, lineItems: 'not-valid-json[' });
    const result = await runScoring({ order });
    expect(result.flags.some((f) => f.text.includes('different items'))).toBe(false);
    expect(result.score).toBe(100);
  });
});

// ─── Tier 3 — Positive Signals ──────────────────────────────────────────────
//
// Every test in this block uses a -30 ipPenalty "dial" (medium severity) so
// that the positive bonus under test is recoverable exactly from the final
// score: score = 100 - 30 + bonus = 70 + bonus. Without the dial, the
// function's own `Math.min(100, score)` clamp would swallow any bonus,
// since there are no other penalties driving the raw score below 100.

describe('Tier 3 — ECI / AVS / CVV2 (cold-start static weights, merchantId=null)', () => {
  test('ECI 5 (full 3DS) → static weight 4.0 → bonus = round(4.0*5) = 20', async () => {
    const order = makeOrder({ amount: 50, eciCode: '5' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('3D Secure authenticated (ECI 5)'))).toBe(true);
    expect(result.score).toBe(90); // 70 + 20
  });

  test('ECI 6 (attempted 3DS) → static weight 3.5 → bonus = round(3.5*5) = round(17.5) = 18 (rounds up)', async () => {
    const order = makeOrder({ amount: 50, eciCode: '6' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('3D Secure authenticated (ECI 6)'))).toBe(true);
    expect(result.score).toBe(88); // 70 + 18
  });

  test('ECI 7 (no 3DS) → not in the ["5","6"] set → no bonus at all', async () => {
    const order = makeOrder({ amount: 50, eciCode: '7' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('3D Secure'))).toBe(false);
    expect(result.score).toBe(70);
  });

  test('AVS=Y → static weight 2.0 → bonus = round(2.0*5) = 10', async () => {
    const order = makeOrder({ amount: 50, avsResponse: 'Y' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Address verification confirmed (AVS Y)'))).toBe(true);
    expect(result.score).toBe(80); // 70 + 10
  });

  test('AVS=N → no bonus', async () => {
    const order = makeOrder({ amount: 50, avsResponse: 'N' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Address verification'))).toBe(false);
    expect(result.score).toBe(70);
  });

  test('CVV2=M → static weight 1.0 → bonus = round(1.0*5) = 5', async () => {
    const order = makeOrder({ amount: 50, cvv2Response: 'M' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('CVV2 matched at authorization'))).toBe(true);
    expect(result.score).toBe(75); // 70 + 5
  });

  test('ECI 5 + AVS Y + CVV2 M all together, under the MAX_POSITIVE_BOOST cap (20+10+5=35 total... wait this exceeds 25, see cap test below) — this test only verifies additivity below the cap using ECI+AVS alone (20+10=30, still over 25 — use AVS+CVV2 alone: 10+5=15, under cap)', async () => {
    const order = makeOrder({ amount: 50, avsResponse: 'Y', cvv2Response: 'M' });
    const result = await runScoring({ order, ipPenalty: 30 });
    expect(result.score).toBe(85); // 70 + 10 + 5 = 85, total bonus 15 is under the 25 cap so it's untouched
  });
});

describe('Tier 3 — returning customer', () => {
  test('1-2 previous good orders (no disputes) → +10 flat bonus, no span check', async () => {
    const order = makeOrder({ amount: 50, email: 'loyal@example.com' });
    const allOrders = [
      { id: 'good-1', amount: 50, email: 'loyal@example.com', createdAt: hoursAgo(100) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Returning customer — 1 previous order'))).toBe(true);
    expect(result.score).toBe(80); // 70 + 10
  });

  test('3+ previous good orders spanning >= 14 days → +20 ("trusted customer"), no rapid-history flag', async () => {
    const order = makeOrder({ amount: 50, email: 'trusted@example.com' });
    const allOrders = [
      { id: 'good-2', amount: 50, email: 'trusted@example.com', createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000) },
      { id: 'good-3', amount: 50, email: 'trusted@example.com', createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000) },
      { id: 'good-4', amount: 50, email: 'trusted@example.com', createdAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Trusted customer — 3 orders over'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('trust farming'))).toBe(false);
    expect(result.score).toBe(90); // 70 + 20
  });

  test('3+ previous good orders spanning < 14 days but >= 3 days → +8 bonus, no rapid-history flag', async () => {
    const order = makeOrder({ amount: 50, email: 'semi@example.com' });
    const allOrders = [
      { id: 'good-5', amount: 50, email: 'semi@example.com', createdAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000) },
      { id: 'good-6', amount: 50, email: 'semi@example.com', createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000) },
      { id: 'good-7', amount: 50, email: 'semi@example.com', createdAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Returning customer — 3 recent orders'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('trust farming'))).toBe(false);
    expect(result.score).toBe(78); // 70 + 8
  });

  test('3+ previous good orders spanning < 3 days → +8 bonus AND a simultaneous -10 "trust farming" flag', async () => {
    const order = makeOrder({ amount: 50, email: 'farmer@example.com' });
    const allOrders = [
      { id: 'good-8', amount: 50, email: 'farmer@example.com', createdAt: hoursAgo(40) },
      { id: 'good-9', amount: 50, email: 'farmer@example.com', createdAt: hoursAgo(20) },
      { id: 'good-10', amount: 50, email: 'farmer@example.com', createdAt: hoursAgo(2) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Returning customer — 3 recent orders'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('possible trust farming pattern'))).toBe(true);
    // score = 100 - 30(dial) - 10(trust farming) + 8(bonus) = 68
    expect(result.score).toBe(68);
  });

  test('disputed previous orders are excluded from the "good orders" count entirely', async () => {
    const order = makeOrder({ amount: 50, email: 'disputed@example.com' });
    const allOrders = [
      { id: 'disputed-1', amount: 50, email: 'disputed@example.com', createdAt: hoursAgo(100) },
    ];
    const disputes = [{ id: 'd-1', orderId: 'disputed-1' }];
    const result = await runScoring({ order, allOrders, disputes, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Returning customer'))).toBe(false);
    expect(result.score).toBe(70); // no bonus at all — the one prior order was excluded
  });
});

describe('Tier 3 — trusted device', () => {
  test('2+ prior successful orders on the same device (no disputes) → +15', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'trusted-device-1' });
    const allOrders = [
      { id: 'dev-good-1', amount: 50, deviceFingerprint: 'trusted-device-1', email: 'a@example.com', createdAt: hoursAgo(100) },
      { id: 'dev-good-2', amount: 50, deviceFingerprint: 'trusted-device-1', email: 'b@example.com', createdAt: hoursAgo(200) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Known trusted device — 2 previous successful orders'))).toBe(true);
    expect(result.score).toBe(85); // 70 + 15
  });

  test('only 1 prior successful order on the same device → below threshold, no bonus', async () => {
    const order = makeOrder({ amount: 50, deviceFingerprint: 'trusted-device-2' });
    const allOrders = [
      { id: 'dev-good-3', amount: 50, deviceFingerprint: 'trusted-device-2', email: 'a@example.com', createdAt: hoursAgo(100) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 30 });
    expect(result.positives.some((p) => p.text.includes('Known trusted device'))).toBe(false);
    expect(result.score).toBe(70);
  });
});

describe('Tier 3 — authenticated account bonus (+5) is applied directly to score, OUTSIDE the MAX_POSITIVE_BOOST cap', () => {
  test('customerLoginId present → +5, stacks additively alongside a separately-capped Tier 3 bonus group', async () => {
    // ECI 5 (20) + AVS Y (10) + CVV2 M (5) + returning-customer trusted
    // (>=14 days span, +20) + trusted device (+15) = 70 total into the
    // capped pool → capped to 25. Login bonus (+5) is added to `score`
    // directly, BEFORE the cap calculation, and is untouched by it.
    // score = 100 - 40(dial) + 5(login, added early) + 25(capped bonus) = 90
    const order = makeOrder({
      amount: 50,
      email: 'vip@example.com',
      deviceFingerprint: 'vip-device',
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
      customerLoginId: 'shopify-cust-123',
    });
    const allOrders = [
      { id: 'vip-good-1', amount: 50, email: 'vip@example.com', deviceFingerprint: 'vip-device', createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000) },
      { id: 'vip-good-2', amount: 50, email: 'vip@example.com', deviceFingerprint: 'vip-device', createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000) },
      { id: 'vip-good-3', amount: 50, email: 'vip@example.com', deviceFingerprint: 'vip-device', createdAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 40 });
    expect(result.positives.some((p) => p.text.includes('Authenticated Shopify account'))).toBe(true);
    expect(result.score).toBe(90);
  });
});

describe('Tier 3 — MAX_POSITIVE_BOOST cap (25)', () => {
  test('stacking ECI(20) + AVS(10) + CVV2(5) + returning-trusted(20) + trusted-device(15) = 70 raw is capped down to exactly 25', async () => {
    // score = 100 - 40(dial) + min(70,25) = 60 + 25 = 85.
    // If the cap did NOT apply, score would clamp at the function's own
    // Math.min(100,...) ceiling → 100 - 40 + 70 = 130 → 100. The two
    // outcomes (85 vs 100) are clearly distinguishable, proving the cap
    // is doing real work here.
    const order = makeOrder({
      amount: 50,
      email: 'capped@example.com',
      deviceFingerprint: 'capped-device',
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
    });
    const allOrders = [
      { id: 'cap-good-1', amount: 50, email: 'capped@example.com', deviceFingerprint: 'capped-device', createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000) },
      { id: 'cap-good-2', amount: 50, email: 'capped@example.com', deviceFingerprint: 'capped-device', createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000) },
      { id: 'cap-good-3', amount: 50, email: 'capped@example.com', deviceFingerprint: 'capped-device', createdAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000) },
    ];
    const result = await runScoring({ order, allOrders, ipPenalty: 40 });
    expect(result.score).toBe(85); // NOT 100 — proves the 25 cap, not just the outer [0,100] clamp
  });
});

// ─── Documented Gap — Homoglyph Bypass in riskScoring.js's normalizeEmail ──

describe('documented gap — homoglyph email spoofing bypasses velocity/dedup checks', () => {
  test('a Cyrillic-"а" variant of an email is NOT recognized as a duplicate for email-velocity purposes, because utils.js normalizeEmail (used by riskScoring.js) has no homoglyph map', async () => {
    // "\u0430hmed@example.com" uses Cyrillic а (U+0430) in place of Latin "a".
    // similarity.js's normalizeEmail WOULD fold this to "ahmed@example.com"
    // via its HOMOGLYPH_MAP, but riskScoring.js imports normalizeEmail from
    // utils.js, which has no such mapping — so these are treated as two
    // completely distinct emails for velocity purposes.
    const spoofedEmail = '\u0430hmed@example.com'; // Cyrillic а
    const realEmail = 'ahmed@example.com';

    const order = makeOrder({ amount: 50, email: spoofedEmail, ipAddress: 'homoglyph-test-ip' });
    const allOrders = [
      { id: 'homo-1', amount: 50, email: realEmail, ipAddress: 'ip-1', createdAt: minutesAgo(10) },
      { id: 'homo-2', amount: 50, email: realEmail, ipAddress: 'ip-2', createdAt: minutesAgo(20) },
      { id: 'homo-3', amount: 50, email: realEmail, ipAddress: 'ip-3', createdAt: minutesAgo(30) },
    ];
    const result = await runScoring({ order, allOrders });

    // If normalizeEmail folded homoglyphs, this would be a 3-match email
    // velocity event (>=3 threshold) and would produce a flag. It does not.
    expect(result.flags.some((f) => f.text.includes('same email in last 6 hours'))).toBe(false);
    expect(result.score).toBe(100);
  });
});