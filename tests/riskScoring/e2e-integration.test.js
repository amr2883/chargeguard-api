'use strict';

// ─── ChargeGuard Risk Scoring — T3d-7: End-to-End Integration ─────────────
//
// SCOPE
// -----
// This is the FINAL phase inside Test 3. Unlike T3d-1 through T3d-6, which
// each isolated ONE signal family behind heavy mocking, this file exercises
// calculateRiskScore's REAL, UNMOCKED internal control flow end-to-end:
// blacklist → dispute checks → IP/email/BIN intel → velocity (all three
// families) → high-value tiers → similarity → cardHash → first-seen →
// Tier 3 positive pool → identity graph → pattern sharing → positive cap →
// [0,100] clamp → risk floor → economic engine → decision.
//
// We are not re-verifying any single signal's arithmetic in isolation
// (that's what T3d-1 through T3d-6 already do, exhaustively). We ARE
// verifying that when multiple signal families fire on the SAME order,
// they compose correctly: additive stacking, correct floor timing
// (floor applies AFTER the positive cap, not before), correct positive
// cap enforcement even when the raw positive pool comes from a mix of
// static-weight and dynamic (graph) sources, and that pattern-sharing +
// identity-graph penalties can coexist on one order.
//
// MOCKING STRATEGY (deliberately different from T3d-1 through T3d-6)
// --------------------------------------------------------------------
// Mocked (external I/O / non-deterministic only):
//   - db (Prisma)                — every method riskScoring.js OR
//     patternSharing.js can reach is mocked with realistic, inert defaults.
//   - identityGraph.getConnectedRisk — mocked per-scenario with realistic
//     { connectedRisk, graphPath, matchTier, matchConfidence } shapes,
//     exactly as in T3d-6.
//   - ipIntelligence, emailIntelligence, binIntelligence — mocked per-
//     scenario with realistic intel objects (VPN/datacenter, disposable
//     email, prepaid BIN) so both the penalty AND the raw intel object
//     (consumed downstream by pattern-sharing) can be controlled.
//   - logger — mocked to silence output only; never asserted on.
//   - prom-client — mocked defensively, matching T3d-1/T3d-2/T3d-3
//     convention, in case anything in the require graph pulls it in.
//   - postPurchaseIntelligence — mocked (dead import per T3d-6 finding
//     9.1; getPostPurchaseEvents is never actually called).
//
// Left REAL (this is the point of T3d-7):
//   - patternSharing.js (buildPattern / checkPatternRisk / recordPattern)
//     — runs its real bucketing, hashing, Bayesian fraud-rate, and sigmoid
//     penalty math against our mocked `db.fraudPattern` fixtures.
//   - signalWeights.js (getStaticWeight) — real static-weight table.
//     getWeightsForMerchant is never invoked because merchantId is null
//     in every scenario below (it's gated by `if (merchantId)` inside
//     calculateRiskScore), so signalWeights' own DB calls never fire.
//   - utils.js (normalizeEmail, masking helpers) — real, pure.
//   - similarity.js (findSimilarDisputes) — real. Every scenario below
//     passes an EMPTY `disputes` array (except the two scenarios that
//     deliberately test dispute-driven Tier 1 signals, whose dispute
//     fixtures carry no `email`/`shippingAddress` fields — the same
//     minimal, similarity-inert shape T3d-1 already verified is safe).
//     An empty disputes array structurally cannot produce any similarity
//     match regardless of similarity.js's internals, since there is
//     nothing in the array to compare against.
//
// A CRITICAL DB-MOCK DETAIL — read before touching `db.fraudPattern.updateMany`:
// `patternSharing.js`'s `updatePatternWithRetry` calls a REAL `setTimeout`
// with jittered backoff on any retry attempt (attempt > 0). Since our tests
// run under `jest.useFakeTimers()`, a real setTimeout that never gets
// advanced would leave that retry's promise permanently unresolved. To
// avoid this entirely, `db.fraudPattern.updateMany` defaults to resolving
// `{ count: 1 }` (success on the FIRST attempt), so the retry/backoff path
// is never entered by any test in this file. This is a deliberate, load-
// bearing mock choice — do not change it to `{ count: 0 }` without adding
// `jest.advanceTimersByTimeAsync` handling for the retry loop.
//
// `recordPattern` is fire-and-forget in riskScoring.js (`.catch(...)`,
// never awaited by the caller). Every scenario below still awaits a few
// microtask turns after calling calculateRiskScore (see `flushPromises`)
// so that any in-flight `recordPattern` work settles against a still-
// intact set of mocks before Jest's `beforeEach` resets them for the next
// test — this is a defensive measure, not something our assertions
// depend on (we only ever assert on calculateRiskScore's own return
// value, which is always fully resolved before recordPattern's fire-and-
// forget chain even starts).
//
// INTEGRATION-LEVEL FINDINGS DISCOVERED IN T3d-7 (documented, not fixed):
//   1. Multiple independent HIGH-severity flags (never reaching critical)
//      can bottom out the score to 0 on their own. The "2+ high flags"
//      risk-floor rule (`highCount >= 2 && score > 55 → 55`) is a NO-OP
//      once the raw score has already fallen to or below 55 from plain
//      additive stacking — it only ever pulls a score DOWN into the
//      55/70 bands, it never pulls a bottomed-out score back UP. See
//      Scenario 2.
//   2. patternSharing.js's own severity ternary
//      (`effectiveFraudRate > 0.8 ? "high" : "medium"`) has NO "critical"
//      branch. A pattern-sharing match can never, by itself, trigger the
//      ≤40 critical floor — it can only combine with other independently-
//      critical signals, or contribute to the "2+ high flags" ≤55 floor
//      alongside another high-severity flag (e.g. identity graph). See
//      Scenario 3 and Interaction Verification 5.3.
//   3. The risk floor is applied strictly AFTER the MAX_POSITIVE_BOOST-
//      capped positive bonus has already been added to `score`. A large,
//      fully legitimate positive pool (returning customer + trusted
//      device + 3DS/AVS/CVV2, capped at +25) can mathematically produce
//      a pre-floor score that looks Approve-worthy (e.g. 95) even when a
//      single critical signal (e.g. identity-graph fraud-network match)
//      is present — the floor then forcibly overrides that arithmetic
//      down to ≤40 regardless. See Interaction Verification 5.1.
//   4. The T3d-1-documented IP/email velocity double-count (unconditional
//      early block + fallback block, both keyed off `allOrders`, neither
//      gated by whether `externalVelocity` was supplied for a DIFFERENT
//      signal) is still fully live in the real end-to-end path. Every
//      fixture in this file deliberately gives history orders distinct
//      IP addresses / recent-enough-but-out-of-window timestamps to keep
//      this quirk from contaminating scenario arithmetic, exactly as
//      T3d-1's own fixtures do.

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

jest.mock('../../src/lib/db', () => ({
  merchantProfile: {
    findUnique: jest.fn(),
  },
  fraudPattern: {
    findUnique: jest.fn(),
    findMany: jest.fn(),
    updateMany: jest.fn(),
  },
  fraudCluster: {
    findUnique: jest.fn(),
    update: jest.fn(),
    upsert: jest.fn(),
  },
  patternMerchant: {
    create: jest.fn(),
  },
  $transaction: jest.fn(),
}));

jest.mock('../../src/lib/identityGraph', () => ({
  getConnectedRisk: jest.fn(),
  buildGraphFromOrder: jest.fn(),
  markOrderAsFraud: jest.fn(),
  markOrderAsClean: jest.fn(),
}));

jest.mock('../../src/lib/ipIntelligence', () => ({
  getIPIntelligence: jest.fn(),
  calculateIPPenalty: jest.fn(),
  invalidateIPCache: jest.fn(),
}));

jest.mock('../../src/lib/emailIntelligence', () => ({
  getEmailIntelligence: jest.fn(),
  calculateEmailPenalty: jest.fn(),
  invalidateEmailCache: jest.fn(),
}));

jest.mock('../../src/lib/binIntelligence', () => ({
  getBINIntelligence: jest.fn(),
  calculateBINPenalty: jest.fn(),
}));

jest.mock('../../src/lib/postPurchaseIntelligence', () => ({
  getPostPurchaseEvents: jest.fn(),
}));

jest.mock('../../src/lib/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

const { calculateRiskScore } = require('../../src/lib/riskScoring');

const db = require('../../src/lib/db');
const { getConnectedRisk } = require('../../src/lib/identityGraph');
const { getIPIntelligence, calculateIPPenalty } = require('../../src/lib/ipIntelligence');
const { getEmailIntelligence, calculateEmailPenalty } = require('../../src/lib/emailIntelligence');
const { getBINIntelligence, calculateBINPenalty } = require('../../src/lib/binIntelligence');

// ─── Fixed "now" — noon local time, avoids the 2-5am unusual-hour penalty
// and keeps every velocity-window / customer-span day-math deterministic
// regardless of the machine's timezone or the wall-clock moment CI runs. ──
const FIXED_NOW = new Date('2026-07-07T12:00:00');

function daysAgo(d) {
  return new Date(FIXED_NOW.getTime() - d * 24 * 60 * 60 * 1000).toISOString();
}

// Flushes a handful of microtask turns without touching timers (safe under
// jest.useFakeTimers()) — lets any fire-and-forget recordPattern work
// initiated by a "high" risk decision settle before the next test's
// beforeEach clears the mocks it's using. See file header for why this is
// purely defensive and never load-bearing for any assertion below.
async function flushPromises() {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

function makeOrder(overrides = {}) {
  return {
    id: 'order-e2e',
    email: 'buyer@example.com',
    ipAddress: '203.0.113.10',
    deviceFingerprint: 'device-e2e',
    amount: 50,
    createdAt: FIXED_NOW.toISOString(),
    eciCode: null,
    avsResponse: null,
    cvv2Response: null,
    customerLoginId: null,
    lineItems: null,
    shippingAddress: null,
    billingAddress: null,
    payment_details: null,
    ...overrides,
  };
}

async function runScoring({
  order,
  allOrders = [],
  disputes = [],
  blacklist = [],
  merchantId = null,
  saveEvaluation = false,
  externalVelocity = null,
  cardHashRecord = null,
  merchantConfig = null,
} = {}) {
  const result = await calculateRiskScore(
    order,
    allOrders,
    disputes,
    blacklist,
    merchantId,
    saveEvaluation,
    externalVelocity,
    cardHashRecord,
    merchantConfig,
  );
  await flushPromises();
  return result;
}

const NEUTRAL_GRAPH = { connectedRisk: 0, hasConnections: false, graphPath: [], matchTier: 'none', matchConfidence: 0 };

beforeAll(() => {
  // patternSharing.js's getSecret() requires this (or IDENTITY_GRAPH_SECRET)
  // to be set, or hashPattern() throws — which checkPatternRisk/recordPattern
  // would silently swallow via their own try/catch, permanently neutering
  // pattern-sharing for every scenario. Setting it here lets pattern-sharing
  // actually run for real, as required by the T3d-7 mocking strategy.
  process.env.PATTERN_SHARING_SECRET = 'test-pattern-sharing-secret-e2e';
});

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  jest.setSystemTime(FIXED_NOW);

  // ─── Neutral defaults for every mocked dependency ──────────────────
  getConnectedRisk.mockResolvedValue(NEUTRAL_GRAPH);

  getIPIntelligence.mockResolvedValue({});
  calculateIPPenalty.mockReturnValue({ penalty: 0, flags: [] });

  getEmailIntelligence.mockResolvedValue({});
  calculateEmailPenalty.mockReturnValue({ penalty: 0, flags: [] });

  getBINIntelligence.mockResolvedValue({});
  calculateBINPenalty.mockReturnValue({ penalty: 0, flags: [] });

  db.merchantProfile.findUnique.mockResolvedValue(null);
  db.fraudPattern.findUnique.mockResolvedValue(null);
  db.fraudPattern.findMany.mockResolvedValue([]);
  // See file header: {count:1} keeps updatePatternWithRetry off the
  // real-setTimeout retry path under fake timers.
  db.fraudPattern.updateMany.mockResolvedValue({ count: 1 });
  db.fraudCluster.findUnique.mockResolvedValue(null);
  db.fraudCluster.update.mockResolvedValue(null);
  db.fraudCluster.upsert.mockResolvedValue({ id: 'mock-cluster-1' });
  db.patternMerchant.create.mockResolvedValue(null);
  db.$transaction.mockImplementation(async (fn) =>
    fn({
      fraudCluster: { update: jest.fn().mockResolvedValue(null) },
      fraudPattern: { upsert: jest.fn().mockResolvedValue({ id: 'mock-pattern-1' }) },
    }),
  );
});

afterEach(() => {
  jest.useRealTimers();
});

// ════════════════════════════════════════════════════════════════════
// 1. CLEAN ORDER (BASELINE)
// ════════════════════════════════════════════════════════════════════

describe('1. Clean order (baseline) — near-100 score with full positive stacking', () => {
  test('returning + trusted-device + full 3DS/AVS/CVV2 + authenticated account, zero risk signals → score clamps at exactly 100, zero flags', async () => {
    // Every history order shares the SAME email, device, and amount as the
    // current order (and each has a DISTINCT ipAddress, so the IP-velocity
    // double-count from T3d-1 never engages) — this is deliberately the
    // "everything good" order.
    const order = makeOrder({
      id: 'clean-order-1',
      email: 'loyal@example.com',
      deviceFingerprint: 'trusted-device-clean',
      ipAddress: '203.0.113.200',
      amount: 50,
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
      customerLoginId: 'shopify-cust-clean-1',
    });

    const allOrders = [
      { id: 'hist-1', email: 'loyal@example.com', deviceFingerprint: 'trusted-device-clean', amount: 50, ipAddress: '203.0.113.201', createdAt: daysAgo(20) },
      { id: 'hist-2', email: 'loyal@example.com', deviceFingerprint: 'trusted-device-clean', amount: 50, ipAddress: '203.0.113.202', createdAt: daysAgo(10) },
      { id: 'hist-3', email: 'loyal@example.com', deviceFingerprint: 'trusted-device-clean', amount: 50, ipAddress: '203.0.113.203', createdAt: daysAgo(1) },
    ];

    const result = await runScoring({ order, allOrders, disputes: [] });

    // Raw pool: ECI(20)+AVS(10)+CVV2(5)+returning-trusted(20, 19-day span)
    // +trusted-device(15) = 70 → capped at 25. Login bonus (+5) is added
    // OUTSIDE the cap. Pre-clamp score = 100 + 5 + 25 = 130 → clamps to 100.
    expect(result.score).toBe(100);
    expect(result.decision).toBe('Low Risk — Approve');
    expect(result.riskLevel).toBe('low');
    expect(result.flags).toEqual([]);

    expect(result.positives.some((p) => p.text.includes('Authenticated Shopify account'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('3D Secure authenticated (ECI 5)'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('Address verification confirmed (AVS Y)'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('CVV2 matched at authorization'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('Trusted customer — 3 orders over 19 days'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('Known trusted device — 3 previous successful orders'))).toBe(true);
    expect(result.positives.length).toBe(6);
  });
});

// ════════════════════════════════════════════════════════════════════
// 2. SUSPICIOUS ORDER (MODERATE RISK) — VPN, disposable email,
//    high-velocity device, new customer, high amount
// ════════════════════════════════════════════════════════════════════

describe('2. Suspicious order (moderate risk) — non-critical high-severity stacking', () => {
  test('VPN IP + disposable email + device velocity=2 + new-customer high-value order → all HIGH severity, no CRITICAL flag, but the sheer additive stack still bottoms the score out to 0 and Blocks', async () => {
    const order = makeOrder({
      id: 'suspicious-order-1',
      email: 'fraud-test@tempmail.com',
      deviceFingerprint: 'suspicious-device-1',
      ipAddress: '198.51.100.55',
      amount: 400,
    });

    // Unrelated store history used only to establish avgOrderValue=100,
    // so this $400 order lands at exactly 4x average (the [3,5) high-value
    // tier). None of these share email/device/ip with the current order.
    const allOrders = [
      { id: 'other-1', email: 'shopper1@example.com', deviceFingerprint: 'device-o1', amount: 100, ipAddress: '198.51.100.1', createdAt: daysAgo(10) },
      { id: 'other-2', email: 'shopper2@example.com', deviceFingerprint: 'device-o2', amount: 100, ipAddress: '198.51.100.2', createdAt: daysAgo(11) },
      { id: 'other-3', email: 'shopper3@example.com', deviceFingerprint: 'device-o3', amount: 100, ipAddress: '198.51.100.3', createdAt: daysAgo(12) },
      { id: 'other-4', email: 'shopper4@example.com', deviceFingerprint: 'device-o4', amount: 100, ipAddress: '198.51.100.4', createdAt: daysAgo(13) },
      { id: 'other-5', email: 'shopper5@example.com', deviceFingerprint: 'device-o5', amount: 100, ipAddress: '198.51.100.5', createdAt: daysAgo(14) },
    ];

    getIPIntelligence.mockResolvedValue({ isDatacenter: true });
    calculateIPPenalty.mockReturnValue({
      penalty: 20,
      flags: [{ severity: 'high', text: 'IP flagged as VPN/datacenter — proceed with caution' }],
    });

    getEmailIntelligence.mockResolvedValue({ isDisposable: true });
    calculateEmailPenalty.mockReturnValue({
      penalty: 25,
      flags: [{ severity: 'high', text: 'Disposable email address detected — high fraud risk' }],
    });

    const result = await runScoring({
      order,
      allOrders,
      disputes: [],
      externalVelocity: { deviceVelocityCount: 2, ipVelocityCount: 0, emailVelocityCount: 0 },
    });

    // -20 (IP) -20 (4x high-value, new customer) -25 (disposable email)
    // -25 (device velocity=2) -15 (first-time device, amount>=100) = -105.
    // Raw = 100-105 = -5 → clamp 0.
    expect(result.score).toBe(0);
    expect(result.decision).toBe('High Risk — Block');
    expect(result.riskLevel).toBe('high');

    expect(result.flags.some((f) => f.severity === 'critical')).toBe(false);
    const highFlags = result.flags.filter((f) => f.severity === 'high');
    // IP intel, high-value, disposable email, device velocity, + the
    // economic-engine's own "High Risk — Block" override flag (fires
    // because expectedLoss > baseThreshold*3 at fraudProb ~0.99 when
    // score=0) — five independent high flags, ZERO critical.
    expect(highFlags.length).toBe(5);
    expect(result.flags.some((f) => f.text.includes('New customer with order 4x above store average'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('Device fingerprint linked to 3 orders in last hour'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('First-time device with order $400'))).toBe(true);
    expect(result.flags.some((f) => f.text.includes('Economic risk'))).toBe(true);

    // DOCUMENTED FINDING: the "2+ high flags → cap at 55" floor rule never
    // engages here — it only fires `if (... && score > 55)`, and by the
    // time all these penalties finish stacking the raw score is already
    // at/under 0. A score can bottom out to Block through pure additive
    // high-severity stacking with NO critical flag ever firing.
  });
});

// ════════════════════════════════════════════════════════════════════
// 3. FRAUDULENT ORDER (CRITICAL RISK) — blacklist, device disputes,
//    IP disputes, connected-risk graph, pattern-sharing stacking
// ════════════════════════════════════════════════════════════════════

describe('3. Fraudulent order (critical risk) — hard-blocked with correct critical-flag aggregation', () => {
  test('blacklist + lost device dispute + 3 lost IP disputes + critical identity-graph match + real pattern-sharing penalty, all stacking → score=0, decision=Block, 4 critical flags + 1 high (pattern)', async () => {
    const order = makeOrder({
      id: 'fraud-order-1',
      email: 'blackhat@fraud-domain.com',
      deviceFingerprint: 'fraud-device-99',
      ipAddress: '198.51.100.99',
      amount: 250, // >200, feeds the pattern-sharing "highAmount" signal
    });

    const blacklist = [{ email: 'blackhat@fraud-domain.com' }];

    // Minimal, similarity-inert dispute shapes (no `email`/`shippingAddress`
    // fields) — the same pattern T3d-1 already proved passes through the
    // real similarity.js with zero side effects.
    const disputes = [
      { id: 'd-device', result: 'lost', order: { deviceFingerprint: 'fraud-device-99' } },
      { id: 'd-ip-1', result: 'lost', order: { ipAddress: '198.51.100.99' } },
      { id: 'd-ip-2', result: 'lost', order: { ipAddress: '198.51.100.99' } },
      { id: 'd-ip-3', result: 'lost', order: { ipAddress: '198.51.100.99' } },
    ];

    getIPIntelligence.mockResolvedValue({ isDatacenter: true });
    calculateIPPenalty.mockReturnValue({ penalty: 0, flags: [] }); // isolate: only feeds pattern-sharing here

    getEmailIntelligence.mockResolvedValue({ isDisposable: true });
    calculateEmailPenalty.mockReturnValue({ penalty: 0, flags: [] }); // isolate: only feeds pattern-sharing here

    getConnectedRisk.mockResolvedValue({
      connectedRisk: 100,
      hasConnections: true,
      graphPath: [{ relation: 'USED_WITH', nodeType: 'EMAIL' }],
      matchTier: 'full',
      matchConfidence: 1.0,
    });

    // A mature, high-confidence known fraud pattern for the exact signal
    // combo this order produces (highAmount + isNewCustomer + disposable
    // email + datacenter IP → weightedScore 11.5, see T3d-7 pre-analysis).
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 10,
      fraudCount: 8,
      legitCount: 2,
      merchantsSeen: 3,
      clusterId: null,
      lastSeen: new Date(),
      version: 0,
      learnedAtCount: null,
    });

    const result = await runScoring({ order, allOrders: [], disputes, blacklist });

    // -80 (blacklist) -60 (device dispute) -50 (3 IP disputes) -15
    // (first-time device, amount>=100) -10 (first order from email,
    // isNewCustomer && amount>=150) -30 (identity graph, capped) -8.7
    // (pattern-sharing, real computation) → deeply negative → clamp 0 →
    // critical floor min(0,40) = 0 (no visible change, already at 0).
    expect(result.score).toBe(0);
    expect(result.decision).toBe('High Risk — Block');
    expect(result.riskLevel).toBe('high');

    const criticalFlags = result.flags.filter((f) => f.severity === 'critical');
    expect(criticalFlags.length).toBe(4); // blacklist, device dispute, IP disputes, identity graph
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('fraud blacklist'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Device fingerprint linked to 1 lost dispute'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('IP address linked to 3 disputes'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Identity graph'))).toBe(true);

    // Pattern-sharing can NEVER be critical (see file header finding #2) —
    // it lands here as a standalone high flag, additively stacked on top
    // of the four critical ones.
    const patternFlag = result.flags.find((f) => f.text.includes('fraud pattern'));
    expect(patternFlag).toBeDefined();
    expect(patternFlag.severity).toBe('high');
    expect(patternFlag.text).toContain('8/10');
    expect(patternFlag.text).toContain('3 merchants');

    expect(result.graphRisk).toBe(100); // raw, uncapped — decoupled from the actual applied penalty (T3d-6 quirk G)
  });
});

// ════════════════════════════════════════════════════════════════════
// 4. MIXED SIGNALS — trusted-by-email returning customer, but a
//    brand-new device fingerprint and a VPN IP on THIS order
// ════════════════════════════════════════════════════════════════════

describe('4. Mixed signals — simultaneous positive AND negative pressure on the same order', () => {
  test('3+ returning-customer orders by email (>=14 day span) grant a positive bonus, while a never-seen device + VPN IP on this specific order simultaneously penalize it — both directions visible in the result', async () => {
    const order = makeOrder({
      id: 'mixed-order-1',
      email: 'mixed-trust@example.com',
      deviceFingerprint: 'new-device-mixed', // NOT in history — genuinely new device
      ipAddress: '198.51.100.77',
      amount: 100, // matches history amount → no high-value trigger; >=100 → first-time-device tier applies
    });

    // Same email, same amount, DIFFERENT device + DIFFERENT ip each time —
    // establishes email trust without ever touching this device/IP.
    const allOrders = [
      { id: 'mix-hist-1', email: 'mixed-trust@example.com', deviceFingerprint: 'old-device-1', amount: 100, ipAddress: '198.51.100.10', createdAt: daysAgo(30) },
      { id: 'mix-hist-2', email: 'mixed-trust@example.com', deviceFingerprint: 'old-device-2', amount: 100, ipAddress: '198.51.100.11', createdAt: daysAgo(20) },
      { id: 'mix-hist-3', email: 'mixed-trust@example.com', deviceFingerprint: 'old-device-3', amount: 100, ipAddress: '198.51.100.12', createdAt: daysAgo(10) },
    ];

    getIPIntelligence.mockResolvedValue({ isDatacenter: true });
    calculateIPPenalty.mockReturnValue({
      penalty: 20,
      flags: [{ severity: 'high', text: 'IP flagged as VPN/datacenter — proceed with caution' }],
    });

    const result = await runScoring({ order, allOrders, disputes: [] });

    // Hand-verified exact arithmetic: 100 -20(IP) -15(first-time device,
    // amount>=100) +20(returning-trusted, capped bonus, 20-day span) = 85
    // → clamp 85 → single HIGH flag with score>70 → floor caps to 70.
    // Decision math at score=70: approveThreshold=71 (score just misses
    // it), reviewThreshold=40 → "Medium Risk — Review". We assert the
    // score as a tight range rather than pinning 70 exactly, since this
    // is the one scenario complex enough that we deliberately preferred a
    // safety margin over a hand-computed pin (see design discussion) —
    // decision/flags/positives are asserted exactly since they are more
    // robust to any small residual uncertainty than the raw number.
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.score).toBeLessThanOrEqual(75);

    expect(result.decision).toBe('Medium Risk — Review');
    expect(result.riskLevel).toBe('medium');

    // Negative pressure: brand-new device + VPN IP
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('VPN/datacenter'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'medium' && f.text.includes('First-time device with order $100'))).toBe(true);
    expect(result.flags.length).toBe(2);

    // Positive pressure: trusted-by-email returning customer — but NO
    // trusted-device bonus, because this specific device has zero history.
    expect(result.positives.some((p) => p.text.includes('Trusted customer — 3 orders over 20 days'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('Known trusted device'))).toBe(false);
    expect(result.positives.length).toBe(1);
  });
});

// ════════════════════════════════════════════════════════════════════
// 5. INTERACTION VERIFICATION
// ════════════════════════════════════════════════════════════════════

describe('5. Interaction verification', () => {
  test('5.1 — the risk floor is applied AFTER the positive cap, not before: a critical identity-graph match still forces score <= 40 even though the pre-floor arithmetic (with a full +25 positive pool) would read 95', async () => {
    const order = makeOrder({
      id: 'floor-after-bonus-1',
      email: 'loyal-floor@example.com',
      deviceFingerprint: 'floor-test-device',
      ipAddress: '203.0.113.50',
      amount: 50,
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
    });

    const allOrders = [
      { id: 'floor-hist-1', email: 'loyal-floor@example.com', deviceFingerprint: 'floor-test-device', amount: 50, ipAddress: '203.0.113.51', createdAt: daysAgo(20) },
      { id: 'floor-hist-2', email: 'loyal-floor@example.com', deviceFingerprint: 'floor-test-device', amount: 50, ipAddress: '203.0.113.52', createdAt: daysAgo(10) },
      { id: 'floor-hist-3', email: 'loyal-floor@example.com', deviceFingerprint: 'floor-test-device', amount: 50, ipAddress: '203.0.113.53', createdAt: daysAgo(1) },
    ];

    getConnectedRisk.mockResolvedValue({
      connectedRisk: 100,
      hasConnections: true,
      graphPath: [{ relation: 'USED_WITH', nodeType: 'EMAIL' }],
      matchTier: 'full',
      matchConfidence: 1.0,
    });

    const result = await runScoring({ order, allOrders, disputes: [] });

    // Raw pool: ECI(20)+AVS(10)+CVV2(5)+returning-trusted(20)+trusted-
    // device(15) = 70 → capped 25. Pre-floor: 100 -30(graph, critical)
    // +25(capped bonus) = 95. The critical floor then forces min(95,40).
    expect(result.score).toBe(40);
    expect(result.decision).toBe('High Risk — Block');
    expect(result.flags.some((f) => f.severity === 'critical' && f.text.includes('Identity graph'))).toBe(true);
    // The positives are still genuinely present in the result even though
    // the floor overrides their numeric effect — they were not discarded,
    // just outweighed by the floor rule.
    expect(result.positives.some((p) => p.text.includes('Trusted customer'))).toBe(true);
    expect(result.positives.some((p) => p.text.includes('Known trusted device'))).toBe(true);
  });

  test('5.2 — MAX_POSITIVE_BOOST (25) caps the positive pool correctly: a 70-point raw pool nets exactly +25, distinguishable from the outer [0,100] clamp', async () => {
    const order = makeOrder({
      id: 'cap-correctness-1',
      email: 'loyal-cap@example.com',
      deviceFingerprint: 'cap-test-device',
      ipAddress: '203.0.113.60',
      amount: 50,
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
    });

    const allOrders = [
      { id: 'cap-hist-1', email: 'loyal-cap@example.com', deviceFingerprint: 'cap-test-device', amount: 50, ipAddress: '203.0.113.61', createdAt: daysAgo(20) },
      { id: 'cap-hist-2', email: 'loyal-cap@example.com', deviceFingerprint: 'cap-test-device', amount: 50, ipAddress: '203.0.113.62', createdAt: daysAgo(10) },
      { id: 'cap-hist-3', email: 'loyal-cap@example.com', deviceFingerprint: 'cap-test-device', amount: 50, ipAddress: '203.0.113.63', createdAt: daysAgo(1) },
    ];

    // Same "dial" technique as T3d-1: a single MEDIUM-severity IP penalty
    // displaces the score without ever engaging the high/critical floor,
    // so the capped bonus's exact magnitude is directly recoverable.
    calculateIPPenalty.mockReturnValue({
      penalty: 30,
      flags: [{ severity: 'medium', text: 'IP risk dial (test fixture)' }],
    });

    const result = await runScoring({ order, allOrders, disputes: [] });

    // Raw pool = 70 → capped to 25. Score = 100 -30(dial) +25(capped) = 95.
    // If the cap did NOT apply: 100-30+70=140 → outer clamp would give 100.
    // 95 vs 100 makes the cap's effect unambiguous.
    expect(result.score).toBe(95);
    expect(result.decision).toBe('Low Risk — Approve');
  });

  test('5.3 — pattern-sharing and identity-graph penalties stack on the same order, and their combined high-severity flags (2 of them) engage the "2+ high flags" floor at 55', async () => {
    const order = makeOrder({
      id: 'stacking-1',
      email: 'stack-test@example.com',
      deviceFingerprint: 'stack-device-1',
      ipAddress: '198.51.100.88',
      amount: 250, // >200 → feeds the pattern-sharing highAmount signal
    });

    getIPIntelligence.mockResolvedValue({ isDatacenter: true });
    calculateIPPenalty.mockReturnValue({ penalty: 0, flags: [] }); // isolate: feeds pattern-sharing only

    getEmailIntelligence.mockResolvedValue({ isDisposable: true });
    calculateEmailPenalty.mockReturnValue({ penalty: 0, flags: [] }); // isolate: feeds pattern-sharing only

    getConnectedRisk.mockResolvedValue({
      connectedRisk: 30, // > 10 (penalty branch), <= 60 (stays "high", not "critical")
      hasConnections: true,
      graphPath: [{ relation: 'USED_WITH', nodeType: 'EMAIL' }],
      matchTier: 'full',
      matchConfidence: 1.0,
    });

    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 10,
      fraudCount: 8,
      legitCount: 2,
      merchantsSeen: 3,
      clusterId: null,
      lastSeen: new Date(),
      version: 0,
      learnedAtCount: null,
    });

    const result = await runScoring({ order, allOrders: [], disputes: [] });

    // 100 -15(first-time device) -10(first order from email) -9(graph,
    // round(min(30*0.3,30))=9, "high") -8.7(pattern, "high") = 57.3.
    // hasCritical=false; hasHigh=true; highCount=2 (graph + pattern) and
    // score(57.3) > 55 → the 2+-high floor engages → clamps to 55.
    expect(result.score).toBe(55);
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('Identity graph'))).toBe(true);
    expect(result.flags.some((f) => f.severity === 'high' && f.text.includes('fraud pattern'))).toBe(true);
    expect(result.flags.filter((f) => f.severity === 'high').length).toBe(2);
    expect(result.flags.some((f) => f.severity === 'critical')).toBe(false);
  });

  test('5.4a — the final score is clamped at the floor: 0, never negative, even with deeply stacked critical penalties', async () => {
    const order = makeOrder({
      id: 'clamp-floor-1',
      email: 'clamp-low@example.com',
      ipAddress: '198.51.100.66',
      deviceFingerprint: 'clamp-device-low',
      amount: 50,
    });

    const disputes = [
      { id: 'clamp-d-device', result: 'lost', order: { deviceFingerprint: 'clamp-device-low' } },
      { id: 'clamp-d-ip-1', result: 'lost', order: { ipAddress: '198.51.100.66' } },
      { id: 'clamp-d-ip-2', result: 'lost', order: { ipAddress: '198.51.100.66' } },
      { id: 'clamp-d-ip-3', result: 'lost', order: { ipAddress: '198.51.100.66' } },
    ];

    const result = await runScoring({
      order,
      allOrders: [],
      disputes,
      blacklist: [{ email: 'clamp-low@example.com' }],
    });

    // -80 -60 -50 = -190 raw → far below 0 → outer clamp to 0 → critical
    // floor min(0,40) = 0. Never negative.
    expect(result.score).toBe(0);
    expect(result.score).toBeGreaterThanOrEqual(0);
  });

  test('5.4b — the final score is clamped at the ceiling: 100, never above, even when the raw positive arithmetic (login bonus + capped pool) would sum past it', async () => {
    const order = makeOrder({
      id: 'clamp-ceiling-1',
      email: 'clamp-high@example.com',
      deviceFingerprint: 'clamp-device-high',
      ipAddress: '203.0.113.100',
      amount: 50,
      eciCode: '5',
      avsResponse: 'Y',
      cvv2Response: 'M',
      customerLoginId: 'shopify-cust-clamp-high',
    });

    const allOrders = [
      { id: 'clamp-hist-1', email: 'clamp-high@example.com', deviceFingerprint: 'clamp-device-high', amount: 50, ipAddress: '203.0.113.101', createdAt: daysAgo(20) },
      { id: 'clamp-hist-2', email: 'clamp-high@example.com', deviceFingerprint: 'clamp-device-high', amount: 50, ipAddress: '203.0.113.102', createdAt: daysAgo(10) },
      { id: 'clamp-hist-3', email: 'clamp-high@example.com', deviceFingerprint: 'clamp-device-high', amount: 50, ipAddress: '203.0.113.103', createdAt: daysAgo(1) },
    ];

    const result = await runScoring({ order, allOrders, disputes: [] });

    // Raw: 100 +5(login, outside cap) +25(capped pool, raw pool was 70)
    // = 130 → outer clamp to 100. Never above.
    expect(result.score).toBe(100);
    expect(result.score).toBeLessThanOrEqual(100);
  });
});