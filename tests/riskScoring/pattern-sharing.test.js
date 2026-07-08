'use strict';

// ─── T3d-5: Pattern Sharing ─────────────────────────────────────────────
//
// SCOPE — read before touching these tests.
//
// This file covers ALL FOUR exported functions of src/lib/patternSharing.js:
//   - buildPattern(order, emailIntel, ipIntel, patternContext)
//   - checkPatternRisk(order, emailIntel, ipIntel, patternContext)
//   - recordPattern(order, emailIntel, ipIntel, isFraud, merchantId, patternContext)
//   - markPatternAsFraud(order, emailIntel, ipIntel, patternContext)
//
// patternSharing.js talks directly to Prisma (`db`) with no other internal
// dependencies besides `crypto` (real Node, untouched). We mock
// `../../src/lib/db` and `../../src/lib/logger`.
//
// PERFORMANCE REWRITE (T3d-5 rev. 2) ─────────────────────────────────────
// The original file called `jest.resetModules()` + `jest.doMock()` + a
// fresh `require(...)` inside `beforeEach`, forcing Jest to re-resolve and
// re-instantiate the whole module graph before every one of the 47 tests
// (~4.1s/test, ~203s total). Only ONE test genuinely needs a clean
// `signalIndex` (see below). Everything else now shares a SINGLE module
// instance, required once in `beforeAll`; `jest.clearAllMocks()` in
// `beforeEach` resets call counters/history without re-requiring anything.
//
// CRITICAL: signalIndex MODULE-LEVEL STATE ──────────────────────────────
// `signalIndex` (a `Map<signal, Set<patternHash>>`) lives at module scope
// inside patternSharing.js, populated by indexPattern() on EVERY successful
// recordPattern() call (both the new-pattern branch and the existing-
// pattern branch call it unconditionally — it is NOT gated by signalCount).
// It is read by getCandidateHashes() during cluster assignment, and that
// read is a UNION across all of the current order's active signals, not an
// intersection.
//
// With a single shared module instance, signalIndex now accumulates across
// all 46 "shared" tests (it did NOT reset per-test any more, unlike before).
// We verified, test-by-test, that this cannot change the observable
// behavior any of the 46 tests assert on:
//   - Every test with signalCount < CLUSTER_CREATE_MIN_SIGNALS(3) never
//     reaches the "create my own cluster" branch regardless of candidate
//     contamination, and none of them assert on fraudCluster.upsert being
//     called with specific counts in a way contamination would break
//     (jest.clearAllMocks() resets call counters every test regardless).
//   - The one signalCount>=3 shared test ("no candidate hashes in the
//     empty, fresh signalIndex") DOES pick up stale candidate hashes from
//     earlier shared tests once signalIndex is shared. To keep this
//     deterministic (rather than relying on an unmocked db.fraudPattern
//     .findMany() resolving to `undefined` and silently crashing inside
//     the cluster-assignment try/catch — which is what the ORIGINAL file
//     already relied on internally, since its own two-orders-in-one-test
//     "documented dead code — merchantTrust" test does the exact same
//     thing across its own two sequential recordPattern() calls), we give
//     `db.fraudPattern.findMany` an explicit default of `[]` in
//     freshDbMock(). This makes "no qualifying candidate" happen via a
//     real empty result instead of a swallowed exception, with byte-
//     identical outcomes for every assertion in this file.
//   - The ONE test that requires signalIndex to start GENUINELY empty is
//     "two sequential calls: a second, signal-overlapping pattern joins
//     the FIRST pattern's cluster via weighted-containment similarity" —
//     it depends on the FIRST of its two recordPattern() calls seeding
//     the cluster with no other clusters/candidates around to interfere.
//     That test lives in its own `describe` block below with its own
//     `jest.resetModules()` + `jest.doMock()` + `require()` in a local
//     `beforeEach`, giving it a completely private module instance (and
//     therefore a private, empty signalIndex) every time it runs. Calling
//     `jest.resetModules()` there does not invalidate the shared top-level
//     `db`/`logger`/`patternSharing` references used by every other test —
//     resetModules() only affects the module registry for FUTURE
//     require() calls, not JS variables that already hold object
//     references from earlier requires.
//
// Also note: patternSharing.js calls `setInterval(...).unref()` at module
// load time for index eviction. With a single shared module instance this
// now only happens ONCE (plus once per run of the isolated test's local
// module) instead of 47 times — strictly fewer timers, still harmless,
// still not itself under test.
//
// SECRET REQUIREMENT ─────────────────────────────────────────────────────
// hashPattern() calls getSecret(), which throws if neither
// PATTERN_SHARING_SECRET nor IDENTITY_GRAPH_SECRET is set. PATTERN_SHARING_
// SECRET is set once in beforeAll and defensively re-asserted in the
// top-level beforeEach. The one dedicated "missing secret" test deletes it
// to prove checkPatternRisk degrades gracefully, then restores it in a
// try/finally so every later shared test still has a valid secret.
//
// MOCK SHAPE — db.js is mocked with:
//   fraudPattern: { findUnique, findMany (defaults to resolving []), updateMany, upsert }
//   fraudCluster: { findUnique, update, upsert }
//   patternMerchant: { create }
//   $transaction: jest.fn((fn) => fn(mockDb))   — synchronously invokes the
//     transaction callback with the SAME mock object, so `tx.fraudCluster
//     .update(...)` and `tx.fraudPattern.upsert(...)` inside the callback
//     are observable via the exact same jest.fn() spies used elsewhere.
//
// KNOWN, DELIBERATELY DOCUMENTED (NOT FIXED) BEHAVIORS — see the dedicated
// "documented dead code" describe block near the bottom of this file:
//   1. merchantTrust is HARDCODED to 0.3 in recordPattern — the real
//      MerchantProfile.trustScore-based lookup is commented-out dead code
//      (visible in source as a `/* ... */` block with a `TODO`). This means
//      trustedWeightedScore = min(weightedScore * 0.3, 5) ALWAYS, and the
//      `!isFraud && merchantTrust < 0.2` guard can never fire (0.3 is never
//      < 0.2) — it is permanently unreachable dead code.
//   2. On a pattern's very first insertion (brand-new pattern, not yet in
//      the DB), `learnedAtCount` is unconditionally null: the check is
//      `firstTotalCount(1) >= MIN_PATTERN_SUPPORT(2)`, which is always
//      false for a freshly-created row. A pattern can only ever become
//      "learned" starting from its SECOND occurrence onward, via
//      updatePatternWithRetry — never on creation.
//   3. The two "cluster-fallback" penalty flags (fired when a pattern
//      exists but has fewer than 5 occurrences, and falls back to its
//      cluster's aggregate stats) explicitly say "matches behavioral
//      cluster" in their flag text, distinct from the main-path flag's
//      "matches fraud pattern" wording — this lets production logs
//      distinguish a cluster-derived penalty from a pattern-derived one by
//      flag content alone, without needing to inspect any other field.

let db;
let logger;
let patternSharing;
let buildPattern, recordPattern, checkPatternRisk, markPatternAsFraud;

function freshDbMock() {
  const mockDb = {
    fraudPattern: {
      findUnique: jest.fn(),
      // Defaults to an empty candidate list rather than `undefined`. With
      // a shared module instance, signalIndex can legitimately contain
      // stale hashes from earlier tests by the time a later test runs; an
      // explicit [] here means "no qualifying candidate found" happens via
      // a real empty array instead of relying on an unmocked findMany()
      // resolving to `undefined` and crashing inside the (swallowing)
      // cluster-assignment try/catch. Any test that needs real candidates
      // overrides this with its own mockResolvedValueOnce/mockResolvedValue.
      findMany: jest.fn().mockResolvedValue([]),
      updateMany: jest.fn(),
      upsert: jest.fn(),
    },
    fraudCluster: {
      findUnique: jest.fn(),
      update: jest.fn(),
      upsert: jest.fn(),
    },
    patternMerchant: {
      create: jest.fn(),
    },
  };
  // Synchronously invokes the callback with the SAME mock object as `tx`,
  // so assertions against e.g. `db.fraudPattern.upsert` also capture calls
  // made as `tx.fraudPattern.upsert` inside a $transaction callback.
  mockDb.$transaction = jest.fn((fn) => fn(mockDb));
  return mockDb;
}

beforeAll(() => {
  process.env.PATTERN_SHARING_SECRET = 'test-secret-for-pattern-sharing-tests';
  delete process.env.IDENTITY_GRAPH_SECRET;

  const mockDbInstance = freshDbMock();
  jest.doMock('../../src/lib/db', () => mockDbInstance);
  jest.doMock('../../src/lib/logger', () => ({
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
  }));

  db = require('../../src/lib/db');
  logger = require('../../src/lib/logger');
  patternSharing = require('../../src/lib/patternSharing');
  ({ buildPattern, recordPattern, checkPatternRisk, markPatternAsFraud } = patternSharing);
});

beforeEach(() => {
  // Resets mock.calls / mock.instances / mock.results on every jest.fn()
  // above WITHOUT re-requiring the module — this is what makes the shared
  // instance safe to reuse: every test's toHaveBeenCalledTimes/With
  // assertion still starts from a clean counter.
  jest.clearAllMocks();
  // Defensive re-assert in case an earlier test mutated env vars and
  // didn't clean up (the one test that deletes these restores them itself
  // in a try/finally, but this is a cheap belt-and-suspenders guard).
  process.env.PATTERN_SHARING_SECRET = 'test-secret-for-pattern-sharing-tests';
  delete process.env.IDENTITY_GRAPH_SECRET;
});

// ─── Test Helpers ───────────────────────────────────────────────────────

function makeOrder(overrides = {}) {
  return {
    id: 'order-1',
    amount: 50,
    createdAt: new Date(2025, 5, 15, 12, 0, 0), // noon — never night (2-5am)
    ...overrides,
  };
}

function nightOrder(overrides = {}) {
  return makeOrder({ createdAt: new Date(2025, 5, 15, 3, 0, 0), ...overrides });
}

function hoursAgo(h) {
  return new Date(Date.now() - h * 60 * 60 * 1000);
}

// ─────────────────────────────────────────────────────────────────────────
// buildPattern — signal detection (pure function, no db)
// ─────────────────────────────────────────────────────────────────────────

describe('buildPattern — individual signal detection', () => {
  test('highAmount: amount > 200 → true, weight 1.5, no bonus alone', () => {
    const result = buildPattern(makeOrder({ amount: 250 }), {}, {}, {});
    expect(result.pattern.highAmount).toBe(true);
    expect(result.activeSignals).toEqual(['highAmount']);
    expect(result.signalCount).toBe(1);
    expect(result.weightedScore).toBeCloseTo(1.5, 5);
  });

  test('highAmount: amount === 200 (not > 200) → false', () => {
    const result = buildPattern(makeOrder({ amount: 200 }), {}, {}, {});
    expect(result.pattern.highAmount).toBe(false);
  });

  test('isNewCustomer: order.isNewCustomer === true → true, weight 1.0', () => {
    const result = buildPattern(makeOrder({ isNewCustomer: true }), {}, {}, {});
    expect(result.pattern.isNewCustomer).toBe(true);
    expect(result.weightedScore).toBeCloseTo(1.0, 5);
  });

  test('isDisposableEmail: emailIntel.isDisposable === true → true, weight 3.0', () => {
    const result = buildPattern(makeOrder(), { isDisposable: true }, {}, {});
    expect(result.pattern.isDisposableEmail).toBe(true);
    expect(result.weightedScore).toBeCloseTo(3.0, 5);
  });

  test('isDatacenterIP: ipIntel.isDatacenter === true → true, weight 2.5', () => {
    const result = buildPattern(makeOrder(), {}, { isDatacenter: true }, {});
    expect(result.pattern.isDatacenterIP).toBe(true);
    expect(result.weightedScore).toBeCloseTo(2.5, 5);
  });

  test('isNightOrder: hour in [2,5] inclusive → true, weight 0.8', () => {
    const result = buildPattern(nightOrder(), {}, {}, {});
    expect(result.pattern.isNightOrder).toBe(true);
    expect(result.weightedScore).toBeCloseTo(0.8, 5);
  });

  test('isHighVelocity: patternContext.isHighVelocity === true → true, weight 2.5', () => {
    const result = buildPattern(makeOrder(), {}, {}, { isHighVelocity: true });
    expect(result.pattern.isHighVelocity).toBe(true);
    expect(result.weightedScore).toBeCloseTo(2.5, 5);
  });

  test('all signals false (baseline order) → empty activeSignals, signalCount 0, weightedScore 0', () => {
    const result = buildPattern(makeOrder(), {}, {}, {});
    expect(result.activeSignals).toEqual([]);
    expect(result.signalCount).toBe(0);
    expect(result.weightedScore).toBe(0);
  });
});

describe('buildPattern — signal interaction bonuses (each isolated)', () => {
  test('disposable + datacenter (no other signals) → weights 5.5 + bonus 2.5 = 8.0', () => {
    const result = buildPattern(makeOrder(), { isDisposable: true }, { isDatacenter: true }, {});
    expect(result.weightedScore).toBeCloseTo(8.0, 5);
  });

  test('newCustomer + highAmount + night (all three, no others) → weights 3.3 + bonus 1.5 = 4.8', () => {
    const result = buildPattern(nightOrder({ amount: 250, isNewCustomer: true }), {}, {}, {});
    expect(result.weightedScore).toBeCloseTo(4.8, 5);
  });

  test('disposable + highAmount (no datacenter/night/newCustomer/highVelocity) → weights 4.5 + bonus 1.0 = 5.5', () => {
    const result = buildPattern(makeOrder({ amount: 250 }), { isDisposable: true }, {}, {});
    expect(result.weightedScore).toBeCloseTo(5.5, 5);
  });

  test('highVelocity + newCustomer (no others) → weights 3.5 + bonus 2.0 = 5.5', () => {
    const result = buildPattern(makeOrder({ isNewCustomer: true }), {}, {}, { isHighVelocity: true });
    expect(result.weightedScore).toBeCloseTo(5.5, 5);
  });

  test('highVelocity + disposable (no others) → weights 5.5 + bonus 3.0 = 8.5', () => {
    const result = buildPattern(makeOrder(), { isDisposable: true }, {}, { isHighVelocity: true });
    expect(result.weightedScore).toBeCloseTo(8.5, 5);
  });
});

describe('buildPattern — multiple bonuses stacking simultaneously', () => {
  test('disposable + datacenter + highAmount → BOTH the disposable+datacenter (+2.5) AND disposable+highAmount (+1.0) bonuses fire: weights 7.0 + bonuses 3.5 = 10.5', () => {
    const result = buildPattern(
      makeOrder({ amount: 250 }),
      { isDisposable: true },
      { isDatacenter: true },
      {},
    );
    expect(result.activeSignals.sort()).toEqual(['highAmount', 'isDatacenterIP', 'isDisposableEmail'].sort());
    expect(result.weightedScore).toBeCloseTo(10.5, 5);
  });
});

describe('buildPattern — edge cases', () => {
  test('malformed createdAt does not throw; getHours() on an Invalid Date is NaN, so isNightOrder resolves to false', () => {
    const order = makeOrder({ createdAt: 'not-a-valid-date' });
    let result;
    expect(() => {
      result = buildPattern(order, {}, {}, {});
    }).not.toThrow();
    expect(result.pattern.isNightOrder).toBe(false);
  });

  test('missing emailIntel/ipIntel (undefined) does not throw; optional chaining defaults both booleans to false', () => {
    let result;
    expect(() => {
      result = buildPattern(makeOrder(), undefined, undefined, {});
    }).not.toThrow();
    expect(result.pattern.isDisposableEmail).toBe(false);
    expect(result.pattern.isDatacenterIP).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// checkPatternRisk — gating & empty pattern store
// ─────────────────────────────────────────────────────────────────────────

describe('checkPatternRisk — gating', () => {
  test('signalCount < 2 (MIN_SIGNAL_COUNT) → immediate neutral result, db.fraudPattern.findUnique never called', async () => {
    const result = await checkPatternRisk(makeOrder(), {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
    expect(db.fraudPattern.findUnique).not.toHaveBeenCalled();
  });

  test('missing PATTERN_SHARING_SECRET (and no IDENTITY_GRAPH_SECRET fallback) → hashPattern throws internally, caught by the outer try/catch → neutral result, no crash', async () => {
    delete process.env.PATTERN_SHARING_SECRET;
    delete process.env.IDENTITY_GRAPH_SECRET;
    try {
      const order = makeOrder({ amount: 250, isNewCustomer: true }); // signalCount=2, passes the first gate
      const result = await checkPatternRisk(order, {}, {}, {});
      expect(result).toEqual({ penalty: 0, flags: [] });
      expect(db.fraudPattern.findUnique).not.toHaveBeenCalled(); // never reached — hashPattern throws first
    } finally {
      // Restore immediately so every later shared test still has a valid
      // secret, even though the top-level beforeEach also re-asserts it.
      process.env.PATTERN_SHARING_SECRET = 'test-secret-for-pattern-sharing-tests';
    }
  });

  test('empty pattern store (findUnique resolves null, no cluster) → neutral result', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
  });

  test('existing pattern found but totalCount < 5 and no clusterId → neutral result (no fallback path available)', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 3,
      fraudCount: 2,
      legitCount: 1,
      merchantsSeen: 1,
      clusterId: null,
      lastSeen: new Date(),
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
    expect(db.fraudCluster.findUnique).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// checkPatternRisk — cluster-fallback penalty (existingPattern.totalCount < 5)
// ─────────────────────────────────────────────────────────────────────────

describe('checkPatternRisk — cluster-fallback penalty (pattern under-evidenced, cluster carries it)', () => {
  test('signalCount=2 → fallback penalty = min(10, 8) = 8, flag text explicitly says "cluster" (distinguishable from a pattern-penalty flag)', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 3, // < 5, forces the fallback branch
      fraudCount: 1,
      legitCount: 1,
      merchantsSeen: 1,
      clusterId: 'cluster-X',
      lastSeen: new Date(),
    });
    db.fraudCluster.findUnique.mockResolvedValue({
      id: 'cluster-X',
      totalCount: 6, // >= CLUSTER_MIN_SUPPORT(5)
      fraudCount: 5, // fraudRate = 5/6 = 0.833 >= FRAUD_RATE_THRESHOLD(0.6)
      merchantsSeen: 2, // >= 2, satisfies the fallback's own merchantsSeen gate
      clusterDesc: 'high-value order + new customer',
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true }); // signalCount=2
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result.penalty).toBe(8);
    expect(result.flags).toHaveLength(1);
    expect(result.flags[0].severity).toBe('medium');
    expect(result.flags[0].text).toContain('cluster'); // debug-ability: distinguishes cluster penalty from pattern penalty
    expect(result.flags[0].text).toContain('5/6');
    expect(result.flags[0].text).toContain('2 merchants');
  });

  test('signalCount=3 → fallback penalty = min(10, 10) = 10, flag still mentions "cluster"', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 2,
      fraudCount: 1,
      legitCount: 1,
      merchantsSeen: 1,
      clusterId: 'cluster-Y',
      lastSeen: new Date(),
    });
    db.fraudCluster.findUnique.mockResolvedValue({
      id: 'cluster-Y',
      totalCount: 8,
      fraudCount: 6, // fraudRate = 0.75 >= 0.6
      merchantsSeen: 3,
      clusterDesc: 'datacenter + high value + new customer',
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true, deviceFingerprint: 'x' });
    // 3 active signals: highAmount, isNewCustomer, isDatacenterIP
    const result = await checkPatternRisk(order, {}, { isDatacenter: true }, {});
    expect(result.penalty).toBe(10);
    expect(result.flags[0].text).toContain('cluster');
    expect(result.flags[0].text).toContain('6/8');
    expect(result.flags[0].text).toContain('3 merchants');
  });

  test('cluster qualifies on totalCount/fraudRate but merchantsSeen < 2 → fallback gate fails → neutral result', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 3,
      fraudCount: 1,
      legitCount: 1,
      merchantsSeen: 1,
      clusterId: 'cluster-Z',
      lastSeen: new Date(),
    });
    db.fraudCluster.findUnique.mockResolvedValue({
      id: 'cluster-Z',
      totalCount: 6,
      fraudCount: 5, // fraudRate 0.833 >= 0.6, would otherwise qualify
      merchantsSeen: 1, // < 2 — fails the fallback's own additional gate
      clusterDesc: 'high-value order + new customer',
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
  });
});

// ─────────────────────────────────────────────────────────────────────────
// checkPatternRisk — main branch (Bayesian smoothing + decay + network boost + sigmoid)
// ─────────────────────────────────────────────────────────────────────────

describe('checkPatternRisk — main branch (existingPattern.totalCount >= 5)', () => {
  test('effectiveFraudRate below FRAUD_RATE_THRESHOLD(0.6) → penalty 0 even with a well-evidenced pattern', async () => {
    // rawFraudRate = (1+1)/(1+10+1+2) = 2/14 ≈ 0.143 — far below 0.6
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 11,
      fraudCount: 1,
      legitCount: 10,
      merchantsSeen: 1,
      clusterId: null,
      lastSeen: new Date(),
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
  });

  test('main-branch penalty, no cluster boost: fraudCount=8,legitCount=2,totalCount=10,merchantsSeen=1,lastSeen=now → rawFraudRate=(8+1)/(8+2+1+2)=9/13≈0.6923, decayFactor=1 (no age), networkBoost=1.0 → effectiveFraudRate≈0.6923 (medium severity, <0.8); currentWeightedScore(order)=2.5 (highAmount+isNewCustomer, no bonus), clusterBoost=1.0 → effectiveScore=2.5 → normalizedScore=(2.5/21.3)*10≈1.174 → sigmoid basePenalty=15/(1+e^(-0.8*(1.174-5)))≈0.671 → rounded to 1dp → penalty≈0.7', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 10,
      fraudCount: 8,
      legitCount: 2,
      merchantsSeen: 1,
      clusterId: null,
      lastSeen: new Date(),
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true }); // highAmount + isNewCustomer, no bonus, weightedScore=2.5
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result.penalty).toBeCloseTo(0.7, 1);
    expect(result.flags).toHaveLength(1);
    expect(result.flags[0].severity).toBe('medium'); // effectiveFraudRate 0.6923 < 0.8
    expect(result.flags[0].text).toContain('fraud pattern'); // distinct wording from the cluster-fallback flag
    expect(result.flags[0].text).toContain('8/10');
    expect(result.flags[0].text).toContain('69.2%');
  });

  test('same fraud-rate inputs as above but clusterId set + a qualifying cluster (merchantsSeen>=3) → clusterBoost≈1.4*confidenceScale boosts effectiveScore, raising the penalty above the no-boost case', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 10,
      fraudCount: 8,
      legitCount: 2,
      merchantsSeen: 1,
      clusterId: 'cluster-boost-1',
      lastSeen: new Date(),
    });
    db.fraudCluster.findUnique.mockResolvedValue({
      id: 'cluster-boost-1',
      totalCount: 10,
      fraudCount: 8, // cluster fraudRate 0.8 >= 0.6 → boost qualifies
      merchantsSeen: 3, // baseBoost tier = 1.4
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true }); // same weightedScore=2.5 as the unboosted test
    const result = await checkPatternRisk(order, {}, {}, {});
    // Same fraud-rate math as the unboosted test (0.6923, medium severity),
    // but effectiveScore = 2.5 * clusterBoost(>1.0) is larger, so penalty
    // must be strictly greater than the unboosted 0.7 result.
    expect(result.flags[0].severity).toBe('medium');
    expect(result.penalty).toBeGreaterThan(0.7);
    expect(result.penalty).toBeCloseTo(1.3, 1);
  });

  test('effectiveFraudRate > 0.8 → severity "high" instead of "medium" (fraudCount=9,legitCount=0,totalCount=9 → rawFraudRate=(9+1)/(9+0+1+2)=10/12≈0.833)', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 9,
      fraudCount: 9,
      legitCount: 0,
      merchantsSeen: 1,
      clusterId: null,
      lastSeen: new Date(),
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true }); // weightedScore=2.5, same as the medium-severity test
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result.flags[0].severity).toBe('high'); // 0.833 > 0.8
    expect(result.penalty).toBeCloseTo(0.7, 1); // same effectiveScore(2.5) as the medium-severity test → same penalty magnitude
  });

  test('time decay: a pattern last seen 30 days ago decays a would-be-0.6923 fraud rate down to ~0.138 (via a 0.2 dynamic floor, not the raw exponential ~0.001), pushing it below threshold → penalty 0', async () => {
    // dynamicFloor = min(0.1 + log10(10)*0.1, 0.35) = min(0.1+0.1, 0.35) = 0.2
    // raw exponential decay alone (0.5^(720/72)=0.5^10≈0.000977) would be
    // far smaller than 0.2 — the floor is what actually governs here,
    // demonstrating the floor genuinely does something rather than the
    // decay simply going to near-zero.
    db.fraudPattern.findUnique.mockResolvedValue({
      totalCount: 10,
      fraudCount: 8,
      legitCount: 2,
      merchantsSeen: 1,
      clusterId: null,
      lastSeen: hoursAgo(720), // 30 days ago
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await checkPatternRisk(order, {}, {}, {});
    expect(result).toEqual({ penalty: 0, flags: [] });
  });

  test('networkBoost tiers: rawFraudRate=0.52 (fraudCount=12,legitCount=10 → (12+1)/(12+10+3)=13/25=0.52) stays below threshold at merchantsSeen=1 (boost 1.0→0.52) AND merchantsSeen=2 (boost 1.1→0.572), but crosses it at merchantsSeen=3 (boost 1.2→0.624)', async () => {
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const basePattern = {
      totalCount: 22,
      fraudCount: 12,
      legitCount: 10,
      clusterId: null,
      lastSeen: new Date(),
    };

    db.fraudPattern.findUnique.mockResolvedValueOnce({ ...basePattern, merchantsSeen: 1 });
    const r1 = await checkPatternRisk(order, {}, {}, {});
    expect(r1).toEqual({ penalty: 0, flags: [] });

    db.fraudPattern.findUnique.mockResolvedValueOnce({ ...basePattern, merchantsSeen: 2 });
    const r2 = await checkPatternRisk(order, {}, {}, {});
    expect(r2).toEqual({ penalty: 0, flags: [] });

    db.fraudPattern.findUnique.mockResolvedValueOnce({ ...basePattern, merchantsSeen: 3 });
    const r3 = await checkPatternRisk(order, {}, {}, {});
    expect(r3.penalty).toBeCloseTo(0.7, 1); // same effectiveScore(2.5) as earlier tests, only the fraud-rate gate crossing differs
    expect(r3.flags[0].severity).toBe('medium'); // 0.624 < 0.8
  });
});

describe('checkPatternRisk — resilience to unexpected db errors', () => {
  test('db.fraudPattern.findUnique rejects → outer catch swallows it → neutral result, no throw, logger.error called', async () => {
    db.fraudPattern.findUnique.mockRejectedValue(new Error('connection reset'));
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    await expect(checkPatternRisk(order, {}, {}, {})).resolves.toEqual({ penalty: 0, flags: [] });
    expect(logger.error).toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// recordPattern — gating
// ─────────────────────────────────────────────────────────────────────────

describe('recordPattern — gating', () => {
  test('signalCount < MIN_SIGNAL_COUNT(2) → null, no db call at all, regardless of isFraud', async () => {
    const order = makeOrder({ amount: 250 }); // only 1 signal: highAmount
    const resultLegit = await recordPattern(order, {}, {}, false, null, {});
    expect(resultLegit).toBeNull();
    expect(db.fraudPattern.findUnique).not.toHaveBeenCalled();

    const resultFraud = await recordPattern(order, {}, {}, true, null, {});
    expect(resultFraud).toBeNull();
    expect(db.fraudPattern.findUnique).not.toHaveBeenCalled();
  });

  test('legit order (isFraud=false) with weightedScore < 2.5 → null, no db call', async () => {
    // isNewCustomer(1.0) + isNightOrder(0.8) = 1.8, no bonus (bonus needs highAmount too)
    const order = nightOrder({ isNewCustomer: true });
    const result = await recordPattern(order, {}, {}, false, null, {});
    expect(result).toBeNull();
    expect(db.fraudPattern.findUnique).not.toHaveBeenCalled();
  });

  test('isFraud=true BYPASSES the weightedScore<2.5 gate entirely — the same low-weight order that was blocked when legit now proceeds to the database', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null); // new pattern
    const order = nightOrder({ isNewCustomer: true }); // weightedScore=1.8, would be blocked if isFraud=false
    const result = await recordPattern(order, {}, {}, true, null, {});
    expect(db.$transaction).toHaveBeenCalled(); // proves the gate was bypassed
    expect(result).not.toBeNull();
    const createCall = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createCall.fraudCount).toBe(1);
    expect(createCall.legitCount).toBe(0);
    // trustedWeightedScore = min(1.8 * 0.3, 5) = 0.54
    expect(createCall.weightedScore).toBeCloseTo(0.54, 5);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// recordPattern — new pattern creation & clustering
// ─────────────────────────────────────────────────────────────────────────

describe('recordPattern — new pattern creation', () => {
  test('new pattern, signalCount=2 (< CLUSTER_CREATE_MIN_SIGNALS(3)) → created via $transaction WITHOUT a cluster; clusterId null, learnedAtCount null (documented: can never be learned on first insert)', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.fraudPattern.upsert.mockResolvedValue({ id: 'pattern-1' });
    const order = makeOrder({ amount: 250, isNewCustomer: false, deviceFingerprint: null });
    // highAmount + isDatacenterIP = 2 signals, weightedScore = 1.5+2.5 = 4.0 (>=2.5, passes legit gate)
    const result = await recordPattern(order, {}, { isDatacenter: true }, false, null, {});

    expect(db.fraudCluster.upsert).not.toHaveBeenCalled();
    expect(db.fraudCluster.update).not.toHaveBeenCalled();
    const createCall = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createCall.clusterId).toBeNull();
    expect(createCall.legitCount).toBe(1);
    expect(createCall.fraudCount).toBe(0);
    expect(createCall.totalCount).toBe(1);
    expect(createCall.learnedAtCount).toBeNull(); // firstTotalCount(1) >= MIN_PATTERN_SUPPORT(2) is always false
    expect(result).toEqual({ id: 'pattern-1' });
  });

  test('new pattern, signalCount=3 (>= CLUSTER_CREATE_MIN_SIGNALS) with no matching candidate found → seeds its OWN new cluster via fraudCluster.upsert', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.fraudCluster.upsert.mockResolvedValue({ id: 'new-cluster-abc' });
    db.fraudPattern.upsert.mockResolvedValue({ id: 'pattern-2' });
    // db.fraudPattern.findMany defaults to [] (see freshDbMock) — whether or
    // not signalIndex happens to contain stale candidate hashes from an
    // earlier shared test, the db lookup itself returns no real candidates,
    // so this deterministically falls through to "create my own cluster."

    const order = makeOrder({ amount: 250, isNewCustomer: true }); // + isDatacenterIP below = 3 signals
    const result = await recordPattern(order, {}, { isDatacenter: true }, false, null, {});

    expect(db.fraudCluster.upsert).toHaveBeenCalledTimes(1);
    expect(db.fraudCluster.update).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: 'new-cluster-abc' } }),
    );
    const createCall = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createCall.clusterId).toBe('new-cluster-abc');
    expect(result).toEqual({ id: 'pattern-2' });
  });
});

// ─────────────────────────────────────────────────────────────────────────
// recordPattern — cluster-similarity join (the ONE test needing a
// genuinely clean, private signalIndex — see file header for why)
// ─────────────────────────────────────────────────────────────────────────

describe('recordPattern — cluster similarity join (requires a private, empty signalIndex)', () => {
  let isoDb, isoRecordPattern;

  beforeEach(() => {
    // ROOT CAUSE (previous version): jest.isolateModules(() => {...}) wraps
    // doMock()+require() in a single callback, but src/lib/db.js does real
    // work at require-time (`new PrismaClient()`). In practice the doMock
    // registration for '../../src/lib/db' did not reliably win the race
    // against patternSharing.js's own internal `require('./db')` inside
    // that swapped-registry callback — so patternSharing.js ended up
    // holding the REAL, unmocked db.js. db.fraudPattern.findUnique() on a
    // real (disconnected, test-env) PrismaClient then threw/rejected,
    // which recordPattern's outer try/catch silently swallowed, returning
    // null before ever reaching fraudCluster.upsert. Hence "0 calls" with
    // no visible error.
    //
    // FIX: use the plain, SEQUENTIAL resetModules()+doMock()+require()
    // recipe — the exact mechanism already proven at 47/47 before the
    // performance rewrite — instead of isolateModules(). This guarantees
    // the mock factories are registered before patternSharing.js (and its
    // require('./db')) is ever evaluated. resetModules() only invalidates
    // the registry for FUTURE require() calls, not JS variables that
    // already hold object references — so this has zero effect on the 46
    // shared tests, which never re-require db/logger/patternSharing after
    // their one-time beforeAll require.
    jest.resetModules();
    process.env.PATTERN_SHARING_SECRET = 'test-secret-for-pattern-sharing-tests';
    delete process.env.IDENTITY_GRAPH_SECRET;

    const mockDbInstance = freshDbMock();
    jest.doMock('../../src/lib/db', () => mockDbInstance);
    jest.doMock('../../src/lib/logger', () => ({
      error: jest.fn(),
      warn: jest.fn(),
      info: jest.fn(),
    }));

    isoDb = mockDbInstance;
    isoRecordPattern = require('../../src/lib/patternSharing').recordPattern;
  });

  test('two sequential calls: a second, signal-overlapping pattern joins the FIRST pattern\'s cluster via weighted-containment similarity (>=0.75) instead of creating its own cluster — exercises the signalIndex populated by the first call', async () => {
    // Call 1 — order A: highAmount + isNewCustomer + isDatacenterIP (3 signals,
    // weightedScore = 1.5+1.0+2.5 = 5.0, no bonus). New pattern, no existing
    // cluster candidates (index still empty — this module instance is
    // private/fresh) → creates its own cluster.
    isoDb.fraudPattern.findUnique.mockResolvedValueOnce(null);
    isoDb.fraudCluster.upsert.mockResolvedValueOnce({ id: 'cluster-A-id' });
    isoDb.fraudPattern.upsert.mockResolvedValueOnce({ id: 'pattern-A-id' });

    const orderA = makeOrder({ amount: 250, isNewCustomer: true });
    await isoRecordPattern(orderA, {}, { isDatacenter: true }, false, null, {});

    expect(isoDb.fraudCluster.upsert).toHaveBeenCalledTimes(1);

    // Call 2 — order B: same 3 signals as A PLUS isNightOrder (4 signals).
    // Its own weightedScore (used only for weightedContainmentSimilarity's
    // denominator) = 1.5+1.0+2.5+0.8 = 5.8. Different pattern hash than A's
    // (since isNightOrder differs), so it is genuinely a "new" pattern from
    // findUnique's point of view — but B's active signals fully CONTAIN A's,
    // so containment similarity = weightedIntersection(5.0)/min(5.8,5.0) = 1.0,
    // well above CLUSTER_SIMILARITY_THRESHOLD(0.75).
    isoDb.fraudPattern.findUnique.mockResolvedValueOnce(null);
    isoDb.fraudPattern.findMany.mockResolvedValueOnce([
      {
        patternHash: 'irrelevant-in-mock',
        clusterId: 'cluster-A-id',
        patternDesc: 'high-value order + new customer + datacenter IP',
        signals: JSON.stringify(['highAmount', 'isNewCustomer', 'isDatacenterIP']),
      },
    ]);
    isoDb.fraudPattern.upsert.mockResolvedValueOnce({ id: 'pattern-B-id' });

    const orderB = nightOrder({ amount: 250, isNewCustomer: true });
    await isoRecordPattern(orderB, {}, { isDatacenter: true }, false, null, {});

    // B must NOT create a second cluster — it joins A's.
    expect(isoDb.fraudCluster.upsert).toHaveBeenCalledTimes(1); // still just the one from call 1
    expect(isoDb.fraudPattern.findMany).toHaveBeenCalledTimes(1); // only B's call had any candidates to look up
    const secondCreateCall = isoDb.fraudPattern.upsert.mock.calls[1][0].create;
    expect(secondCreateCall.clusterId).toBe('cluster-A-id');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// recordPattern — existing pattern update & anti-replay protection
// ─────────────────────────────────────────────────────────────────────────

describe('recordPattern — existing pattern update', () => {
  test('existing pattern, legit, CAS succeeds on first attempt → updateMany called with correct version/data, final result returned from the post-update findUnique', async () => {
    db.fraudPattern.findUnique
      .mockResolvedValueOnce({
        // outer `existing` lookup
        clusterId: null,
        legitCount: 5,
        version: 2,
        totalCount: 10,
        fraudCount: 3,
        learnedAtCount: null,
      })
      .mockResolvedValueOnce({
        // updatePatternWithRetry's own version-fetch
        version: 2,
        totalCount: 10,
        fraudCount: 3,
        legitCount: 5,
        learnedAtCount: null,
      })
      .mockResolvedValueOnce({
        // final post-update fetch
        totalCount: 11,
        fraudCount: 3,
        legitCount: 6,
        version: 3,
      });
    db.fraudPattern.updateMany.mockResolvedValue({ count: 1 });

    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await recordPattern(order, {}, {}, false, null, {});

    expect(db.fraudPattern.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { patternHash: expect.any(String), version: 2 },
        data: expect.objectContaining({
          totalCount: { increment: 1 },
          legitCount: { increment: 1 },
          fraudCount: undefined,
        }),
      }),
    );
    expect(db.fraudCluster.update).not.toHaveBeenCalled(); // clusterId was null
    expect(result).toEqual({ totalCount: 11, fraudCount: 3, legitCount: 6, version: 3 });
  });

  test('existing pattern, legit, legitCount already >= MAX_LEGIT_INFLUENCE(50) → blocked immediately, returns null, updateMany never called', async () => {
    db.fraudPattern.findUnique.mockResolvedValue({
      clusterId: null,
      legitCount: 50,
      version: 1,
      totalCount: 80,
      fraudCount: 5,
    });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await recordPattern(order, {}, {}, false, null, {});
    expect(result).toBeNull();
    expect(db.fraudPattern.updateMany).not.toHaveBeenCalled();
  });

  test('existing pattern, isFraud=true, legitCount >= 50 → the anti-replay cap does NOT apply (it only gates legit recordings) — proceeds to updateMany normally', async () => {
    db.fraudPattern.findUnique
      .mockResolvedValueOnce({ clusterId: null, legitCount: 50, version: 1, totalCount: 80, fraudCount: 5 })
      .mockResolvedValueOnce({ version: 1, totalCount: 80, fraudCount: 5, legitCount: 50, learnedAtCount: null })
      .mockResolvedValueOnce({ totalCount: 81, fraudCount: 6, legitCount: 50, version: 2 });
    db.fraudPattern.updateMany.mockResolvedValue({ count: 1 });

    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await recordPattern(order, {}, {}, true, null, {});
    expect(db.fraudPattern.updateMany).toHaveBeenCalled();
    expect(result).not.toBeNull();
  });
});

describe('recordPattern — optimistic-lock retry exhaustion', () => {
  test('db.fraudPattern.updateMany always reports count:0 (CAS never wins) → all 3 attempts are used, then null is returned and a warning is logged', async () => {
    db.fraudPattern.findUnique
      .mockResolvedValueOnce({ clusterId: null, legitCount: 1, version: 1, totalCount: 10, fraudCount: 1 }) // outer existing
      .mockResolvedValue({ version: 1, totalCount: 10, fraudCount: 1, legitCount: 1, learnedAtCount: null }); // every retry's version-fetch
    db.fraudPattern.updateMany.mockResolvedValue({ count: 0 }); // CAS always fails

    const order = makeOrder({ amount: 250, isNewCustomer: true });
    const result = await recordPattern(order, {}, {}, false, null, {});

    expect(result).toBeNull();
    expect(db.fraudPattern.updateMany).toHaveBeenCalledTimes(3); // maxRetries default = 3
    expect(logger.warn).toHaveBeenCalled();
  }, 10000);
});

// ─────────────────────────────────────────────────────────────────────────
// recordPattern — merchant registration error handling
// ─────────────────────────────────────────────────────────────────────────

describe('recordPattern — patternMerchant registration error handling', () => {
  test('registerPatternMerchant hits a Prisma unique-constraint violation (P2002 — merchant already registered for this pattern) → returns false silently, recordPattern completes normally with merchantsSeen:0', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null); // new pattern
    db.fraudPattern.upsert.mockResolvedValue({ id: 'pattern-p2002' });
    db.patternMerchant.create.mockRejectedValue({ code: 'P2002' });

    const order = makeOrder({ amount: 250, isNewCustomer: false, deviceFingerprint: null });
    // highAmount + isDatacenterIP = 2 signals (< 3, skips cluster creation entirely)
    const result = await recordPattern(order, {}, { isDatacenter: true }, false, 'merchant-123', {});

    expect(result).not.toBeNull();
    const createCall = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createCall.merchantsSeen).toBe(0); // isNewPatternMerchant was false, not the 1 it would be on success
  });

  test('registerPatternMerchant hits a non-P2002 error → it is RE-THROWN internally, propagates up through recordPattern\'s own try/catch → recordPattern resolves to null (never throws to its caller), db.$transaction is never reached', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.patternMerchant.create.mockRejectedValue(new Error('connection timeout'));

    const order = makeOrder({ amount: 250, isNewCustomer: false, deviceFingerprint: null });
    const result = await recordPattern(order, {}, { isDatacenter: true }, false, 'merchant-456', {});

    expect(result).toBeNull();
    expect(db.$transaction).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// markPatternAsFraud
// ─────────────────────────────────────────────────────────────────────────

describe('markPatternAsFraud', () => {
  test('delegates to recordPattern with isFraud forced to true and merchantId forced to null — a low-weightedScore order that would be blocked as legit proceeds anyway, and no merchant is ever registered', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null); // new pattern
    db.fraudPattern.upsert.mockResolvedValue({ id: 'pattern-mark-fraud' });

    const order = nightOrder({ isNewCustomer: true }); // weightedScore=1.8, would fail the legit gate
    const result = await markPatternAsFraud(order, {}, {}, {});

    expect(db.$transaction).toHaveBeenCalled(); // proves the legit-only weight gate was bypassed
    // markPatternAsFraud's signature has no merchantId parameter at all —
    // confirming merchantId is unconditionally null, patternMerchant.create
    // must never be invoked regardless of any db state.
    expect(db.patternMerchant.create).not.toHaveBeenCalled();
    expect(result).not.toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Documented dead code
// ─────────────────────────────────────────────────────────────────────────

describe('documented dead code — merchantTrust is hardcoded to 0.3', () => {
  test('trustedWeightedScore always equals weightedScore * 0.3 exactly (the real MerchantProfile.trustScore-based lookup is commented-out dead code) — verified at two different weightedScore magnitudes, including the min(...,5) cap engaging', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.fraudPattern.upsert.mockResolvedValue({ id: 'trust-test' });

    // Case A: disposable + datacenter → weightedScore = 3.0+2.5 + bonus(2.5) = 8.0
    // trustedWeightedScore = min(8.0 * 0.3, 5) = min(2.4, 5) = 2.4 (well under the cap)
    const orderA = makeOrder({ amount: 50 });
    await recordPattern(orderA, { isDisposable: true }, { isDatacenter: true }, true, null, {});
    const createA = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createA.weightedScore).toBeCloseTo(2.4, 5);

    // Case B: ALL 6 signals active → weightedScore = MAX_WEIGHTED_SCORE = 21.3
    // trustedWeightedScore = min(21.3 * 0.3, 5) = min(6.39, 5) = 5 — the cap engages
    const orderB = nightOrder({ amount: 250, isNewCustomer: true });
    await recordPattern(
      orderB,
      { isDisposable: true },
      { isDatacenter: true },
      true,
      null,
      { isHighVelocity: true },
    );
    const createB = db.fraudPattern.upsert.mock.calls[1][0].create;
    expect(createB.weightedScore).toBe(5); // capped, NOT 6.39
  });

  test('the `!isFraud && merchantTrust < 0.2` guard is permanently unreachable, since merchantTrust is always exactly 0.3 (never < 0.2) — a legit order with a qualifying weightedScore is never blocked by this specific gate', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.fraudPattern.upsert.mockResolvedValue({ id: 'trust-gate-test' });
    const order = makeOrder({ amount: 250, isNewCustomer: false, deviceFingerprint: null });
    // highAmount + isDatacenterIP → weightedScore = 4.0, passes the (separate) weightedScore>=2.5 legit gate
    const result = await recordPattern(order, {}, { isDatacenter: true }, false, null, {});
    expect(db.fraudPattern.findUnique).toHaveBeenCalled(); // proves we passed the trust gate to reach the db lookup
    expect(result).not.toBeNull();
  });
});

describe('documented dead code — learnedAtCount is always null on a pattern\'s first creation', () => {
  test('even with isFraud=true and a large fraudCount-to-totalCount ratio implied, firstTotalCount is always 1 on creation, which is < MIN_PATTERN_SUPPORT(2) — learnedAtCount can never be set on insert, only from the second occurrence onward', async () => {
    db.fraudPattern.findUnique.mockResolvedValue(null);
    db.fraudPattern.upsert.mockResolvedValue({ id: 'learned-at-test' });
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    await recordPattern(order, {}, { isDatacenter: true }, true, null, {});
    const createCall = db.fraudPattern.upsert.mock.calls[0][0].create;
    expect(createCall.learnedAtCount).toBeNull();
    expect(createCall.totalCount).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Generic db-error resilience (both public functions never throw to caller)
// ─────────────────────────────────────────────────────────────────────────

describe('generic db error resilience', () => {
  test('recordPattern: an unexpected error mid-flow (e.g. findUnique throws) is caught by the outer try/catch → resolves to null, never throws, logs the error', async () => {
    db.fraudPattern.findUnique.mockRejectedValue(new Error('db unavailable'));
    const order = makeOrder({ amount: 250, isNewCustomer: true });
    await expect(recordPattern(order, {}, {}, false, null, {})).resolves.toBeNull();
    expect(logger.error).toHaveBeenCalled();
  });
});