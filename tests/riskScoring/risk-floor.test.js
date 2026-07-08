'use strict';

// ─── T3d-2: Risk Floor + Decision Assignment ───────────────────────────────
//
// SCOPE — read before touching these tests.
//
// This file covers two things from riskScoring.js:
//   1. calculateThresholds() — the standalone exported pure function.
//   2. The risk-floor clamp + decision-assignment block inside
//      calculateRiskScore (BEFORE the economic engine override layer,
//      which is already covered by T3d-3 / economic-engine.test.js).
//
// MOCKING STRATEGY — identical to T3d-3, reused verbatim:
//   - ipIntelligence  → jest.mock'd. calculateIPPenalty's return value is
//     our score-setting dial, always with severity 'medium' unless a test
//     says otherwise, so it never itself trips the critical/high floor.
//   - patternSharing  → jest.mock'd (no DB dependency).
//   - prom-client     → jest.mock'd (see T3d-3 root-cause notes — required
//     because some unmocked dependency in the require graph pulls it in
//     at load time).
//   - emailIntelligence, binIntelligence, identityGraph, similarity, db →
//     left REAL and simply never exercised: order.email is always left
//     unset (normalizeEmail → '' → getEmailIntelligence short-circuits),
//     no `bin` or `deviceId` is ever passed (skips BIN/graph call sites),
//     merchantId is null except where a merchant profile is explicitly
//     needed to unlock the reviewThreshold floor for fatigue testing (see
//     below), and `disputes` is always [] or filtered so that whatever
//     reaches findSimilarDisputes is an empty array.
//
// WHY MERCHANTPROFILE APPEARS IN THE FATIGUE TESTS:
//   reviewThresholdBase = round(32 + merchantAdjustment*0.7). With no
//   profile, merchantAdjustment=0, base=32, and the floor
//   Math.max(40, base + fatigueAdjustment) swallows ALL fatigue tiers
//   (32+8=40, still exactly the floor). To make fatigue's 0/4/8 tiers
//   observably different from each other, reviewThresholdBase must sit
//   above 32. The profile below was chosen and hand-traced (see inline
//   comments) purely as a lever for that — getMerchantAdjustment's own
//   correctness is explicitly out of scope (that's T3d-4).
//
// KNOWN, DELIBERATELY UNUSED SIGNALS: IP velocity and email velocity are
// each computed in two places in riskScoring.js and double-penalize/
// double-flag when externalVelocity isn't supplied. Not used anywhere in
// this file — flagged separately, not exploited or worked around here.

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

const {
  calculateRiskScore,
  calculateThresholds,
} = require('../../src/lib/riskScoring');

const { getIPIntelligence, calculateIPPenalty } = require('../../src/lib/ipIntelligence');

// ─── Test Helpers ───────────────────────────────────────────────────────────

function makeOrder({
  amount = 50,
  ipAddress = '203.0.113.10',
  orderId = 'order-1',
  shippingAddress,
  billingAddress,
} = {}) {
  return {
    id: orderId,
    amount,
    ipAddress,
    // Fixed local-noon timestamp — avoids the 2-5am "unusual hour" penalty
    // regardless of the machine's timezone (same convention as T3d-3).
    createdAt: new Date(2025, 5, 15, 12, 0, 0),
    shippingAddress,
    billingAddress,
  };
}

// runFloor — drives the real calculateRiskScore with every non-essential
// subsystem neutralized. `ipPenalty`/`ipSeverity` is the score-setting dial
// (severity defaults to 'medium' so it never itself trips the floor).
async function runFloor({
  amount = 50,
  ipPenalty = 0,
  ipSeverity = 'medium',
  blacklist = [],
  cardHashRecord = null,
  shippingAddress,
  billingAddress,
  allOrders = [],
  merchantId = null,
  orderId = 'order-1',
} = {}) {
  getIPIntelligence.mockResolvedValue({});
  calculateIPPenalty.mockReturnValue({
    penalty: ipPenalty,
    flags: ipPenalty > 0
      ? [{ severity: ipSeverity, text: 'Elevated IP risk (test fixture)' }]
      : [],
  });

  const order = makeOrder({ amount, orderId, shippingAddress, billingAddress });
  return calculateRiskScore(
    order,
    allOrders,
    [],           // disputes
    blacklist,
    merchantId,
    false,        // saveEvaluation
    null,         // externalVelocity
    cardHashRecord,
    null,         // merchantConfig
  );
}

// A "low value" history order used purely to drag avgOrderValue down so the
// test order's orderMultiple crosses the >=5 tier (HIGH_VALUE, severity
// always "high" per source regardless of isNewCustomer). Distinct email/ip
// so it can't be mistaken for velocity or returning-customer signals.
function lowValueHistoryOrder() {
  return {
    id: 'history-1',
    amount: 10,
    ipAddress: '198.51.100.5',
    email: 'unrelated-history@example.com',
    createdAt: new Date(2025, 5, 1, 12, 0, 0),
    riskLevel: 'low',
  };
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ─── calculateThresholds — baseline & clamps (merchantProfile=null) ───────

describe('calculateThresholds — baseline (no merchant profile, no fatigue)', () => {
  test('amount=0 → approveThreshold=62 (floor of the amount-based clamp), reviewThreshold=40 (floor)', () => {
    const { approveThreshold, reviewThreshold } = calculateThresholds(0, null, []);
    expect(approveThreshold).toBe(62);
    expect(reviewThreshold).toBe(40);
  });

  test('amount=1 behaves identically to amount=0 (log(1)=0, same logScale)', () => {
    const a = calculateThresholds(1, null, []);
    const b = calculateThresholds(0, null, []);
    expect(a).toEqual(b);
  });

  test('very large amount clamps approveThreshold at its ceiling of 82 (62 + max logScale of 20)', () => {
    const { approveThreshold, reviewThreshold } = calculateThresholds(1e10, null, []);
    expect(approveThreshold).toBe(82);
    expect(reviewThreshold).toBe(40);
  });

  test('approveThreshold is monotonically non-decreasing as order amount increases', () => {
    const amounts = [0, 1, 10, 50, 100, 500, 1000, 5000, 50000, 1e7];
    const thresholds = amounts.map((a) => calculateThresholds(a, null, []).approveThreshold);
    for (let i = 1; i < thresholds.length; i++) {
      expect(thresholds[i]).toBeGreaterThanOrEqual(thresholds[i - 1]);
    }
  });

  test('approveThreshold never drops below its floor of 60, never exceeds its ceiling of 90, across a wide amount range', () => {
    const amounts = [0, 0.01, 5, 500, 1e6, 1e12];
    for (const amount of amounts) {
      const { approveThreshold } = calculateThresholds(amount, null, []);
      expect(approveThreshold).toBeGreaterThanOrEqual(60);
      expect(approveThreshold).toBeLessThanOrEqual(90);
    }
  });
});

// ─── calculateThresholds — Review Fatigue Management ──────────────────────
//
// merchantProfile below is fixed across all fatigue tests so that
// reviewThresholdBase sits above the 40 floor (see file header for why
// this is necessary). Hand-traced from getMerchantAdjustment's exact
// source:
//   fraudRate = (20+1)/(400+20) = 21/420 = 0.05
//   adjustment (pre-winrate) = min(8, max(-4, (0.05-0.01)*200)) = min(8,8) = 8
//   smoothedWinRate = (0+2)/(20+2+3) = 2/25 = 0.08 < 0.3 → +2 → 10
//   confidence = min(1, 400/500) = 0.8
//   adjustment = 10 * 0.8 = 8.0 (exact, no rounding ambiguity)
//   reviewThresholdBase = round(32 + 8.0*0.7) = round(37.6) = 38
// So: fatigueAdjustment 0/4/8 → reviewThreshold 40/42/46 (all distinct).
const FATIGUE_MERCHANT_PROFILE = { totalOrders: 400, totalDisputes: 20, wonDisputes: 0 };

function ordersWithRiskLevels(counts) {
  // counts: array of riskLevel strings, oldest-to-newest by construction order
  return counts.map((riskLevel, i) => ({
    id: `fatigue-${i}`,
    riskLevel,
    createdAt: new Date(2025, 0, 1 + i, 12, 0, 0),
  }));
}

describe('calculateThresholds — Review Fatigue Management', () => {
  test('fewer than 20 total orders → fatigue never engages, reviewThreshold stays at the floor (40) even with a high medium-rate', () => {
    const orders = ordersWithRiskLevels([...Array(10).fill('medium'), ...Array(9).fill('low')]); // 19 total
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(40);
  });

  test('reviewRate <= 0.15 (exactly 3/20 = 0.15) → no fatigue adjustment → reviewThreshold=40', () => {
    const orders = ordersWithRiskLevels([...Array(3).fill('medium'), ...Array(17).fill('low')]);
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(40);
  });

  test('reviewRate exactly 0.20 (4/20) → falls in the ">0.15" tier (+4), NOT the ">0.20" tier, since 0.20 is not strictly greater than 0.20', () => {
    const orders = ordersWithRiskLevels([...Array(4).fill('medium'), ...Array(16).fill('low')]);
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(42);
  });

  test('reviewRate > 0.20 (5/20 = 0.25) → top fatigue tier (+8) → reviewThreshold=46', () => {
    const orders = ordersWithRiskLevels([...Array(5).fill('medium'), ...Array(15).fill('low')]);
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(46);
  });

  test('high-risk orders are excluded from both the numerator and denominator of reviewRate', () => {
    // 10 "high" orders mixed in alongside the same 4-medium/16-low set used
    // above. If high-risk orders were NOT excluded, mediumCount/total would
    // change (4/30 = 0.133, a different tier). Expect the SAME result (42)
    // as the equivalent 20-order case, proving exclusion is correct.
    const orders = ordersWithRiskLevels([
      ...Array(10).fill('high'),
      ...Array(4).fill('medium'),
      ...Array(16).fill('low'),
    ]);
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(42);
  });

  test('only the most recent 100 (non-high) orders count — older orders outside that window are excluded', () => {
    // 50 OLDER "medium" orders + 100 NEWER "low" orders (150 total, all
    // non-high). If the code correctly sorts by createdAt descending and
    // takes the most recent 100, recent100 should be exactly the 100 "low"
    // orders (0 medium) → reviewRate=0 → no fatigue adjustment.
    // If the slice/sort were buggy (e.g. no sort, or wrong direction), the
    // older "medium" orders could leak into the window and change the rate.
    const olderMedium = Array.from({ length: 50 }, (_, i) => ({
      id: `old-medium-${i}`,
      riskLevel: 'medium',
      createdAt: new Date(2020, 0, 1 + i, 12, 0, 0), // clearly older
    }));
    const newerLow = Array.from({ length: 100 }, (_, i) => ({
      id: `new-low-${i}`,
      riskLevel: 'low',
      createdAt: new Date(2025, 0, 1 + i, 12, 0, 0), // clearly newer
    }));
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, [...olderMedium, ...newerLow]);
    expect(reviewThreshold).toBe(40);
  });

  test('reviewRate=1.0 (all 20 medium) still yields exactly the +8 ceiling, not more', () => {
    const orders = ordersWithRiskLevels(Array(20).fill('medium'));
    const { reviewThreshold } = calculateThresholds(0, FATIGUE_MERCHANT_PROFILE, orders);
    expect(reviewThreshold).toBe(46); // same ceiling as the 0.25 case above
  });
});

// ─── Decision assignment boundaries (integration via calculateRiskScore) ──
//
// Uses calculateThresholds() itself to derive the expected boundary values
// dynamically — this also serves as a consistency guard: if
// calculateRiskScore's inline (duplicated) threshold logic ever drifts from
// calculateThresholds(), these tests will start failing at the boundary.
// merchantId stays null throughout (reviewThreshold is fixed at 40; see
// baseline section above), so only approveThreshold varies with amount.

describe('decision assignment boundaries (no risk-floor interference)', () => {
  test('score one point below reviewThreshold(40) → Block; at reviewThreshold → Review (amount=50, no other penalties)', async () => {
    const { reviewThreshold } = calculateThresholds(50, null, []);
    expect(reviewThreshold).toBe(40);

    const below = await runFloor({ amount: 50, ipPenalty: 61 }); // 100-61=39
    expect(below.score).toBe(39);
    expect(below.decision).toBe('High Risk — Block');

    const at = await runFloor({ amount: 50, ipPenalty: 60 }); // 100-60=40
    expect(at.score).toBe(40);
    expect(at.decision).toBe('Medium Risk — Review');
  });

  test('score one point below approveThreshold → Review; at approveThreshold → Approve (amount=50 → approveThreshold=70)', async () => {
    const { approveThreshold } = calculateThresholds(50, null, []);
    expect(approveThreshold).toBe(70);

    const below = await runFloor({ amount: 50, ipPenalty: 31 }); // 100-31=69
    expect(below.score).toBe(69);
    expect(below.decision).toBe('Medium Risk — Review');

    const at = await runFloor({ amount: 50, ipPenalty: 30 }); // 100-30=70
    expect(at.score).toBe(70);
    expect(at.decision).toBe('Low Risk — Approve');
  });

  test('approveThreshold boundary shifts correctly at a larger amount (amount=1000 → approveThreshold=76); accounts for the -10 "first order >=$150" penalty that fires whenever isNewCustomer && amount>=150', async () => {
    const { approveThreshold, reviewThreshold } = calculateThresholds(1000, null, []);
    expect(approveThreshold).toBe(76);
    expect(reviewThreshold).toBe(40);

    // raw = 100 - 10 (new-customer high-value penalty, always fires here
    // since allOrders=[] makes isNewCustomer permanently true) - ipPenalty
    const below = await runFloor({ amount: 1000, ipPenalty: 15 }); // 100-10-15=75
    expect(below.score).toBe(75);
    expect(below.decision).toBe('Medium Risk — Review');

    const at = await runFloor({ amount: 1000, ipPenalty: 14 }); // 100-10-14=76
    expect(at.score).toBe(76);
    expect(at.decision).toBe('Low Risk — Approve');
  });
});

// ─── Risk floor — critical signal forces Block regardless of score ────────

describe('risk floor — hasCriticalSignal', () => {
  test('a critical flag with raw score comfortably above 40 still gets clamped down to exactly 40', async () => {
    // cardHashRecord: attemptBonus=min(3*5,25)=15, blockBonus=20 (blockCount>0)
    // → cardPenalty=35 > 30 → severity "critical". raw = 100-35 = 55 (>40).
    const result = await runFloor({
      amount: 50,
      cardHashRecord: { attemptCount: 3, blockCount: 1 },
    });
    expect(result.flags.some((f) => f.severity === 'critical')).toBe(true);
    expect(result.score).toBe(40);
    expect(result.decision).toBe('High Risk — Block');
  });

  test('a critical flag with raw score already below 40 is left unchanged (Math.min clamp, not a hard reset)', async () => {
    // blacklist match: -80. raw = 100-80 = 20 (<40).
    const result = await runFloor({
      amount: 50,
      blacklist: [{ ip: '203.0.113.10' }],
    });
    expect(result.score).toBe(20);
    expect(result.decision).toBe('High Risk — Block');
  });

  test('REGRESSION GUARD — the exact anti-pattern the code comments describe: a critical-clamped score of 40 must still decide Block, not Review, even though reviewThreshold is also 40 (score >= reviewThreshold would normally mean Review)', async () => {
    const { reviewThreshold } = calculateThresholds(50, null, []);
    expect(reviewThreshold).toBe(40);

    const result = await runFloor({
      amount: 50,
      cardHashRecord: { attemptCount: 3, blockCount: 1 }, // same as above, clamps to 40
    });
    expect(result.score).toBe(40);
    expect(result.score).toBeGreaterThanOrEqual(reviewThreshold); // would be Review by score alone
    expect(result.decision).toBe('High Risk — Block'); // but isn't, because hasCriticalSignal short-circuits first
  });

  test('CRITICAL branch takes priority over the "2+ high flags" branch when both are structurally satisfied', async () => {
    // 1 critical (cardHash, -35) + 2 high (shipping/billing mismatch -15,
    // and HIGH_VALUE >=5x tier -30 via a synthetic low-value history order).
    // raw = 100-35-15-30 = 20.
    // If the branches were NOT correctly ordered as if/else-if (i.e. if the
    // "2+ high" branch fired instead), the result would be a HARD-SET 55,
    // not a clamp of the raw value — so 20 vs 55 is a real, distinguishing
    // check of branch priority, not a coincidence of small numbers.
    const result = await runFloor({
      amount: 50,
      cardHashRecord: { attemptCount: 3, blockCount: 1 }, // critical, -35
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }), // -15, high
      allOrders: [lowValueHistoryOrder()], // avgOrderValue=10, order.amount=50 → multiple=5 → -30, high
    });
    const highFlags = result.flags.filter((f) => f.severity === 'high');
    expect(highFlags.length).toBeGreaterThanOrEqual(2);
    expect(result.flags.some((f) => f.severity === 'critical')).toBe(true);
    expect(result.score).toBe(20); // NOT 55
    expect(result.decision).toBe('High Risk — Block');
  });
});

// ─── Risk floor — single high flag caps at 70 ─────────────────────────────

describe('risk floor — single high signal (highCount < 2)', () => {
  test('raw score below 70 is left untouched (69 stays 69)', async () => {
    // shipping/billing mismatch: -15 (high, fixed). ipPenalty=16 (medium,
    // doesn't count toward highCount). raw = 100-15-16 = 69.
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      ipPenalty: 16,
    });
    expect(result.flags.filter((f) => f.severity === 'high').length).toBe(1);
    expect(result.score).toBe(69);
  });

  test('raw score exactly 70 is left untouched (strict ">70" condition does not include the boundary itself)', async () => {
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      ipPenalty: 15, // raw = 100-15-15 = 70
    });
    expect(result.score).toBe(70);
  });

  test('raw score of 71 gets capped down to exactly 70', async () => {
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      ipPenalty: 14, // raw = 100-15-14 = 71
    });
    expect(result.score).toBe(70);
  });
});

// ─── Risk floor — 2+ high flags caps at 55 ─────────────────────────────────

describe('risk floor — multiple high signals (highCount >= 2)', () => {
  test('raw score of 54 (below the 55 boundary) is left untouched', async () => {
    // shipping mismatch (-15, high) + cardHash (attemptCount=1,blockCount=0
    // → cardPenalty=5, not >30 → high) + ipPenalty dial (medium) to reach 54.
    // raw = 100-15-5-26 = 54.
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      cardHashRecord: { attemptCount: 1, blockCount: 0 },
      ipPenalty: 26,
    });
    expect(result.flags.filter((f) => f.severity === 'high').length).toBe(2);
    expect(result.score).toBe(54);
  });

  test('raw score of exactly 55 is left untouched (strict ">55" condition)', async () => {
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      cardHashRecord: { attemptCount: 1, blockCount: 0 },
      ipPenalty: 25, // raw = 100-15-5-25 = 55
    });
    expect(result.score).toBe(55);
  });

  test('raw score of 56 gets capped down to exactly 55', async () => {
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      cardHashRecord: { attemptCount: 1, blockCount: 0, blockCount: 0 },
      ipPenalty: 24, // raw = 100-15-5-24 = 56
    });
    expect(result.score).toBe(55);
  });

  test('"2+ high" branch takes priority over the single-high "70" branch when both are numerically satisfied (raw=80, same fixture as T3d-3-style but without the ipPenalty dial)', async () => {
    // shipping (-15, high) + cardHash attemptCount=1,blockCount=0 (-5, high)
    // → raw = 100-15-5 = 80. This is simultaneously >55 (2+ high branch
    // condition) AND >70 (single-high branch condition). Since the
    // 2+ high branch is checked first in the else-if chain, the correct
    // result is 55 — if the single-high branch had fired instead
    // (wrong priority, or the branches were independent ifs), the result
    // would be 70. 55 vs 70 is a real, distinguishing check.
    const result = await runFloor({
      amount: 50,
      shippingAddress: JSON.stringify({ country: 'US' }),
      billingAddress: JSON.stringify({ country: 'EG' }),
      cardHashRecord: { attemptCount: 1, blockCount: 0 },
    });
     // sanity note, see assertion below
    expect(result.score).toBe(55);
  });
});