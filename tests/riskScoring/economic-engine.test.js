'use strict';
jest.mock('../../tests/setup/resetRateLimits');
// ─── T3d-3: Economic Engine ────────────────────────────────────────────────
//
// MOCKING STRATEGY — read this before touching the tests below.
//
// `calculateEconomicRisk` is called INSIDE `calculateRiskScore` as a bare
// same-module function reference (`calculateEconomicRisk(...)`), not via
// `module.exports.calculateEconomicRisk(...)`. jest.mock/jest.spyOn only
// intercept the exported binding, so they CANNOT intercept this internal
// call. The brief's approach (a) — "mock calculateEconomicRisk directly" —
// does not work for this reason and was abandoned in favor of driving the
// real `calculateRiskScore` end-to-end, with every OTHER dependency
// neutralized:
//
//   - ipIntelligence   → jest.mock'd. calculateIPPenalty's return value is
//     our single "penalty dial" — the only lever needed to hit any target
//     pre-economic score deterministically.
//   - emailIntelligence → left REAL. With order.email unset, normalizeEmail
//     returns '', and getEmailIntelligence('') returns `_skipped()` on its
//     very first line — zero network calls, zero risk.
//   - binIntelligence, identityGraph → never invoked at all: no `bin` and no
//     `deviceId` are passed, so both call-sites are skipped by the
//     `if (bin)` / `if (deviceId)` guards already in riskScoring.js.
//   - patternSharing → jest.mock'd (checkPatternRisk/recordPattern always
//     called regardless of signal count; mocking avoids any DB dependency
//     and keeps this phase decoupled from T3d-5).
//   - db (Prisma) → merchantId is always `null` in these tests, which skips
//     the only `db.merchantProfile.findUnique` call inside
//     calculateRiskScore entirely. No db mock needed.
//
// KNOWN FIXED PENALTY: with no order history (`allOrders: []`) and no
// deviceId, `isNewCustomer` is always true. The block
// `if (isNewCustomer && order.amount >= 150) { score -= 10; ... }` is NOT
// gated on deviceId and fires unconditionally whenever amount >= 150. Every
// test below that uses a large amount accounts for this -10 explicitly in
// its score budget (documented inline per test).

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

const {
  calculateRiskScore,
  calculateEconomicRisk,
  scoreToProbability,
} = require('../../src/lib/riskScoring');

const { getIPIntelligence, calculateIPPenalty } = require('../../src/lib/ipIntelligence');

// ─── Test Helpers ───────────────────────────────────────────────────────────

function makeOrder({ amount = 50, ipAddress = '203.0.113.10', orderId = 'order-1' } = {}) {
  return {
    id: orderId,
    amount,
    ipAddress,
    // Fixed LOCAL-time noon via discrete Date components (year, month, day,
    // hour, ...) — .getHours() then always returns 12 regardless of the
    // test runner's timezone, safely avoiding the 2-5AM "unusual hour"
    // penalty without relying on an ISO/UTC string that could shift across
    // timezones.
    createdAt: new Date(2025, 5, 15, 12, 0, 0),
  };
}

// Runs calculateRiskScore with every non-economic dependency neutralized.
// `ipPenalty`/`ipSeverity` control the one deliberate "dial" on the score.
async function runScoring({
  amount,
  ipAddress = '203.0.113.10',
  ipPenalty = 0,
  ipSeverity = 'medium',
  blacklist = [],
  orderId = 'order-1',
}) {
  getIPIntelligence.mockResolvedValue({}); // truthy → calculateIPPenalty branch runs
  calculateIPPenalty.mockReturnValue({
    penalty: ipPenalty,
    flags: ipPenalty > 0
      ? [{ severity: ipSeverity, text: 'Elevated IP risk (test fixture)' }]
      : [],
  });

  const order = makeOrder({ amount, ipAddress, orderId });
  return calculateRiskScore(
    order,
    /* allOrders */ [],
    /* disputes */ [],
    /* blacklist */ blacklist,
    /* merchantId */ null,
    /* saveEvaluation */ false,
    /* externalVelocity */ null,
    /* cardHashRecord */ null,
    /* merchantConfig */ null,
  );
}

beforeEach(() => {
  jest.clearAllMocks();
});

// ─── scoreToProbability (pure, standalone) ─────────────────────────────────

describe('scoreToProbability', () => {
  test('score=50 (sigmoid midpoint) with no merchant fraud history returns exactly 0.5', () => {
    expect(scoreToProbability(50, 0)).toBeCloseTo(0.5, 10);
  });

  test('score=100 (best case) returns a very low probability, floor not engaged', () => {
    // rawProb = 1/(1+e^5) ≈ 0.0066929, which is already above dynamicMin
    // (0.005 at merchantFraudRate=0) — the floor should NOT alter it.
    const result = scoreToProbability(100, 0);
    expect(result).toBeCloseTo(0.006692851, 6);
    expect(result).toBeGreaterThan(0.005);
  });

  test('score=0 (worst case) returns a very high probability, approaching but not reaching 1.0', () => {
    // rawProb = 1/(1+e^-5) ≈ 0.993307
    expect(scoreToProbability(0, 0)).toBeCloseTo(0.993307149, 6);
  });

  test('is monotonically non-increasing as score increases, at a fixed merchant fraud rate', () => {
    const scores = [0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    const probs = scores.map((s) => scoreToProbability(s, 0));
    for (let i = 1; i < probs.length; i++) {
      expect(probs[i]).toBeLessThanOrEqual(probs[i - 1]);
    }
  });

  test('dynamic floor DOES engage when the raw sigmoid probability falls below it (high score + high merchant fraud rate)', () => {
    // score=95, merchantFraudRate=0.1 → riskFactor=min(1, 0.1/0.05)=1 →
    // dynamicMin=0.005+(0.02-0.005)*1=0.02. rawProb ≈ 0.010987 < 0.02.
    const result = scoreToProbability(95, 0.1);
    expect(result).toBeCloseTo(0.02, 10);
  });

  test('dynamic floor is capped at 0.02 even when merchantFraudRate exceeds 0.05 (riskFactor clamped to 1)', () => {
    const atCap = scoreToProbability(100, 0.05);
    const beyondCap = scoreToProbability(100, 0.5); // 10x past the 0.05 reference point
    expect(atCap).toBeCloseTo(0.02, 10);
    expect(beyondCap).toBeCloseTo(0.02, 10); // same floor — riskFactor is clamped, not linear beyond 0.05
  });
});

// ─── calculateEconomicRisk (pure, standalone) ──────────────────────────────

describe('calculateEconomicRisk', () => {
  test('standard case: null merchant profile uses merchantFraudRate=0 and avgOrderValue default of 50', () => {
    const result = calculateEconomicRisk(50, 100, null);
    expect(result.merchantFraudRate).toBe(0);
    expect(result.fraudProb).toBeCloseTo(0.5, 10);
    expect(result.baseThreshold).toBeCloseTo(40, 10); // max(20, max(50, 30)*0.8)
    expect(result.expectedLoss).toBeCloseTo(50, 10);
    expect(result.safeLoss).toBeCloseTo(50, 10); // uncapped — well under 3x baseThreshold
  });

  test('merchantProfile with totalOrders < 20 is treated identically to no profile (fraud rate guard)', () => {
    const belowGuard = calculateEconomicRisk(50, 100, { totalOrders: 19, totalDisputes: 15 });
    const noProfile = calculateEconomicRisk(50, 100, null);
    expect(belowGuard.merchantFraudRate).toBe(0);
    expect(belowGuard.fraudProb).toBeCloseTo(noProfile.fraudProb, 10);
  });

  test('merchantProfile with totalOrders >= 20 computes a real fraud rate that feeds scoreToProbability', () => {
    const profile = { totalOrders: 100, totalDisputes: 10 }; // rate = 0.1
    const result = calculateEconomicRisk(70, 200, profile);
    expect(result.merchantFraudRate).toBeCloseTo(0.1, 10);
    expect(result.fraudProb).toBeCloseTo(scoreToProbability(70, 0.1), 10);
  });

  test('an explicit avgOrderValue of 0 still falls back to the 50 default (falsy-zero quirk — `0 || 50` — locked in as current behavior)', () => {
    const explicitZero = calculateEconomicRisk(50, 10, { totalOrders: 25, totalDisputes: 0, avgOrderValue: 0 });
    const noProfile = calculateEconomicRisk(50, 10, null);
    expect(explicitZero.baseThreshold).toBeCloseTo(noProfile.baseThreshold, 10);
    expect(explicitZero.baseThreshold).toBeCloseTo(40, 10);
  });

  test('baseThreshold has an absolute floor of 20, even for a merchant with a tiny avgOrderValue and a tiny order', () => {
    const result = calculateEconomicRisk(50, 10, { totalOrders: 25, totalDisputes: 0, avgOrderValue: 10 });
    // max(20, max(10, 10*0.3=3)*0.8=8) = 20 — the floor, not 8
    expect(result.baseThreshold).toBeCloseTo(20, 10);
  });

  test('safeLoss is capped at 3x baseThreshold when expectedLoss exceeds it', () => {
    const result = calculateEconomicRisk(0, 1000, null); // worst-case score → fraudProb ≈ 0.9933
    expect(result.baseThreshold).toBeCloseTo(240, 10); // max(20, max(50,300)*0.8)
    expect(result.expectedLoss).toBeCloseTo(993.307149, 3); // uncapped
    expect(result.safeLoss).toBeCloseTo(720, 10); // capped at 3*240
    expect(result.expectedLoss).toBeGreaterThan(result.safeLoss);
  });

  test('zero order amount produces zero expected/safe loss, but baseThreshold stays at its floor', () => {
    const result = calculateEconomicRisk(50, 0, null);
    expect(result.expectedLoss).toBe(0);
    expect(result.safeLoss).toBe(0);
    expect(result.baseThreshold).toBeCloseTo(40, 10); // driven by the avgOrderValue=50 default, not amount
  });

  test('REGRESSION GUARD — at score=60 (the lowest score at which an Approve decision is possible, given the hard clamp floor in calculateRiskScore), the safeLoss/baseThreshold ratio never reaches 1.5 (Override 2) or 3.0 (Override 1), for any amount or merchant profile', () => {
    // This documents why Override 2 (Approve→Review) is unreachable via
    // calculateRiskScore's normal parameter space, and why Override 1 can
    // never fire FROM an Approve decision either: both require a ratio this
    // function structurally cannot produce once score >= 60.
    const amounts = [1, 10, 50, 100, 500, 1000, 5000, 20000, 100000];
    const profiles = [
      null,
      { totalOrders: 25, totalDisputes: 0, avgOrderValue: 1 },
      { totalOrders: 25, totalDisputes: 0, avgOrderValue: 10 },
      { totalOrders: 25, totalDisputes: 0, avgOrderValue: 1000 },
      { totalOrders: 100, totalDisputes: 50 }, // extreme 50% historical fraud rate
    ];

    for (const profile of profiles) {
      for (const amount of amounts) {
        const { safeLoss, baseThreshold } = calculateEconomicRisk(60, amount, profile);
        expect(safeLoss).toBeLessThanOrEqual(baseThreshold * 1.5);
        expect(safeLoss).toBeLessThanOrEqual(baseThreshold * 3); // a fortiori
      }
    }
  });

  test('POSITIVE CONTROL — the same ratio comfortably EXCEEDS both multipliers at a lower (Review-range) score, confirming the ceiling above is score-dependent, not a trivial always-true assertion', () => {
    const { safeLoss, baseThreshold } = calculateEconomicRisk(40, 60000, null);
    expect(safeLoss).toBeGreaterThan(baseThreshold * 1.5);
    expect(safeLoss).toBeGreaterThan(baseThreshold * 3 - 1); // safeLoss caps at exactly 3x when uncapped value exceeds it
  });
});

// ─── Economic Overrides — integration via calculateRiskScore ──────────────

describe('economic override branches (integration via calculateRiskScore)', () => {
  test('baseline: no override fires in an ordinary mid-Review scenario; decisionBefore === decisionAfter', async () => {
    // amount=500 → -10 new-customer penalty applies. Target score=60.
    // 100 - ipPenalty(30) - 10 = 60.
    const result = await runScoring({ amount: 500, ipPenalty: 30 });

    expect(result.score).toBe(60);
    expect(result.decision).toBe('Medium Risk — Review');
    expect(result.economicData.decisionBefore).toBe('Medium Risk — Review');
    expect(result.economicData.decisionAfter).toBe('Medium Risk — Review');
    expect(result.flags.some((f) => f.text.includes('fraud probability'))).toBe(false);
    expect(result.positives.some((p) => p.text.startsWith('Low economic exposure'))).toBe(false);
  });

  test('Override 1 fires: escalates Review → Block when expectedLoss > 3x baseThreshold and fraudProb > 0.25', async () => {
    // amount=60000 → -10 new-customer penalty. Target score=40.
    // 100 - ipPenalty(50, severity high) - 10 = 40.
    const result = await runScoring({ amount: 60000, ipPenalty: 50, ipSeverity: 'high' });

    expect(result.score).toBe(40); // sanity check on the score dial + fixed -10
    const expectedEcon = calculateEconomicRisk(40, 60000, null);
    expect(expectedEcon.expectedLoss).toBeGreaterThan(expectedEcon.baseThreshold * 3);
    expect(expectedEcon.fraudProb).toBeGreaterThan(0.25);

    expect(result.economicData.decisionBefore).toBe('Medium Risk — Review');
    expect(result.decision).toBe('High Risk — Block');
    expect(result.economicData.decisionAfter).toBe('High Risk — Block');
    expect(result.economicData.fraudProb).toBeCloseTo(Number(expectedEcon.fraudProb.toFixed(4)), 3);
    expect(result.economicData.baseThreshold).toBeCloseTo(Number(expectedEcon.baseThreshold.toFixed(2)), 1);

    const overrideFlag = result.flags.find((f) => f.text.includes('fraud probability'));
    expect(overrideFlag).toBeDefined();
    expect(overrideFlag.text).toContain('above safe limit');
  });

  test('Override 1 does NOT fire when fraudProb <= 0.25, even though the absolute expected loss is large', async () => {
    // amount=60000 → -10 new-customer penalty. Target score=65 (fraudProb ≈ 0.182 < 0.25).
    // 100 - ipPenalty(25) - 10 = 65.
    const result = await runScoring({ amount: 60000, ipPenalty: 25 });

    expect(result.score).toBe(65);
    const econ = calculateEconomicRisk(65, 60000, null);
    expect(econ.fraudProb).toBeLessThan(0.25);

    expect(result.decision).toBe('Medium Risk — Review'); // unchanged
    expect(result.economicData.decisionBefore).toBe(result.economicData.decisionAfter);
    expect(result.flags.some((f) => f.text.includes('fraud probability'))).toBe(false);
  });

  test("Override 1's !hasCriticalSignal guard is respected: numeric conditions ARE met, but a critical flag (blacklist) blocks the override from adding its own flag", async () => {
    const blacklistedIp = '203.0.113.77';
    // amount=60000 → -80 (blacklist, critical) and -10 (new customer) → score=10.
    // ipPenalty left at 0 to keep the arithmetic simple.
    const result = await runScoring({
      amount: 60000,
      ipAddress: blacklistedIp,
      ipPenalty: 0,
      blacklist: [{ ip: blacklistedIp }],
    });

    expect(result.score).toBe(10);
    expect(result.flags.some((f) => f.severity === 'critical')).toBe(true); // hasCriticalSignal confirmed true

    // Confirm the override's NUMERIC conditions genuinely would have been
    // met here, so the absence of its flag below is proof the guard fired,
    // not a coincidence of the conditions never being met.
    const econ = calculateEconomicRisk(10, 60000, null);
    expect(econ.expectedLoss).toBeGreaterThan(econ.baseThreshold * 3);
    expect(econ.fraudProb).toBeGreaterThan(0.25);

    expect(result.decision).toBe('High Risk — Block'); // already Block via the risk floor
    expect(result.economicData.decisionBefore).toBe('High Risk — Block');
    expect(result.economicData.decisionAfter).toBe('High Risk — Block'); // no visible change...
    expect(result.flags.some((f) => f.text.includes('fraud probability'))).toBe(false); // ...and no override flag was added, proving the guard held
  });

  test('Override 3 fires: de-escalates Review → Approve when safeLoss < 0.2x baseThreshold and fraudProb < 0.05', async () => {
    // amount=60000 → -10 new-customer penalty. Target score=81 (fraudProb ≈ 0.043 < 0.05).
    // Uses a MEDIUM-severity mock flag deliberately: a high-severity flag at
    // score=81 (>70) would trigger the ">70 → cap 70" risk-floor rule and
    // silently overwrite our target score before the economic layer ever runs.
    // 100 - ipPenalty(9, severity medium) - 10 = 81.
    const result = await runScoring({ amount: 60000, ipPenalty: 9, ipSeverity: 'medium' });

    expect(result.score).toBe(81);
    const econ = calculateEconomicRisk(81, 60000, null);
    expect(econ.fraudProb).toBeLessThan(0.05);
    expect(econ.safeLoss).toBeLessThan(econ.baseThreshold * 0.2);

    expect(result.economicData.decisionBefore).toBe('Medium Risk — Review');
    expect(result.decision).toBe('Low Risk — Approve');
    expect(result.economicData.decisionAfter).toBe('Low Risk — Approve');

    const positiveNote = result.positives.find((p) => p.text.startsWith('Low economic exposure'));
    expect(positiveNote).toBeDefined();
  });

  test('Override 3 respects the strict decision === "Medium Risk — Review" gate: numeric conditions ARE met, but decision is already Approve', async () => {
    // amount=1 (below the 150 threshold — the fixed -10 new-customer penalty
    // does NOT apply here, simplifying the score budget).
    // Target score=85. 100 - ipPenalty(15) = 85.
    const result = await runScoring({ amount: 1, ipPenalty: 15 });

    expect(result.score).toBe(85);
    const econ = calculateEconomicRisk(85, 1, null);
    expect(econ.fraudProb).toBeLessThan(0.05);
    expect(econ.safeLoss).toBeLessThan(econ.baseThreshold * 0.2);

    expect(result.economicData.decisionBefore).toBe('Low Risk — Approve'); // NOT Review
    expect(result.decision).toBe('Low Risk — Approve'); // unchanged — gate held
    expect(result.economicData.decisionAfter).toBe('Low Risk — Approve');
    expect(result.positives.some((p) => p.text.startsWith('Low economic exposure'))).toBe(false);
  });

  test('Override 3 does NOT fire near the fraudProb=0.05 boundary from the Review side (both its conditions fail together this close to the line)', async () => {
    // amount=60000 → -10 new-customer penalty. Target score=79 (fraudProb ≈ 0.052, just OVER 0.05).
    // 100 - ipPenalty(11) - 10 = 79.
    const result = await runScoring({ amount: 60000, ipPenalty: 11 });

    expect(result.score).toBe(79);
    const econ = calculateEconomicRisk(79, 60000, null);
    // Both conditions move together as functions of score/amount this close
    // to the boundary — this test demonstrates the guard holding overall,
    // not a clean isolation of the fraudProb clause alone.
    expect(econ.fraudProb).toBeGreaterThanOrEqual(0.05);

    expect(result.decision).toBe('Medium Risk — Review'); // unchanged
    expect(result.economicData.decisionBefore).toBe(result.economicData.decisionAfter);
    expect(result.positives.some((p) => p.text.startsWith('Low economic exposure'))).toBe(false);
  });

  test('the three overrides are mutually exclusive per call (if/else-if): only one economicData.decisionAfter transition is ever recorded', async () => {
    // Reuses the Override 1 scenario. If the branches were independent
    // (plain `if` instead of `if/else if`), a sufficiently large loss could
    // in principle trigger more than one branch's side effects in the same
    // call. Confirms exactly one transition occurred.
    const result = await runScoring({ amount: 60000, ipPenalty: 50, ipSeverity: 'high' });

    expect(result.economicData.decisionBefore).not.toBe(result.economicData.decisionAfter);
    // Only Override 1's flag should be present — no Override 3 "positives" text.
    expect(result.positives.some((p) => p.text.startsWith('Low economic exposure'))).toBe(false);
  });
});