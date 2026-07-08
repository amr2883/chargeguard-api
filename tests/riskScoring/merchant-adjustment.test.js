'use strict';

// ─── T3d-4: Merchant Threshold Adjustment ──────────────────────────────────
//
// SCOPE
//   getMerchantAdjustment(profile) is a PURE function — no DB, no async, no
//   external intel calls. This file drives it directly via unit-style calls,
//   plus a small cross-check against calculateThresholds() (the documented
//   "single source of truth" for threshold math) to catch drift between the
//   two.
//
// MOCKING STRATEGY (identical rationale to T3d-2/T3d-3, reused verbatim):
//   - prom-client, ipIntelligence, patternSharing → jest.mock'd purely to
//     satisfy riskScoring.js's require graph at load time. None of their
//     functions are ever called from these tests — getMerchantAdjustment
//     touches none of them.
//   - No `db`, no Supertest, no Docker dependency: this is pure in-memory
//     arithmetic, confirmed by reading the source (no `await`, no db.*).
//
// IMPORTANT: calculateRiskScore does NOT call calculateThresholds() — despite
// the comment atop calculateThresholds() claiming it's the function
// "يستخدمها calculateRiskScore" (used by calculateRiskScore), the main
// scoring function actually re-implements the identical formula inline
// (duplicated, not shared). That inline copy is NOT independently
// exercisable here without the full DB/mocking machinery T3d-2 already
// built for it — so "consistency" in this file means: getMerchantAdjustment
// vs. calculateThresholds (the two things reachable from this test's scope).
// Drift between calculateThresholds and calculateRiskScore's inline copy is
// a separate architectural risk, flagged here but tested at the integration
// level in T3d-2/risk-floor.test.js, not duplicated in this file.
//
// ARITHMETIC CONVENTION: every expected number below was hand-derived from
// the exact fraction (e.g. 21/520), not eyeballed from a decimal. Where the
// result is an exact rounding-to-1-decimal value, we assert with toBeCloseTo
// at high precision (floating point safety) rather than brittle toBe on raw
// floats.

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
  getMerchantAdjustment,
  calculateThresholds,
} = require('../../src/lib/riskScoring');

beforeEach(() => {
  jest.clearAllMocks();
});

// ─── Guard clause (totalOrders < 20) ───────────────────────────────────────

describe('getMerchantAdjustment — guard clause (totalOrders < 20)', () => {
  test('null profile → {adjustment: 0, reason: null}', () => {
    expect(getMerchantAdjustment(null)).toEqual({ adjustment: 0, reason: null });
  });

  test('undefined profile → {adjustment: 0, reason: null}', () => {
    expect(getMerchantAdjustment(undefined)).toEqual({ adjustment: 0, reason: null });
  });

  test('totalOrders=0 → guard fires regardless of disputes/wins', () => {
    const result = getMerchantAdjustment({ totalOrders: 0, totalDisputes: 999, wonDisputes: 0 });
    expect(result).toEqual({ adjustment: 0, reason: null });
  });

  test('totalOrders=19 (one below the boundary) → guard fires', () => {
    const result = getMerchantAdjustment({ totalOrders: 19, totalDisputes: 5, wonDisputes: 0 });
    expect(result).toEqual({ adjustment: 0, reason: null });
  });

  test('totalOrders=20 (exactly at the boundary) → guard does NOT fire; a small but non-zero adjustment is computed', () => {
    // fraudRate = (0+1)/(20+20) = 1/40 = 0.025
    // pre = (0.025-0.01)*200 = 3.0
    // smoothedWinRate = (0+2)/(0+2+3) = 0.4 >= 0.3 → no bonus
    // confidence = min(1, 20/500) = 0.04
    // adjustment = 3.0 * 0.04 = 0.12 → round(1.2)/10 = 0.1
    const result = getMerchantAdjustment({ totalOrders: 20, totalDisputes: 0, wonDisputes: 0 });
    expect(result.adjustment).toBeCloseTo(0.1, 5);
    expect(result.reason).toBeNull();
    // The key distinguishing assertion: boundary is NOT the same as "below guard".
    expect(result.adjustment).not.toBe(0);
  });
});

// ─── Fraud rate calculation with Bayesian smoothing ────────────────────────

describe('getMerchantAdjustment — fraud rate calculation (Bayesian smoothing)', () => {
  test('mid-range fraud rate, no win-rate bonus, full confidence: exact hand-traced value', () => {
    // totalOrders=500, totalDisputes=10, wonDisputes=10
    // fraudRate = 11/520 = 0.021153846...
    // pre = (0.021153846-0.01)*200 = 2.230769231 (no clamp needed)
    // smoothedWinRate = (10+2)/(10+2+3) = 12/15 = 0.8 >= 0.3 → no bonus
    // confidence = min(1, 500/500) = 1
    // adjustment = 2.230769... → round(22.30769)/10 = 2.2
    const result = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 10, wonDisputes: 10 });
    expect(result.adjustment).toBeCloseTo(2.2, 5);
    expect(result.reason).toBeNull(); // fraudRate 2.12% sits in the no-comment middle band
  });

  test('the "+1 dispute / +20 orders" prior smooths a small sample toward the industry baseline instead of a raw 0% rate', () => {
    // A merchant with genuinely ZERO disputes over exactly 20 orders is not
    // treated as a literal 0% fraud rate — the prior injects a non-zero
    // floor. fraudRate = (0+1)/(20+20) = 0.025, not 0.
    const result = getMerchantAdjustment({ totalOrders: 20, totalDisputes: 0, wonDisputes: 0 });
    // If the smoothing prior were absent, fraudRate would be 0 and
    // adjustment would clamp to -4*confidence, a materially different value.
    expect(result.adjustment).toBeGreaterThan(0);
  });
});

// ─── Win-rate modifier ──────────────────────────────────────────────────────

describe('getMerchantAdjustment — win-rate modifier (Bayesian smoothing)', () => {
  test('isolates the +2 win-rate bonus: identical fraud rate, only wonDisputes differs, at full confidence', () => {
    // totalOrders=500, totalDisputes=10 fixed (fraudRate=11/520=0.021153846,
    // pre=2.230769231) — only wonDisputes varies.
    const highWinRate = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 10, wonDisputes: 10 });
    // smoothedWinRate = 12/15 = 0.8 >= 0.3 → no bonus → 2.230769 → 2.2
    expect(highWinRate.adjustment).toBeCloseTo(2.2, 5);

    const lowWinRate = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 10, wonDisputes: 0 });
    // smoothedWinRate = (0+2)/15 = 0.1333 < 0.3 → +2 → 4.230769 → 4.2
    expect(lowWinRate.adjustment).toBeCloseTo(4.2, 5);

    // The isolated effect of the bonus, before rounding noise: exactly +2.0
    expect(lowWinRate.adjustment - highWinRate.adjustment).toBeCloseTo(2.0, 5);
  });

  test('smoothedWinRate exactly 0.3 does NOT trigger the bonus (strict "< 0.3" condition)', () => {
    // totalOrders=500, totalDisputes=5 → fraudRate=6/520=0.011538462,
    // pre=0.307692308
    // wonDisputes=1 → smoothedWinRate=(1+2)/(5+2+3)=3/10=0.3 exactly
    const atBoundary = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 5, wonDisputes: 1 });
    expect(atBoundary.adjustment).toBeCloseTo(0.3, 5); // no bonus applied
  });

  test('smoothedWinRate just below 0.3 DOES trigger the bonus', () => {
    // Same base as above but wonDisputes=0 → smoothedWinRate=2/10=0.2 < 0.3
    const belowBoundary = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 5, wonDisputes: 0 });
    // pre=0.307692308 + 2 = 2.307692308 → round(23.07692)/10 = 2.3
    expect(belowBoundary.adjustment).toBeCloseTo(2.3, 5);
  });

  test('the prior (2 wins / 3 losses) prevents a single lost dispute from reading as a 0% win rate', () => {
    // A merchant with exactly 1 dispute, lost (wonDisputes=0) is not scored
    // as if their win rate were literally 0 — smoothedWinRate = 2/6 = 0.333.
    // totalOrders must be >=20 to escape the guard; pick 20 with 1 dispute.
    const result = getMerchantAdjustment({ totalOrders: 20, totalDisputes: 1, wonDisputes: 0 });
    // smoothedWinRate = (0+2)/(1+2+3) = 2/6 = 0.3333... >= 0.3 → NO bonus
    // (this is the exact scenario the source comment calls out — confirm
    // it lands just on the "no penalty" side of the line)
    const noPrior = getMerchantAdjustment({ totalOrders: 20, totalDisputes: 1, wonDisputes: 0 });
    // fraudRate=(1+1)/40=0.05, pre=(0.05-0.01)*200=8 (capped), confidence=0.04
    // With no bonus: 8*0.04=0.32 → round(3.2)/10=0.3
    expect(result.adjustment).toBeCloseTo(0.3, 5);
  });
});

// ─── Volume confidence scaling ──────────────────────────────────────────────

describe('getMerchantAdjustment — volume confidence scaling', () => {
  test('confidence scales adjustment proportionally when the pre-confidence value is held fixed (fraud-rate term saturated at its 8.0 cap)', () => {
    // fraudRate held at exactly 0.05 in every case below (saturates the
    // fraud-rate clamp at 8.0), and wonDisputes chosen so smoothedWinRate
    // never dips below 0.3 (no bonus) — isolating confidence as the only
    // variable.
    const n100 = getMerchantAdjustment({ totalOrders: 100, totalDisputes: 5, wonDisputes: 2 });
    // fraudRate=6/120=0.05 exact; confidence=100/500=0.2; adjustment=8*0.2=1.6
    expect(n100.adjustment).toBeCloseTo(1.6, 5);

    const n480 = getMerchantAdjustment({ totalOrders: 480, totalDisputes: 24, wonDisputes: 7 });
    // fraudRate=25/500=0.05 exact; confidence=480/500=0.96; adjustment=8*0.96=7.68→7.7
    expect(n480.adjustment).toBeCloseTo(7.7, 5);

    const n500 = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 25, wonDisputes: 7 });
    // fraudRate=26/520=0.05 exact; confidence=1; adjustment=8.0
    expect(n500.adjustment).toBeCloseTo(8.0, 5);

    // Monotonic increase as confidence rises toward 1, all else held equal.
    expect(n100.adjustment).toBeLessThan(n480.adjustment);
    expect(n480.adjustment).toBeLessThan(n500.adjustment);
  });

  test('confidence is clamped at 1.0 — totalOrders far beyond 500 produces the identical result as exactly 500', () => {
    const n500 = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 25, wonDisputes: 7 });
    const n1000 = getMerchantAdjustment({ totalOrders: 1000, totalDisputes: 50, wonDisputes: 15 });
    // fraudRate=51/1020=0.05 exact (same saturation); confidence=min(1,1000/500)=1 (clamped, same as N=500)
    expect(n1000.adjustment).toBeCloseTo(n500.adjustment, 5);
    expect(n1000.adjustment).toBeCloseTo(8.0, 5);
  });
});

// ─── Monotonicity and reasonable bounds ─────────────────────────────────────

describe('getMerchantAdjustment — monotonicity and reasonable bounds', () => {
  test('adjustment is monotonically non-decreasing as fraud rate rises, at fixed totalOrders/confidence and a win rate that never dips below the bonus threshold', () => {
    // totalOrders=500 (confidence=1) fixed. wonDisputes=totalDisputes for
    // each point, which keeps smoothedWinRate=(D+2)/(D+5) >= 0.4 for all
    // D>=0 (minimum at D=0), so the win-rate bonus never fires anywhere in
    // this series — isolating the fraud-rate term's monotonicity alone.
    const disputeCounts = [0, 5, 10, 20, 30, 50, 100];
    const adjustments = disputeCounts.map((d) =>
      getMerchantAdjustment({ totalOrders: 500, totalDisputes: d, wonDisputes: d }).adjustment
    );
    // Hand-traced: -1.6, 0.3, 2.2, 6.1, 8.0, 8.0, 8.0
    expect(adjustments[0]).toBeCloseTo(-1.6, 5);
    expect(adjustments[1]).toBeCloseTo(0.3, 5);
    expect(adjustments[2]).toBeCloseTo(2.2, 5);
    expect(adjustments[3]).toBeCloseTo(6.1, 5);
    expect(adjustments[4]).toBeCloseTo(8.0, 5);
    expect(adjustments[5]).toBeCloseTo(8.0, 5);
    expect(adjustments[6]).toBeCloseTo(8.0, 5);
    for (let i = 1; i < adjustments.length; i++) {
      expect(adjustments[i]).toBeGreaterThanOrEqual(adjustments[i - 1]);
    }
  });

  test('adjustment never falls outside its TRUE bound of [-4, 10] (not the naively-assumed [-4, 8]) across a wide sweep of profiles', () => {
    // See the dedicated "clamp order-of-operations" section below for why
    // 10, not 8, is the correct upper bound.
    const ordersOptions = [20, 25, 50, 100, 250, 500, 1000];
    const disputeOptions = [0, 1, 5, 20, 50, 100];
    const wonFractions = [0, 0.5, 1]; // 0%, 50%, 100% of disputes won

    for (const totalOrders of ordersOptions) {
      for (const totalDisputes of disputeOptions) {
        for (const frac of wonFractions) {
          const wonDisputes = Math.round(totalDisputes * frac);
          const { adjustment, reason } = getMerchantAdjustment({ totalOrders, totalDisputes, wonDisputes });
          expect(adjustment).toBeGreaterThanOrEqual(-4);
          expect(adjustment).toBeLessThanOrEqual(10);
          expect(reason === null || typeof reason === 'string').toBe(true);
        }
      }
    }
  });
});

// ─── Explainability reason ───────────────────────────────────────────────────

describe('getMerchantAdjustment — explainability reason', () => {
  test('"High merchant fraud rate" reason fires when fraudRate > 0.03, with the percentage formatted to 1 decimal', () => {
    // totalOrders=500, totalDisputes=20 → fraudRate=21/520=0.040384615 → 4.0%
    const result = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 20, wonDisputes: 5 });
    expect(result.reason).toBe('High merchant fraud rate (4.0%) — thresholds tightened');
  });

  test('"Excellent merchant fraud rate" reason fires when fraudRate < 0.005 AND totalOrders >= 50', () => {
    // totalOrders=250, totalDisputes=0 → fraudRate=1/270=0.0037037 → 0.4%
    const result = getMerchantAdjustment({ totalOrders: 250, totalDisputes: 0, wonDisputes: 0 });
    expect(result.reason).toBe('Excellent merchant fraud rate (0.4%) — thresholds relaxed');
  });

  test('no reason in the unremarkable middle band (0.5% <= fraudRate <= 3%)', () => {
    // Reuses the isolated fraud-rate test case: fraudRate=2.115%
    const result = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 10, wonDisputes: 10 });
    expect(result.reason).toBeNull();
  });

  test('"High" reason boundary: fraudRate exactly 0.03 does NOT fire (strict ">"); 0.031 does', () => {
    // totalOrders=980, totalDisputes=29 → fraudRate=30/1000=0.03 exactly
    const atBoundary = getMerchantAdjustment({ totalOrders: 980, totalDisputes: 29, wonDisputes: 20 });
    expect(atBoundary.reason).toBeNull();

    // totalOrders=980, totalDisputes=30 → fraudRate=31/1000=0.031
    const justAbove = getMerchantAdjustment({ totalOrders: 980, totalDisputes: 30, wonDisputes: 20 });
    expect(justAbove.reason).toBe('High merchant fraud rate (3.1%) — thresholds tightened');
  });
});

// ─── Consistency with calculateThresholds ───────────────────────────────────

describe('getMerchantAdjustment — consistency with calculateThresholds', () => {
  test('the adjustment returned by getMerchantAdjustment matches what calculateThresholds derives approveThreshold from, at amount=0 (logScale=0, no fatigue)', () => {
    const profile = { totalOrders: 500, totalDisputes: 20, wonDisputes: 5 };

    // Hand-traced: fraudRate=21/520=0.040384615, pre=6.076923077,
    // smoothedWinRate=(5+2)/25=0.28<0.3→+2 → 8.076923077, confidence=1
    // → adjustment=8.076923 → round(80.76923)/10 = 8.1
    const { adjustment } = getMerchantAdjustment(profile);
    expect(adjustment).toBeCloseTo(8.1, 5);

    const { approveThreshold, reviewThreshold } = calculateThresholds(0, profile, []);
    // approveThreshold = clamp(round(62 + 0 + 8.1), 60, 90) = clamp(70,60,90) = 70
    expect(approveThreshold).toBe(70);
    // reviewThresholdBase = round(32 + 8.1*0.7) = round(37.67) = 38 → floor 40
    expect(reviewThreshold).toBe(40);
  });
});

// ═════════════════════════════════════════════════════════════════════════
// REGRESSION GUARDS — findings from T3d-4 Chain-of-Thought analysis
// ═════════════════════════════════════════════════════════════════════════

describe('REGRESSION GUARD (finding #1) — the -4 floor on the fraud-rate term is dead code', () => {
  test('the true infimum of the fraud-rate term is -2, not -4: the floor never binds because fraudRate can never reach 0 (the +1 prior guarantees fraudRate > 0 always)', () => {
    // As totalOrders → ∞ with totalDisputes=0, fraudRate → 0, and
    // (fraudRate - 0.01) * 200 → -2, never -4. Verified with an extreme,
    // but finite, totalOrders.
    const result = getMerchantAdjustment({ totalOrders: 1_000_000, totalDisputes: 0, wonDisputes: 0 });
    // fraudRate = 1/1000020 ≈ 0.0000009998, pre ≈ -1.9998, confidence=1 (clamped)
    expect(result.adjustment).toBeCloseTo(-2.0, 1);
    expect(result.adjustment).toBeGreaterThan(-4); // the coded floor is never actually reached
  });
});

describe('REGRESSION GUARD (finding #2) — the "totalOrders >= 50" gate on the Excellent reason is redundant dead code', () => {
  test('any profile that can satisfy fraudRate < 0.005 already requires totalOrders > 180 (with the best-case totalDisputes=0), so the >=50 gate never independently excludes anything', () => {
    // Minimum totalOrders for fraudRate < 0.005 at totalDisputes=0:
    // 1/(N+20) < 0.005  =>  N > 180.
    // N=180 → fraudRate = 1/200 = 0.005 exactly (NOT < 0.005) → no reason.
    const atTheoreticalFloor = getMerchantAdjustment({ totalOrders: 180, totalDisputes: 0, wonDisputes: 0 });
    expect(atTheoreticalFloor.reason).toBeNull();

    // N=181 → fraudRate = 1/201 = 0.0049751... < 0.005 → reason fires.
    // totalOrders=181 already vastly exceeds the stated >=50 gate — the
    // gate was never the deciding factor and could be removed with zero
    // behavioral change.
    const justPastFloor = getMerchantAdjustment({ totalOrders: 181, totalDisputes: 0, wonDisputes: 0 });
    expect(justPastFloor.reason).toContain('Excellent merchant fraud rate');
    expect(181).toBeGreaterThan(50); // the redundant gate, trivially satisfied
  });
});

describe('REGRESSION GUARD (finding #3) — reviewThreshold is structurally invisible to merchant adjustment without fatigue', () => {
  test('reviewThreshold stays at its 40 floor across the ENTIRE possible adjustment range [-4, 10], as long as fatigueAdjustment=0', () => {
    // reviewThresholdBase = round(32 + adjustment*0.7). Even at the true
    // maximum adjustment of 10 (see finding #5 below): round(32+7)=39 < 40.
    // Even at the true minimum of ~-2 (finding #1): round(32-1.4)=~31 < 40.
    // The floor swallows the entire range — merchant adjustment can NEVER
    // move reviewThreshold on its own; only fatigueAdjustment (T3d-2) can.
    const maxAdjustmentProfile = { totalOrders: 500, totalDisputes: 25, wonDisputes: 0 }; // adjustment=10.0
    const { adjustment: maxAdj } = getMerchantAdjustment(maxAdjustmentProfile);
    expect(maxAdj).toBeCloseTo(10.0, 5);
    const { reviewThreshold: reviewAtMax } = calculateThresholds(0, maxAdjustmentProfile, []);
    expect(reviewAtMax).toBe(40);

    const minAdjustmentProfile = { totalOrders: 1_000_000, totalDisputes: 0, wonDisputes: 0 }; // adjustment≈-2.0
    const { reviewThreshold: reviewAtMin } = calculateThresholds(0, minAdjustmentProfile, []);
    expect(reviewAtMin).toBe(40);
  });
});

describe('REGRESSION GUARD (finding #4) — NaN propagation and guard-bypass on malformed/missing profile fields', () => {
  test('BUG: totalDisputes missing (undefined) with totalOrders >= 20 silently produces adjustment=NaN, not an error', () => {
    const result = getMerchantAdjustment({ totalOrders: 100, wonDisputes: 10 }); // totalDisputes omitted
    expect(result.adjustment).toBeNaN();
    expect(result.reason).toBeNull(); // NaN comparisons are all false, so reason quietly stays null too
  });

  test('BUG: wonDisputes missing (undefined) does NOT NaN the whole adjustment, but silently and permanently skips the win-rate bonus check — producing a MORE LENIENT adjustment than an explicit wonDisputes=0 would', () => {
    const profile = { totalOrders: 500, totalDisputes: 25 }; // wonDisputes omitted
    const missingWon = getMerchantAdjustment(profile);
    // smoothedWinRate = NaN, "NaN < 0.3" is false → bonus silently never applies
    // fraudRate=26/520=0.05 (defined fine), pre=8.0 (capped), confidence=1
    expect(missingWon.adjustment).toBeCloseTo(8.0, 5);

    const explicitZeroWon = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 25, wonDisputes: 0 });
    // Same fraud rate, but explicit 0 correctly triggers the low-win-rate
    // bonus (+2): 8+2=10.0
    expect(explicitZeroWon.adjustment).toBeCloseTo(10.0, 5);

    // The bug in one sentence: a merchant record with a MISSING wonDisputes
    // field is treated as LESS risky (smaller adjustment, more lenient
    // thresholds) than one explicitly recording zero wins — backwards from
    // what conservative handling of missing data should do.
    expect(missingWon.adjustment).toBeLessThan(explicitZeroWon.adjustment);
  });

  test('BUG: a profile object with totalOrders entirely absent (not null, not 0 — just missing) BYPASSES the guard clause and reaches NaN, unlike an equivalent profile with an explicit small totalOrders', () => {
    // undefined < 20 evaluates to false in JS (NaN coercion), so
    // `!profile || profile.totalOrders < 20` is false here — the function
    // does NOT return early, and proceeds into full computation.
    const missingTotalOrders = { totalDisputes: 5, wonDisputes: 2 }; // no totalOrders key at all
    const result = getMerchantAdjustment(missingTotalOrders);
    expect(result.adjustment).toBeNaN(); // confidence = min(1, undefined/500) = NaN, poisons everything

    // Contrast: the SAME dispute data with an explicit small totalOrders
    // correctly hits the guard and returns a clean, safe {0, null}.
    const explicitSmallOrders = getMerchantAdjustment({ totalOrders: 5, totalDisputes: 5, wonDisputes: 2 });
    expect(explicitSmallOrders).toEqual({ adjustment: 0, reason: null });

    // The asymmetry: a profile missing totalOrders (arguably LESS
    // trustworthy than one with an explicit low value) is handled WORSE
    // than one with explicit, known-small totalOrders.
  });
});

describe("BONUS FINDING (#5) — clamp order-of-operations: pre-confidence adjustment can reach 10, not the seemingly implied ceiling of 8", () => {
  test('the [-4, 8] clamp wraps only the fraud-rate term; the win-rate +2 bonus is added AFTER, uncapped, so confidence=1 cases can hit exactly 10.0', () => {
    // fraudRate saturates the fraud-rate term at exactly 8 (0.05 boundary),
    // AND wonDisputes=0 triggers the win-rate bonus on top of that cap.
    const result = getMerchantAdjustment({ totalOrders: 500, totalDisputes: 25, wonDisputes: 0 });
    expect(result.adjustment).toBeCloseTo(10.0, 5);
    // If the clamp had been (correctly, per its own apparent intent) applied
    // AFTER the win-rate bonus too, this would cap at 8.0, not 10.0. Locking
    // in current behavior as a regression guard, not asserting it's "right".
  });
});