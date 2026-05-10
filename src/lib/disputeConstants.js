// ─── ChargeGuard Dispute Intelligence Constants ────────────────────────────
// All scoring weights and thresholds in one place.
// To recalibrate the model, edit here only — never edit magic numbers inline.

// ─── Friendly Fraud Probability Weights ──────────────────────────────────

export const FFP_WEIGHTS = {
  // Condition signals
  FRAUD_CONDITION:          30, // 10.4 is the most common friendly fraud vector

  // Customer risk profile — individual signal weights
  PROFILE_DISPUTE_COUNT:    20, // customer has 3+ prior disputes
  PROFILE_LATE_CLAIM_RATE:  25, // customer files > 70% of disputes late
  PROFILE_AVG_DAYS:         15, // customer averages > 60 days before claiming
  PROFILE_CAP:              40, // max contribution from profile (signals are correlated)

  // Evidence signals — positive (merchant-friendly)
  DELIVERY_PROOF_BONUS:     25, // confirmed delivery — strong merchant signal
  TRACKING_BONUS:           10, // customer viewed tracking — aware of shipment
  LOGIN_BONUS:              10, // customer logged in after purchase
  USAGE_LOGS_BONUS: -20, // digital product with usage logs
  CE_ELIGIBLE_BONUS:        20, // CE 3.0 eligible — liability shift signal
  TRACKING_DELIVERY_BONUS:  10, // both tracking + delivery confirmed

  // Evidence signals — negative (fraud-friendly)
  NO_DELIVERY_PENALTY:      20, // no delivery proof
  NO_TRACKING_PENALTY:      10, // no tracking viewed
  NO_LOGIN_PENALTY:         10, // no login or click-to-accept
  NO_USAGE_LOGS_PENALTY:    20, // digital product without usage logs

  // Time gap signals
  LATE_CLAIM_60_DAYS:       15, // dispute filed > 60 days after order
  LATE_CLAIM_30_DAYS:        5, // dispute filed > 30 days after order
};

// ─── Win Probability Thresholds ──────────────────────────────────────────

export const WIN_PROB = {
  // Base probability matrix — evidenceStrength is primary driver
  BASE_HIGH_EVIDENCE_HIGH_FF:   75, // evidenceStrength >= 60 && friendlyFraudProb >= 60
  BASE_HIGH_EVIDENCE:           60, // evidenceStrength >= 60
  BASE_MID_EVIDENCE_HIGH_FF:    50, // evidenceStrength >= 40 && friendlyFraudProb >= 60
  BASE_MID_EVIDENCE:            35, // evidenceStrength >= 40
  BASE_LOW_EVIDENCE:            20, // evidenceStrength >= 20
  BASE_VERY_LOW_EVIDENCE:       10, // evidenceStrength < 20

  // Merchant historical adjustment clamps
  MULTIPLIER_MAX:              2.0, // max boost from merchant win rate
  MULTIPLIER_MIN:              0.3, // max penalty from merchant win rate
  MULTIPLIER_BASELINE:         0.5, // baseline win rate expectation

  // Final probability clamps
  FINAL_MAX:                   95, // never show 100% confidence
  FINAL_MIN:                    5, // never show 0% confidence

  // Recommendation thresholds
  FIGHT_THRESHOLD:             60, // winProb >= 60 → fight
  NEGOTIATE_THRESHOLD:         40, // winProb >= 40 → negotiate

  // CE 3.0 direct boost — applied after base probability calculation
  // CE 3.0 is a Visa-defined liability shift mechanism, not just an evidence signal
  CE_ELIGIBLE_BOOST:           10, // flat boost when CE 3.0 criteria are met
};

// ─── Case Scoring Weights ─────────────────────────────────────────────────
// Signal weights for the rule-based case scoring engine.
// Changing a threshold here automatically affects scoring, recommendations,
// and missing-evidence hints across the entire application.

export const CASE_SCORE = {
  // Signal weights
  ECI_PROTECTION:       4,
  CE_ELIGIBLE:          3,
  DELIVERY_PROOF:       3,
  REFUND_PROCESSED:     3,
  AVS_WITH_DELIVERY:    2,
  LOGIN_AFTER_PURCHASE: 2,
  CLICK_TO_ACCEPT:      2,
  TRACKING_CONFIRMED:   2,
  PRE_CHARGE_NOTICE:    2,
  USAGE_LOGS:           2,
  NO_CANCELLATION:      2,
  CUSTOMER_LOGIN_ID:    1,

  // Score cap
  MAX_SCORE:            10,

  // Recommendation thresholds
  FIGHT_THRESHOLD:      8,
  CONSIDER_THRESHOLD:   6,
  RISKY_THRESHOLD:      4,
};

// ─── Friendly Fraud Risk Weights (assessFriendlyFraudRisk) ───────────────

export const FFR_WEIGHTS = {
  DELIVERY_CONFIRMED:   40, // delivery confirmed for item_not_received dispute
  LOGIN_AFTER:          20, // customer logged in after order
  REVIEW_SUBMITTED:     35, // customer submitted review before dispute
  CE30_ELIGIBLE:        25, // CE 3.0 eligible

  // Recommendation thresholds
  REPRESENTMENT_THRESHOLD:  40, // friendlyFraudScore >= 40 → recommend representment
  SUSPECTED_FF_THRESHOLD:   30, // friendlyFraudScore >= 30 → suspected friendly fraud
};