// chargeguard-simulation.js
//
// ChargeGuard Staging Validation — Store API Checkout Load Test
// -----------------------------------------------------------------------
// Purpose: Reproduce the REQUEST-METADATA PATTERN of the Store API /
// Block Checkout card-testing vector (missing headers, rate bursts,
// BIN-cluster shape) using ONLY Stripe's official non-functional test
// tokens. No real or generated card numbers are used anywhere.
//
// This script intentionally does NOT contain any card-number generation,
// BIN list, or Luhn logic — only the fixed, publicly documented Stripe
// test tokens below, which cannot process a real charge on any account.
//
// Run with: k6 run chargeguard-simulation.js
// -----------------------------------------------------------------------

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------
// SAFETY GATE — refuses to run against anything that doesn't look like
// a staging/local target unless explicitly overridden.
// ---------------------------------------------------------------------
const TARGET_URL = __ENV.TARGET_URL || '';
const ALLOW_NONSTAGING = (__ENV.ALLOW_NONSTAGING || 'false').toLowerCase() === 'true';

if (!TARGET_URL) {
  throw new Error('TARGET_URL env var is required, e.g. https://staging.example.com');
}
const looksLikeStaging = /staging|localhost|127\.0\.0\.1|\.test\b/i.test(TARGET_URL);
if (!looksLikeStaging && !ALLOW_NONSTAGING) {
  throw new Error(
    `TARGET_URL "${TARGET_URL}" doesn't look like a staging/local host. ` +
    `If this really is your test environment, re-run with ALLOW_NONSTAGING=true.`
  );
}

// ---------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------
const CHECKOUT_PATH = '/wp-json/wc/store/v1/checkout';
const REVIEW_PATH = '/wp-json/wc/store/v1/checkout/update-customer'; // maps to update_order_review-equivalent

// Official Stripe test tokens (https://docs.stripe.com/testing) — fixed
// list only, never generated or enumerated.
const STRIPE_TEST_TOKENS = [
  { token: 'tok_visa',                 label: 'visa_success' },
  { token: 'tok_visa_debit',           label: 'visa_debit_success' },
  { token: 'tok_mastercard',           label: 'mastercard_success' },
  { token: 'tok_mastercard_debit',     label: 'mastercard_debit_success' },
  { token: 'tok_amex',                 label: 'amex_success' },
  { token: 'tok_chargeDeclined',       label: 'generic_decline' },
  { token: 'tok_chargeDeclinedInsufficientFunds', label: 'decline_insufficient_funds' },
  { token: 'tok_chargeDeclinedFraudulent',        label: 'decline_fraudulent' },
  { token: 'tok_chargeDeclinedIncorrectCvc',      label: 'decline_bad_cvc' },
];

// Custom metrics for later analysis / harness cross-check
const attackRequests = new Counter('attack_requests_sent');
const legitRequests = new Counter('legit_requests_sent');
const blockedResponses = new Counter('blocked_responses');
const reviewResponses = new Counter('review_responses');
const approvedResponses = new Counter('approved_responses');
const responseTime = new Trend('checkout_response_time');

// ---------------------------------------------------------------------
// k6 SCENARIOS — ramping stages: 1 req/s -> 50 req/s over configurable window
// ---------------------------------------------------------------------
export const options = {
  scenarios: {
    ramping_attack_traffic: {
      executor: 'ramping-arrival-rate',
      startRate: 1,
      timeUnit: '1s',
      preAllocatedVUs: 60,
      maxVUs: 120,
      stages: [
        { target: 1, duration: '10s' },   // baseline — matches ramp-up tolerance window
        { target: 5, duration: '15s' },   // low-intensity probing
        { target: 20, duration: '20s' },  // mid ramp
        { target: 50, duration: '30s' },  // sustained burst (upper bound of documented range)
        { target: 50, duration: '30s' },  // hold at burst
        { target: 0, duration: '10s' },   // cooldown
      ],
    },
  },
};

// ---------------------------------------------------------------------
// HELPERS — build request bodies that carry the ATTACK FINGERPRINT
// (missing headers, Origin: Unknown, no session) vs. a LEGITIMATE
// checkout (full headers, session cookie, realistic navigation history).
// ---------------------------------------------------------------------

function randomTestToken() {
  return STRIPE_TEST_TOKENS[Math.floor(Math.random() * STRIPE_TEST_TOKENS.length)];
}

function buildAttackRequest() {
  const card = randomTestToken();
  const body = JSON.stringify({
    payment_method: 'stripe',
    payment_data: [
      { key: 'stripe_token', value: card.token },
    ],
    billing_address: {
      first_name: 'Test',
      last_name: 'Buyer',
      address_1: '123 Test St',
      city: 'Testville',
      state: 'CA',
      postcode: '90001',
      country: 'US',
      email: `synthetic+${Math.random().toString(36).slice(2)}@example-test.invalid`,
      phone: '',
    },
  });

  // Attack fingerprint: no User-Agent, no Referer, no cookie, Origin: Unknown.
  // These are the header-omission patterns documented in the threat intel —
  // not a technique for evading detection, but the exact signal set
  // ChargeGuard needs to key on.
  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'Unknown',
      // Deliberately no User-Agent, no Referer, no Cookie
    },
    tags: { request_type: 'attack' },
  };

  return { body, params, cardLabel: card.label };
}

function buildLegitRequest() {
  const card = { token: 'tok_visa', label: 'visa_success' }; // legit traffic always "succeeds"
  const body = JSON.stringify({
    payment_method: 'stripe',
    payment_data: [
      { key: 'stripe_token', value: card.token },
    ],
    billing_address: {
      first_name: 'Real',
      last_name: 'Customer',
      address_1: '456 Legit Ave',
      city: 'Realtown',
      state: 'NY',
      postcode: '10001',
      country: 'US',
      email: `legit+${Math.random().toString(36).slice(2)}@example-test.invalid`,
      phone: '555-0100',
    },
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Origin': TARGET_URL,
      'Referer': `${TARGET_URL}/cart/`,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
      'Cookie': `woocommerce_session=synthetic_legit_${Math.random().toString(36).slice(2)}`,
    },
    tags: { request_type: 'legit' },
  };

  return { body, params, cardLabel: card.label };
}

// ---------------------------------------------------------------------
// MAIN — 90% attack-shaped, 10% legitimate-shaped, matching the volume
// asymmetry described in the threat intel for an active campaign.
// ---------------------------------------------------------------------
export default function () {
  const isLegit = Math.random() < 0.10;
  const req = isLegit ? buildLegitRequest() : buildAttackRequest();

  const res = http.post(`${TARGET_URL}${CHECKOUT_PATH}`, req.body, req.params);

  responseTime.add(res.timings.duration);

  if (isLegit) {
    legitRequests.add(1);
  } else {
    attackRequests.add(1);
  }

  // Classify ChargeGuard's decision from the response. Adjust field names
  // to match your actual API contract (assumed: JSON body with a
  // `chargeguard_decision` field, or a custom header — update as needed).
  let decision = 'unknown';
  try {
    const json = res.json();
    decision = json.chargeguard_decision || res.headers['X-Chargeguard-Decision'] || 'unknown';
  } catch (e) {
    decision = res.headers['X-Chargeguard-Decision'] || 'unknown';
  }

  if (decision === 'block') blockedResponses.add(1);
  else if (decision === 'review') reviewResponses.add(1);
  else if (decision === 'approve') approvedResponses.add(1);

  check(res, {
    'status is 200 or 4xx (not 5xx crash)': (r) => r.status < 500,
    'response has a chargeguard decision': () => decision !== 'unknown',
  });

  // Small jitter so requests within a VU aren't perfectly periodic
  sleep(Math.random() * 0.2);
}

// ---------------------------------------------------------------------
// SUMMARY — printed at end of run; feed these numbers into Deliverable 3
// ---------------------------------------------------------------------
export function handleSummary(data) {
  console.log('--- ChargeGuard Simulation Summary ---');
  console.log(`Attack-shaped requests sent: ${data.metrics.attack_requests_sent?.values.count || 0}`);
  console.log(`Legit-shaped requests sent: ${data.metrics.legit_requests_sent?.values.count || 0}`);
  console.log(`Blocked: ${data.metrics.blocked_responses?.values.count || 0}`);
  console.log(`Review: ${data.metrics.review_responses?.values.count || 0}`);
  console.log(`Approved: ${data.metrics.approved_responses?.values.count || 0}`);
  return {
    'stdout': JSON.stringify(data, null, 2),
  };
}