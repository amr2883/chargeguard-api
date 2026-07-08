'use strict';

/**
 * ══════════════════════════════════════════════════════════════════════════
 * SCOPE: Fail‑Closed Startup Verification
 * --------------------------------------------------------------------------
 * Covers 4 test cases from the T10 mapping table §5.8:
 *   1. SECRET_SALT missing → require('../../src/routes/risk') throws eagerly.
 *   2. SECRET_SALT missing → require('../../src/lib/velocityDetector') throws eagerly.
 *   3. SECRET_SALT set → require succeeds, no throw.
 *   4. (documented quirk) IDENTITY_GRAPH_SECRET / PATTERN_SHARING_SECRET
 *      missing does NOT throw at require‑time. The check for those vars is
 *      lazy — it lives inside getSecret() / hashValue(), not at module top
 *      level — so the server would start but fail later when those functions
 *      are actually called.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * MOCKING STRATEGY:
 * --------------------------------------------------------------------------
 *   - NO jest.mock() calls. We are testing the REAL require‑time behavior of
 *     the actual source modules. The only thing we control is process.env.
 *   - jest.resetModules() is called in beforeEach to guarantee a clean
 *     module registry for each test. Without it, Node's require cache would
 *     serve the previously‑required (and possibly failed) module instance.
 *   - process.env is saved/restored around each test to prevent cross‑test
 *     contamination.
 *   - The tests use jest.isolateModules() to sandbox the require() calls,
 *     ensuring that any side effects (like a thrown error) do not leak
 *     into the outer test scope or corrupt the module registry for other
 *     tests in this file.
 *
 * ══════════════════════════════════════════════════════════════════════════
 * QUIRK DOCUMENTED:
 * --------------------------------------------------------------------------
 *   - IDENTITY_GRAPH_SECRET and PATTERN_SHARING_SECRET are NOT required for
 *     server startup. identityGraph.js, patternSharing.js, and utils.js only
 *     check them lazily inside getSecret() / hashValue() / hashPattern().
 *     If these env vars are missing, the server will boot successfully but
 *     will throw when any graph or pattern function is actually invoked.
 *     This is a deliberate design choice — it allows the server to start
 *     even if those optional features are not configured, as long as the
 *     calling code handles the thrown error gracefully (which it does, via
 *     try/catch in checkPatternRisk / recordPattern / getConnectedRisk).
 *     Only SECRET_SALT is truly mandatory at boot time.
 */

// ─── Original env snapshot for restoration ─────────────────────────────────
const ORIGINAL_ENV = { ...process.env };

// ─── Helpers ──────────────────────────────────────────────────────────────
function deleteEnvVars(...vars) {
  for (const v of vars) {
    delete process.env[v];
  }
}

function restoreEnvVars(original) {
  // Delete any keys added during the test that weren't in the original.
  for (const key of Object.keys(process.env)) {
    if (!(key in original)) {
      delete process.env[key];
    }
  }
  // Restore original values.
  Object.assign(process.env, original);
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe('fail-closed startup', () => {

  beforeEach(() => {
    jest.resetModules();
    deleteEnvVars('SECRET_SALT', 'IDENTITY_GRAPH_SECRET', 'PATTERN_SHARING_SECRET');
  });

  afterEach(() => {
    restoreEnvVars(ORIGINAL_ENV);
  });

  // ── 1. SECRET_SALT missing → routes/risk throws ───────────────────────
  test('SECRET_SALT missing → require("../../src/routes/risk") throws eagerly at module load', () => {
    // Ensure the env var is genuinely absent.
    expect(process.env.SECRET_SALT).toBeUndefined();

    // Use isolateModules to capture the require-time throw cleanly.
    jest.isolateModules(() => {
      expect(() => {
        require('../../src/routes/risk');
      }).toThrow('[risk] SECRET_SALT environment variable is required');
    });
  });

  // ── 2. SECRET_SALT missing → velocityDetector throws ──────────────────
  test('SECRET_SALT missing → require("../../src/lib/velocityDetector") throws eagerly at module load', () => {
    expect(process.env.SECRET_SALT).toBeUndefined();

    jest.isolateModules(() => {
      expect(() => {
        require('../../src/lib/velocityDetector');
      }).toThrow('[velocityDetector] SECRET_SALT environment variable is required');
    });
  });

  // ── 3. SECRET_SALT set → require succeeds ─────────────────────────────
  test('SECRET_SALT set → both modules load successfully without throwing', () => {
    process.env.SECRET_SALT = 'test-salt-value';

    jest.isolateModules(() => {
      expect(() => {
        require('../../src/routes/risk');
      }).not.toThrow();

      // Reset modules again so velocityDetector is required fresh inside
      // the same sandbox (routes/risk already required it, but isolateModules
      // gives us a clean slate for the second require).
    });

    jest.isolateModules(() => {
      expect(() => {
        require('../../src/lib/velocityDetector');
      }).not.toThrow();
    });
  });

  // ── 4. (documented quirk) IDENTITY_GRAPH_SECRET / PATTERN_SHARING_SECRET
  //      missing does NOT throw at require-time ──────────────────────────
  test('IDENTITY_GRAPH_SECRET and PATTERN_SHARING_SECRET missing do NOT prevent require (lazy check, only SECRET_SALT is eager)', () => {
    // Set only SECRET_SALT — leave the other two deliberately absent.
    process.env.SECRET_SALT = 'test-salt-value';
    expect(process.env.IDENTITY_GRAPH_SECRET).toBeUndefined();
    expect(process.env.PATTERN_SHARING_SECRET).toBeUndefined();

    jest.isolateModules(() => {
      // These modules import identityGraph / patternSharing transitively,
      // but because their checks are lazy (inside function bodies, not at
      // module top level), the require succeeds.
      expect(() => {
        require('../../src/routes/risk');
      }).not.toThrow();

      expect(() => {
        require('../../src/lib/velocityDetector');
      }).not.toThrow();
    });

    // DOCUMENTED QUIRK:
    // identityGraph.js, patternSharing.js, and utils.js define getSecret()
    // and hashValue(), which check for IDENTITY_GRAPH_SECRET and
    // PATTERN_SHARING_SECRET only when called — not at require-time.
    // This means the server will boot even if those vars are missing, but
    // will throw later when a request actually triggers graph/pattern logic.
    // The callers (checkPatternRisk, recordPattern, getConnectedRisk) wrap
    // those calls in try/catch and degrade gracefully. This is intentional.
    //
    // If someone "fixes" this by making those checks eager, THIS test will
    // break — which is exactly the signal they need to review the cascading
    // impact on startup behavior before merging.
  });

});