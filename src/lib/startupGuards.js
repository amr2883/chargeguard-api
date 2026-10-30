'use strict';

/**
 * MOCK1 + REQUIRED_ENV: refuse to start in production when the config is
 * unsafe or incomplete.
 *
 * - MOCK1: MOCK_IP_INTEL=true in production would silently replace real
 *   IP intelligence (IPLOCATE_API_KEY lookup) with mock data.
 *
 * - REQUIRED_ENV: every entry below is read at runtime by at least one
 *   consumer (see references). Most have no fallback. Two have SILENT
 *   fallbacks that hide configuration mistakes:
 *     - PATTERN_SHARING_SECRET ?? IDENTITY_GRAPH_SECRET  (patternSharing.js:148)
 *     - IDENTITY_GRAPH_SECRET ?? null                    (identityGraph.js:57)
 *   Enforcing them at boot turns silent degradation into a loud, actionable
 *   failure - better to crash before serve than to serve with a shared or
 *   missing secret.
 *
 * The check is intentionally strict:
 *   - Empty string is treated as missing (a secret that is present but
 *     empty is a misconfiguration, not a valid value).
 *   - The check runs only when NODE_ENV === 'production'; dev and test
 *     are unaffected.
 *
 * This function is testable in isolation (no side effects, no process.exit).
 * The call site in src/server.js catches the throw and calls process.exit(1).
 */

const REQUIRED_ENV_VARS = [
  'DATABASE_URL',            // prisma/schema.prisma:8 (env("DATABASE_URL"))
  'CARD_HASH_SECRET',        // enrichmentProcessor.js:71
  'API_KEY_HASH_SECRET',     // apiKeyHash.js:13
  'UPDATE_DOWNLOAD_SECRET',  // updates.js:10
  'ADMIN_SECRET',            // admin.js:156
  'SECRET_SALT',             // enrichmentProcessor.js:19, velocityDetector.js:80, admin.js:44, auth.js:42, risk.js:4
  'CHALLENGE_TICKET_SECRET', // deviceToken.js:107
  'DEVICE_TOKEN_SECRET',     // deviceToken.js:13
  'IDENTITY_GRAPH_SECRET',   // identityGraph.js:57 (?? null), utils.js:159
  'PATTERN_SHARING_SECRET'   // patternSharing.js:148 (?? IDENTITY_GRAPH_SECRET - silent)
];

function enforceProductionGuards() {
  const violations = [];

  if (process.env.NODE_ENV === 'production') {
    // --- MOCK1 ---
    if (process.env.MOCK_IP_INTEL === 'true') {
      violations.push(
        'MOCK_IP_INTEL=true is not allowed in production - ' +
        'it would silently replace real IP intelligence with mock data, ' +
        'invalidating every risk decision that depends on it'
      );
    }

    // --- REQUIRED_ENV ---
    const missing = REQUIRED_ENV_VARS.filter(function (k) { return !process.env[k]; });
    if (missing.length > 0) {
      violations.push(
        'Missing required environment variable(s): ' + missing.join(', ') +
        ' - see src/lib/startupGuards.js for the full list and each consumer'
      );
    }
  }

  if (violations.length > 0) {
    throw new Error(
      'Production startup guard failed:\n  - ' + violations.join('\n  - ')
    );
  }
}

module.exports = { enforceProductionGuards, REQUIRED_ENV_VARS };