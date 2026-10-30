'use strict';

/**
 * MOCK1: refuse to start in production when unsafe mock flags are enabled.
 *
 * MOCK_IP_INTEL=true in production would silently replace real IP intelligence
 * (IPLOCATE_API_KEY lookup) with mock data, invalidating every risk decision
 * that depends on geolocation, ASN, or proxy detection. This is a silent
 * degradation - the app would keep returning 200 and merchants would keep
 * approving/blocking on fake data without any error signal.
 *
 * The check is intentionally strict (=== 'true') to match the existing pattern
 * in src/lib/ipIntelligence.js:128. Any other value ('false', unset, '', '1',
 * 'yes') is safe - only the exact string 'true' triggers mock mode.
 *
 * This function is testable in isolation (no side effects, no process.exit).
 * The call site in src/server.js catches the throw and calls process.exit(1).
 */
function enforceProductionGuards() {
  const violations = [];

  if (process.env.NODE_ENV === 'production') {
    if (process.env.MOCK_IP_INTEL === 'true') {
      violations.push(
        'MOCK_IP_INTEL=true is not allowed in production - ' +
        'it would silently replace real IP intelligence with mock data, ' +
        'invalidating every risk decision that depends on it'
      );
    }
    // future additions (MOCK_BIN_INTEL, DEBUG_ERRORS, EMAIL_VERIFICATION_DISABLED)
    // belong here, appended to the same violations array
  }

  if (violations.length > 0) {
    throw new Error(
      'Production startup guard failed:\n  - ' + violations.join('\n  - ')
    );
  }
}

module.exports = { enforceProductionGuards };