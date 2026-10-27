require('dotenv').config({ path: '.env.test', override: true });
require('./assertSafeTestDb').assertSafeTestDb();
// Deterministic Turnstile secret for tests: Cloudflare's published always-pass
// TEST secret (public, not a credential). Set unconditionally so results never
// depend on a developer's shell or on the git-ignored .env.test.
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';
