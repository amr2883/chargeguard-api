'use strict';

const SAFE_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// Query parameters that only tune the connection. Anything else (host, hostaddr,
// dbname, user, port, socket, ...) could redirect it, so it is rejected.
const ALLOWED_PARAMS = new Set([
  'schema',
  'connection_limit',
  'pool_timeout',
  'connect_timeout',
  'sslmode',
  'pgbouncer',
]);

function assertSafeTestDb(rawUrl = process.env.DATABASE_URL) {
  if (!rawUrl) {
    throw new Error(
      '[test-guard] DATABASE_URL is not set. Refusing to run: app.js would fall back to the production .env.'
    );
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch (_) {
    // Do not include rawUrl in the message: it may contain a password.
    throw new Error('[test-guard] DATABASE_URL is not a valid URL. Refusing to run tests.');
  }
  const host = u.hostname;
  const dbName = decodeURIComponent(u.pathname.replace(/^\//, ''));
  if (!SAFE_HOSTS.has(host) || !/test/i.test(dbName)) {
    throw new Error(
      `[test-guard] Refusing to run tests against host="${host}" db="${dbName}". ` +
      'Allowed: localhost/127.0.0.1/::1 and a database name containing "test".'
    );
  }
  for (const key of u.searchParams.keys()) {
    if (!ALLOWED_PARAMS.has(key.toLowerCase())) {
      throw new Error(
        `[test-guard] Refusing to run: DATABASE_URL has query parameter "${key}" which is not allowlisted ` +
        `(it could redirect the connection). Allowed: ${[...ALLOWED_PARAMS].join(', ')}.`
      );
    }
  }
}

module.exports = { assertSafeTestDb };
