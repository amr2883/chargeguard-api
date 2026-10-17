'use strict';
// [#62] Permanent tests for the test-DB guard (#26).
// Pure function tests: no DB connection is made. Each rejection case asserts the
// specific message, so a case cannot pass through the wrong branch.
const { assertSafeTestDb } = require('./assertSafeTestDb');

const PW = 'pw-never-print-9f3a';
const mk = (rest) => `postgresql://u:${PW}@${rest}`;

const NOT_SET = /DATABASE_URL is not set/;
const INVALID = /not a valid URL/;
const HOST = /Refusing to run tests against host=/;

function messageOf(fn) {
  try { fn(); } catch (e) { return e.message; }
  return null;
}

describe('assertSafeTestDb (#26)', () => {
  const original = process.env.DATABASE_URL;
  afterEach(() => {
    if (original === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = original;
  });

  const accepted = [
    ['localhost', mk('localhost:5433/chargeguard_test')],
    ['127.0.0.1', mk('127.0.0.1:5433/x_test')],
    ['::1', mk('[::1]:5433/x_test')],
    ['schema param', mk('localhost:5433/x_test?schema=public')],
    ['sslmode + connection_limit', mk('localhost:5433/x_test?sslmode=disable&connection_limit=5')],
  ];

  test.each(accepted)('accepts: %s', (_name, url) => {
    expect(messageOf(() => assertSafeTestDb(url))).toBeNull();
  });

  const rejected = [
    ['empty string', '', NOT_SET],
    ['garbage', 'not a url ' + PW, INVALID],
    ['remote host', mk('db.example.invalid:5432/x_test'), HOST],
    ['no "test" in db name', mk('localhost:5433/chargeguard'), HOST],
    ['lookalike host', mk('localhost.example.invalid:5432/x_test'), HOST],
    ['userinfo trick', `postgresql://localhost:${PW}@db.example.invalid:5432/x_test`, HOST],
    ['host in query', mk('localhost:5433/x_test?host=db.example.invalid'), /query parameter "host"/],
    ['HOST uppercase in query', mk('localhost:5433/x_test?HOST=db.example.invalid'), /query parameter "HOST"/],
    ['hostaddr in query', mk('localhost:5433/x_test?hostaddr=203.0.113.5'), /query parameter "hostaddr"/],
    ['dbname in query', mk('localhost:5433/x_test?dbname=prod'), /query parameter "dbname"/],
    ['options in query', mk('localhost:5433/x_test?options=-c%20search_path%3Dx'), /query parameter "options"/],
    ['allowed + host mixed', mk('localhost:5433/x_test?schema=public&host=db.example.invalid'), /query parameter "host"/],
    ['multi host', mk('localhost,db.example.invalid:5432/x_test'), /not a valid URL|Refusing to run tests against host=/],
  ];

  test.each(rejected)('rejects: %s', (_name, url, re) => {
    const msg = messageOf(() => assertSafeTestDb(url));
    expect(msg).not.toBeNull();
    expect(msg).toMatch(re);
    expect(msg).not.toContain(PW);
  });

  describe('default argument reads process.env.DATABASE_URL', () => {
    test('unset env is refused with the "not set" message', () => {
      delete process.env.DATABASE_URL;
      expect(messageOf(() => assertSafeTestDb())).toMatch(NOT_SET);
    });

    test('remote env is refused when called without an argument', () => {
      process.env.DATABASE_URL = mk('db.example.invalid:5432/x_test');
      const msg = messageOf(() => assertSafeTestDb());
      expect(msg).toMatch(HOST);
      expect(msg).not.toContain(PW);
    });

    test('safe env is accepted when called without an argument', () => {
      process.env.DATABASE_URL = mk('localhost:5433/chargeguard_test');
      expect(messageOf(() => assertSafeTestDb())).toBeNull();
    });
  });
});