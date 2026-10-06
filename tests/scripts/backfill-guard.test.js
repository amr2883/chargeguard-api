// [#316/#322] Target-DB guard of scripts/backfill-normalized-emails.js.
// Every case must be refused by the guard BEFORE the script loads the DB layer.
// Safety: the child gets an explicit minimal env and a fake target on
// 127.0.0.1:1 (nothing listens there), so even a broken guard cannot reach a real DB.
const { spawnSync } = require('child_process');
const path = require('path');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'backfill-normalized-emails.js');
const TARGET = '127.0.0.1:1/chargeguard_test';
const PASSWORD = 'pw-must-never-print';
const BASE_URL = 'postgresql://user:' + PASSWORD + '@' + TARGET;
const MAIN_BANNER = 'normalized-value backfill';

function run(args, databaseUrl) {
  const env = { PATH: process.env.PATH };
  if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  if (databaseUrl !== undefined) env.DATABASE_URL = databaseUrl;
  const r = spawnSync(process.execPath, [SCRIPT, ...args], {
    env,
    encoding: 'utf8',
    timeout: 10000,
  });
  const stdout = r.stdout || '';
  const stderr = r.stderr || '';
  return { status: r.status, stdout, stderr, out: stdout + stderr };
}

function expectRefused(r, message) {
  expect(r.status).toBe(2);
  expect(r.stderr).toContain(message);
  expect(r.stdout).not.toContain(MAIN_BANNER);
  expect(r.out).not.toContain(PASSWORD);
}

describe('backfill-normalized-emails target-DB guard', () => {
  it('refuses a ?host= query parameter', () => {
    const r = run(['--dry-run'], BASE_URL + '?host=other.example');
    expectRefused(r, 'outside the allowlist: host (values not printed)');
    expect(r.out).not.toContain('other.example');
  });

  it('refuses a ?hostaddr= query parameter', () => {
    const r = run(['--dry-run'], BASE_URL + '?hostaddr=127.0.0.1');
    expectRefused(r, 'outside the allowlist: hostaddr (values not printed)');
  });

  it('refuses when DATABASE_URL is not set', () => {
    const r = run(['--dry-run'], undefined);
    expectRefused(r, 'DATABASE_URL is not set');
  });

  it('refuses a DATABASE_URL that is not a valid URL', () => {
    const r = run(['--dry-run'], 'not a url');
    expectRefused(r, 'not a valid URL');
  });

  it('refuses a LIVE run without --confirm-target', () => {
    const r = run([], BASE_URL);
    expectRefused(r, 'LIVE run needs --confirm-target=' + TARGET);
    expect(r.stdout).toContain('Target DB: ' + TARGET);
  });

  it('refuses a LIVE run with a wrong --confirm-target', () => {
    const r = run(['--confirm-target=127.0.0.1:1/other_db'], BASE_URL);
    expectRefused(r, 'LIVE run needs --confirm-target=' + TARGET);
    expect(r.stdout).toContain('Target DB: ' + TARGET);
  });
});