/**
 * REG-EMAIL regression tests (D-lite).
 *
 * The bug (risk.js:3597 before fix): findUnique({ where: { email } }) is
 * case-sensitive against Tenant.email (@unique, schema.prisma:14). A second
 * registration differing only in casing created a second row. Additionally,
 * the raw email (whitespace/casing as typed) was stored verbatim, and
 * non-string inputs threw TypeError via .includes() -> 500.
 *
 * The fix (risk.js:3588-): type guard, trim + lowercase before storage,
 * and lower(email) = lower($1::text) for the duplicate check.
 *
 * Mutation coverage: T1-T5 fail on the pre-fix code.
 */
const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');

// email.js exports several async functions (sendConfirmationEmail, sendApiKeyEmail,
// sendChallengeOtpEmail, etc.). Plain auto-mock (jest.mock without a factory) returns
// `undefined` from those calls. risk.js:3673/3690 chains `.catch(...)` on the return
// value, so auto-mock produces a synchronous TypeError that the route's outer
// try/catch converts to 500. Use a factory that returns Promise.resolve() from every
// exported function; requireActual preserves the export list so notify.js and other
// consumers that destructure from email.js still get valid references.
jest.mock('../../src/lib/email', () => {
  const actual = jest.requireActual('../../src/lib/email');
  const mocked = {};
  for (const key of Object.keys(actual)) {
    mocked[key] = typeof actual[key] === 'function'
      ? jest.fn(() => Promise.resolve())
      : actual[key];
  }
  return mocked;
});

const prisma = new PrismaClient();

const TURNSTILE = 'dummy-test-token';
const STORE_URL = 'https://reg-email-case.example.com';

function postRegister(body) {
  return request(app)
    .post('/api/risk/tenants/register')
    .send({ turnstileToken: TURNSTILE, website: '', storeUrl: STORE_URL, ...body });
}

beforeAll(() => {
  process.env.EMAIL_VERIFICATION_DISABLED = 'false';
});

afterAll(async () => {
  await prisma.tenant.deleteMany({
    where: { email: { in: [
      'alice@example.com',
      'bob@example.com',
      'carol@example.com',
      'dave@example.com',
    ] } },
  });
  await prisma.$disconnect();
});

describe('REG-EMAIL: registration email casing / normalization', () => {

  it('T1: rejects a second registration that differs only in case', async () => {
    const first = await postRegister({ email: 'alice@example.com' });
    expect([200, 201]).toContain(first.status);

    const second = await postRegister({ email: 'ALICE@Example.COM' });
    expect(second.status).toBe(400);
    expect(second.body).toEqual({ error: 'Email already registered' });

    const count = await prisma.tenant.count({ where: { email: 'alice@example.com' } });
    expect(count).toBe(1);
  });

  it('T2: trims leading/trailing whitespace before storing', async () => {
    const res = await postRegister({ email: '  bob@example.com  ' });
    expect([200, 201]).toContain(res.status);

    const row = await prisma.tenant.findUnique({ where: { email: 'bob@example.com' } });
    expect(row).not.toBeNull();
    expect(row.email).toBe('bob@example.com');

    const withSpaces = await prisma.tenant.findFirst({ where: { email: '  bob@example.com  ' } });
    expect(withSpaces).toBeNull();
  });

  it('T3: stores the email in lowercase', async () => {
    const res = await postRegister({ email: 'CAROL@EXAMPLE.COM' });
    expect([200, 201]).toContain(res.status);

    const row = await prisma.tenant.findUnique({ where: { email: 'carol@example.com' } });
    expect(row).not.toBeNull();
    expect(row.email).toBe('carol@example.com');
  });

  it('T4: rejects a numeric email with 400 (not 500)', async () => {
    const res = await postRegister({ email: 123 });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Valid email is required' });
  });

  it('T5: rejects an object email with 400 (not 500)', async () => {
    const res = await postRegister({ email: { a: 1 } });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Valid email is required' });
  });

  it('T6: rejects a null email with 400', async () => {
    const res = await postRegister({ email: null });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Valid email is required' });
  });

  it('T7: rejects whitespace-only email with 400', async () => {
    const res = await postRegister({ email: '   ' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Valid email is required' });
  });

  it('T8: accepts a normal lowercase email (control)', async () => {
    const res = await postRegister({ email: 'dave@example.com' });
    expect([200, 201]).toContain(res.status);

    const row = await prisma.tenant.findUnique({ where: { email: 'dave@example.com' } });
    expect(row).not.toBeNull();
    expect(row.email).toBe('dave@example.com');
  });
});