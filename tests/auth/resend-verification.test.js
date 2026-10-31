// C1: POST /api/auth/resend-verification
//   UE1: the only caller is an HTML form (application/x-www-form-urlencoded). Before the
//        fix req.body was undefined and the route answered 500.
//   RESEND-MIXEDCASE: a tenant stored with upper-case letters was never found.
//   RESEND-LOOKUP-ILIKE-RISK: '_' in the submitted address must not act as a wildcard.
// Real local DB, mocked mail module (same pattern as tests/registration).

const request = require('supertest');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');

jest.mock('../../src/lib/email');
const mail = require('../../src/lib/email');

const prisma = new PrismaClient();
const ROUTE = '/api/auth/resend-verification';
const GENERIC = 'If this email is registered, a new confirmation link has been sent.';
const VERIFIED = 'This account is already verified. Check your inbox for your API key.';
const DAY_MS = 24 * 60 * 60 * 1000;

const createdIds = [];
let seq = 0;
const uniq = () => Date.now().toString(36) + (seq++).toString(36) + Math.random().toString(36).slice(2, 8);

async function makeTenant(addr, extra = {}) {
  const t = await prisma.tenant.create({ data: { email: addr, emailVerified: false, ...extra } });
  createdIds.push(t.id);
  return t;
}
const tokenOf = async (id) => (await prisma.tenant.findUnique({ where: { id } })).emailVerifyToken;
const sentTo = () => mail.sendConfirmationEmail.mock.calls.map((c) => c[0]);

describe('POST /api/auth/resend-verification (C1)', () => {
  // Warm-up: first request in a fresh Jest process pays the Prisma cold start.
  beforeAll(async () => {
    mail.sendConfirmationEmail.mockResolvedValue(undefined);
    await request(app).post(ROUTE).type('form').send({ email: `warmup-${uniq()}@example.com` });
  }, 60000);

  beforeEach(() => {
    mail.sendConfirmationEmail.mockReset();
    mail.sendConfirmationEmail.mockResolvedValue(undefined);
  });

  afterAll(async () => {
    if (createdIds.length) await prisma.tenant.deleteMany({ where: { id: { in: createdIds } } });
    await prisma.$disconnect();
  });

  test('T1 UE1: urlencoded form body is parsed (was 500); token rotated; mail goes to the stored address', async () => {
    const addr = `form-${uniq()}@example.com`;
    const t = await makeTenant(addr, {
      emailVerifyToken: `old-${uniq()}`,
      emailVerifyExpiresAt: new Date(Date.now() + DAY_MS - 120000),
    });
    const res = await request(app).post(ROUTE).type('form').send({ email: addr });
    expect(res.status).toBe(200);
    expect(res.body.message).toBe(GENERIC);
    expect(mail.sendConfirmationEmail).toHaveBeenCalledTimes(1);
    const [to, link] = mail.sendConfirmationEmail.mock.calls[0];
    expect(to).toBe(addr);
    expect(link).toMatch(/\/api\/auth\/verify-email\?token=[0-9a-f]{64}$/);
    const tok = await tokenOf(t.id);
    expect(tok).toMatch(/^[0-9a-f]{64}$/);
    expect(link.endsWith(tok)).toBe(true);
  });

  test('T2 control: JSON body with a lower-case tenant still works', async () => {
    const addr = `json-${uniq()}@example.com`;
    await makeTenant(addr);
    const res = await request(app).post(ROUTE).send({ email: addr });
    expect(res.status).toBe(200);
    expect(sentTo()).toEqual([addr]);
  });

  test('T3 RESEND-MIXEDCASE (JSON): upper-case stored address is found; input is trimmed and case-folded', async () => {
    const addr = `Mixed.Case-${uniq()}@Example.COM`;
    await makeTenant(addr);
    const res = await request(app).post(ROUTE).send({ email: `  ${addr.toLowerCase()}  ` });
    expect(res.status).toBe(200);
    expect(sentTo()).toEqual([addr]);
  });

  test('T4 form + mixed-case (the real browser scenario)', async () => {
    const addr = `Form.Mixed-${uniq()}@Example.COM`;
    await makeTenant(addr);
    const res = await request(app).post(ROUTE).type('form').send({ email: `  ${addr.toLowerCase()}  ` });
    expect(res.status).toBe(200);
    expect(sentTo()).toEqual([addr]);
  });

  test('T5 underscore is not a wildcard: u_s-<id> must not match uXs-<id>', async () => {
    const s = uniq();
    const t = await makeTenant(`uXs-${s}@example.com`, { emailVerifyToken: `keep-${s}` });
    const res = await request(app).post(ROUTE).send({ email: `u_s-${s}@example.com` });
    expect(res.status).toBe(200);
    expect(res.body.message).toBe(GENERIC);
    expect(mail.sendConfirmationEmail).not.toHaveBeenCalled();
    expect(await tokenOf(t.id)).toBe(`keep-${s}`);
  });

  test('T6 unknown address: generic 200, no mail', async () => {
    const res = await request(app).post(ROUTE).send({ email: `nobody-${uniq()}@example.com` });
    expect(res.status).toBe(200);
    expect(res.body.message).toBe(GENERIC);
    expect(mail.sendConfirmationEmail).not.toHaveBeenCalled();
  });

  test('T7 already verified: 200 with the verified message, no mail', async () => {
    const addr = `ver-${uniq()}@example.com`;
    await makeTenant(addr, { emailVerified: true });
    const res = await request(app).post(ROUTE).send({ email: addr });
    expect(res.status).toBe(200);
    expect(res.body.message).toBe(VERIFIED);
    expect(mail.sendConfirmationEmail).not.toHaveBeenCalled();
  });

  test('T8 token issued less than 60s ago: 429 with retryAfter, token unchanged, no mail', async () => {
    const s = uniq();
    const addr = `fresh-${s}@example.com`;
    const t = await makeTenant(addr, { emailVerifyToken: `fresh-${s}`, emailVerifyExpiresAt: new Date(Date.now() + DAY_MS) });
    const res = await request(app).post(ROUTE).send({ email: addr });
    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/wait \d+ second/);
    expect(res.body.retryAfter).toBeGreaterThan(0);
    expect(res.body.retryAfter).toBeLessThanOrEqual(60);
    expect(mail.sendConfirmationEmail).not.toHaveBeenCalled();
    expect(await tokenOf(t.id)).toBe(`fresh-${s}`);
  });

  test('T9 first request succeeds, an immediate second one is rate limited', async () => {
    const addr = `twice-${uniq()}@example.com`;
    await makeTenant(addr);
    const first = await request(app).post(ROUTE).send({ email: addr });
    expect(first.status).toBe(200);
    const second = await request(app).post(ROUTE).send({ email: addr });
    expect(second.status).toBe(429);
    expect(mail.sendConfirmationEmail).toHaveBeenCalledTimes(1);
  });

  test('T10 missing or invalid email: 400, never 500', async () => {
    const sends = [
      () => request(app).post(ROUTE),
      () => request(app).post(ROUTE).type('form').send({}),
      () => request(app).post(ROUTE).send({ email: 12345 }),
      () => request(app).post(ROUTE).send({ email: '' }),
    ];
    for (const go of sends) {
      const res = await go();
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email is required');
    }
    expect(mail.sendConfirmationEmail).not.toHaveBeenCalled();
  });

  test('T11 two rows that differ only by case: the unverified one wins', async () => {
    const s = uniq();
    const lowerAddr = `dup.${s}@example.com`;
    const upperAddr = `Dup.${s}@example.com`;
    const verifiedRow = await makeTenant(lowerAddr, { emailVerified: true });
    const unverifiedRow = await makeTenant(upperAddr, { emailVerifyToken: `u-${s}` });
    const res = await request(app).post(ROUTE).send({ email: lowerAddr });
    expect(res.status).toBe(200);
    expect(sentTo()).toEqual([upperAddr]);
    expect(await tokenOf(verifiedRow.id)).toBeNull();
    expect(await tokenOf(unverifiedRow.id)).not.toBe(`u-${s}`);
  });
});
