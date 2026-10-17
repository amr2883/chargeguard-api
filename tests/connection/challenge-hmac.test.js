const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { signV3 } = require('../helpers/signV3');

jest.mock('../../src/lib/email');
const { sendChallengeOtpEmail } = require('../../src/lib/email');
const logger = require('../../src/lib/logger');

const prisma = new PrismaClient();

describe('POST /api/risk/challenge/request — v3 (الصيغة اللي الـ plugin بيبعتها فعلاً)', () => {
  let tenant, domain, apiKey, warnSpy;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  beforeAll(async () => {
    const label = 'chal3' + Math.random().toString(36).slice(2, 8);
    domain = `example-${label}-store.com`;
    apiKey = crypto.randomBytes(32).toString('base64');
    tenant = await prisma.tenant.create({
      data: {
        email: `${label}-${Date.now()}@example.com`,
        storeUrl: `https://${domain}`,
        allowedDomains: [domain],
        webhookSecret: crypto.randomBytes(32).toString('hex'),
        apiKeyHash: hashApiKey(apiKey),
        apiKey: null,
        isActive: true,
        emailVerified: true,
        plan: 'early_access',
      },
    });
  });

  afterAll(async () => {
    if (tenant) await prisma.tenant.deleteMany({ where: { id: tenant.id } });
    await prisma.$disconnect();
  });

  beforeEach(() => {
    sendChallengeOtpEmail.mockClear();
    warnSpy = jest.spyOn(logger, 'warn');
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  // بيتأكد إن سبب الـ 401 هو الكود المقصود بالظبط (مش أي 401 من طبقة تانية).
  const warnedWith = (code) => warnSpy.mock.calls.some((c) => c[1] === code);

  // requestId: القيمة اللي اتوقّع بيها. headerRequestId: القيمة اللي تتبعت فعلاً
  // في الـ header (undefined = نفس requestId، null = ماتبعتش الـ header خالص).
  const postV3 = ({ body, signBody, requestId, headerRequestId, ts }) => {
    const headers = signV3({ secret: tenant.webhookSecret, domain, requestId, method: 'POST', target: '/api/risk/challenge/request', body: signBody ?? body, timestamp: ts });
    const sent = headerRequestId === undefined ? requestId : headerRequestId;
    if (sent === null) delete headers['x-chargeguard-request-id'];
    else headers['x-chargeguard-request-id'] = sent;
    return request(app)
      .post('/api/risk/challenge/request')
      .set('Content-Type', 'application/json')
      .set('X-API-Key', apiKey)
      .set(headers)
      .send(body);
  };

  test('control: v3 صحيح → 200 والـ email اتنادى بيه', async () => {
    const body = '{"deviceFingerprint":"v3fpplain1","email":"buyer-v3a@example.com"}';
    const res = await postV3({ body, requestId: crypto.randomUUID() });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, emailSent: true, expiresInSeconds: 600 });
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
    expect(sendChallengeOtpEmail.mock.calls[0][0]).toBe('buyer-v3a@example.com');
  });

  test('PHP json_encode style (\\/ و \\u00e9) على v3 → الـ handler استلم القيم المفكوكة', async () => {
    const body = '{"deviceFingerprint":"v3fp\\/abc\\u00e9x","email":"caf\\u00e9\\/x@example.com"}';
    const res = await postV3({ body, requestId: crypto.randomUUID() });
    expect(res.status).toBe(200);
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
    expect(sendChallengeOtpEmail.mock.calls[0][0]).toBe('café/x@example.com');
  });

  test('body متعدّل بعد التوقيع → 401 بسبب HMAC ومفيش إيميل اتبعت', async () => {
    const body = '{"deviceFingerprint":"v3fpplain2","email":"buyer-v3b@example.com"}';
    const other = '{"deviceFingerprint":"v3fpplain2","email":"attacker@example.com"}';
    const res = await postV3({ body, signBody: other, requestId: crypto.randomUUID() });
    expect(res.status).toBe(401);
    expect(warnedWith('HMAC_SIGNATURE_MISMATCH')).toBe(true);
    expect(sendChallengeOtpEmail).not.toHaveBeenCalled();
  });

  test('request-id في الـ header غير الموقّع → 401 بسبب HMAC (الـ id جزء من التوقيع)', async () => {
    const body = '{"deviceFingerprint":"v3fpplain3","email":"buyer-v3c@example.com"}';
    const res = await postV3({
      body,
      requestId: crypto.randomUUID(),
      headerRequestId: crypto.randomUUID(),
    });
    expect(res.status).toBe(401);
    expect(warnedWith('HMAC_SIGNATURE_MISMATCH')).toBe(true);
    expect(sendChallengeOtpEmail).not.toHaveBeenCalled();
  });

  test('توقيع v3 من غير header الـ request-id → 401 HMAC_V3_MISSING_REQUEST_ID', async () => {
    const body = '{"deviceFingerprint":"v3fpplain4","email":"buyer-v3d@example.com"}';
    const res = await postV3({ body, requestId: crypto.randomUUID(), headerRequestId: null });
    expect(res.status).toBe(401);
    expect(warnedWith('HMAC_V3_MISSING_REQUEST_ID')).toBe(true);
    expect(sendChallengeOtpEmail).not.toHaveBeenCalled();
  });

  test('request-id أطول من 128 حرف → 401 HMAC_REQUEST_ID_TOO_LONG', async () => {
    const body = '{"deviceFingerprint":"v3fpplain5","email":"buyer-v3e@example.com"}';
    const res = await postV3({ body, requestId: 'a'.repeat(129) });
    expect(res.status).toBe(401);
    expect(warnedWith('HMAC_REQUEST_ID_TOO_LONG')).toBe(true);
    expect(sendChallengeOtpEmail).not.toHaveBeenCalled();
  });

  test('#72-shape: requestId with dot (invalid char) -> 401 HMAC_REQUEST_ID_INVALID', async () => {
    const body = '{"deviceFingerprint":"v3fpshape1","email":"buyer-shape@example.com"}';
    const res = await postV3({ body, requestId: 'abc.def' });
    expect(res.status).toBe(401);
    expect(warnedWith('HMAC_REQUEST_ID_INVALID')).toBe(true);
    expect(sendChallengeOtpEmail).not.toHaveBeenCalled();
  });

  test('#72-boundary: requestId exactly 128 hex chars (max allowed) -> 200', async () => {
    const body = '{"deviceFingerprint":"v3fpboundary","email":"buyer-128@example.com"}';
    const rid = require('crypto').randomBytes(64).toString('hex'); // 128 chars, all [0-9a-f]
    const res = await postV3({ body, requestId: rid });
    expect(res.status).toBe(200);
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
  });

  test('replay: نفس request-id مرتين → نفس الرد المخزّن والـ handler مايتنفّذش تاني', async () => {
    const body = '{"deviceFingerprint":"v3fpplain6","email":"buyer-v3f@example.com"}';
    const rid = crypto.randomUUID();
    const first = await postV3({ body, requestId: rid });
    expect(first.status).toBe(200);
    // completeRequest() بتتنادى من غير await جوه verifyHmac.js، فبنستنى
    // شوية عشان الـ claim يتحوّل لـ completed قبل الطلب التاني.
    await sleep(300);
    const second = await postV3({ body, requestId: rid });
    expect(second.status).toBe(200);
    expect(second.body).toEqual(first.body);
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
  });

  test('retry - same request-id with different timestamp and signature: same reply, handler runs once', async () => {
    const body = '{"deviceFingerprint":"v3fpretry7","email":"buyer-v3g@example.com"}';
    const rid = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    const first = await postV3({ body, requestId: rid, ts: String(now - 5) });
    expect(first.status).toBe(200);
    await sleep(300);
    const second = await postV3({ body, requestId: rid, ts: String(now) });
    expect(second.status).toBe(200);
    expect(second.body).toEqual(first.body);
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
  });

  test('v2 signature (deprecated, #55 phase 1): still 200, deprecation header set, HMAC_V2_DEPRECATED_SIGNATURE_USED logged', async () => {
    const body = '{"deviceFingerprint":"v2phase1a","email":"buyer-v2@example.com"}';
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = 'v2=' + crypto.createHmac('sha256', tenant.webhookSecret).update(`${ts}.${domain}.${body}`).digest('hex');
    const res = await request(app)
      .post('/api/risk/challenge/request')
      .set('Content-Type', 'application/json')
      .set('X-API-Key', apiKey)
      .set({ 'x-store-domain': domain, 'x-chargeguard-signature': sig, 'x-chargeguard-timestamp': ts })
      .send(body);
    expect(res.status).toBe(200);
    expect(res.headers['x-chargeguard-signature-deprecated']).toMatch(/^v2 signatures are deprecated/);
    expect(warnedWith('HMAC_V2_DEPRECATED_SIGNATURE_USED')).toBe(true);
    expect(sendChallengeOtpEmail).toHaveBeenCalledTimes(1);
  });
});