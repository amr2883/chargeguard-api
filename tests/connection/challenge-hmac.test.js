const request = require('supertest');
const crypto = require('crypto');
const app = require('../../src/app');
const { PrismaClient } = require('@prisma/client');
const { hashApiKey } = require('../../src/lib/apiKeyHash');

jest.mock('../../src/lib/email');

const prisma = new PrismaClient();

// Same v2 format verifyHmac.js expects and the PHP plugin sends:
// HMAC-SHA256(secret, `${timestamp}.${storeDomain}.${rawBody}`), prefixed "v2=".
function signV2(secret, domain, bodyString) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedStr = `${timestamp}.${domain}.${bodyString}`;
  const signature = 'v2=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return { timestamp, signature };
}

describe('POST /api/risk/challenge/request — HMAC over the raw bytes the plugin signed', () => {
  let tenant, domain, apiKey;

  beforeAll(async () => {
    const label = 'chal' + Math.random().toString(36).slice(2, 8);
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

  const post = (bodyString, signBody) => {
    const { timestamp, signature } = signV2(tenant.webhookSecret, domain, signBody ?? bodyString);
    return request(app)
      .post('/api/risk/challenge/request')
      .set('Content-Type', 'application/json')
      .set('X-API-Key', apiKey)
      .set('X-Store-Domain', domain)
      .set('X-ChargeGuard-Signature', signature)
      .set('X-ChargeGuard-Timestamp', timestamp)
      .send(bodyString);
  };

  test('control: plain ASCII body, compact JSON, signature accepted', async () => {
    const body = '{"deviceFingerprint":"fpplain1","email":"buyer@example.com"}';
    const res = await post(body);
    expect(res.status).not.toBe(401);
  });

  test('PHP json_encode style body (escaped slash + \\uXXXX) is accepted', async () => {
    // PHP json_encode default output: "/" -> "\/", "é" -> "\u00e9"
    const body = '{"deviceFingerprint":"fp\\/abc\\u00e9x","email":"caf\\u00e9\\/x@example.com"}';
    const res = await post(body);
    expect(res.status).not.toBe(401);
  });

  test('signature computed over a different body is rejected (401)', async () => {
    const body = '{"deviceFingerprint":"fpplain2","email":"buyer2@example.com"}';
    const other = '{"deviceFingerprint":"fpplain2","email":"attacker@example.com"}';
    const res = await post(body, other);
    expect(res.status).toBe(401);
  });
});
