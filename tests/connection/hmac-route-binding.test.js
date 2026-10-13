'use strict';

// v3 endpoint binding (#78): the signed string covers METHOD + path, so a signature made
// for one route or method must not be accepted on another. Real app + real test DB.
// Every negative case is paired with a control that sends the SAME signed headers to the
// route they were made for and must succeed, so a 401 can only come from the binding.

const request = require('supertest');
const crypto = require('crypto');
const { PrismaClient } = require('@prisma/client');
const app = require('../../src/app');
const { hashApiKey } = require('../../src/lib/apiKeyHash');
const { signV3 } = require('../helpers/signV3');

const prisma = new PrismaClient();
jest.setTimeout(30000);

describe('HMAC endpoint-binding regression (v3: method + path)', () => {
  let tenant;
  let apiKey;
  let domain;
  const values = [];

  beforeAll(async () => {
    const label = `hmac-route-${crypto.randomBytes(6).toString('hex')}`;
    domain = `${label}.example.com`;
    apiKey = crypto.randomBytes(32).toString('base64');
    tenant = await prisma.tenant.create({
      data: {
        email: `${label}@example.com`,
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
    try {
      if (tenant?.id) {
        // Let the middleware finish its asynchronous replay-cache write.
        await new Promise((resolve) => setTimeout(resolve, 300));
        if (values.length) {
          await prisma.whitelistEntry.deleteMany({ where: { merchantId: tenant.id, value: { in: values } } });
          await prisma.blacklistEntry.deleteMany({ where: { merchantId: tenant.id, value: { in: values } } });
        }
        await prisma.processedRequest.deleteMany({ where: { tenantId: tenant.id } });
        await prisma.tenant.deleteMany({ where: { id: tenant.id } });
      }
    } finally {
      await prisma.$disconnect();
    }
  });

  const uniqueValue = () => {
    const v = `route-bind-${crypto.randomBytes(8).toString('hex')}@example.com`;
    values.push(v);
    return v;
  };
  const bodyFor = (value) => JSON.stringify({ type: 'EMAIL', value, reason: 'route-binding-regression-test' });
  const sign = (method, target, body) => signV3({ secret: tenant.webhookSecret, domain, method, target, body });
  const send = (method, url, headers, body) => {
    let r = request(app)[method.toLowerCase()](url)
      .set('Content-Type', 'application/json')
      .set('X-API-Key', apiKey);
    for (const [k, v] of Object.entries(headers)) r = r.set(k, v);
    return body ? r.send(body) : r;
  };
  const expectOk = (res) => {
    expect(res.status).toBeGreaterThanOrEqual(200);
    expect(res.status).toBeLessThan(300);
  };

  test('control: a signature is accepted on the exact method and path it was made for', async () => {
    const body = bodyFor(uniqueValue());
    const res = await send('POST', '/api/risk/blacklist', sign('POST', '/api/risk/blacklist', body), body);
    expectOk(res);
  });

  test('rejects a signature moved from blacklist to whitelist; the same headers still work on blacklist', async () => {
    const value = uniqueValue();
    const body = bodyFor(value);
    const headers = sign('POST', '/api/risk/blacklist', body);
    const swapped = await send('POST', '/api/risk/whitelist', headers, body);
    expect(swapped.status).toBe(401);
    expect(await prisma.whitelistEntry.count({ where: { merchantId: tenant.id, value } })).toBe(0);
    const control = await send('POST', '/api/risk/blacklist', headers, body);
    expectOk(control);
  });

  test('rejects a GET signature replayed as POST on the same path; the same headers still work as GET', async () => {
    const headers = sign('GET', '/api/risk/blacklist', '');
    const swapped = await send('POST', '/api/risk/blacklist', headers, '');
    expect(swapped.status).toBe(401);
    const control = await send('GET', '/api/risk/blacklist', headers, '');
    expectOk(control);
  });

  test('rejects a signature made for the mount-relative path (/blacklist): the signed path is req.originalUrl', async () => {
    const body = bodyFor(uniqueValue());
    const res = await send('POST', '/api/risk/blacklist', sign('POST', '/blacklist', body), body);
    expect(res.status).toBe(401);
  });

  test('the query string is not part of the signed path (documented decision, #101)', async () => {
    const body = bodyFor(uniqueValue());
    const headers = sign('POST', '/api/risk/blacklist', body);
    const res = await send('POST', '/api/risk/blacklist?x=1', headers, body);
    expectOk(res);
  });
});