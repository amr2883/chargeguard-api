'use strict';

// S3: shared per-IP failed-attempt limiter on the three routes that call
// resolveTenantByApiKey directly (outside requireAuth):
//   GET /api/auth/verify, GET /api/risk/verify-key, GET /api/updates/info
if (!process.env.UPDATE_DOWNLOAD_SECRET) process.env.UPDATE_DOWNLOAD_SECRET = 'test-update-download-secret';

jest.mock('../../src/lib/apiKeyAuth', () => ({
  ...jest.requireActual('../../src/lib/apiKeyAuth'),
  resolveTenantByApiKey: jest.fn(),
}));

const request = require('supertest');
const app = require('../../src/app');
const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const { _authFailLimiter, _resetAuthFailLimiterForTests } = require('../../src/middleware/authenticate');

jest.setTimeout(60000);

const MAX = _authFailLimiter.AUTH_FAIL_MAX_ATTEMPTS;

const ROUTES = [
  { name: '/api/auth/verify', path: '/api/auth/verify', viaHeader: true, body429: { error: 'Too Many Requests' } },
  { name: '/api/risk/verify-key', path: '/api/risk/verify-key', viaHeader: true, body429: { valid: false, message: 'Too Many Requests' } },
  { name: '/api/updates/info', path: '/api/updates/info', viaHeader: false, body429: { error: 'Too Many Requests' } },
];

// key === undefined -> request without any key. IP is chosen via X-Forwarded-For
// (app.js sets trust proxy = 2, so a single XFF entry becomes req.ip).
function hit(route, ip, key) {
  let r = request(app).get(route.path).set('X-Forwarded-For', ip);
  if (key === undefined) return r;
  if (route.viaHeader) return r.set('x-api-key', key);
  return r.query({ key });
}

describe('S3 failed-attempt limiter on direct-lookup routes', () => {
  beforeEach(() => {
    _resetAuthFailLimiterForTests();
    resolveTenantByApiKey.mockReset();
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
  });

  describe.each(ROUTES)('$name', (route) => {
    it('returns 429 after the max failed attempts from one IP, with no further lookups', async () => {
      for (let i = 0; i < MAX; i++) {
        const r = await hit(route, '45.1.1.10', 'bad-' + i);
        expect(r.status).toBe(401);
      }
      const res = await hit(route, '45.1.1.10', 'bad-final');
      expect(res.status).toBe(429);
      expect(res.body).toEqual(route.body429);
      expect(resolveTenantByApiKey).toHaveBeenCalledTimes(MAX);
    });

    it('does not count requests with a missing key', async () => {
      for (let i = 0; i < MAX + 40; i++) {
        const r = await hit(route, '45.1.1.11');
        expect([400, 401]).toContain(r.status);
      }
      expect(resolveTenantByApiKey).not.toHaveBeenCalled();
      const res = await hit(route, '45.1.1.11', 'bad');
      expect(res.status).toBe(401);
      expect(resolveTenantByApiKey).toHaveBeenCalledTimes(1);
    });

    it('keeps independent buckets per IP', async () => {
      for (let i = 0; i < MAX; i++) {
        await hit(route, '45.1.1.12', 'bad-' + i);
      }
      const blocked = await hit(route, '45.1.1.12', 'x');
      expect(blocked.status).toBe(429);
      const other = await hit(route, '45.1.1.13', 'x');
      expect(other.status).toBe(401);
    });
  });

  it('shares one bucket across /verify, /updates/info and /verify-key', async () => {
    const ip = '45.1.1.14';
    const half = Math.floor(MAX / 2);
    for (let i = 0; i < half; i++) await hit(ROUTES[0], ip, 'a-' + i);
    for (let i = 0; i < MAX - half; i++) await hit(ROUTES[2], ip, 'b-' + i);
    const res = await hit(ROUTES[1], ip, 'c');
    expect(res.status).toBe(429);
    expect(res.body).toEqual(ROUTES[1].body429);
  });
});