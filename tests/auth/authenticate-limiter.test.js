'use strict';

jest.mock('../../src/lib/apiKeyAuth', () => ({ resolveTenantByApiKey: jest.fn() }));

const { resolveTenantByApiKey } = require('../../src/lib/apiKeyAuth');
const {
  requireAuth,
  _resetAuthFailLimiterForTests,
  _authFailLimiter,
} = require('../../src/middleware/authenticate');

function makeRes() {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  res.set = jest.fn(() => res);
  return res;
}
function makeReq(ip = '9.9.9.9', key = 'bad-key') {
  return { ip, headers: { 'x-api-key': key } };
}

const VALID_TENANT = { id: 1, isActive: true, emailVerified: true };
const ADVANCE = 250; // > AUTH_FAIL_DELAY_MS (200)

describe('authenticate fail limiter (S2)', () => {
  const mw = requireAuth({ id: true });

  beforeEach(() => {
    _resetAuthFailLimiterForTests();
    resolveTenantByApiKey.mockReset();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  it('T1: 429 after max failed attempts from same IP (mutation coverage)', async () => {
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const max = _authFailLimiter.AUTH_FAIL_MAX_ATTEMPTS;
    for (let i = 0; i < max; i++) {
      await mw(makeReq('9.9.9.9', 'bad-' + i), makeRes(), jest.fn());
    }
    const res = makeRes();
    const next = jest.fn();
    await mw(makeReq('9.9.9.9', 'bad-final'), res, next);
    // 429 path is synchronous (no setTimeout)
    expect(res.status).toHaveBeenCalledWith(429);
    expect(next).not.toHaveBeenCalled();
    expect(resolveTenantByApiKey).toHaveBeenCalledTimes(max);
  });

  it('T2: successful auth does not count toward the limiter', async () => {
    resolveTenantByApiKey.mockResolvedValue({ tenant: VALID_TENANT, usedPreviousKey: false });
    for (let i = 0; i < 100; i++) {
      const next = jest.fn();
      await mw(makeReq('9.9.9.9'), makeRes(), next);
      expect(next).toHaveBeenCalledTimes(1);
    }
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const res = makeRes();
    await mw(makeReq('9.9.9.9', 'bad'), res, jest.fn());
    jest.advanceTimersByTime(ADVANCE);
    expect(res.status).not.toHaveBeenCalledWith(429);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('T3: skipInternalLimiter bypasses the limiter', async () => {
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const max = _authFailLimiter.AUTH_FAIL_MAX_ATTEMPTS;
    for (let i = 0; i < max; i++) {
      await mw(makeReq('9.9.9.8', 'bad-' + i), makeRes(), jest.fn());
    }
    const skipped = requireAuth({ id: true }, { skipInternalLimiter: true });
    const res = makeRes();
    await skipped(makeReq('9.9.9.8', 'bad'), res, jest.fn());
    jest.advanceTimersByTime(ADVANCE);
    expect(res.status).not.toHaveBeenCalledWith(429);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('T4: different IPs have independent buckets', async () => {
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const max = _authFailLimiter.AUTH_FAIL_MAX_ATTEMPTS;
    for (let i = 0; i < max; i++) {
      await mw(makeReq('9.9.9.7', 'bad-' + i), makeRes(), jest.fn());
    }
    const res = makeRes();
    await mw(makeReq('9.9.9.6', 'bad'), res, jest.fn());
    jest.advanceTimersByTime(ADVANCE);
    expect(res.status).not.toHaveBeenCalledWith(429);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('T5: missing x-api-key does not count toward the limiter', async () => {
    const noKeyReq = () => ({ ip: '9.9.9.5', headers: {} });
    for (let i = 0; i < 100; i++) {
      await mw(noKeyReq(), makeRes(), jest.fn());
    }
    resolveTenantByApiKey.mockResolvedValue({ tenant: null, usedPreviousKey: false });
    const res = makeRes();
    await mw(makeReq('9.9.9.5', 'bad'), res, jest.fn());
    jest.advanceTimersByTime(ADVANCE);
    expect(res.status).not.toHaveBeenCalledWith(429);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});