'use strict';

// Covers src/lib/webhook.js: P0-03 (connection pinning) and C2 (DNS validation,
// delivery-time revalidation, redirect refusal).
// No network (dns, undici, global.fetch are mocked). Needs the test Postgres only because jest setupFilesAfterEnv connects to it.

jest.mock('dns', () => ({ promises: { resolve4: jest.fn(), resolve6: jest.fn() } }));
jest.mock('undici', () => ({ Agent: jest.fn() }));
jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
}));

const dns = require('dns').promises;
const { Agent } = require('undici');
const logger = require('../../src/lib/logger');
const { sendWebhookAlert, validateWebhookUrl } = require('../../src/lib/webhook');

const PUBLIC_V4 = '93.184.216.34';
const BLOCKED = { valid: false, error: 'Internal or private IPs are not allowed' };
const TENANT = { id: 'tenant_ssrf_001', webhookUrl: 'https://hooks.example.com/x', webhookType: 'custom' };

const realFetch = global.fetch;
const agents = [];
const resp = (over) => ({ ok: true, status: 200, type: 'basic', text: async () => '', ...over });
const noRecord = () => Object.assign(new Error('queryA ENODATA'), { code: 'ENODATA' });

function setDns({ a4, a6 } = {}) {
  if (a4) dns.resolve4.mockResolvedValue(a4); else dns.resolve4.mockRejectedValue(noRecord());
  if (a6) dns.resolve6.mockResolvedValue(a6); else dns.resolve6.mockRejectedValue(noRecord());
}

beforeEach(() => {
  jest.resetAllMocks();
  agents.length = 0;
  Agent.mockImplementation(function (opts) {
    this.opts = opts;
    this.close = jest.fn().mockResolvedValue(undefined);
    agents.push(this);
  });
  global.fetch = jest.fn().mockResolvedValue(resp());
});

afterAll(() => {
  global.fetch = realFetch;
});

describe('P0-03: delivery connects only to the validated address', () => {
  const lookupOf = () => agents[0].opts.connect.lookup;

  test('fetch goes through the pinned Agent', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await expect(sendWebhookAlert(TENANT, 1, 10)).resolves.toBeUndefined();
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(agents).toHaveLength(1);
    expect(global.fetch.mock.calls[0][1].dispatcher).toBe(agents[0]);
  });

  test('lookup returns the validated address', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await sendWebhookAlert(TENANT, 1, 10);
    const cb = jest.fn();
    lookupOf()('hooks.example.com', {}, cb);
    expect(cb).toHaveBeenCalledWith(null, PUBLIC_V4, 4);
  });

  test('lookup answers with an array when options.all is set', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await sendWebhookAlert(TENANT, 1, 10);
    const cb = jest.fn();
    lookupOf()('hooks.example.com', { all: true }, cb);
    expect(cb).toHaveBeenCalledWith(null, [{ address: PUBLIC_V4, family: 4 }]);
  });

  test('lookup ignores the hostname it is asked about', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await sendWebhookAlert(TENANT, 1, 10);
    const cb = jest.fn();
    lookupOf()('rebind.attacker.example', {}, cb);
    expect(cb).toHaveBeenCalledWith(null, PUBLIC_V4, 4);
  });

  test('AAAA-only host is pinned to its IPv6 address', async () => {
    setDns({ a6: ['2606:4700:4700::1111'] });
    await sendWebhookAlert(TENANT, 1, 10);
    const cb = jest.fn();
    lookupOf()('hooks.example.com', {}, cb);
    expect(cb).toHaveBeenCalledWith(null, '2606:4700:4700::1111', 6);
  });

  test('Agent is closed after a successful delivery', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await sendWebhookAlert(TENANT, 1, 10);
    expect(agents[0].close).toHaveBeenCalledTimes(1);
  });

  test('Agent is closed after a failed delivery', async () => {
    setDns({ a4: [PUBLIC_V4] });
    global.fetch.mockResolvedValue(resp({ ok: false, status: 404, text: async () => 'nope' }));
    await expect(sendWebhookAlert(TENANT, 1, 10)).rejects.toThrow('HTTP 404');
    expect(agents[0].close).toHaveBeenCalledTimes(1);
  });
});

describe('C2: re-validation at delivery time', () => {
  test.each([
    ['private A record', { a4: ['10.0.0.5'] }],
    ['public A followed by a private A', { a4: [PUBLIC_V4, '169.254.169.254'] }],
    ['public A with a link-local AAAA', { a4: [PUBLIC_V4], a6: ['fe80::1'] }],
    ['AAAA loopback only', { a6: ['::1'] }],
    ['IPv4-mapped AAAA pointing at loopback', { a6: ['::ffff:7f00:1'] }],
    ['CGNAT address', { a4: ['100.64.0.1'] }],
  ])('%s: no delivery, no Agent, warning logged', async (_label, answer) => {
    setDns(answer);
    await expect(sendWebhookAlert(TENANT, 1, 10)).resolves.toBeUndefined();
    expect(global.fetch).not.toHaveBeenCalled();
    expect(agents).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ tenantId: TENANT.id }),
      'WEBHOOK_URL_FAILED_DELIVERY_TIME_REVALIDATION'
    );
    await expect(validateWebhookUrl(TENANT.webhookUrl)).resolves.toEqual(BLOCKED);
  });

  test('fails closed when both lookups fail', async () => {
    setDns({});
    await expect(sendWebhookAlert(TENANT, 1, 10)).resolves.toBeUndefined();
    expect(global.fetch).not.toHaveBeenCalled();
    await expect(validateWebhookUrl(TENANT.webhookUrl)).resolves.toEqual(BLOCKED);
  });

  test('fails closed when the host resolves to nothing', async () => {
    dns.resolve4.mockResolvedValue([]);
    dns.resolve6.mockResolvedValue([]);
    await expect(validateWebhookUrl(TENANT.webhookUrl)).resolves.toEqual(BLOCKED);
  });

  test('one failing record type is fine when the other is public', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await expect(validateWebhookUrl(TENANT.webhookUrl)).resolves.toEqual({ valid: true });
  });

  test.each([
    ['IPv4-mapped loopback', 'https://[::ffff:127.0.0.1]/hook'],
    ['IPv4-mapped RFC1918', 'https://[::ffff:10.0.0.1]/hook'],
    ['IPv4-mapped metadata address', 'https://[::ffff:169.254.169.254]/hook'],
    ['decimal IPv4 loopback', 'https://2130706433/hook'],
    ['hex IPv4 loopback', 'https://0x7f.1/hook'],
  ])('%s literal is blocked without any DNS query', async (_label, url) => {
    await expect(validateWebhookUrl(url)).resolves.toEqual(BLOCKED);
    expect(dns.resolve4).not.toHaveBeenCalled();
    expect(dns.resolve6).not.toHaveBeenCalled();
  });
});

describe('C2: redirects are never followed', () => {
  test('fetch is told not to follow redirects', async () => {
    setDns({ a4: [PUBLIC_V4] });
    await sendWebhookAlert(TENANT, 1, 10);
    expect(global.fetch.mock.calls[0][1].redirect).toBe('manual');
  });

  test.each([
    ['302 response', { ok: false, status: 302, type: 'basic' }],
    ['opaqueredirect response', { ok: false, status: 0, type: 'opaqueredirect' }],
  ])('%s is a non-retryable failure', async (_label, over) => {
    setDns({ a4: [PUBLIC_V4] });
    global.fetch.mockResolvedValue(resp(over));
    await expect(sendWebhookAlert(TENANT, 1, 10)).rejects.toThrow(/redirect/i);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});
