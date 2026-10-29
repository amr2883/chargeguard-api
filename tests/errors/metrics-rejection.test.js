// C2c: the /metrics failure path. A rejection from the Prometheus registry must reach the
// global error handler (registered after all routes since C2) and answer 500 JSON,
// never the default HTML error page. No DB access.

const request = require('supertest');
const app = require('../../src/app');
const prometheus = require('../../src/lib/prometheus');

const TOKEN = 'metrics-c2c-token-0123456789abcdef';

describe('GET /metrics failure path (C2c)', () => {
  let saved;
  beforeAll(async () => {
    await request(app).get('/api/ping');
  }, 60000);
  beforeEach(() => {
    saved = process.env.METRICS_TOKEN;
    process.env.METRICS_TOKEN = TOKEN;
  });
  afterEach(() => {
    jest.restoreAllMocks();
    if (saved === undefined) delete process.env.METRICS_TOKEN;
    else process.env.METRICS_TOKEN = saved;
  });

  test('M1: registry rejection -> 500 JSON, not the default HTML page, no message leak', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(prometheus.registry, 'metrics').mockRejectedValue(new Error('boom-c2c'));
    const res = await request(app).get('/metrics').set('Authorization', 'Bearer ' + TOKEN);
    expect(res.status).toBe(500);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(typeof res.body.error).toBe('string');
    expect(res.text).not.toContain('boom-c2c');
    expect(res.text).not.toMatch(/<!DOCTYPE|<html/i);
  });

  test('M2: after the failure the endpoint recovers (200 with the right token)', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const spy = jest.spyOn(prometheus.registry, 'metrics').mockRejectedValueOnce(new Error('boom-once'));
    const bad = await request(app).get('/metrics').set('Authorization', 'Bearer ' + TOKEN);
    expect(bad.status).toBe(500);
    spy.mockRestore();
    const ok = await request(app).get('/metrics').set('Authorization', 'Bearer ' + TOKEN);
    expect(ok.status).toBe(200);
    expect(ok.text).toContain('# HELP');
  });
});