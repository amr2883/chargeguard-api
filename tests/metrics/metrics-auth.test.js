const request = require('supertest');
const app = require('../../src/app');

const TOKEN = 'metrics-test-token-0123456789abcdef';

describe('GET /metrics access control', () => {
  let saved;
  beforeEach(() => { saved = process.env.METRICS_TOKEN; });
  afterEach(() => {
    if (saved === undefined) delete process.env.METRICS_TOKEN;
    else process.env.METRICS_TOKEN = saved;
  });

  test('404 when METRICS_TOKEN is not configured, even with a header', async () => {
    delete process.env.METRICS_TOKEN;
    const res = await request(app).get('/metrics').set('Authorization', 'Bearer ' + TOKEN);
    expect(res.status).toBe(404);
    expect(res.text).not.toContain('# HELP');
  });

  test('401 without Authorization header', async () => {
    process.env.METRICS_TOKEN = TOKEN;
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(401);
    expect(res.text).not.toContain('# HELP');
  });

  test('401 with wrong token of the same length', async () => {
    process.env.METRICS_TOKEN = TOKEN;
    const wrong = 'x'.repeat(TOKEN.length);
    const res = await request(app).get('/metrics').set('Authorization', 'Bearer ' + wrong);
    expect(res.status).toBe(401);
    expect(res.text).not.toContain('# HELP');
  });

  test('401 with wrong token of a different length', async () => {
    process.env.METRICS_TOKEN = TOKEN;
    const res = await request(app).get('/metrics').set('Authorization', 'Bearer short');
    expect(res.status).toBe(401);
    expect(res.text).not.toContain('# HELP');
  });

  test('401 with a non-Bearer scheme carrying the right token', async () => {
    process.env.METRICS_TOKEN = TOKEN;
    const res = await request(app).get('/metrics').set('Authorization', 'Basic ' + TOKEN);
    expect(res.status).toBe(401);
  });

  test('200 with the correct token and Prometheus content type', async () => {
    process.env.METRICS_TOKEN = TOKEN;
    const res = await request(app).get('/metrics').set('Authorization', 'Bearer ' + TOKEN);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/plain/);
    expect(res.text).toContain('# HELP');
  });
});
