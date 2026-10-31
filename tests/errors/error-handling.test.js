// C2b: app-level 404 JSON and client-error handling in the global error handler.
//   E1/E2 (control): an unmatched route answers 404 JSON (already true since C2).
//   E3: malformed JSON keeps status 400 AND now answers a matching generic body
//       (before C2b the body was "Internal server error"), with no parser text or stack.
//   E4: an oversize JSON body keeps status 413 with a matching generic body.
// No DB access: the requests are rejected before any route runs.

const request = require('supertest');
const app = require('../../src/app');

const MISSING = '/__c2b_no_such_route__';

describe('app-level 404 and client-error handling (C2b)', () => {
  beforeAll(async () => {
    await request(app).get('/api/ping');
  }, 60000);

  test('E1 control: unmatched GET -> 404 JSON', async () => {
    const res = await request(app).get(MISSING);
    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body).toEqual({ error: 'Not found' });
  });

  test('E2 control: unmatched POST with a valid JSON body -> 404 JSON', async () => {
    const res = await request(app).post(MISSING).type('json').send(JSON.stringify({ a: 1 }));
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'Not found' });
  });

  test('E3: malformed JSON -> 400 with a generic Bad request body (no parser text, no stack)', async () => {
    const res = await request(app).post(MISSING).type('json').send('{bad');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Bad request' });
    expect(res.text).not.toMatch(/syntaxerror|unexpected|stack/i);
  });

  test('E4: oversize JSON body -> 413 with a generic Payload too large body', async () => {
    const big = JSON.stringify({ a: 'x'.repeat(200 * 1024) });
    const res = await request(app).post(MISSING).type('json').send(big);
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ error: 'Payload too large' });
    expect(res.text).not.toMatch(/stack/i);
  });
});