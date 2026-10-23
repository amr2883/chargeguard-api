const request = require('supertest');
const app = require('../src/app');
const MARK = 'LEAKCHK_9f3a7c';
function capture() {
  const out = [];
  const push = (...a) => out.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
  const spies = ['error', 'warn', 'info', 'log'].map((m) => jest.spyOn(console, m).mockImplementation(push));
  return { out, text: () => out.join('\n'), restore: () => spies.forEach((s) => s.mockRestore()) };
}
async function run(fn) {
  const c = capture();
  let res;
  try {
    res = await fn();
    await new Promise((r) => setTimeout(r, 150));
  } finally {
    c.restore();
  }
  return { res, c };
}
test('F113: malformed URI path returns 400, not 500', async () => {
  const { res } = await run(() => request(app).get('/api/risk/blacklist/%E0%A4%A'));
  expect(res.status).toBe(400);
});
test('F110: malformed JSON body returns 400 and is not echoed into logs', async () => {
  const { res, c } = await run(() =>
    request(app).post('/api/f110-probe').set('Content-Type', 'application/json').send('[1,' + MARK + ']'));
  expect(res.status).toBe(400);
  expect(c.out.length).toBeGreaterThan(0);
  expect(c.text()).not.toContain('LEAKCHK');
});
test('F110: oversized JSON body returns 413 and logs no body content', async () => {
  const big = JSON.stringify({ x: 'a'.repeat(200 * 1024), marker: MARK });
  const { res, c } = await run(() =>
    request(app).post('/api/f110-probe').set('Content-Type', 'application/json').send(big));
  expect(res.status).toBe(413);
  expect(c.text()).not.toContain('LEAKCHK');
});
