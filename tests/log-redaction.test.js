const request = require('supertest');
const app = require('../src/app');
const CANARY = 'CANARY_SECRET_9f3a7c';
function flat(args) {
  return args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
}
test('F105: access log must not contain query values', async () => {
  const chunks = [];
  const spy = jest.spyOn(process.stdout, 'write').mockImplementation((c) => { chunks.push(String(c)); return true; });
  try {
    await request(app).get('/health?key=' + CANARY);
    await new Promise((r) => setTimeout(r, 150));
  } finally {
    spy.mockRestore();
  }
  const out = chunks.join('');
  expect(out).toContain('/health');
  expect(out).not.toContain(CANARY);
});
test('F108: error/warn logs must not contain query values', async () => {
  const spies = ['error', 'warn'].map((m) => jest.spyOn(console, m).mockImplementation(() => {}));
  let out = '';
  let calls = 0;
  try {
    await request(app).get('/api/risk/blacklist/%E0%A4%A?key=' + CANARY);
    await new Promise((r) => setTimeout(r, 150));
    calls = spies.reduce((n, s) => n + s.mock.calls.length, 0);
    out = spies.flatMap((s) => s.mock.calls.map((c) => flat(c))).join('\n');
  } finally {
    spies.forEach((s) => s.mockRestore());
  }
  expect(calls).toBeGreaterThan(0);
  expect(out).not.toContain(CANARY);
});
