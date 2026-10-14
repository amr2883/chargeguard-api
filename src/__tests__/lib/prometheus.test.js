const { EventEmitter } = require('events');
const prom = require('../../lib/prometheus');

function hit(p, status, route) {
  const res = new EventEmitter();
  res.statusCode = status;
  prom.httpMetricsMiddleware({ method: 'GET', path: p, route }, res, () => {});
  res.emit('finish');
}

async function httpLines() {
  const text = await prom.registry.metrics();
  return text.split('\n').filter(l => l.startsWith('chargeguard_http_request'));
}

describe('httpMetricsMiddleware cardinality', () => {
  beforeEach(() => { prom.registry.resetMetrics(); });

  test('1000 unique unmatched paths do not create new series', async () => {
    hit('/a-0', 404, undefined);
    const baseline = (await httpLines()).length;
    for (let i = 1; i < 1000; i++) hit('/a-' + i, 404, undefined);
    expect((await httpLines()).length).toBe(baseline);
  });

  test('unmatched paths are labelled "unmatched"', async () => {
    hit('/some/random/path', 404, undefined);
    const lines = (await httpLines()).join('\n');
    expect(lines).toContain('route="unmatched"');
    expect(lines).not.toContain('/some/random/path');
  });

  test('matched routes keep their route pattern', async () => {
    hit('/blacklist/123', 200, { path: '/blacklist/:id' });
    const lines = (await httpLines()).join('\n');
    expect(lines).toContain('route="/blacklist/:id"');
    expect(lines).toContain('route="/blacklist/:id"');
    expect(lines).not.toContain('/blacklist/123');
  });
});
