// tests/feedback/feedback-route.test.js
// Guards N23: POST /risk/feedback must pass req.storeId to processFeedback.
// Runs the final route handler directly (no DB, no network, middlewares skipped).

jest.mock('../../src/lib/feedbackLoop', () => ({
  processFeedback: jest.fn(),
}));
jest.mock('../../src/lib/cloudflareRanges', () => ({
  getCloudflareRanges: jest.fn(),
}));
jest.mock('../../src/lib/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

const riskRouter = require('../../src/routes/risk');
const { processFeedback } = require('../../src/lib/feedbackLoop');

function getFeedbackHandlers() {
  const layer = riskRouter.stack.find(
    (l) => l.route && l.route.path === '/feedback' && l.route.methods.post
  );
  if (!layer) throw new Error('Route not found: POST /feedback');
  return layer.route.stack.map((s) => s.handle);
}

function makeRes() {
  const res = { statusCode: 200 };
  res.status = jest.fn((c) => { res.statusCode = c; return res; });
  res.json = jest.fn(() => res);
  return res;
}

async function callFeedback(req) {
  const handlers = getFeedbackHandlers();
  const res = makeRes();
  await handlers[handlers.length - 1](req, res, () => {});
  return res;
}

describe('POST /risk/feedback -- store attribution (N23)', () => {
  beforeEach(() => { processFeedback.mockReset(); processFeedback.mockResolvedValue(undefined); });

  test('route stack is auth, domain, hmac, handler (4 layers)', () => {
    expect(getFeedbackHandlers()).toHaveLength(4);
  });

  test('T-R1: passes req.storeId as the 4th argument', async () => {
    const res = await callFeedback({ body: { orderId: '1001', isFraud: true }, tenant: { id: 't1' }, storeId: 's1' });
    expect(processFeedback).toHaveBeenCalledWith('1001', 'lost', 't1', 's1');
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: true }));
  });

  test('T-R2: passes null when the request has no store', async () => {
    await callFeedback({ body: { orderId: '1002', isFraud: true }, tenant: { id: 't1' } });
    expect(processFeedback).toHaveBeenCalledWith('1002', 'lost', 't1', null);
  });

  test('T-R3: isFraud false maps to won', async () => {
    await callFeedback({ body: { orderId: '1003', isFraud: false }, tenant: { id: 't1' }, storeId: 's2' });
    expect(processFeedback).toHaveBeenCalledWith('1003', 'won', 't1', 's2');
  });
});
