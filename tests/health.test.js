const request = require('supertest');
const app = require('../src/app');

test('health check responds', async () => {
  const res = await request(app).get('/health');
  expect(res.status).toBe(200);
});