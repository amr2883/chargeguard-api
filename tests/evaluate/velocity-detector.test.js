'use strict';

const crypto = require('crypto');
const db = require('../../src/lib/db');
const { checkVelocity, recordFailedAttempt } = require('../../src/lib/velocityDetector');

// --- Test helpers -----------------------------------------------------------
// resetRateLimits.js only clears RegistrationAttempt / ConnectAttempt, so this
// suite owns cleanup of CardTestAttempt itself. Every merchantId created here
// is prefixed so afterAll can scope its cleanup instead of truncating the
// whole table.
const FILE_PREFIX = `t3c-${crypto.randomUUID()}`;
const uniqueMerchant = (label) => `${FILE_PREFIX}-${label}-${crypto.randomUUID()}`;

afterAll(async () => {
  await db.cardTestAttempt.deleteMany({
    where: { merchantId: { startsWith: FILE_PREFIX } },
  });
  await db.$disconnect();
});

describe('velocityDetector — T3c', () => {
  describe('IP threshold', () => {
    it('does NOT block at 4 attempts from the same IP (below threshold)', async () => {
      const merchantId = uniqueMerchant('ip-below');
      const ip = '203.0.113.10';

      for (let i = 0; i < 4; i++) {
        await recordFailedAttempt({ ip, merchantId, amount: 10 });
      }

      const result = await checkVelocity({ ip, merchantId });
      expect(result.blocked).toBe(false);
    });

    it('blocks at exactly 5 attempts from the same IP within 10 minutes', async () => {
      const merchantId = uniqueMerchant('ip-trigger');
      const ip = '203.0.113.11';

      for (let i = 0; i < 5; i++) {
        await recordFailedAttempt({ ip, merchantId, amount: 10 });
      }

      const result = await checkVelocity({ ip, merchantId });
      expect(result.blocked).toBe(true);
      expect(result.reason).toEqual(expect.stringContaining('IP'));
    });

    it('does not count attempts outside the 10-minute window', async () => {
      const merchantId = uniqueMerchant('ip-window');
      const ip = '203.0.113.12';

      // 5 attempts, but 11 minutes stale — must not count toward the threshold.
      const staleTime = new Date(Date.now() - 11 * 60 * 1000);
      const ipHash = crypto
        .createHmac('sha256', process.env.SECRET_SALT)
        .update(ip)
        .digest('hex');

      for (let i = 0; i < 5; i++) {
        await db.cardTestAttempt.create({
          data: {
            merchantId,
            ipHash,
            amount: 10,
            wasBlocked: true,
            createdAt: staleTime,
          },
        });
      }

      const result = await checkVelocity({ ip, merchantId });
      expect(result.blocked).toBe(false);
    });
  });

  describe('Device threshold', () => {
    it('does NOT block at 4 attempts from the same device fingerprint (below threshold)', async () => {
      const merchantId = uniqueMerchant('device-below');
      const deviceFingerprint = 'device-fp-below';

      for (let i = 0; i < 4; i++) {
        await recordFailedAttempt({ deviceFingerprint, merchantId, amount: 10 });
      }

      const result = await checkVelocity({ deviceFingerprint, merchantId });
      expect(result.blocked).toBe(false);
    });

    it('blocks at exactly 5 attempts from the same device fingerprint within 10 minutes', async () => {
      const merchantId = uniqueMerchant('device-trigger');
      const deviceFingerprint = 'device-fp-trigger';

      for (let i = 0; i < 5; i++) {
        await recordFailedAttempt({ deviceFingerprint, merchantId, amount: 10 });
      }

      const result = await checkVelocity({ deviceFingerprint, merchantId });
      expect(result.blocked).toBe(true);
      expect(result.reason).toEqual(expect.stringContaining('Device'));
    });
  });

  describe('Tenant isolation', () => {
    it('a different merchantId with the same IP is not cross-counted', async () => {
      const merchantA = uniqueMerchant('isolation-a');
      const merchantB = uniqueMerchant('isolation-b');
      const ip = '203.0.113.20';

      // 5 attempts under merchant A trip the threshold for merchant A only.
      for (let i = 0; i < 5; i++) {
        await recordFailedAttempt({ ip, merchantId: merchantA, amount: 10 });
      }

      const resultA = await checkVelocity({ ip, merchantId: merchantA });
      const resultB = await checkVelocity({ ip, merchantId: merchantB });

      expect(resultA.blocked).toBe(true);
      expect(resultB.blocked).toBe(false);
    });
  });

  describe('Fail-open behavior', () => {
    it('returns blocked: false (not a thrown exception) when the DB errors', async () => {
      const merchantId = uniqueMerchant('fail-open');
      const ip = '203.0.113.30';

      const countSpy = jest
        .spyOn(db.cardTestAttempt, 'count')
        .mockRejectedValue(new Error('simulated DB outage'));

      try {
        await expect(checkVelocity({ ip, merchantId })).resolves.toEqual({
          blocked: false,
          reason: null,
        });
      } finally {
        countSpy.mockRestore();
      }
    });

    it('recordFailedAttempt swallows DB errors without throwing', async () => {
      const merchantId = uniqueMerchant('fail-open-record');
      const createSpy = jest
        .spyOn(db.cardTestAttempt, 'create')
        .mockRejectedValue(new Error('simulated DB outage'));

      try {
        await expect(
          recordFailedAttempt({ ip: '203.0.113.31', merchantId, amount: 10 })
        ).resolves.toBeUndefined();
      } finally {
        createSpy.mockRestore();
      }
    });
  });
});