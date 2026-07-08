'use strict';

const crypto = require('crypto');
const {
  checkBINSequence,
  recordBINAttempt,
  getBINStats,
  THRESHOLDS,
} = require('../../src/lib/binSequenceDetector');

// --- Test helpers -----------------------------------------------------------
// Unique tenant/prefix per test to avoid contaminating the module-scope Map,
// which persists for the lifetime of this test file (no reset hook exists).
const uniqueTenant = (label) => `t3b-${label}-${crypto.randomUUID()}`;

// Builds a synthetic BIN: 4-digit prefix + numeric suffix. Real BINs are
// 6-16 digits; the exact length doesn't matter to the module, only that
// bin.slice(4) parses as an integer.
const bin = (prefix, suffix) => `${prefix}${suffix}`;

describe('binSequenceDetector — T3b', () => {
  describe('Layer 1: BIN prefix velocity', () => {
    it('does NOT trigger with 7 unique BINs from the same prefix (below threshold)', () => {
      const tenantId = uniqueTenant('layer1-below');
      const prefix = '4111';
      let lastResult;

      for (let i = 0; i < THRESHOLDS.UNIQUE_BINS_PER_PREFIX - 1; i++) {
        // Widely spaced suffixes so this scenario can never accidentally
        // satisfy Layer 2 (sequential scan) as a side effect.
        lastResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, 1000 + i * 1000),
          ipAddress: '10.0.0.1',
        });
      }

      expect(lastResult.blocked).toBe(false);
      expect(lastResult.layer).toBeNull();
    });

    it('triggers on the Nth unique BIN from the same prefix within the window', () => {
      const tenantId = uniqueTenant('layer1-trigger');
      const prefix = '4111';
      let lastResult;

      for (let i = 0; i < THRESHOLDS.UNIQUE_BINS_PER_PREFIX; i++) {
        lastResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, 1000 + i * 1000),
          ipAddress: '10.0.0.1',
        });
      }

      // Guard assertion: fail loudly with context if the wrong layer fired,
      // rather than just "expected true, got false".
      expect({
        blocked: lastResult.blocked,
        layer: lastResult.layer,
        reason: lastResult.reason,
      }).toEqual({
        blocked: true,
        layer: 1,
        reason: expect.stringContaining(`${prefix}xx`),
      });
      expect(lastResult.riskAddition).toBe(35);
    });

    it('does not count BINs outside the 10-minute window', () => {
      const tenantId = uniqueTenant('layer1-window');
      const prefix = '4111';
      const now = Date.now();

      const dateNowSpy = jest.spyOn(Date, 'now');
      try {
        // 7 BINs recorded 11 minutes ago — outside the window.
        dateNowSpy.mockReturnValue(now - 11 * 60 * 1000);
        for (let i = 0; i < THRESHOLDS.UNIQUE_BINS_PER_PREFIX - 1; i++) {
          recordBINAttempt({ tenantId, bin: bin(prefix, 1000 + i * 1000), entity: '10.0.0.1' });
        }

        // Back to "now" — only the 1 fresh BIN below should be active.
        dateNowSpy.mockReturnValue(now);
        const result = checkBINSequence({ tenantId, bin: bin(prefix, 9999), ipAddress: '10.0.0.1' });

        expect(result.blocked).toBe(false);
      } finally {
        dateNowSpy.mockRestore();
      }
    });
  });

  describe('Layer 2: Sequential scan detection', () => {
    it('triggers when 5+ BINs have ascending suffixes with diff <= 2', () => {
      const tenantId = uniqueTenant('layer2-trigger');
      const prefix = '4222';
      // Diffs: 1, 2, 1, 2 — a streak of 5, all under THRESHOLDS.UNIQUE_BINS_PER_PREFIX (8)
      // so Layer 1 cannot fire first.
      const suffixes = [100, 101, 103, 104, 106];
      expect(suffixes.length).toBeLessThan(THRESHOLDS.UNIQUE_BINS_PER_PREFIX);
      let lastResult;

      for (const suffix of suffixes) {
        lastResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, suffix),
          ipAddress: '10.0.0.2',
        });
      }

      expect(lastResult.blocked).toBe(true);
      expect(lastResult.layer).toBe(2);
      expect(lastResult.riskAddition).toBe(40);
    });

    it('does NOT trigger when suffix gaps exceed 2 (not a sequential pattern)', () => {
      const tenantId = uniqueTenant('layer2-nonseq');
      const prefix = '4223';
      const suffixes = [100, 200, 300, 400, 500]; // gaps of 100 — not sequential
      let lastResult;

      for (const suffix of suffixes) {
        lastResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, suffix),
          ipAddress: '10.0.0.2',
        });
      }

      expect(lastResult.blocked).toBe(false);
    });
  });

  describe('Layer 3: Cross-entity linking', () => {
    it('triggers when >= 6 distinct entities share >= 4 BINs from the same prefix', () => {
      const tenantId = uniqueTenant('layer3-trigger');
      const prefix = '4333';
      // 4 distinct BINs (B1..B4), spaced far apart to avoid any accidental
      // Layer 2 read — though with only 4 unique BINs, detectSequentialScan's
      // own `bins.length < 5` guard makes Layer 2 impossible here regardless.
      const bins = [1000, 5000, 9000, 13000].map((s) => bin(prefix, s));

      // 6 calls: entities all distinct, BINs cycle through the 4 above so
      // the unique-BIN count caps at 4 while unique-entity count climbs to 6.
      const calls = [
        { bin: bins[0], entity: 'ip-1' },
        { bin: bins[1], entity: 'ip-2' },
        { bin: bins[2], entity: 'ip-3' },
        { bin: bins[3], entity: 'ip-4' }, // 4 BINs, 4 entities — not yet triggered
        { bin: bins[0], entity: 'ip-5' }, // 4 BINs, 5 entities — not yet triggered
        { bin: bins[1], entity: 'ip-6' }, // 4 BINs, 6 entities — should trigger
      ];

      let lastResult;
      for (const c of calls) {
        lastResult = checkBINSequence({ tenantId, bin: c.bin, ipAddress: c.entity });
      }

      expect(lastResult.blocked).toBe(true);
      expect(lastResult.layer).toBe(3);
      expect(lastResult.riskAddition).toBe(30);
    });

    it('does NOT trigger with < 6 distinct entities even if >= 4 BINs are shared', () => {
      const tenantId = uniqueTenant('layer3-below');
      const prefix = '4334';
      const bins = [1000, 5000, 9000, 13000].map((s) => bin(prefix, s));
      const calls = [
        { bin: bins[0], entity: 'ip-1' },
        { bin: bins[1], entity: 'ip-2' },
        { bin: bins[2], entity: 'ip-3' },
        { bin: bins[3], entity: 'ip-4' },
        { bin: bins[0], entity: 'ip-5' }, // only 5 distinct entities total
      ];

      let lastResult;
      for (const c of calls) {
        lastResult = checkBINSequence({ tenantId, bin: c.bin, ipAddress: c.entity });
      }

      expect(lastResult.blocked).toBe(false);
    });
  });

  describe('Tenant isolation (CWE-653 fix)', () => {
    it("Tenant A's attack does not block or appear in Tenant B's stats", () => {
      const tenantA = uniqueTenant('isolation-a');
      const tenantB = uniqueTenant('isolation-b');
      const prefix = '4111'; // deliberately the SAME prefix for both tenants

      // Trigger a Layer 1 block for Tenant A only.
      let resultA;
      for (let i = 0; i < THRESHOLDS.UNIQUE_BINS_PER_PREFIX; i++) {
        resultA = checkBINSequence({
          tenantId: tenantA,
          bin: bin(prefix, 1000 + i * 1000),
          ipAddress: '10.0.0.1',
        });
      }
      expect(resultA.blocked).toBe(true);

      // Tenant B, same prefix, fresh BIN — must be completely unaffected.
      const resultB = checkBINSequence({
        tenantId: tenantB,
        bin: bin(prefix, 999),
        ipAddress: '10.0.0.99',
      });
      expect(resultB.blocked).toBe(false);
      expect(resultB.riskAddition).toBe(0);

      const statsA = getBINStats(tenantA);
      const statsB = getBINStats(tenantB);

      expect(statsA.blockedPrefixes).toBe(1);
      expect(statsB.blockedPrefixes).toBe(0);
      // Guard assertion: Tenant B's active-BIN telemetry must not include
      // any of Tenant A's attack volume.
      expect(statsB.totalActiveBINs).toBe(1);
    });
  });

  describe('Block lifecycle', () => {
    it('blocks for 1 hour, then clears once the block expires', () => {
      const tenantId = uniqueTenant('lifecycle');
      const prefix = '4444';
      const T0 = Date.now();
      const dateNowSpy = jest.spyOn(Date, 'now');

      try {
        // 1. Trigger the block at T0 via Layer 1.
        dateNowSpy.mockReturnValue(T0);
        let triggerResult;
        for (let i = 0; i < THRESHOLDS.UNIQUE_BINS_PER_PREFIX; i++) {
          triggerResult = checkBINSequence({
            tenantId,
            bin: bin(prefix, 1000 + i * 1000),
            ipAddress: '10.0.0.5',
          });
        }
        expect(triggerResult.blocked).toBe(true);
        expect(triggerResult.layer).toBe(1); // the triggering call reports the firing layer...

        // 2. The very next call (same instant) hits the "already blocked" branch —
        //    a different response shape (layer 0, riskAddition 50, generic reason).
        const nextCallResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, 999999),
          ipAddress: '10.0.0.5',
        });
        expect(nextCallResult.blocked).toBe(true);
        expect(nextCallResult.layer).toBe(0);
        expect(nextCallResult.riskAddition).toBe(50);
        expect(nextCallResult.reason).toEqual(expect.stringContaining('temporarily blocked'));

        // 3. 30 minutes later — still within the 1-hour block window.
        dateNowSpy.mockReturnValue(T0 + 30 * 60 * 1000);
        const midResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, 888888),
          ipAddress: '10.0.0.5',
        });
        expect(midResult.blocked).toBe(true);
        expect(midResult.layer).toBe(0);

        // 4. 61 minutes later — block has expired. Note: blockedUntil is never
        //    cleared internally; we assert on observed behavior, not on
        //    internal field state.
        dateNowSpy.mockReturnValue(T0 + 61 * 60 * 1000);
        const expiredResult = checkBINSequence({
          tenantId,
          bin: bin(prefix, 777777),
          ipAddress: '10.0.0.5',
        });
        expect(expiredResult.blocked).toBe(false);
        expect(expiredResult.layer).toBeNull();
      } finally {
        dateNowSpy.mockRestore();
      }
    });
  });

  describe('Edge cases', () => {
    it('treats a BIN shorter than 4 digits as a no-op (no store mutation, no crash)', () => {
      const tenantId = uniqueTenant('edge-short-bin');

      const result = checkBINSequence({ tenantId, bin: '12', ipAddress: '10.0.0.1' });

      expect(result).toEqual({ blocked: false, riskAddition: 0, reason: null });

      const stats = getBINStats(tenantId);
      expect(stats).toEqual({ activePrefixes: 0, blockedPrefixes: 0, totalActiveBINs: 0 });
    });

    it('falls back to deviceFingerprint as the entity when ipAddress is absent', () => {
      const tenantId = uniqueTenant('edge-device-fallback');
      const prefix = '4555';

      // Should not throw, and should still be trackable via getBINStats.
      const result = checkBINSequence({
        tenantId,
        bin: bin(prefix, 1),
        deviceFingerprint: 'device-abc',
      });

      expect(result.blocked).toBe(false);
      expect(getBINStats(tenantId).totalActiveBINs).toBe(1);
    });
  });
});