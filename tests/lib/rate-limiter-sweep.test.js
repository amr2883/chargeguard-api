'use strict';

require('../../src/routes/privacy');
require('../../src/routes/settings');

// S5: verify the periodic sweeps in privacy.js and settings.js actually
// remove expired entries and leave fresh entries untouched. The sweep
// functions are exported on globalThis so this test does not have to wait
// for the real 1h / 15min timers to fire.

describe('rate limiter sweeps (S5)', () => {
  let savedPriv, savedSettings;

  beforeEach(() => {
    savedPriv = globalThis.__cgPrivRate ? new Map(globalThis.__cgPrivRate) : null;
    savedSettings = globalThis.__cgSettingsRate ? new Map(globalThis.__cgSettingsRate) : null;
    if (globalThis.__cgPrivRate) globalThis.__cgPrivRate.clear();
    if (globalThis.__cgSettingsRate) globalThis.__cgSettingsRate.clear();
  });

  afterEach(() => {
    if (globalThis.__cgPrivRate && savedPriv) {
      globalThis.__cgPrivRate.clear();
      for (const [k, v] of savedPriv) globalThis.__cgPrivRate.set(k, v);
    }
    if (globalThis.__cgSettingsRate && savedSettings) {
      globalThis.__cgSettingsRate.clear();
      for (const [k, v] of savedSettings) globalThis.__cgSettingsRate.set(k, v);
    }
  });

  it('T1: privacy sweep removes stale entries and keeps fresh ones', () => {
    const m = globalThis.__cgPrivRate;
    const sweep = globalThis.__cgPrivSweep;
    const windowMs = globalThis.__cgPrivWindowMs;
    expect(m).toBeInstanceOf(Map);
    expect(typeof sweep).toBe('function');
    expect(typeof windowMs).toBe('number');

    const now = Date.now();
    m.set('stale-a', { count: 3, firstAt: now - windowMs - 1000 });
    m.set('stale-b', { count: 1, firstAt: now - windowMs * 3 });
    m.set('fresh',   { count: 2, firstAt: now - Math.floor(windowMs / 2) });

    sweep(now);

    expect(m.has('stale-a')).toBe(false);
    expect(m.has('stale-b')).toBe(false);
    expect(m.has('fresh')).toBe(true);
    expect(m.get('fresh').count).toBe(2);
  });

  it('T2: privacy sweep on an empty map is a no-op', () => {
    const m = globalThis.__cgPrivRate;
    const sweep = globalThis.__cgPrivSweep;
    m.clear();
    expect(() => sweep(Date.now())).not.toThrow();
    expect(m.size).toBe(0);
  });

  it('T3: settings sweep removes stale entries and keeps fresh ones', () => {
    const m = globalThis.__cgSettingsRate;
    const sweep = globalThis.__cgSettingsSweep;
    const windowMs = globalThis.__cgSettingsWindowMs;
    expect(m).toBeInstanceOf(Map);
    expect(typeof sweep).toBe('function');
    expect(typeof windowMs).toBe('number');

    const now = Date.now();
    m.set('stale-a', { count: 5, firstAt: now - windowMs - 1000 });
    m.set('fresh',   { count: 1, firstAt: now - Math.floor(windowMs / 3) });

    sweep(now);

    expect(m.has('stale-a')).toBe(false);
    expect(m.has('fresh')).toBe(true);
    expect(m.get('fresh').count).toBe(1);
  });

  it('T4: settings sweep on an empty map is a no-op', () => {
    const m = globalThis.__cgSettingsRate;
    const sweep = globalThis.__cgSettingsSweep;
    m.clear();
    expect(() => sweep(Date.now())).not.toThrow();
    expect(m.size).toBe(0);
  });
});