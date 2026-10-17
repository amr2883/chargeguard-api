'use strict';

/**
 * Permanent tests for src/lib/replayGuard.js (P0-01 / #49).
 *
 * Replaces the manual script scripts/test-replay-guard.js. Two groups:
 *   1. Real DB (chargeguard_test only, guarded by tests/setup/assertSafeTestDb.js).
 *      Every row uses the dedicated tenantId below and random request keys,
 *      and cleanup is scoped to that tenantId (never deleteMany({})).
 *   2. Fake db object (no DB access) for branches that cannot be reached
 *      deterministically against a real DB (P2025 swallow, retry-after-reclaim).
 *
 * Constants below MIRROR replayGuard.js (they are not exported). If the source
 * constants change, update them here. Offsets use +/-5s margins around the
 * 45s stale window so the tests are not sensitive to DB round-trip time.
 */

const crypto = require('crypto');
const db = require('../../src/lib/db');
const {
  claimRequestOnce,
  completeRequest,
  releaseRequest,
  startCleanupJob,
} = require('../../src/lib/replayGuard');

jest.setTimeout(30000);

const STALE_MS = 45 * 1000; // STALE_PROCESSING_MS
const RETENTION_MS = 15 * 60 * 1000; // RETENTION_MS
const MAX_BODY_BYTES = 100 * 1024; // MAX_CACHED_BODY_BYTES

const TENANT = 'jest-replay-guard';

const uniqueKey = (label) => `${label}-${crypto.randomBytes(8).toString('hex')}`;
const ago = (ms) => new Date(Date.now() - ms);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const rowById = (id) => db.processedRequest.findUnique({ where: { id } });
const backdate = (id, ms) =>
  db.processedRequest.update({ where: { id }, data: { createdAt: ago(ms) } });

const cleanTenantRows = () => db.processedRequest.deleteMany({ where: { tenantId: TENANT } });

beforeEach(cleanTenantRows);

afterAll(async () => {
  await cleanTenantRows();
  await db.$disconnect();
});

describe('claimRequestOnce (real DB)', () => {
  test('first claim succeeds and writes a processing row', async () => {
    const key = uniqueKey('first');
    const claim = await claimRequestOnce(TENANT, key);

    expect(claim.claimed).toBe(true);
    expect(typeof claim.claimId).toBe('string');

    const row = await rowById(claim.claimId);
    expect(row).toMatchObject({ tenantId: TENANT, requestKey: key, status: 'processing' });
  });

  test('duplicate while in-flight is rejected and the original row is untouched', async () => {
    const key = uniqueKey('inflight');
    const first = await claimRequestOnce(TENANT, key);
    const second = await claimRequestOnce(TENANT, key);

    expect(second).toEqual({ claimed: false, cached: null });

    const row = await rowById(first.claimId);
    expect(row).not.toBeNull();
    expect(row.status).toBe('processing');
  });

  test('processing row just inside the stale window (40s) is still rejected', async () => {
    const key = uniqueKey('fresh40');
    const first = await claimRequestOnce(TENANT, key);
    await backdate(first.claimId, STALE_MS - 5000);

    const second = await claimRequestOnce(TENANT, key);

    expect(second).toEqual({ claimed: false, cached: null });
    expect(await rowById(first.claimId)).not.toBeNull();
  });

  test('processing row past the stale window (50s) is reclaimed; old row is deleted', async () => {
    const key = uniqueKey('stale50');
    const first = await claimRequestOnce(TENANT, key);
    await backdate(first.claimId, STALE_MS + 5000);

    const second = await claimRequestOnce(TENANT, key);

    expect(second.claimed).toBe(true);
    expect(second.claimId).not.toBe(first.claimId);
    expect(await rowById(first.claimId)).toBeNull();

    const row = await rowById(second.claimId);
    expect(row.status).toBe('processing');
    expect(Date.now() - row.createdAt.getTime()).toBeLessThan(10 * 1000);
  });

  test('completed response is replayed from cache', async () => {
    const key = uniqueKey('cached');
    const marker = crypto.randomBytes(6).toString('hex');
    const first = await claimRequestOnce(TENANT, key);
    await completeRequest(TENANT, key, first.claimId, 200, { ok: true, marker });

    const again = await claimRequestOnce(TENANT, key);

    expect(again.claimed).toBe(false);
    expect(again.cached.code).toBe(200);
    expect(JSON.parse(again.cached.body).marker).toBe(marker);
  });

  test('completed row older than the stale window is still served from cache, never reclaimed', async () => {
    const key = uniqueKey('cached-old');
    const first = await claimRequestOnce(TENANT, key);
    await completeRequest(TENANT, key, first.claimId, 200, { ok: true });
    await backdate(first.claimId, STALE_MS + 5000);

    const again = await claimRequestOnce(TENANT, key);

    expect(again.claimed).toBe(false);
    expect(again.cached).toMatchObject({ code: 200 });
    expect(await rowById(first.claimId)).not.toBeNull();
  });

  test('release then reclaim: row is deleted and the next claim gets a fresh id', async () => {
    const key = uniqueKey('release');
    const first = await claimRequestOnce(TENANT, key);
    await releaseRequest(TENANT, key, first.claimId);

    expect(await rowById(first.claimId)).toBeNull();

    const second = await claimRequestOnce(TENANT, key);
    expect(second.claimed).toBe(true);
    expect(second.claimId).not.toBe(first.claimId);
  });
});

describe('completeRequest (real DB)', () => {
  test('stores status, code, serialized body and completedAt', async () => {
    const key = uniqueKey('complete');
    const claim = await claimRequestOnce(TENANT, key);
    await completeRequest(TENANT, key, claim.claimId, 201, { a: 1 });

    const row = await rowById(claim.claimId);
    expect(row.status).toBe('completed');
    expect(row.responseCode).toBe(201);
    expect(row.responseBody).toBe(JSON.stringify({ a: 1 }));
    expect(row.completedAt).not.toBeNull();
  });

  test('body of exactly 100KB is cached; one byte more is dropped but the code is kept', async () => {
    const exactKey = uniqueKey('body-exact');
    const overKey = uniqueKey('body-over');

    const exact = await claimRequestOnce(TENANT, exactKey);
    await completeRequest(TENANT, exactKey, exact.claimId, 200, 'x'.repeat(MAX_BODY_BYTES));
    const exactRow = await rowById(exact.claimId);
    expect(exactRow.responseBody).not.toBeNull();
    expect(exactRow.responseBody.length).toBe(MAX_BODY_BYTES);

    const over = await claimRequestOnce(TENANT, overKey);
    await completeRequest(TENANT, overKey, over.claimId, 200, 'x'.repeat(MAX_BODY_BYTES + 1));
    const overRow = await rowById(over.claimId);
    expect(overRow.status).toBe('completed');
    expect(overRow.responseCode).toBe(200);
    expect(overRow.responseBody).toBeNull();

    const replay = await claimRequestOnce(TENANT, overKey);
    expect(replay).toEqual({ claimed: false, cached: { code: 200, body: null } });
  });

  test('fencing: complete with a superseded claimId does not touch the reclaimed row', async () => {
    const key = uniqueKey('fence-complete');
    const first = await claimRequestOnce(TENANT, key);
    await backdate(first.claimId, STALE_MS + 5000);
    const second = await claimRequestOnce(TENANT, key);
    expect(second.claimed).toBe(true);

    await completeRequest(TENANT, key, first.claimId, 200, { stale: true });

    const row = await rowById(second.claimId);
    expect(row.status).toBe('processing');
    expect(row.responseCode).toBeNull();
    expect(row.responseBody).toBeNull();
  });

  test('completing twice keeps the first response', async () => {
    const key = uniqueKey('complete-twice');
    const claim = await claimRequestOnce(TENANT, key);
    await completeRequest(TENANT, key, claim.claimId, 200, { v: 1 });
    await completeRequest(TENANT, key, claim.claimId, 500, { v: 2 });

    const row = await rowById(claim.claimId);
    expect(row.status).toBe('completed');
    expect(row.responseCode).toBe(200);
    expect(JSON.parse(row.responseBody).v).toBe(1);
  });
});

describe('releaseRequest (real DB)', () => {
  test('release with a superseded claimId does not delete the reclaimed row', async () => {
    const key = uniqueKey('fence-release');
    const first = await claimRequestOnce(TENANT, key);
    await backdate(first.claimId, STALE_MS + 5000);
    const second = await claimRequestOnce(TENANT, key);
    expect(second.claimed).toBe(true);

    await releaseRequest(TENANT, key, first.claimId);

    const row = await rowById(second.claimId);
    expect(row).not.toBeNull();
    expect(row.status).toBe('processing');
  });

  test('release never deletes a completed row (the cache is preserved)', async () => {
    const key = uniqueKey('release-completed');
    const claim = await claimRequestOnce(TENANT, key);
    await completeRequest(TENANT, key, claim.claimId, 200, { ok: true });

    await releaseRequest(TENANT, key, claim.claimId);

    const row = await rowById(claim.claimId);
    expect(row).not.toBeNull();
    expect(row.status).toBe('completed');
  });
});

describe('startCleanupJob (real DB)', () => {
  test('removes rows older than retention (15 min) and keeps younger ones', async () => {
    const oldClaim = await claimRequestOnce(TENANT, uniqueKey('ret-old'));
    await backdate(oldClaim.claimId, RETENTION_MS + 60 * 1000);
    const keepClaim = await claimRequestOnce(TENANT, uniqueKey('ret-keep'));
    await backdate(keepClaim.claimId, RETENTION_MS - 60 * 1000);
    const freshClaim = await claimRequestOnce(TENANT, uniqueKey('ret-fresh'));

    // cleanupExpired() runs immediately and is not awaited by startCleanupJob,
    // so stop the interval right away and poll for the effect.
    clearInterval(startCleanupJob());

    let oldGone = false;
    for (let i = 0; i < 80 && !oldGone; i += 1) {
      oldGone = (await rowById(oldClaim.claimId)) === null;
      if (!oldGone) await sleep(100);
    }

    expect(oldGone).toBe(true);
    expect(await rowById(keepClaim.claimId)).not.toBeNull();
    expect(await rowById(freshClaim.claimId)).not.toBeNull();
  });
});

describe('claimRequestOnce branch handling (fake db, no real DB access)', () => {
  const conflict = () => Object.assign(new Error('unique constraint'), { code: 'P2002' });
  const withCode = (code) => Object.assign(new Error(`db error ${code}`), { code });
  const staleRow = () => ({
    id: 'old-row',
    tenantId: 't',
    requestKey: 'k',
    status: 'processing',
    createdAt: ago(STALE_MS + 5000),
  });

  // Every fake call is counted; runaway recursion becomes a rejected promise
  // instead of an event-loop-starving hang.
  function counted(impl, limit = 6) {
    let n = 0;
    return jest.fn(async (...args) => {
      n += 1;
      if (n > limit) throw new Error('runaway recursion guard');
      return impl(n, ...args);
    });
  }

  function loadGuard(fake) {
    let mod;
    jest.isolateModules(() => {
      jest.doMock('../../src/lib/db', () => ({ processedRequest: fake }));
      jest.doMock('../../src/lib/logger', () => ({
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
      }));
      mod = require('../../src/lib/replayGuard');
    });
    jest.dontMock('../../src/lib/db');
    jest.dontMock('../../src/lib/logger');
    return mod;
  }

  test('P2025 on the reclaim-delete is swallowed and the retry claims successfully', async () => {
    const fake = {
      create: counted((n) => {
        if (n === 1) throw conflict();
        return { id: 'new-row' };
      }),
      findUnique: counted(() => staleRow()),
      delete: counted(() => {
        throw withCode('P2025');
      }),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).resolves.toEqual({
      claimed: true,
      claimId: 'new-row',
    });
    expect(fake.delete).toHaveBeenCalledTimes(1);
    expect(fake.delete).toHaveBeenCalledWith({ where: { id: 'old-row' } });
  });

  test('a non-P2025 error while deleting the stale row is rethrown', async () => {
    const fake = {
      create: counted(() => {
        throw conflict();
      }),
      findUnique: counted(() => staleRow()),
      delete: counted(() => {
        throw withCode('P9999');
      }),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).rejects.toMatchObject({ code: 'P9999' });
    expect(fake.create).toHaveBeenCalledTimes(1);
  });

  test('a non-P2002 error on create is rethrown without reading the row', async () => {
    const fake = {
      create: counted(() => {
        throw withCode('P1001');
      }),
      findUnique: counted(() => null),
      delete: counted(() => ({})),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).rejects.toMatchObject({ code: 'P1001' });
    expect(fake.findUnique).not.toHaveBeenCalled();
  });

  test('stale row still conflicting after the reclaim-delete gives up after one retry', async () => {
    const fake = {
      create: counted(() => {
        throw conflict();
      }),
      findUnique: counted(() => staleRow()),
      delete: counted(() => ({})),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).resolves.toEqual({
      claimed: false,
      cached: null,
    });
    expect(fake.create).toHaveBeenCalledTimes(2);
    expect(fake.delete).toHaveBeenCalledTimes(2);
  });

  test('row vanishing between create and findUnique is retried once and then claims', async () => {
    const fake = {
      create: counted((n) => {
        if (n === 1) throw conflict();
        return { id: 'new-row' };
      }),
      findUnique: counted(() => null),
      delete: counted(() => ({})),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).resolves.toEqual({
      claimed: true,
      claimId: 'new-row',
    });
    expect(fake.findUnique).toHaveBeenCalledTimes(1);
  });

  test('row still missing on the retry returns not-claimed instead of looping', async () => {
    const fake = {
      create: counted(() => {
        throw conflict();
      }),
      findUnique: counted(() => null),
      delete: counted(() => ({})),
    };
    const guard = loadGuard(fake);

    await expect(guard.claimRequestOnce('t', 'k')).resolves.toEqual({
      claimed: false,
      cached: null,
    });
    expect(fake.create).toHaveBeenCalledTimes(2);
    expect(fake.findUnique).toHaveBeenCalledTimes(2);
  });
});