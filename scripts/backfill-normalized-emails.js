// scripts/backfill-normalized-emails.js
//
// [Bug #7 fix — ADR-10 step 5] Backfills BlacklistEntry.normalizedValue,
// WhitelistEntry.normalizedValue, and Order.normalizedEmail for rows
// written before the write-path fix shipped. MUST complete (verified via
// --verify) before the read-path changes in risk.js / enrichmentProcessor.js
// are deployed — see ADR-10 §6 rollout order.
//
// Usage:
//   node scripts/backfill-normalized-emails.js               # run for real
//   node scripts/backfill-normalized-emails.js --dry-run     # count only, no writes
//   node scripts/backfill-normalized-emails.js --verify      # check completion, no writes
//
// Safe to re-run any number of times — every query is scoped to
// `normalizedValue IS NULL` / `normalizedEmail IS NULL`, so a completed
// run is a fast no-op on subsequent invocations.

const db = require('../src/lib/db');
const { normalizeEmail } = require('../src/lib/utils');

const BATCH_SIZE = 500;
const CONCURRENCY = 20; // bounded parallel updates per batch — avoids
                         // saturating the DB connection pool on a single
                         // batch of individual UPDATE statements.

const DRY_RUN = process.argv.includes('--dry-run');
const VERIFY_ONLY = process.argv.includes('--verify');

// ─── computeNormalizedValue — MUST stay identical to risk.js's copy ───────
// EMAIL: full normalizeEmail() (homoglyph/case/plus-tag/dot aware) — this
// is the actual Bug #7 fix. IP/DEVICE_FINGERPRINT: trim only, no fuzzy
// matching (out of scope for this fix). BIN: unchanged — already
// normalized to 6 digits at write time in both blacklist/whitelist routes.
function computeNormalizedValue(type, value) {
  if (value == null) return null;
  if (type === 'EMAIL') return normalizeEmail(value);
  if (type === 'IP' || type === 'DEVICE_FINGERPRINT') return String(value).trim();
  return String(value);
}

// Bounded-concurrency runner — processes `items` with at most
// `CONCURRENCY` in-flight promises at once, using `fn` to process each.
async function runWithConcurrency(items, fn, concurrency) {
  let index = 0;
  let errors = 0;
  async function worker() {
    while (index < items.length) {
      const i = index++;
      try {
        await fn(items[i]);
      } catch (err) {
        errors++;
        console.error(`  ✗ Failed on row id=${items[i]?.id}: ${err.message}`);
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, worker);
  await Promise.all(workers);
  return errors;
}

// ─── Generic backfill for BlacklistEntry / WhitelistEntry ─────────────────
async function backfillListModel(modelName, dbModel) {
  console.log(`\n── Backfilling ${modelName}.normalizedValue ──`);

  const totalToProcess = await dbModel.count({ where: { normalizedValue: null } });
  console.log(`  Rows needing backfill: ${totalToProcess}`);

  if (totalToProcess === 0) {
    console.log(`  ✅ Nothing to do — already complete.`);
    return { processed: 0, errors: 0 };
  }

  if (DRY_RUN) {
    console.log(`  [dry-run] Would process ${totalToProcess} rows. No writes performed.`);
    return { processed: 0, errors: 0 };
  }

  let processed = 0;
  let totalErrors = 0;

  // Always re-query the SAME condition (normalizedValue: null) — every
  // successfully updated row leaves this result set, so there is no
  // offset/cursor to track and no risk of skipping or double-processing
  // rows as the table changes underneath us.
  while (true) {
    const batch = await dbModel.findMany({
      where: { normalizedValue: null },
      select: { id: true, type: true, value: true },
      take: BATCH_SIZE,
    });

    if (batch.length === 0) break;

    const errors = await runWithConcurrency(
      batch,
      async (row) => {
        const normalizedValue = computeNormalizedValue(row.type, row.value);
        await dbModel.update({
          where: { id: row.id },
          data: { normalizedValue },
        });
      },
      CONCURRENCY
    );

    processed += batch.length;
    totalErrors += errors;
    console.log(`  Processed ${processed}/${totalToProcess} (${errors} errors this batch)`);
  }

  console.log(`  ✅ Done — ${processed} rows processed, ${totalErrors} total errors.`);
  return { processed, errors: totalErrors };
}

// ─── Order.normalizedEmail backfill ────────────────────────────────────────
async function backfillOrders() {
  console.log(`\n── Backfilling Order.normalizedEmail ──`);

  const where = { email: { not: null }, normalizedEmail: null };
  const totalToProcess = await db.order.count({ where });
  console.log(`  Rows needing backfill: ${totalToProcess}`);

  if (totalToProcess === 0) {
    console.log(`  ✅ Nothing to do — already complete.`);
    return { processed: 0, errors: 0 };
  }

  if (DRY_RUN) {
    console.log(`  [dry-run] Would process ${totalToProcess} rows. No writes performed.`);
    return { processed: 0, errors: 0 };
  }

  let processed = 0;
  let totalErrors = 0;

  while (true) {
    const batch = await db.order.findMany({
      where,
      select: { id: true, email: true },
      take: BATCH_SIZE,
    });

    if (batch.length === 0) break;

    const errors = await runWithConcurrency(
      batch,
      async (row) => {
        const normalizedEmail = normalizeEmail(row.email);
        await db.order.update({
          where: { id: row.id },
          data: { normalizedEmail },
        });
      },
      CONCURRENCY
    );

    processed += batch.length;
    totalErrors += errors;
    console.log(`  Processed ${processed}/${totalToProcess} (${errors} errors this batch)`);
  }

  console.log(`  ✅ Done — ${processed} rows processed, ${totalErrors} total errors.`);
  return { processed, errors: totalErrors };
}

// ─── Verification — the gate before deploying the read-path changes ───────
async function verifyCompletion() {
  console.log(`\n── Verification ──`);

  const blacklistRemaining = await db.blacklistEntry.count({ where: { normalizedValue: null } });
  const whitelistRemaining = await db.whitelistEntry.count({ where: { normalizedValue: null } });
  const orderRemaining = await db.order.count({ where: { email: { not: null }, normalizedEmail: null } });

  console.log(`  BlacklistEntry rows still NULL: ${blacklistRemaining}`);
  console.log(`  WhitelistEntry rows still NULL: ${whitelistRemaining}`);
  console.log(`  Order rows still NULL (with email set): ${orderRemaining}`);

  const complete = blacklistRemaining === 0 && whitelistRemaining === 0 && orderRemaining === 0;

  if (complete) {
    console.log(`\n  ✅ ALL CLEAR — safe to deploy the read-path changes (risk.js / enrichmentProcessor.js).`);
  } else {
    console.log(`\n  ⚠️  NOT complete yet — do NOT deploy the read-path changes. Re-run this script without --verify.`);
  }

  return complete;
}

// ─── Main ───────────────────────────────────────────────────────────────
async function main() {
  const startedAt = Date.now();
  console.log('ChargeGuard — normalized-value backfill');
  console.log(`Mode: ${VERIFY_ONLY ? 'VERIFY ONLY' : DRY_RUN ? 'DRY RUN' : 'LIVE'}`);

  try {
    if (VERIFY_ONLY) {
      const complete = await verifyCompletion();
      process.exitCode = complete ? 0 : 1;
      return;
    }

    const results = [];
    results.push(await backfillListModel('BlacklistEntry', db.blacklistEntry));
    results.push(await backfillListModel('WhitelistEntry', db.whitelistEntry));
    results.push(await backfillOrders());

    if (!DRY_RUN) {
      await verifyCompletion();
    }

    const totalErrors = results.reduce((sum, r) => sum + r.errors, 0);
    const elapsedSec = ((Date.now() - startedAt) / 1000).toFixed(1);
    console.log(`\nFinished in ${elapsedSec}s.`);
    process.exitCode = totalErrors > 0 ? 1 : 0;
  } catch (err) {
    console.error('Fatal error during backfill:', err);
    process.exitCode = 1;
  } finally {
    await db.$disconnect();
  }
}

main();