// scripts/backfill-card-bin-prefix.js
//
// [BIN Velocity fix] Backfills Order.cardBinPrefix by extracting `bin`
// from the historical signalsSnapshot JSON blob (the only place BIN was
// ever recorded before this migration). Most historical orders will have
// no bin at all (see ADR-0: BIN only arrives via /enrich, post-payment) —
// that's expected and correctly left as cardBinPrefix = null.
//
// CRITICAL DESIGN NOTE — cursor-based, NOT condition-based:
// Unlike scripts/backfill-normalized-emails.js (which re-queries
// `WHERE normalizedValue IS NULL` and is safe because every row CAN be
// normalized), this script CANNOT use that pattern: most rows have no
// bin and will永远 stay cardBinPrefix = null after processing, so a
// `WHERE cardBinPrefix IS NULL` re-query would return the exact same
// unprocessable rows forever — an infinite loop. Instead, this walks the
// table exactly once via an ascending `id` cursor that always advances
// after each batch, regardless of whether any row in that batch was
// actually updated.
//
// Usage:
//   node scripts/backfill-card-bin-prefix.js               # run for real
//   node scripts/backfill-card-bin-prefix.js --dry-run     # count only
//
// Safe to re-run: every row's cardBinPrefix is deterministically derived
// from its own signalsSnapshot, and already-processed rows (whether they
// got a value or stayed null) are simply recomputed to the same result.

const db = require('../src/lib/db');

const BATCH_SIZE = 500;
const CONCURRENCY = 20;

const DRY_RUN = process.argv.includes('--dry-run');

function extractCardBinPrefix(signalsSnapshotRaw) {
  if (!signalsSnapshotRaw) return null;
  let snapshot;
  try {
    snapshot = JSON.parse(signalsSnapshotRaw);
  } catch {
    return null;
  }
  const rawBin = snapshot?.bin;
  if (!rawBin) return null;
  const cleaned = String(rawBin).replace(/\D/g, '').slice(0, 6);
  return cleaned.length === 6 ? cleaned : null;
}

async function runWithConcurrency(items, fn, concurrency) {
  let index = 0;
  let updated = 0;
  let errors = 0;
  async function worker() {
    while (index < items.length) {
      const i = index++;
      try {
        const didUpdate = await fn(items[i]);
        if (didUpdate) updated++;
      } catch (err) {
        errors++;
        console.error(`  ✗ Failed on row id=${items[i]?.id}: ${err.message}`);
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, worker);
  await Promise.all(workers);
  return { updated, errors };
}

async function main() {
  const startedAt = Date.now();
  console.log('ChargeGuard — Order.cardBinPrefix backfill');
  console.log(`Mode: ${DRY_RUN ? 'DRY RUN' : 'LIVE'}`);

  if (DRY_RUN) {
    const totalCandidates = await db.order.count({
      where: { cardBinPrefix: null, signalsSnapshot: { not: null } },
    });
    console.log(`  [dry-run] ${totalCandidates} rows have cardBinPrefix=NULL and a signalsSnapshot to inspect.`);
    console.log(`  [dry-run] Actual extractable bins will be a subset of this (most orders never carried a BIN — see ADR-0).`);
    await db.$disconnect();
    return;
  }

  let cursor = null;
  let scanned = 0;
  let totalUpdated = 0;
  let totalErrors = 0;

  while (true) {
    const batch = await db.order.findMany({
      where: {
        signalsSnapshot: { not: null },
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      select: { id: true, signalsSnapshot: true, cardBinPrefix: true },
      orderBy: { id: 'asc' },
      take: BATCH_SIZE,
    });

    if (batch.length === 0) break;

    // Cursor advances unconditionally — this is what guarantees
    // termination even though most rows won't get an update.
    cursor = batch[batch.length - 1].id;

    const { updated, errors } = await runWithConcurrency(
      batch,
      async (row) => {
        // Skip rows already correctly populated — cheap re-run safety,
        // avoids redundant writes on repeated invocations.
        if (row.cardBinPrefix) return false;

        const cardBinPrefix = extractCardBinPrefix(row.signalsSnapshot);
        if (!cardBinPrefix) return false; // no bin recorded for this order — expected for most rows

        await db.order.update({
          where: { id: row.id },
          data: { cardBinPrefix },
        });
        return true;
      },
      CONCURRENCY
    );

    scanned += batch.length;
    totalUpdated += updated;
    totalErrors += errors;
    console.log(`  Scanned ${scanned} rows so far — ${totalUpdated} updated with a real BIN prefix, ${totalErrors} errors.`);
  }

  const elapsedSec = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log(`\nDone in ${elapsedSec}s. Scanned ${scanned} total rows, updated ${totalUpdated} with a cardBinPrefix.`);
  console.log(`(The remaining ${scanned - totalUpdated} rows genuinely had no BIN recorded — left as NULL, correctly.)`);

  process.exitCode = totalErrors > 0 ? 1 : 0;
  await db.$disconnect();
}

main().catch(err => {
  console.error('Fatal error during backfill:', err);
  process.exitCode = 1;
});