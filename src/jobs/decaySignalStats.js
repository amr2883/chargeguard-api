// src/jobs/decaySignalStats.js
//
// Periodic batch decay for SignalStat rows. Complements — does not
// replace — the read-time decay already applied by applyDecay() in
// signalWeights.js. That function decays rawWins/rawLosses at query
// time based on elapsed days since lastDecayAt, but lastDecayAt itself
// is reset to "now" on every single feedback event (see updateSignalStat()
// in feedbackLoop.js) — meaning a signal that keeps receiving events
// never actually has decay materialized into its stored rawWins/rawLosses,
// no matter how old the underlying history is. This job periodically
// consolidates that decay into the stored values themselves, so stale
// history genuinely loses weight over time even for signals that stay
// active.
//
// Concurrency design: the entire decay computation (EXP/EXTRACT/ROUND)
// runs INSIDE a single UPDATE statement's SET clause, reading
// "rawWins"/"rawLosses"/"lastDecayAt" as they exist at the moment
// Postgres executes that statement under its normal row lock — not from
// a JS-held snapshot taken earlier. There is no read-then-write gap in
// application code, so there is nothing for a concurrent
// updateSignalStat() call to race against: whichever statement (this
// job's UPDATE or a live feedback event's UPDATE) commits second simply
// sees the other's already-committed values as its starting point. No
// optimistic-lock comparison is needed or used.

const { Prisma } = require('@prisma/client');
const db = require('../lib/db');
const logger = require('../lib/logger');

const DECAY_INTERVAL_MS = 24 * 60 * 60 * 1000;    // run once per day
const MIN_AGE_FOR_DECAY_MS = 24 * 60 * 60 * 1000; // only touch rows whose last decay is 1+ day old
const DECAY_LAMBDA = 0.003;        // must match signalWeights.js's applyDecay() exactly
const DECAY_LAMBDA_LOSS = 0.0015;  // DECAY_LAMBDA * 0.5 — matches applyDecay()'s asymmetric loss factor
const BATCH_SIZE = 200;

async function decayOnce() {
  const cutoff = new Date(Date.now() - MIN_AGE_FOR_DECAY_MS);

  let candidateIds;
  try {
    // Only select IDs here — the actual rawWins/rawLosses values are never
    // read into JS. This step exists solely to bound the batch size and
    // pick which rows to touch this sweep; the UPDATE below recomputes
    // everything from live DB state regardless of what we saw here.
    const candidates = await db.signalStat.findMany({
      where: { lastDecayAt: { lte: cutoff } },
      select: { id: true },
      take: BATCH_SIZE,
    });
    candidateIds = candidates.map(c => c.id);
  } catch (err) {
    logger.error({ module: 'decaySignalStats', error: err.message }, 'Failed to load candidate rows for decay');
    return;
  }

  if (candidateIds.length === 0) {
    logger.info({ module: 'decaySignalStats', scanned: 0 }, 'No rows due for decay this sweep');
    return;
  }

  let affected = 0;
  try {
    // Single atomic statement for the whole batch. daysSince is computed
    // from each row's OWN lastDecayAt at execution time — rows in this
    // batch can have different ages, and each gets its own correct factor.
    //
    // GREATEST(..., 1) for any strictly-positive count: prevents a rare
    // but real signal (small rawWins/rawLosses) from rounding down to
    // exactly 0 purely from decay — it keeps a residual weight of 1
    // instead of vanishing outright. A count that was already 0 stays 0
    // (the first branch of each CASE only fires when the value is > 0).
    // This is a deliberate compromise for the Int column type rather than
    // widening rawWins/rawLosses to Float, which would be a larger,
    // separate schema migration — see the design discussion for why.
    //
    // The WHERE clause re-checks lastDecayAt <= cutoff (not just id IN
    // (...)) as a final safety net: if a row in this batch already
    // received a live feedback event between our SELECT above and this
    // UPDATE (which would have bumped its lastDecayAt to "now"), this
    // condition naturally excludes it — no explicit lock needed, Postgres
    // just evaluates WHERE against current row state.
    const result = await db.$executeRaw`
      UPDATE "SignalStat"
      SET
        "rawWins" = CASE WHEN "rawWins" > 0
          THEN GREATEST(
            ROUND("rawWins" * EXP(-${DECAY_LAMBDA} * EXTRACT(EPOCH FROM (NOW() - "lastDecayAt")) / 86400.0))::int,
            1
          )
          ELSE 0 END,
        "rawLosses" = CASE WHEN "rawLosses" > 0
          THEN GREATEST(
            ROUND("rawLosses" * EXP(-${DECAY_LAMBDA_LOSS} * EXTRACT(EPOCH FROM (NOW() - "lastDecayAt")) / 86400.0))::int,
            1
          )
          ELSE 0 END,
        "lastDecayAt" = NOW()
      WHERE id IN (${Prisma.join(candidateIds)}) AND "lastDecayAt" <= ${cutoff}
    `;
    affected = result;
  } catch (err) {
    logger.error({ module: 'decaySignalStats', error: err.message }, 'Batch decay UPDATE failed');
    return;
  }

  logger.info(
    { module: 'decaySignalStats', candidates: candidateIds.length, decayed: affected },
    'Decay sweep complete'
  );
}

function start() {
  setInterval(() => {
    decayOnce().catch(err => logger.error({ module: 'decaySignalStats', error: err.message }, 'Decay sweep crashed'));
  }, DECAY_INTERVAL_MS).unref();
}

module.exports = { start, decayOnce };