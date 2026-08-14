-- SignalStat: rawWins/rawLosses are counts but stored as Float to support
-- fractional weight updates from the feedback loop (decay + confidence weighting).
ALTER TABLE "SignalStat"
  ALTER COLUMN "rawWins" TYPE DOUBLE PRECISION,
  ALTER COLUMN "rawLosses" TYPE DOUBLE PRECISION;
