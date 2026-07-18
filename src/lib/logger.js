// src/lib/logger.js
// مؤقت - سيتم استبداله لاحقًا بنظام تسجيل حقيقي (مثل Pino)
//
// Log level control:
//   Set the LOG_LEVEL environment variable to control verbosity.
//   Levels (least to most severe): debug < info < warn < error
//   Only methods at or above the configured level will print.
//
//     LOG_LEVEL=debug   -> debug, info, warn, error all print (default if unset; good for local dev)
//     LOG_LEVEL=info    -> info, warn, error print; debug is silent
//     LOG_LEVEL=warn    -> warn, error print; debug and info are silent (RECOMMENDED for production)
//     LOG_LEVEL=error   -> only error prints
//
//   warn and error are never fully disabled by this mechanism for any LOG_LEVEL
//   value in the table above — they are the production safety net (circuit-breaker
//   trips, decrypt failures, signature mismatches) and must remain visible.
//
//   This is parsed once at module load into a numeric threshold, so each log call
//   only pays the cost of a single integer comparison.

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

const configuredLevel = (process.env.LOG_LEVEL || 'debug').toLowerCase();
const threshold = LEVELS.hasOwnProperty(configuredLevel)
  ? LEVELS[configuredLevel]
  : LEVELS.debug; // fall back safely if LOG_LEVEL is set to something unrecognized

const logger = {
  debug: (obj, msg) => { if (threshold <= LEVELS.debug) console.debug(`[DEBUG] ${msg}`, obj); },
  info:  (obj, msg) => { if (threshold <= LEVELS.info)  console.log(`[INFO] ${msg}`, obj); },
  warn:  (obj, msg) => { if (threshold <= LEVELS.warn)  console.warn(`[WARN] ${msg}`, obj); },
  error: (obj, msg) => { if (threshold <= LEVELS.error) console.error(`[ERROR] ${msg}`, obj); },
};

module.exports = logger;