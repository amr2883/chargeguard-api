// src/lib/logger.js
// مؤقت - سيتم استبداله لاحقًا بنظام تسجيل حقيقي (مثل Pino)

const logger = {
  info: (obj, msg) => console.log(`[INFO] ${msg}`, obj),
  warn: (obj, msg) => console.warn(`[WARN] ${msg}`, obj),
  error: (obj, msg) => console.error(`[ERROR] ${msg}`, obj),
  debug: (obj, msg) => console.debug(`[DEBUG] ${msg}`, obj),
};

module.exports = logger;