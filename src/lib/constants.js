// src/lib/constants.js
'use strict';

module.exports = {
  // ── إحصائيات مالية ──────────────────────────────────────────────────────
  // يجب أن يتطابق هذا الرقم في كل تقرير وإشعار وحساب
  SAVINGS_PER_ATTACK: 0.30,

  // ── إعدادات Attack Alert ─────────────────────────────────────────────────
  ATTACK_WINDOW_MS:   10 * 60 * 1000,
  ATTACK_THRESHOLD:   10,
  COOLDOWN_MS:        6  * 60 * 60 * 1000,

  // ── إعدادات Weekly Summary ───────────────────────────────────────────────
  QUIET_STREAK_THRESHOLD: 3,

  // ── إعدادات Monthly Report ───────────────────────────────────────────────
  REPORT_GENERATION_HOUR_UTC: 10,   // أول يوم من الشهر 10:00 UTC
  REPORT_FREE_MONTHS_LIMIT:    1,   // المجاني يرى آخر تقرير فقط
};