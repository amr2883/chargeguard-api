const crypto = require('crypto');
const logger = require('../lib/logger');

const TIMESTAMP_TOLERANCE_SEC = 300; // 5 دقائق

function verifyHmacSignature(req, res, next) {
  const signature  = req.headers['x-chargeguard-signature'];
  const timestamp  = req.headers['x-chargeguard-timestamp'];

  // Legacy mode: Plugin قديم لا يرسل الهيدرات الجديدة
  if (!signature && !timestamp) {
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      'HMAC_LEGACY_REQUEST — no signature headers, allowing through'
    );
    return next();
  }

  // إذا أرسل أحد الهيدرين فقط، هذا خطأ
  if (!signature || !timestamp) {
    logger.warn(
      { tenantId: req.tenant?.id, signature: !!signature, timestamp: !!timestamp },
      'HMAC_PARTIAL_HEADERS'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من صحة الـ Timestamp (숫자 فقط)
  const tsNum = parseInt(timestamp, 10);
  if (isNaN(tsNum) || String(tsNum) !== timestamp) {
    logger.warn({ tenantId: req.tenant?.id }, 'HMAC_INVALID_TIMESTAMP_FORMAT');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من النافذة الزمنية
  const nowSec = Math.floor(Date.now() / 1000);
  const diff   = Math.abs(nowSec - tsNum);
  if (diff > TIMESTAMP_TOLERANCE_SEC) {
    logger.warn(
      { tenantId: req.tenant?.id, diff, tolerance: TIMESTAMP_TOLERANCE_SEC },
      'HMAC_TIMESTAMP_EXPIRED'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // التحقق من وجود الـ webhookSecret
  const secret = req.tenant?.webhookSecret;
  if (!secret) {
    logger.warn({ tenantId: req.tenant?.id }, 'HMAC_NO_SECRET_CONFIGURED');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // بناء الـ signed string
  const rawBody     = req.body instanceof Buffer ? req.body : Buffer.from(JSON.stringify(req.body));
  const signedStr   = `${timestamp}.${rawBody.toString('utf8')}`;

  // حساب الـ expected signature
  const expected    = 'v1=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');

  // المقارنة الآمنة
  let isValid = false;
  try {
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expected);
    if (sigBuf.length === expBuf.length) {
      isValid = crypto.timingSafeEqual(sigBuf, expBuf);
    }
  } catch (_) {
    isValid = false;
  }

  if (!isValid) {
    logger.warn(
      { tenantId: req.tenant?.id, path: req.path },
      'HMAC_SIGNATURE_MISMATCH'
    );
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // الـ signature صحيح — parse الـ body وتابع
  if (req.body instanceof Buffer) {
    try {
      req.body = JSON.parse(req.body.toString('utf8'));
    } catch (_) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
  }

  next();
}

module.exports = verifyHmacSignature;