const db = require('./db');
const logger = require('./logger');

// أي توقيع اتقبل لازم يكون timestamp عمره أقل من TIMESTAMP_TOLERANCE_SEC
// (300 ثانية) في verifyHmac.js. يعني بعد 15 دقيقة، requestKey مستحيل
// يتكرر بشكل شرعي أصلاً — الهامش (3x) بس عشان أي تفاوت ساعة.
const RETENTION_MS = 15 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

// أطول timeout بيستخدمه الـPHP client فعليًا هو 15 ثانية (شوف
// class-api-client.php)، والـretry بتاعه (attempt واحد إضافي على 5xx/
// network error) ممكن يوصل بالسيناريو الأسوأ لـ 2×15=30 ثانية قبل ما
// PHP يستسلم نهائيًا. بنحط هامش فوق ده (45 ثانية) عشان لو claim فضل
// 'processing' أكتر من كده، يبقى الأرجح إن الـprocess اللي كان شايله
// وقع (crash) أو اتعلّق (hang) من غير ما يقدر يرجع أي رد خالص — مش مجرد
// بطء عادي. في الحالة دي، نعتبر الـclaim متروك (abandoned) ونسمح
// لمحاولة تانية تاخده، بدل ما تفضل الطلبات مرفوضة بـ409 للأبد.
const STALE_PROCESSING_MS = 45 * 1000;

// لو الرد أكبر من كده، منخزنوش جسمه (نادر جدًا لطلبات الـmutating اللي
// بنحميها، لكن احتياط ضد unbounded storage growth).
const MAX_CACHED_BODY_BYTES = 100 * 1024;

/**
 * يحاول يحجز requestKey معيّن لتنفيذ فعلي واحد.
 *
 * بيرجّع claimId (= id بتاع الصف) مع claimed:true — ده fencing token
 * لازم يتمرر بالظبط لـ completeRequest/releaseRequest بعد كده، عشان لو
 * الـclaim اتسحب من تحته (reclaimed كـabandoned بينما هو لسه شغال فعليًا
 * ببطء)، الـcomplete/release القديمة تفضل بلا أثر على الـclaim الجديد
 * (منع lost-update / ABA problem).
 */
async function claimRequestOnce(tenantId, requestKey, _isRetry = false) {
  try {
    const row = await db.processedRequest.create({
      data: { tenantId, requestKey, status: 'processing' },
    });
    return { claimed: true, claimId: row.id };
  } catch (err) {
    if (err.code !== 'P2002') {
      logger.error({ module: 'replayGuard', tenantId, err }, 'claimRequestOnce error');
      throw err;
    }
  }

  const existing = await db.processedRequest.findUnique({
    where: { tenantId_requestKey: { tenantId, requestKey } },
  });

  if (!existing) {
    // نادر جدًا: اتمسح بين محاولة الـcreate والـfindUnique (مثلاً
    // completeRequest/releaseRequest لصف اتنفذ في نفس اللحظة بالظبط).
    // محاولة واحدة تانية كفاية، مفيش داعي لحلقة أعقد من كده.
    if (_isRetry) {
      return { claimed: false, cached: null };
    }
    return claimRequestOnce(tenantId, requestKey, true);
  }

  if (existing.status === 'completed') {
    return { claimed: false, cached: { code: existing.responseCode, body: existing.responseBody } };
  }

  // status === 'processing'
  const ageMs = Date.now() - existing.createdAt.getTime();
  if (ageMs > STALE_PROCESSING_MS) {
    // Claim متروك على الأرجح — نسحبه ونحجز واحد جديد بدلاً منه. الحذف
    // بالـid تحديدًا (مش بالـtenantId+requestKey بس) عشان لو حصل تعارض
    // نادر واتغيّر الصف من تحتنا، منمسحش حاجة لسه سليمة بالغلط.
    try {
      await db.processedRequest.delete({ where: { id: existing.id } });
    } catch (delErr) {
      if (delErr.code !== 'P2025') { // P2025 = مش موجود أصلاً، تجاهله بأمان
        logger.error({ module: 'replayGuard', tenantId, err: delErr }, 'claimRequestOnce reclaim-delete error');
        throw delErr;
      }
    }
    if (_isRetry) {
      // منع أي حلقة لا نهائية في سيناريو نادر جدًا (سباق متكرر) — لو
      // فشلنا في الحجز بعد محاولتين، نرجّع "لسه مشغول" بدل ما نلف للأبد.
      return { claimed: false, cached: null };
    }
    return claimRequestOnce(tenantId, requestKey, true);
  }

  // لسه شغال فعليًا وضمن مهلة معقولة — تكرار متزامن حقيقي.
  return { claimed: false, cached: null };
}

async function completeRequest(tenantId, requestKey, claimId, code, body) {
  try {
    let bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    if (bodyStr && Buffer.byteLength(bodyStr, 'utf8') > MAX_CACHED_BODY_BYTES) {
      bodyStr = null;
    }
    // updateMany بشرط id/status بدل update() المباشر: لو الـclaim اتسحب
    // من تحتنا (reclaimed كـabandoned) بينما إحنا لسه شغالين ببطء، الصف
    // الحالي بقى بـid مختلف — الشرط ده يمنعنا نكتب فوق claim حد تاني
    // بالغلط (lost-update). لو count=0، معناها كده حصل بالفعل: نتجاهل
    // بهدوء، الرد أصلاً راجع للعميل اللي طلبه عبر الـHTTP response نفسه.
    const { count } = await db.processedRequest.updateMany({
      where: { id: claimId, tenantId, requestKey, status: 'processing' },
      data: { status: 'completed', responseCode: code, responseBody: bodyStr, completedAt: new Date() },
    });
    if (count === 0) {
      logger.warn({ module: 'replayGuard', tenantId, requestKey, claimId }, 'completeRequest: claim already superseded, skipped cache write');
    }
  } catch (err) {
    logger.error({ module: 'replayGuard', tenantId, requestKey, err }, 'completeRequest error');
  }
}

/**
 * بيتنادى بدل completeRequest لما الرد النهائي يكون 5xx. عن قصد
 * **مبيكاشش** الرد ده: خطأ سيرفر مؤقت (بعكس نجاح فعلي أو قرار منطقي
 * زي 400/403) مش نتيجة "نهائية" تستاهل تتخزن وترجع لأي retry لاحق —
 * العكس هو المطلوب: نديله فرصة ينفّذ من جديد فعليًا. نفس المبدأ اللي
 * Stripe بتتبعه في تصميم idempotency keys بتاعتها: أخطاء ناتجة عن
 * مشكلة في إتمام الطلب بترجع قابلة لإعادة محاولة حقيقية، مش cached.
 */
async function releaseRequest(tenantId, requestKey, claimId) {
  try {
    const { count } = await db.processedRequest.deleteMany({
      where: { id: claimId, tenantId, requestKey, status: 'processing' },
    });
    if (count === 0) {
      // نفس منطق الـfencing فوق: لو مسحناش حاجة، يبقى الـclaim اتسحب أو
      // اتقفل من مصدر تاني قبلنا — مفيش داعي نعمل حاجة.
      logger.warn({ module: 'replayGuard', tenantId, requestKey, claimId }, 'releaseRequest: claim already superseded, nothing released');
    }
  } catch (err) {
    logger.error({ module: 'replayGuard', tenantId, requestKey, err }, 'releaseRequest error');
  }
}

async function cleanupExpired() {
  try {
    const cutoff = new Date(Date.now() - RETENTION_MS);
    const { count } = await db.processedRequest.deleteMany({ where: { createdAt: { lt: cutoff } } });
    if (count > 0) logger.info({ module: 'replayGuard', count }, 'cleaned expired processed-request rows');
  } catch (err) {
    logger.error({ module: 'replayGuard', err }, 'cleanupExpired error');
  }
}

function startCleanupJob() {
  cleanupExpired();
  return setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);
}

module.exports = { claimRequestOnce, completeRequest, releaseRequest, startCleanupJob };