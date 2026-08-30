// src/lib/atomicIdentityGate.js
// ─── Atomic, TOCTOU-safe distinct-member counter (Postgres advisory lock) ──
//
// يقفل فجوة الـ TOCTOU الموثّقة في risk.js's قسم 1c: الاستعلام القديم
// (db.order.findMany لعدّ distinct fingerprints من نفس IP) كان بيقرا العدد
// الحالي، وبعدين الكتابة (db.order.upsert) كانت بتحصل في آخر الـ handler —
// فجوة زمنية فيها استعلامات تانية كتير (BIN check, risk scoring, graph
// building). N طلب متزامن فعليًا كانوا يقدروا كلهم يشوفوا نفس العدد القديم
// ويعدّوا كلهم من البوابة.
//
// الحل هنا: القراءة + قرار الحظر + الحجز (الكتابة) بتحصل كخطوة ذرية واحدة،
// محمية بـ pg_advisory_xact_lock مبني على (merchantId, scope, storeId,
// groupKey) — طلبين لمفتاحين مختلفين مبيستناوش بعض أبدًا، بس طلبين لنفس
// المفتاح (نفس IP لنفس التاجر) بيتسلسلوا لحظيًا. القفل بيتفك تلقائيًا لما
// الـ transaction تتقفل (commit)، فمدته ميلي ثواني بس — باقي الـ handler
// (BIN check, risk scoring) بيكمل من غيره تمامًا.
//
// ─── قرارات تصميمية موثّقة (ليه، مش بس إيه) ────────────────────────────────
//
// 1. مين بيقرر "هل الـ member مؤهل للعدّ؟" (فيه fingerprint + مش synthetic
//    fallback ID زي wc_<orderId>): المستدعي (risk.js)، مش هذا الملف. لو
//    كررنا ثابت الـ synthetic prefix في مكانين، وحد غيّره في مكان ونسي
//    التاني، بتتفتح فجوة تلوّث صامتة — بالظبط زي الفجوة اللي اكتشفناها في
//    checkVelocity الأصلية. الفصل ده متعمد.
//
// 2. "هل الـ member ده جديد فعلًا؟" (لسه ماتسجّلش لنفس groupKey خلال
//    النافذة): بيتحدد هنا جوه الـ transaction نفسها، مش من المستدعي —
//    لأنه محتاج يقرا حالة الجدول نفسه لحظة الفحص، ومينفعش يتحسب مقدمًا.
//
// 3. سلوك فشل الـ transaction (DB error): **الخطأ بيتصعّد (propagate)،
//    مفيش try/catch هنا خالص.** ده قرار أمني مقصود، مش إهمال: نفس نمط
//    الهجوم اللي البوابة دي بتصده (موجة طلبات متزامنة لنفس IP) هو بالظبط
//    اللي ممكن يضرب lock_timeout عمدًا. لو خلّينا الفشل "fail-open بهدوء"،
//    بنديله مفتاح تحكم مباشر: يفتعل الزحمة، يضرب الـ timeout قصدًا، وكل
//    الطلبات اللي فشل قفلها تتحول approve بالافتراض. تصعيد الخطأ (503/500
//    على هذا الطلب فقط) مطابق تمامًا للسلوك الحالي في نفس القسم (1c
//    الأصلي مفيهوش try/catch حول db.order.findMany أصلًا)، فمفيش أي
//    تراجع في التوفر (availability) عن الوضع الحالي.
//
// 4. التنظيف الدوري: بره الـ transaction، بعد الـ commit (fire-and-forget)
//    — مش جواها. لو حطيناه جوه، القفل هيفضل ممسوك طول مدة الـ deleteMany
//    كمان، فأي طلب تاني لنفس IP هيستنى وقت أطول بلا داعي في كل مرة يشتغل
//    فيها التنظيف. تنفيذه بعد الـ commit بيحرر القفل فورًا.
//
// 5. storeId: مكتوبة دايمًا (attribution، زي Order.storeId's unconditional
//    write pattern)، لكن الفلترة في الاستعلام والقفل بتحترم storeScope
//    اللي بيبعتها المستدعي (نفس getStoreScope() المستخدمة في كل استعلام
//    تاني في risk.js) — {} لتجار pooled (تجميع عبر كل المتاجر)، أو
//    { storeId } لتجار per_store (عزل كامل). القفل بيتضمن نفس الفلترة دي
//    عشان يمنع تزامن على بالظبط نفس نطاق العدّ، مش أوسع أو أضيق منه.

const db = require('./db');
const logger = require('./logger');

// أقصى مدة مسموحة لكل الـ transaction (قفل + قراءة + كتابة) — أعلى من
// الـ default الضمني بتاع Prisma (5000ms) كهامش أمان موثّق صراحة، بدل
// الاعتماد على قيمة افتراضية ممكن تتغير مع أي ترقية مستقبلية لـ Prisma.
const TRANSACTION_TIMEOUT_MS = 6000;

// أقصى مدة انتظار داخل الـ transaction نفسها على القفل، قبل ما نستسلم
// ونرجّع خطأ واضح بدل ما نعلّق الطلب. أقل من TRANSACTION_TIMEOUT_MS بهامش
// كافي عشان باقي الاستعلامات (COUNT + findFirst + INSERT) تلحق تتنفذ.
const LOCK_TIMEOUT_MS = 2000;

// احتمالية تشغيل التنظيف الانتهازي في أي استدعاء — نفس نمط
// tenants/register's opportunistic RegistrationAttempt cleanup الموجود
// بالفعل في risk.js.
const CLEANUP_PROBABILITY = 0.02;

// هامش أمان سخي فوق أطول نافذة زمنية متوقعة لأي scope هيستخدم الجدول ده
// (حاليًا ip_rotation بس، نافذته ساعة واحدة). 24 ساعة كافية جدًا كسقف
// عام يغطي أي scope مستقبلي محتمل من غير ما نربط منطق التنظيف بقيمة
// نافذة scope واحد بعينه.
const CLEANUP_RETENTION_MS = 24 * 60 * 60 * 1000;

/**
 * فحص وحجز ذري لعدّاد أعضاء مميزين (distinct members) ضمن نافذة زمنية،
 * محمي بـ Postgres advisory lock — بديل TOCTOU-safe لنمط "اقرا ثم اكتب
 * لاحقًا" القديم.
 *
 * @param {object} params
 * @param {string} params.merchantId
 * @param {string|null} params.storeId - للـ attribution بس، بتتكتب دايمًا
 *   بغض النظر عن وضع العزل (زي Order.storeId).
 * @param {object} params.storeScope - {} أو { storeId } — نفس ناتج
 *   getStoreScope() بالظبط، بيتحدد بيه نطاق الفلترة والقفل.
 * @param {string} params.scope - مُعرّف آلية الكشف، مثلاً 'ip_rotation'.
 * @param {string} params.groupKey - القيمة اللي بيتحسب العدّ بالنسبة
 *   لها (مثلاً ipAddress).
 * @param {string|null} params.memberKey - القيمة المميزة اللي بتتعدّ
 *   (مثلاً deviceFingerprint)، أو null لو الطلب الحالي مالوش واحدة.
 * @param {boolean} params.isEligibleMember - بيتحدد من المستدعي: فيه
 *   memberKey فعلي ومش synthetic fallback ID.
 * @param {string} params.orderId - orderId التجاري، لحماية idempotency
 *   إضافية (دفاع في العمق، مش بديل عن القفل).
 * @param {number} params.windowMs - عرض النافذة الزمنية بالميلي ثانية.
 * @param {number} params.threshold - عتبة الحظر.
 *
 * @returns {Promise<{ blocked: boolean, count: number }>}
 *
 * ملاحظة حرجة: أي خطأ DB (فشل اتصال، ضرب lock_timeout، إلخ) بيتصعّد
 * (throw) — مفيش try/catch هنا عمدًا. راجع التعليق التوضيحي رقم 3 فوق.
 */
async function checkAndReserve({
  merchantId,
  storeId = null,
  storeScope = {},
  scope,
  groupKey,
  memberKey = null,
  isEligibleMember = false,
  orderId,
  windowMs,
  threshold,
}) {
  if (!merchantId || !scope || !groupKey) {
    return { blocked: false, count: 0 };
  }

  const windowStart = new Date(Date.now() - windowMs);

  // مفتاح القفل بيعكس بالظبط نفس نطاق الفلترة المستخدم في الاستعلامات
  // تحت — طلبين لنفس (merchantId, scope, storeId-إن-وُجد, groupKey)
  // بيتسلسلوا لحظيًا؛ أي مفتاح مختلف (IP مختلف، أو store مختلف لتاجر
  // per_store) مبيستناش على الإطلاق.
  const lockKeyA = `${merchantId}:${scope}:${storeScope.storeId ?? ''}`;
  const lockKeyB = groupKey;

  return db.$transaction(async (tx) => {
    // قيمة ثابتة مكتوبة في الكود (مش user input) — $executeRawUnsafe آمن
    // هنا لأن مفيش أي جزء من القيمة جاي من خارج هذا الملف.
    await tx.$executeRawUnsafe(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT_MS}ms'`);

    // القيم الديناميكية (lockKeyA, lockKeyB) بتتمرر عبر tagged template —
    // Prisma بيحوّلها لـ prepared statement parameters تلقائيًا، آمن من
    // SQL injection حتى لو أي جزء منها جاي أصلًا من مدخلات المستخدم
    // (زي ipAddress في groupKey).
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${lockKeyA}), hashtext(${lockKeyB}))`;

    const baseWhere = {
      merchantId,
      ...storeScope,
      scope,
      groupKey,
      seenAt: { gte: windowStart },
    };

    // هل الـ member ده (لو مؤهل) شفناه بالفعل خلال النافذة، ولا جديد
    // كليًا؟ الفحص ده لازم يحصل جوه الـ transaction نفسها (بعد القفل)،
    // لأنه بيعتمد على حالة الجدول لحظة الفحص، مش حاجة يحسبها المستدعي
    // مقدمًا.
    let isNewMember = false;
    if (isEligibleMember) {
      const existingMemberRow = await tx.identitySighting.findFirst({
        where: { ...baseWhere, memberKey },
        select: { id: true },
      });
      isNewMember = !existingMemberRow;
    }

    const currentCount = await tx.identitySighting.count({ where: baseWhere });
    const projectedCount = currentCount + (isEligibleMember && isNewMember ? 1 : 0);
    const blocked = projectedCount >= threshold;

    // نضيف صف جديد بس لو: (أ) مش هنحظر، و(ب) فيه member مؤهل فعلًا، و(ج)
    // هو جديد فعلًا. لو الحظر سببه العدد القديم بس (تفصيلة موثّقة من
    // النقاش الأصلي)، مفيش داعي نلوّث الجدول بصف من غير fingerprint حقيقي
    // جديد.
    if (!blocked && isEligibleMember && isNewMember) {
      try {
        await tx.identitySighting.create({
          data: {
            merchantId,
            storeId: storeId ?? null,
            scope,
            groupKey,
            memberKey,
            orderId,
          },
        });
      } catch (createErr) {
        // P2002 = خرق الـ @@unique([merchantId, scope, orderId]) — نفس
        // الطلب اتفحص مرتين (retry غير ملحوظ من idempotency check، أو
        // خطأ برمجي مستقبلي). العدّ فوق بالفعل صحيح بغض النظر — تجاهل
        // هذا الخطأ تحديدًا بس، وأي خطأ تاني يتصعّد عادي.
        if (createErr.code !== 'P2002') throw createErr;
      }
    }

    return { blocked, count: projectedCount };
  }, {
    timeout: TRANSACTION_TIMEOUT_MS,
  });
}

/**
 * تنظيف انتهازي — بيتنادى بعد الـ commit (fire-and-forget)، مش جوه أي
 * transaction. باحتمالية صغيرة (~2%) في كل استدعاء، بيمسح الصفوف الأقدم
 * من هامش الأمان المحدد فوق. المستدعي (risk.js) بينادي عليها بعد ما
 * checkAndReserve() ترجع، من غير await (نفس نمط notifyBINSequenceAlert
 * الموجود بالفعل في الملف).
 */
function maybeCleanupOldSightings() {
  if (Math.random() >= CLEANUP_PROBABILITY) return;

  const cutoff = new Date(Date.now() - CLEANUP_RETENTION_MS);
  db.identitySighting
    .deleteMany({ where: { seenAt: { lt: cutoff } } })
    .catch((err) => {
      logger.error(
        { module: 'atomicIdentityGate', err: err.message },
        'Opportunistic IdentitySighting cleanup failed'
      );
    });
}

module.exports = { checkAndReserve, maybeCleanupOldSightings };