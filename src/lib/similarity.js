// ─── ChargeGuard Similarity Engine ───────────────────────────────────────
// Detects fuzzy identity mutations — catches attackers who change data slightly
//
// Covers:
// 1. Email similarity (Levenshtein distance)
// 2. Address similarity (Jaccard token similarity)
// 3. IP subnet proximity (/24 subnet check)
//
// Design principles:
// - Conservative thresholds (avoid false positives)
// - Fast — no external calls
// - Used to augment exact matching, not replace it

const { normalizeIP } = require('./ipIntelligence');
const { maskValue, normalizeEmail } = require('./utils');
const logger = require('./logger');

// ─── Levenshtein Distance ─────────────────────────────────────────────────
// Classic edit distance algorithm
// Returns number of single-character edits needed to transform a → b

function levenshtein(a, b) {
  // Equality first — fastest path, handles ("", "") correctly.
  if (a === b) return 0;
  // Null/undefined — treat as empty string for distance calculation.
  if (a == null) return (b ?? "").length;
  if (b == null) return a.length;
  // One side is empty string — distance = length of the other.
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const m = a.length;
  const n = b.length;

  // Use single array for memory efficiency
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1]);
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

// ─── Email Normalization ──────────────────────────────────────────────────
// [Bug #7 fix] normalizeEmail() (بما فيها الـ homoglyph map) اتنقلت لـ
// utils.js عشان تبقى المصدر الوحيد للحقيقة — مستوردة فوق في require().
// كل الدوال تحت (areEmailsSimilar, findSimilarDisputes) بتستخدمها زي ما هي.

// ─── Email Similarity ─────────────────────────────────────────────────────
// Checks if two emails are suspiciously similar
// Conservative: distance = 1 only (one character change)
//
// maxDistance = 1 متعمد — في Fraud engine الـ false positive أخطر من false negative
//
// Examples:
// ahmed@gmail.com  → ahmed@gmail.com  (after normalization) = exact match → false
// ahmed@gmail.com  → ahme d@gmail.com = similar ✓
// ahmed@gmail.com  → ahm3d@gmail.com  = similar ✓
// ahmed@gmail.com  → john@gmail.com   = different ✗

function areEmailsSimilar(email1, email2, maxDistance = 1) {
  if (!email1 || !email2) return false;

  // Normalize أولاً — يشمل NFKC + domain canonicalization + dots/plus
  const e1 = normalizeEmail(email1);
  const e2 = normalizeEmail(email2);

  if (!e1 || !e2) return false;

  // بعد الـ normalization لو بقوا identical → exact match مش similarity
  if (e1 === e2) return false;

  // Destructure once — avoids four split("@") calls on the same strings.
  // Safe to use split("@") here — e1/e2 come from normalizeEmail which always
  // returns a clean "local@domain" format with exactly one "@".
  const [local1, domain1] = e1.split("@");
  const [local2, domain2] = e2.split("@");
  if (!domain1 || !domain2 || domain1 !== domain2) return false;

  // Skip if too different in length (likely different people)
  if (Math.abs(local1.length - local2.length) > maxDistance) return false;

  const distance = levenshtein(local1, local2);
  return distance > 0 && distance <= maxDistance;
}

// ─── Address Similarity ───────────────────────────────────────────────────
// Jaccard similarity on address tokens
// Returns 0.0 → 1.0 (1.0 = identical)
//
// Examples:
// "123 Main St Cairo"  vs "123 Main Street Cairo"  → 0.75 (similar)
// "123 Main St Cairo"  vs "456 Other Rd Alex"       → 0.10 (different)

// Abbreviation normalization — يحوّل كل أشكال اسم نوع الشارع لنسخة قصيرة
// ثم STREET_STOPWORDS تحذفها كلها → "street" و "strt" يصبحان identical tokens
const STREET_ABBREV = {
  "street":    "st",
  "strt":      "st",
  "road":      "rd",
  "avenue":    "ave",
  "boulevard": "blvd",
  "lane":      "ln",
  "drive":     "dr",
  "court":     "ct",
  "place":     "pl",
  "square":    "sq",
};

// موسَّعة عن النسخة السابقة ["st","str","rd","ave","blvd","ln"]
const STREET_STOPWORDS = new Set(["st", "str", "rd", "ave", "blvd", "ln", "dr", "ct", "pl", "sq"]);

function addressSimilarity(addr1, addr2) {
  if (!addr1 || !addr2) return 0;

  // Tokenize and normalize
  // [FIX] Unicode-aware regex — يحفظ العربية والفرنسية وكل أحرف Unicode
  // /[^a-z0-9\s]/g كانت تحذف "شارع النيل" بالكامل → tokens فارغة
  const tokenize = (addr) => {
    return addr
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s]/gu, " ")
      .split(/\s+/)
      .filter(t => t.length > 0)
      .map(t => STREET_ABBREV[t] ?? t)
      .filter(t => !STREET_STOPWORDS.has(t));
  };

  const tokens1 = tokenize(addr1);
  const tokens2 = tokenize(addr2);

  if (tokens1.length === 0 || tokens2.length === 0) return 0;

  // الأرقام (street numbers) أهم من الكلمات العادية في العناوين
  // لو الـ street number مختلف → penalty قوية على الـ similarity
  const nums1 = tokens1.filter(t => /^\d+$/.test(t));
  const nums2 = tokens2.filter(t => /^\d+$/.test(t));
  const numberMismatch = nums1.length > 0 && nums2.length > 0 &&
    !nums1.some(n => nums2.includes(n));

  // Jaccard على كل الـ tokens
  const set1 = new Set(tokens1);
  const set2 = new Set(tokens2);
  const intersection = new Set([...set1].filter(t => set2.has(t)));
  const union = new Set([...set1, ...set2]);
  const jaccard = intersection.size / union.size;

  // لو الأرقام مختلفة → خفّض الـ score بشكل ملحوظ
  return numberMismatch ? jaccard * 0.5 : jaccard;
}

function areAddressesSimilar(addr1, addr2, threshold = 0.80) {
  if (!addr1 || !addr2) return false;
  if (addr1 === addr2) return false;
  return addressSimilarity(addr1, addr2) >= threshold;
}

// ─── IP Subnet Proximity ──────────────────────────────────────────────────
// Checks if two IPs are in the same /24 subnet
// يعني أول 3 أجزاء متطابقة: 192.168.1.x
//
// لماذا /24؟
// - /24 = 256 عنوان في نفس الـ network
// - المحتال ممكن يغير آخر رقم بس
// - Residential networks غالباً /24

// [FIX #4] Private/reserved IP ranges — RFC 1918 + loopback + link-local + CGNAT
// هذه العناوين لا تمثل هوية حقيقية للمستخدم وتسبب false positives
// في test environments و office networks وشبكات الـ mobile ISP
const PRIVATE_IP_PREFIXES = [
  /^10\./,                              // 10.0.0.0/8
  /^172\.(1[6-9]|2\d|3[01])\./,        // 172.16.0.0/12
  /^192\.168\./,                        // 192.168.0.0/16
  /^127\./,                             // 127.0.0.0/8  loopback
  /^169\.254\./,                        // 169.254.0.0/16 link-local (APIPA)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 CGNAT (RFC 6598) — mobile ISPs
  /^::1$/,                              // IPv6 loopback
];

function isPrivateIP(ip) {
  return PRIVATE_IP_PREFIXES.some(re => re.test(ip));
}

function areSameSubnet(ip1, ip2) {
  if (!ip1 || !ip2) return false;

  // Normalize first — handles ::ffff:x.x.x.x, bracketed IPv6, IP:port formats.
  // Must come before isPrivateIP — unnormalized IPs can bypass private range checks.
  const n1 = normalizeIP(ip1);
  const n2 = normalizeIP(ip2);

  if (!n1 || !n2) return false;
  if (n1 === n2) return false;

  // [FIX #4] تجاهل Private/reserved IPs — لا تمثل identity حقيقية
  if (isPrivateIP(n1) || isPrivateIP(n2)) return false;

  // IPv4 only
  const parts1 = n1.split(".");
  const parts2 = n2.split(".");

  if (parts1.length !== 4 || parts2.length !== 4) return false;

  // Validate each octet is a real number (0-255)
  const isValidOctet = (p) => /^\d{1,3}$/.test(p) && Number(p) <= 255;
  if (!parts1.every(isValidOctet) || !parts2.every(isValidOctet)) return false;

  // Compare first 3 octets (/24 subnet)
  return parts1[0] === parts2[0] &&
         parts1[1] === parts2[1] &&
         parts1[2] === parts2[2];
}

// ─── Bulk Similarity Check ────────────────────────────────────────────────
// بيشيك على مجموعة orders ويرجع الـ similar ones
// Used in riskScoring to find fuzzy matches in disputes/orders

// كام dispute نشيك عليهم كحد أقصى — يمنع event loop blocking
const MAX_DISPUTES_TO_SCAN = 200;

// ─── Address String Builder ───────────────────────────────────────────────
// [FIX #6] أضفنا street/line1 للمقارنة
// قرار: وزن العنوان كاملًا أقوى من city+zip فقط
// المحتال لو غير رقم الشقة أو اسم الشارع بس — نمسكه دلوقتي

function buildAddressString(parsed) {
  // الأولوية: street line أولاً (أكثر uniqueness)، ثم city/zip/country
  const parts = [
    parsed.street ?? parsed.line1 ?? parsed.address1,
    parsed.city,
    parsed.zip ?? parsed.postalCode ?? parsed.postal_code,
    parsed.country,
  ];
  return parts.filter(Boolean).join(" ");
}

function findSimilarDisputes(currentEmail, currentIP, currentAddress, disputes) {
  logger.debug({ module: 'similarity', email: maskValue('EMAIL', currentEmail), ip: maskValue('IP', currentIP), disputesCount: disputes.length }, 'findSimilarDisputes called');
  const results = {
    similarEmail: [],
    similarIP:    [],
    similarAddr:  [],
  };

  // Normalize currentIP once — areSameSubnet normalizes DB IPs per iteration,
  // normalizing here ensures consistency if currentIP is used elsewhere in future.
  const normalizedCurrentIP = normalizeIP(currentIP);

  // Pre-parse الـ current address مرة واحدة بره الـ loop
  let currentAddrStr = null;
  if (currentAddress) {
    try {
      const parsed = JSON.parse(currentAddress);
      // [FIX #6] استخدام buildAddressString بدلًا من city+zip+country فقط
      currentAddrStr = buildAddressString(parsed);
    } catch { /* skip malformed */ }
  }

  // [FIX #3] Sort by createdAt descending قبل الـ slice
  // يضمن إننا بنفحص أحدث 200 dispute وليس random 200
  // Schwartzian transform — compute timestamp once per dispute, not once per comparison.
  // Without this, sort comparator calls new Date() O(n log n) times instead of O(n).
  const disputesToScan = disputes
    .map(d => ({ d, t: d.createdAt ? new Date(d.createdAt).getTime() : 0 }))
    .sort((a, b) => b.t - a.t)
    .slice(0, MAX_DISPUTES_TO_SCAN)
    .map(({ d }) => d);

  for (const dispute of disputesToScan) {
    const order = dispute.order;
    if (!order) continue;

    // Email similarity
    if (order.email && areEmailsSimilar(currentEmail, order.email)) {
      results.similarEmail.push(dispute);
    }

    // IP subnet
    if (order.ipAddress && areSameSubnet(normalizedCurrentIP, order.ipAddress)) {
      results.similarIP.push(dispute);
    }

    // Address similarity — pre-parsed currentAddrStr بدل JSON.parse في كل iteration
    if (order.shippingAddress && currentAddrStr) {
      try {
        const addr1 = JSON.parse(order.shippingAddress);
        // [FIX #6] نفس الـ builder للـ consistency
        const addrStr1 = buildAddressString(addr1);
        if (addrStr1 && areAddressesSimilar(addrStr1, currentAddrStr)) {
          results.similarAddr.push(dispute);
        }
      } catch { /* skip malformed */ }
    }
  }

  return results;
}
module.exports = {
  normalizeEmail,
  areEmailsSimilar,
  addressSimilarity,
  areAddressesSimilar,
  areSameSubnet,
  findSimilarDisputes,
};