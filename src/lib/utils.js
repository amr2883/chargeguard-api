// src/lib/utils.js
const crypto = require('crypto');

function normalizeEmail(email) {
  if (!email || typeof email !== 'string') return '';
  let normalized = email.normalize('NFKC').toLowerCase().trim();
  const atIndex = normalized.lastIndexOf('@');
  if (atIndex === -1) return normalized;
  let local = normalized.slice(0, atIndex);
  const domain = normalized.slice(atIndex + 1);
  
  // إزالة الـ plus tag
  local = local.split('+')[0];
  
  // تحويل googlemail.com إلى gmail.com
  const canonicalDomain = domain === 'googlemail.com' ? 'gmail.com' : domain;
  
  // إزالة النقاط من الـ local فقط إذا كان النطاق gmail.com
  if (canonicalDomain === 'gmail.com') {
    local = local.replace(/\./g, '');
  }
  
  return local + '@' + canonicalDomain;
}

function hashValue(type, value) {
  const normalized = normalizeValue(type, value);
  if (!normalized) return null;
  const secret = process.env.IDENTITY_GRAPH_SECRET;
  if (!secret) {
    throw new Error('[utils] IDENTITY_GRAPH_SECRET environment variable is required');
  }
  return crypto.createHmac('sha256', secret).update(`${type}:${normalized}`).digest('hex');
}

function normalizeValue(type, value) {
  if (!value) return '';
  switch (type) {
    case 'EMAIL': {
      const lower = value.normalize('NFKC').toLowerCase().trim();
      const [local, domain] = lower.split('@');
      if (!domain) return lower;
      const cleanLocal = local.split('+')[0];
      const gmailDomains = ['gmail.com', 'googlemail.com'];
      const finalLocal = gmailDomains.includes(domain) ? cleanLocal.replace(/\./g, '') : cleanLocal;
      return `${finalLocal}@${domain === 'googlemail.com' ? 'gmail.com' : domain}`;
    }
    case 'IP': return value.trim();
    case 'DEVICE':
    case 'FINGERPRINT': return value.trim();
    case 'ADDRESS': return value.normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
    default: return value.trim();
  }
}

function maskValue(type, value) {
  if (!value) return null;
  switch (type) {
    case 'EMAIL': {
      const [local, domain] = value.split('@');
      if (!domain) return value;
      const masked = local.length <= 2 ? local[0] + '***' : local.slice(0, 2) + '***';
      return `${masked}@${domain}`;
    }
    case 'IP': {
      const parts = value.split('.');
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
      return value.slice(0, 6) + '***';
    }
    case 'DEVICE':
    case 'FINGERPRINT': return value.slice(0, 8) + '***';
    case 'ADDRESS': {
      const words = value.split(' ');
      return words.slice(0, 2).join(' ') + '***';
    }
    default: return value.slice(0, 4) + '***';
  }
}

function maskDeviceId(deviceId) {
  if (!deviceId) return null;
  return deviceId.slice(0, 8) + '***';
}

module.exports = { normalizeEmail, hashValue, normalizeValue, maskValue, maskDeviceId };