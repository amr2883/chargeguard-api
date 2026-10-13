'use strict';

// Shared v3 request signer for tests. Mirrors src/middleware/verifyHmac.js.
// buildSignedString is the ONLY place that knows the signed-string format.
// Signed string (#78): timestamp.domain.requestId.METHOD.path, then a newline, then the body.
// `target` is the path as the server sees it (req.originalUrl before any '?').

const crypto = require('crypto');

function buildSignedString({ timestamp, domain, requestId, method, target, body }) {
  if (typeof method !== 'string' || !/^[A-Z]+$/.test(method)) {
    throw new Error('signV3: method must be an uppercase HTTP method, got ' + String(method));
  }
  if (typeof target !== 'string' || target.charAt(0) !== '/' || target.indexOf('?') !== -1) {
    throw new Error('signV3: target must be a path starting with / and without a query, got ' + String(target));
  }
  return `${timestamp}.${domain}.${requestId}.${method}.${target}\n${body}`;
}

function signV3({ secret, domain, requestId, method, target, body = '', timestamp, ageSec = 0 }) {
  const rid = requestId === undefined ? crypto.randomUUID() : requestId;
  const ts = timestamp === undefined
    ? String(Math.floor(Date.now() / 1000) - ageSec)
    : String(timestamp);
  const signedStr = buildSignedString({ timestamp: ts, domain, requestId: rid, method, target, body });
  const signature = 'v3=' + crypto.createHmac('sha256', secret).update(signedStr).digest('hex');
  return {
    'x-store-domain': domain,
    'x-chargeguard-signature': signature,
    'x-chargeguard-timestamp': ts,
    'x-chargeguard-request-id': rid,
  };
}

module.exports = { signV3, buildSignedString };