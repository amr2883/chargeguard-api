'use strict';

// Shared v3 request signer for tests. Mirrors src/middleware/verifyHmac.js.
// buildSignedString is the ONLY place that knows the signed-string format.
// `method` and `target` are accepted now but deliberately unused: the current
// v3 format does not bind them (#78). The binding commit changes one line below.

const crypto = require('crypto');

function buildSignedString({ timestamp, domain, requestId, method, target, body }) {
  return `${timestamp}.${domain}.${requestId}.${body}`;
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