'use strict';

// Test-only stand-in for Cloudflare Turnstile's siteverify endpoint.
//
// Why: six suites POST to /register or /connect, and each one used to hit
// Cloudflare for real. A transient ETIMEDOUT there surfaces as a 503 from the
// app (fail-closed) and fails an unrelated test (seen once in dev-mode.test.js).
//
// How: the answer is derived from the `secret` in the request body, exactly
// like Cloudflare's published dummy secrets, so tests that swap
// process.env.TURNSTILE_SECRET_KEY at request time keep working:
//   secret starts with "1x" -> success: true
//   secret starts with "2x" -> success: false (invalid-input-response)
//   anything else           -> success: false (invalid-input-secret)
// Every other URL is passed through to the real fetch untouched.
//
// This does NOT prove Cloudflare itself behaves this way. Set TURNSTILE_REAL=1
// to disable the mock and run against the real endpoint.

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

if (!process.env.TURNSTILE_REAL && typeof globalThis.fetch === 'function' && !globalThis.fetch.__turnstileMock) {
  const realFetch = globalThis.fetch;

  const urlOf = (input) => {
    if (typeof input === 'string') return input;
    if (input && typeof input.url === 'string') return input.url;
    if (input && typeof input.href === 'string') return input.href;
    return String(input);
  };

  const mockedFetch = async function mockedFetch(input, init) {
    if (!urlOf(input).startsWith(SITEVERIFY)) return realFetch(input, init);

    let params;
    try {
      params = new URLSearchParams(init && init.body);
    } catch (_e) {
      return realFetch(input, init);
    }

    const secret = params.get('secret') || '';
    let body;
    if (secret.startsWith('1x')) {
      body = { success: true, 'error-codes': [], challenge_ts: new Date().toISOString(), hostname: 'example.com' };
    } else if (secret.startsWith('2x')) {
      body = { success: false, 'error-codes': ['invalid-input-response'] };
    } else {
      body = { success: false, 'error-codes': ['invalid-input-secret'] };
    }

    const text = JSON.stringify(body);
    if (typeof Response === 'function') {
      return new Response(text, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return { ok: true, status: 200, json: async () => body, text: async () => text };
  };

  mockedFetch.__turnstileMock = true;
  globalThis.fetch = mockedFetch;
}