'use strict';

const dns = require('dns').promises;
const net = require('net');
const db = require('./db');

// Mirrors the SSRF-defense rationale already used for webhookResolvedIp
// (see prisma/schema.prisma comment on that field) — a merchant-supplied
// storeUrl is the same untrusted-URL shape as a merchant-supplied
// webhookUrl, so it gets the same DNS-resolution + private-range check
// before the backend ever makes an outbound request to it.
const isPrivateOrReservedIp = (ip) => {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127 ||
      (parts[0] === 169 && parts[1] === 254) ||
      parts[0] === 0
    );
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
  }
  return true; // unrecognized format — fail closed
};

const REQUEST_TIMEOUT_MS = 5000;

/**
 * Fetches the merchant's allow-listed plugin config via the plugin's
 * own REST route, with the same SSRF discipline used elsewhere in this
 * codebase for merchant-supplied URLs.
 *
 * @param {string} tenantId
 * @returns {Promise<{success:boolean, code:string, settings?:object, message?:string}>}
 */
async function fetchRemoteConfig(tenantId) {
  const tenant = await db.tenant.findUnique({
    where: { id: tenantId },
    select: { id: true, storeUrl: true, remoteConfigKey: true },
  });
  if (!tenant) return { success: false, code: 'TENANT_NOT_FOUND', message: 'Tenant not found' };
  if (!tenant.remoteConfigKey) {
    return { success: false, code: 'NO_CONFIG_KEY', message: 'No remote config key set for this tenant — use "Set Config Key" first' };
  }
  if (!tenant.storeUrl) {
    return { success: false, code: 'NO_STORE_URL', message: 'Tenant has no storeUrl on file' };
  }

  let target;
  try {
    target = new URL('/wp-json/chargeguard/v1/admin/settings', tenant.storeUrl);
  } catch {
    return { success: false, code: 'INVALID_STORE_URL', message: 'storeUrl is not a valid URL' };
  }
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return { success: false, code: 'INVALID_STORE_URL', message: 'storeUrl must be http(s)' };
  }

  // DNS-resolve and reject private/loopback/link-local targets — closes
  // the SSRF path a raw fetch(tenant.storeUrl) would otherwise open.
  try {
    const addresses = await dns.lookup(target.hostname, { all: true });
    if (addresses.some(a => isPrivateOrReservedIp(a.address))) {
      return { success: false, code: 'BLOCKED_TARGET', message: 'storeUrl resolves to a private/reserved address — refusing to fetch' };
    }
  } catch {
    return { success: false, code: 'DNS_RESOLUTION_FAILED', message: 'Could not resolve storeUrl hostname' };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(target.toString(), {
      method: 'GET',
      redirect: 'manual', // no following redirects to an unvalidated location
      headers: { Authorization: `Bearer ${tenant.remoteConfigKey}` },
      signal: controller.signal,
    });

    if (res.status === 401 || res.status === 403) {
      return { success: false, code: 'AUTH_REJECTED', message: 'Merchant site rejected the config key — it may have been regenerated' };
    }
    if (!res.ok) {
      return { success: false, code: 'SITE_ERROR', message: `Merchant site returned HTTP ${res.status}` };
    }

    const body = await res.json();
    if (!body || typeof body !== 'object' || !body.settings) {
      return { success: false, code: 'INVALID_RESPONSE', message: 'Unexpected response shape from plugin endpoint' };
    }

    return {
      success: true,
      code: 'FETCHED',
      settings: body.settings,
      pluginVersion: body.pluginVersion ?? null,
      fetchedAt: new Date().toISOString(),
    };
  } catch (err) {
    const code = err.name === 'AbortError' ? 'TIMEOUT' : 'SITE_UNREACHABLE';
    return { success: false, code, message: `Could not reach merchant site: ${err.message}` };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Stores/updates the admin-entered remote config key. Deliberately no
 * validation beyond non-empty — the value is opaque from the backend's
 * perspective (it's the plugin, not this function, that decides whether
 * it's correct, via hash_equals on the next fetch attempt).
 */
async function setRemoteConfigKey(tenantId, key) {
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true } });
  if (!tenant) return { success: false, code: 'TENANT_NOT_FOUND', message: 'Tenant not found' };
  if (!key || typeof key !== 'string' || !key.trim()) {
    return { success: false, code: 'INVALID_KEY', message: 'A non-empty key is required' };
  }

  await db.tenant.update({ where: { id: tenantId }, data: { remoteConfigKey: key.trim() } });
  return { success: true, code: 'KEY_SET', message: 'Remote config key saved' };
}

module.exports = { fetchRemoteConfig, setRemoteConfigKey };