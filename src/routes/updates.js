const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const router = express.Router();
const logger = require('../lib/logger');
const db = require('../lib/db');
const { resolveTenantByApiKey } = require('../lib/apiKeyAuth');

const UPDATE_DOWNLOAD_SECRET = process.env.UPDATE_DOWNLOAD_SECRET;
if (!UPDATE_DOWNLOAD_SECRET) {
  throw new Error('[updates] UPDATE_DOWNLOAD_SECRET environment variable is required');
}

// Must point at a Render Disk mount (persistent volume), NOT the service's
// default ephemeral filesystem — anything written outside a mounted Disk
// is wiped on every deploy/restart. Configure in Render dashboard:
// Settings → Disks → Add Disk → mount path e.g. /var/data/releases, then
// set RELEASES_DIR=/var/data/releases as an env var on this service.
const RELEASES_DIR = process.env.RELEASES_DIR;
if (!RELEASES_DIR) {
  throw new Error('[updates] RELEASES_DIR environment variable is required (must point at a mounted Render Disk)');
}

const TOKEN_TTL_MS = 2 * 60 * 1000;

function signDownloadPayload(releaseId, tenantId, jti, exp) {
  const signedString = `${releaseId}.${tenantId}.${jti}.${exp}`;
  return crypto.createHmac('sha256', UPDATE_DOWNLOAD_SECRET).update(signedString).digest('hex');
}

router.get('/info', async (req, res) => {
  try {
    const apiKey = req.query.key;
    const channel = req.query.channel === 'beta' ? 'beta' : 'stable';

    if (!apiKey) {
      return res.status(400).json({ error: 'Missing key parameter' });
    }

    const { tenant } = await resolveTenantByApiKey(apiKey, {
      id: true, isActive: true, emailVerified: true, plan: true, subscriptionStatus: true,
    });

    if (!tenant || !tenant.isActive) {
      return res.status(401).json({ error: 'Invalid or inactive API key' });
    }

    if (!tenant.emailVerified && process.env.EMAIL_VERIFICATION_DISABLED !== 'true') {
      return res.status(403).json({ error: 'Email not verified' });
    }

    const release = await db.pluginRelease.findFirst({
      where: { channel, isActive: true },
      orderBy: { createdAt: 'desc' },
    });

    if (!release) {
      return res.status(404).json({ error: 'No release available' });
    }

    const jti = crypto.randomBytes(16).toString('hex');
    const exp = Date.now() + TOKEN_TTL_MS;

    await db.updateDownloadToken.create({
      data: { jti, releaseId: release.id, tenantId: tenant.id, expiresAt: new Date(exp) },
    });

    const signature = signDownloadPayload(release.id, tenant.id, jti, exp);
    const token = Buffer.from(JSON.stringify({ releaseId: release.id, tenantId: tenant.id, jti, exp, sig: signature })).toString('base64url');

    const baseUrl = process.env.RENDER_EXTERNAL_URL || 'https://chargeguard-api.onrender.com';

    return res.status(200).json({
      name: 'ChargeGuard for WooCommerce',
      version: release.version,
      download_url: `${baseUrl}/api/updates/download?token=${token}`,
      requires: release.minWpVersion || undefined,
      tested: release.testedWpVersion || undefined,
      requires_php: release.minPhpVersion || undefined,
      sections: {
        changelog: release.changelog || 'No changelog provided.',
      },
      checksum_sha256: release.checksumSha256,
    });
  } catch (error) {
    logger.error({ module: 'updates', endpoint: 'info', error: error.message }, 'updates/info error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/download', async (req, res) => {
  try {
    const raw = req.query.token;
    if (!raw) return res.status(400).json({ error: 'Missing token' });

    let payload;
    try {
      payload = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'Malformed token' });
    }

    const { releaseId, tenantId, jti, exp, sig } = payload;
    if (!releaseId || !tenantId || !jti || !exp || !sig) {
      return res.status(400).json({ error: 'Malformed token' });
    }

    const expected = signDownloadPayload(releaseId, tenantId, jti, exp);
    const sigBuf = Buffer.from(sig, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    if (Date.now() > exp) {
      return res.status(401).json({ error: 'Token expired' });
    }

    const claim = await db.updateDownloadToken.updateMany({
      where: { jti, usedAt: null, expiresAt: { gt: new Date() } },
      data: { usedAt: new Date() },
    });
    if (claim.count === 0) {
      return res.status(401).json({ error: 'Token already used or expired' });
    }

    const release = await db.pluginRelease.findUnique({ where: { id: releaseId } });
    if (!release || !release.isActive) {
      return res.status(404).json({ error: 'Release not found or has been pulled' });
    }

    // release.s3Key is treated as a relative filename under RELEASES_DIR —
    // resolve and verify it stays inside that directory before opening,
    // so a corrupted/tampered DB row (e.g. "../../etc/passwd") can never
    // be used to read a file outside the releases folder (path traversal).
    const resolvedPath = path.resolve(RELEASES_DIR, release.s3Key);
    if (!resolvedPath.startsWith(path.resolve(RELEASES_DIR) + path.sep)) {
      logger.error({ module: 'updates', endpoint: 'download', releaseId, s3Key: release.s3Key }, 'Rejected path outside RELEASES_DIR');
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!fs.existsSync(resolvedPath)) {
      logger.error({ module: 'updates', endpoint: 'download', releaseId, resolvedPath }, 'Release row exists but file is missing on disk');
      return res.status(404).json({ error: 'Release file not found' });
    }

    logger.info({ module: 'updates', endpoint: 'download', tenantId, version: release.version }, 'Plugin ZIP downloaded');

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="chargeguard-woocommerce-${release.version}.zip"`);
    res.setHeader('Cache-Control', 'no-store');
    fs.createReadStream(resolvedPath).pipe(res);
  } catch (error) {
    logger.error({ module: 'updates', endpoint: 'download', error: error.message }, 'updates/download error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;