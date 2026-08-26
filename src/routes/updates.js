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

// Free-tier Render web services cannot attach a persistent Disk at all
// (no shell access, no one-off jobs, no Disks — see Render's free-tier
// docs), so release ZIPs are hosted externally (currently: GitHub
// Releases) and release.s3Key stores the full https:// download URL
// rather than a relative on-disk filename. RELEASES_DIR stays optional
// and only powers the legacy local-disk path below, for if this service
// is ever upgraded to a paid instance with a Disk attached.
const RELEASES_DIR = process.env.RELEASES_DIR || null;

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

    logger.info({ module: 'updates', endpoint: 'download', tenantId, version: release.version }, 'Plugin ZIP downloaded');

    // release.s3Key is an absolute https:// URL when the ZIP is hosted
    // externally (currently GitHub Releases) — the only delivery path
    // that works on a free-tier Render instance with no persistent Disk.
    // The signed, single-use token already validated above is what gates
    // who receives this URL; the redirect itself carries no further
    // secret, since the GitHub release asset is public regardless.
    if (/^https?:\/\//i.test(release.s3Key)) {
      res.setHeader('Cache-Control', 'no-store');
      return res.redirect(302, release.s3Key);
    }

    // Legacy local-disk delivery path — only reachable if this service is
    // ever upgraded to a paid Render instance with RELEASES_DIR pointed
    // at an attached persistent Disk.
    if (!RELEASES_DIR) {
      logger.error({ module: 'updates', endpoint: 'download', releaseId }, 'Release s3Key is a relative path but RELEASES_DIR is not configured');
      return res.status(500).json({ error: 'Internal server error' });
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