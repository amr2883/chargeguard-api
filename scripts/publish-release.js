#!/usr/bin/env node
/**
 * Usage: node scripts/publish-release.js <version> <channel> <checksum> <s3Key> ["changelog text"]
 * Example:
 *   node scripts/publish-release.js 1.2.0 stable abc123...def releases/chargeguard-woocommerce-1.2.0.zip "Fixed webhook retry bug"
 *
 * Inserts (or updates) the PluginRelease row that /api/updates/info reads
 * from. Run this only AFTER the ZIP referenced by <s3Key> has actually been
 * uploaded to the bucket named in RELEASES_S3_BUCKET — this script does not
 * upload anything itself, it only registers metadata.
 */

require('dotenv').config();
const db = require('../src/lib/db');

async function main() {
  const [, , version, channel, checksum, s3Key, changelog] = process.argv;

  if (!version || !channel || !checksum || !s3Key) {
    console.error('Usage: node scripts/publish-release.js <version> <channel> <checksum> <s3Key> ["changelog"]');
    process.exit(1);
  }

  if (!['stable', 'beta'].includes(channel)) {
    console.error(`Error: channel must be "stable" or "beta", got "${channel}"`);
    process.exit(1);
  }

  if (!/^[0-9a-f]{64}$/i.test(checksum)) {
    console.error('Error: checksum must be a 64-character hex SHA-256 digest.');
    process.exit(1);
  }

  const release = await db.pluginRelease.upsert({
    where: { version_channel: { version, channel } },
    create: {
      version,
      channel,
      s3Key,
      checksumSha256: checksum.toLowerCase(),
      changelog: changelog || null,
      isActive: true,
    },
    update: {
      s3Key,
      checksumSha256: checksum.toLowerCase(),
      changelog: changelog || null,
      isActive: true,
    },
  });

  console.log(`Published release: ${release.version} (${release.channel})`);
  console.log(`  id:       ${release.id}`);
  console.log(`  s3Key:    ${release.s3Key}`);
  console.log(`  checksum: ${release.checksumSha256}`);
}

main()
  .catch((err) => {
    console.error('Failed to publish release:', err.message);
    process.exit(1);
  })
  .finally(() => process.exit());