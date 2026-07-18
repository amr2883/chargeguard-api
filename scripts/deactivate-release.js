#!/usr/bin/env node
/**
 * Usage: node scripts/deactivate-release.js <version> <channel>
 * Example: node scripts/deactivate-release.js 1.2.0 stable
 *
 * Pulls a bad release: sites polling /api/updates/info will fall back to
 * the next most recent isActive:true release on the same channel.
 */

require('dotenv').config();
const db = require('../src/lib/db');

async function main() {
  const [, , version, channel] = process.argv;

  if (!version || !channel) {
    console.error('Usage: node scripts/deactivate-release.js <version> <channel>');
    process.exit(1);
  }

  try {
    const release = await db.pluginRelease.update({
      where: { version_channel: { version, channel } },
      data: { isActive: false },
    });
    console.log(`Deactivated: ${release.version} (${release.channel})`);
  } catch (err) {
    if (err.code === 'P2025') {
      console.error(`No release found for version=${version} channel=${channel}`);
      process.exit(1);
    }
    throw err;
  }
}

main()
  .catch((err) => {
    console.error('Failed to deactivate release:', err.message);
    process.exit(1);
  })
  .finally(() => process.exit());