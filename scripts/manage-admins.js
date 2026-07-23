#!/usr/bin/env node
'use strict';

/**
 * Local CLI for managing AdminUser rows (per-agent admin dashboard keys).
 * Requires direct DB access — run locally or on a bastion host with
 * DATABASE_URL pointed at the right environment. Does not go over HTTP.
 *
 * Usage:
 *   node scripts/manage-admins.js list
 *   node scripts/manage-admins.js create "Jane Doe" admin
 *   node scripts/manage-admins.js create "New Hire" readonly
 *   node scripts/manage-admins.js deactivate <id>
 *   node scripts/manage-admins.js activate <id>
 *   node scripts/manage-admins.js role <id> admin|readonly
 */

const crypto = require('crypto');
const db = require('../src/lib/db');

const ADMIN_KEY_HASH_SECRET = process.env.ADMIN_KEY_HASH_SECRET || process.env.SECRET_SALT;

if (!ADMIN_KEY_HASH_SECRET) {
  console.error('ADMIN_KEY_HASH_SECRET (or SECRET_SALT) must be set in the environment.');
  process.exit(1);
}

const hashAdminKey = (key) =>
  crypto.createHmac('sha256', ADMIN_KEY_HASH_SECRET).update(key).digest('hex');

const genKey = () => crypto.randomBytes(32).toString('base64url'); // ~43 chars, URL-safe

async function list() {
  const users = await db.adminUser.findMany({ orderBy: { createdAt: 'asc' } });
  if (!users.length) {
    console.log('No admin users yet — the ADMIN_SECRET bootstrap key is still the only path in.');
    return;
  }
  console.table(users.map((u) => ({
    id: u.id,
    name: u.name,
    role: u.role,
    isActive: u.isActive,
    lastUsedAt: u.lastUsedAt ? u.lastUsedAt.toISOString() : 'never',
    createdAt: u.createdAt.toISOString(),
  })));
}

async function create(name, role = 'readonly') {
  if (!name) throw new Error('Usage: create "<name>" <admin|readonly>');
  if (!['admin', 'readonly'].includes(role)) {
    throw new Error(`role must be 'admin' or 'readonly', got '${role}'`);
  }

  const key = genKey();
  const keyHash = hashAdminKey(key);
  const user = await db.adminUser.create({ data: { name, keyHash, role, isActive: true } });

  console.log(`Created admin user: ${user.id} (${name}, role=${role})`);
  console.log('');
  console.log('  ── PERSONAL ADMIN KEY (shown once, not recoverable) ──');
  console.log(`  ${key}`);
  console.log('  ───────────────────────────────────────────────────');
  console.log('');
  console.log('Give this to the agent for the x-admin-key header. It cannot be shown again — deactivate and recreate the user if it is lost.');
}

async function setActive(id, isActive) {
  const user = await db.adminUser.update({ where: { id }, data: { isActive } });
  console.log(`${user.name} (${user.id}) is now ${isActive ? 'active' : 'deactivated'}.`);
}

async function setRole(id, role) {
  if (!['admin', 'readonly'].includes(role)) {
    throw new Error(`role must be 'admin' or 'readonly', got '${role}'`);
  }
  const user = await db.adminUser.update({ where: { id }, data: { role } });
  console.log(`${user.name} (${user.id}) role is now ${user.role}.`);
}

async function main() {
  const [, , cmd, ...args] = process.argv;
  switch (cmd) {
    case 'list': return list();
    case 'create': return create(args[0], args[1]);
    case 'deactivate': return setActive(args[0], false);
    case 'activate': return setActive(args[0], true);
    case 'role': return setRole(args[0], args[1]);
    default:
      console.log('Usage:');
      console.log('  node scripts/manage-admins.js list');
      console.log('  node scripts/manage-admins.js create "<name>" <admin|readonly>');
      console.log('  node scripts/manage-admins.js deactivate <id>');
      console.log('  node scripts/manage-admins.js activate <id>');
      console.log('  node scripts/manage-admins.js role <id> <admin|readonly>');
      process.exit(cmd ? 1 : 0);
  }
}

main()
  .catch((err) => {
    console.error('Error:', err.message);
    process.exitCode = 1;
  })
  .finally(() => db.$disconnect());