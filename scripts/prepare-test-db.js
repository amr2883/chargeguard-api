// Prepares a LOCAL test database from prisma/migrations, then drops the legacy
// tenant-wide unique index (part 2 of 2 of C4, see docs/migrations-pending/).
// Never run against Render: refuses non-local hosts and names without "test".
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { assertSafeTestDb } = require('../tests/setup/assertSafeTestDb');

const root = path.join(__dirname, '..');
const mask = (s) => String(s).replace(/postgres(ql)?:\/\/\S+/g, '<url>').replace(/[^\x20-\x7E\r\n]/g, '~');
const abort = (m) => { console.log('ABORT: ' + m); process.exit(2); };

const raw = process.env.DATABASE_URL;
if (!raw) abort('DATABASE_URL not set');
let u;
try { u = new URL(raw); } catch (e) { abort('DATABASE_URL is not a valid URL'); }
if (!['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) abort('host is not local');
const dbName = decodeURIComponent(u.pathname.replace(/^\//, ''));
if (!/test/i.test(dbName)) abort('database name must contain "test"');
if (u.searchParams.has('host')) abort('query param "host" is not allowed');
try { assertSafeTestDb(raw); } catch (e) { abort('guard rejected: ' + mask(e && e.message)); }
console.log('target: ' + u.host + u.pathname);

const prismaBin = path.join(root, 'node_modules', 'prisma', 'build', 'index.js');
if (!fs.existsSync(prismaBin)) abort('prisma CLI not found in node_modules');

console.log('--- migrate deploy ---');
const r = spawnSync(process.execPath, [prismaBin, 'migrate', 'deploy'], {
  cwd: root, env: { ...process.env, CHECKPOINT_DISABLE: '1' }, encoding: 'utf8',
});
for (const l of mask((r.stdout || '') + (r.stderr || '')).split(/\r?\n/).filter(Boolean).slice(-8)) console.log('  ' + l);
console.log('migrate exit: ' + r.status);
if (r.status !== 0) process.exit(1);

const { PrismaClient } = require('@prisma/client');
const db = new PrismaClient({ log: [] });
(async () => {
  try {
    console.log('--- drop legacy index ---');
    await db.$executeRawUnsafe('DROP INDEX IF EXISTS "Order_merchantId_orderId_key"');
    const ix = await db.$queryRawUnsafe("SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'Order' AND indexname LIKE 'Order_merchantId%' ORDER BY indexname");
    const names = ix.map((x) => x.indexname);
    for (const n of names) console.log('  ' + n);
    const ok = !names.includes('Order_merchantId_orderId_key')
      && names.includes('Order_merchantId_orderId_pooled_key')
      && names.includes('Order_merchantId_storeId_orderId_key');
    console.log('final state ok: ' + ok);
    process.exitCode = ok ? 0 : 1;
  } catch (e) {
    console.log('ERROR code=' + (e.code || '?') + ' msg=' + mask(e.message).replace(/\s+/g, ' ').slice(0, 300));
    process.exitCode = 1;
  } finally {
    await db.$disconnect();
  }
})();