// run_migration.js
// Runs a raw SQL migration file directly against Postgres using the `pg`
// library, bypassing Prisma's schema-engine binary entirely (used as a
// workaround when the Rust engine cannot reach the DB server for reasons
// unrelated to the connection itself, e.g. local OS-level interference).
//
// Usage:
//   node run_migration.js "postgresql://user:pass@host:5432/dbname?sslmode=require" "prisma/migrations/<folder>/migration.sql"

const fs = require('fs');
const { Client } = require('pg');

async function main() {
  const [, , connectionString, sqlFilePath] = process.argv;

  if (!connectionString || !sqlFilePath) {
    console.error('Usage: node run_migration.js "<DATABASE_URL>" "<path_to_migration.sql>"');
    process.exit(1);
  }

  // The migration.sql file was generated via PowerShell's `>` redirection,
  // which writes UTF-16LE by default. Reading it as 'utf8' would corrupt
  // it with embedded NUL bytes, breaking Postgres's wire protocol. Detect
  // encoding by BOM and decode accordingly.
  const buf = fs.readFileSync(sqlFilePath);
  let sql;
  if (buf[0] === 0xFF && buf[1] === 0xFE) {
    sql = buf.toString('utf16le', 2);
  } else if (buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) {
    sql = buf.toString('utf8', 3);
  } else {
    sql = buf.toString('utf8');
  }

  console.log('--- SQL to execute ---');
  console.log(sql);
  console.log('----------------------');

  const client = new Client({
    connectionString,
    ssl: { rejectUnauthorized: false },
  });

  try {
    console.log('Connecting...');
    await client.connect();
    console.log('Connected. Executing SQL...');
    await client.query(sql);
    console.log('✅ Migration SQL executed successfully.');
  } catch (err) {
    console.error('❌ Error executing migration:', err.message);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main();