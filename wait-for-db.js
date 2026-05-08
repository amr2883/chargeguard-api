// wait-for-db.js – ينتظر حتى تصبح قاعدة البيانات جاهزة، مع تجاهل أخطاء cold start
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function waitForDb(retries = 10, delayMs = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      await prisma.$executeRawUnsafe('SELECT 1');
      console.log('✅ Database is ready');
      await prisma.$disconnect();
      process.exit(0);
    } catch (e) {
      console.log(`⏳ Waiting for database... (attempt ${i + 1}/${retries}): ${e.message}`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  console.error('❌ Database did not become ready');
  process.exit(1);
}

waitForDb();