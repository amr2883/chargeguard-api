const { PrismaClient } = require('@prisma/client');
const { assertSafeTestDb } = require('./assertSafeTestDb');

const prisma = process.env.DATABASE_URL
  ? new PrismaClient()
  : null;

beforeEach(async () => {
  if (globalThis.__cgAuthFailMap) globalThis.__cgAuthFailMap.clear();
  if (!prisma) return;
  assertSafeTestDb();
  try {
    await prisma.registrationAttempt.deleteMany({});
    await prisma.connectAttempt.deleteMany({});
  } catch (err) {
    if (err.name !== 'PrismaClientInitializationError') {
      throw err;
    }
  }
});

afterAll(async () => {
  if (prisma) await prisma.$disconnect();
});