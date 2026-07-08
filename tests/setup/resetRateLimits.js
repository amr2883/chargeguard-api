const { PrismaClient } = require('@prisma/client');

const prisma = process.env.DATABASE_URL
  ? new PrismaClient()
  : null;

beforeEach(async () => {
  if (!prisma) return;
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