// src/lib/db.js
const { PrismaClient } = require('@prisma/client');

// منع إنشاء اتصالات متعددة في وضع التطوير بسبب Hot Reload
const globalForPrisma = globalThis;

const prisma = globalForPrisma.prisma || new PrismaClient();

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

module.exports = prisma;
