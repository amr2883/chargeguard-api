// insert-merchant.js
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  await prisma.merchant.create({
    data: {
      id: 'test-merchant-001',
      name: 'Test Merchant',
    },
  });
  console.log('✅ Merchant inserted successfully.');
}

main()
  .catch((e) => {
    console.error(e);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });