const { PrismaClient } = require('@prisma/client');
const db = new PrismaClient();

(async () => {
  const tenant = await db.tenant.findUnique({ where: { email: 'amrsayed98754@gmail.com' } });
  if (!tenant) {
    console.log('Tenant not found');
    return;
  }

  const orders = await db.order.findMany({
    where: { merchantId: tenant.id },
    orderBy: { createdAt: 'desc' },
    take: 30,
    select: {
      orderId: true,
      ipAddress: true,
      deviceFingerprint: true,
      email: true,
      decision: true,
      riskScore: true,
      amount: true,
      signalsSnapshot: true,
      createdAt: true,
    },
  });

  orders.forEach((o) => {
    const s = o.signalsSnapshot ? JSON.parse(o.signalsSnapshot) : {};
    console.log(
      o.orderId, '|',
      o.decision, '| score:', o.riskScore,
      '| amount:', o.amount,
      '| ip:', o.ipAddress,
      '| device:', o.deviceFingerprint,
      '| ipVel:', s.ipVelocityCount,
      '| devVel:', s.deviceVelocityCount,
      '| emailVel:', s.emailVelocityCount,
      '| flags:', JSON.stringify(s.flags),
      '| time:', o.createdAt
    );
  });

  await db.$disconnect();
})();