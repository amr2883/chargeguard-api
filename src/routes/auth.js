const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../lib/db');
const logger = require('../lib/logger');

/**
 * POST /api/auth/connect
 * التاجر يبعت الـ email بتاعه بس
 * الـ backend يرجعله كل حاجة تلقائياً
 */
router.post('/connect', async (req, res) => {
  try {
    const { email, siteUrl } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email is required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // ابحث عن التاجر بالـ email
    const tenant = await db.tenant.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        apiKey: true,
        webhookSecret: true,
        isActive: true,
        storeUrl: true,
      }
    });

    if (!tenant) {
      return res.status(404).json({
        error: 'Email not found. Please register at chargeguard-io.netlify.app first.'
      });
    }

    if (!tenant.isActive) {
      return res.status(403).json({
        error: 'Account is inactive. Please contact support.'
      });
    }

    // لو مفيش webhookSecret — نعمله تلقائياً ونحفظه
    let webhookSecret = tenant.webhookSecret;
    if (!webhookSecret) {
      webhookSecret = crypto.randomBytes(32).toString('hex');
      await db.tenant.update({
        where: { email: normalizedEmail },
        data: { webhookSecret }
      });
    }

    // لو التاجر بعت الـ siteUrl — نحدثه
    if (siteUrl && siteUrl !== tenant.storeUrl) {
      await db.tenant.update({
        where: { email: normalizedEmail },
        data: { storeUrl: siteUrl }
      });
    }

    logger.info(`Tenant connected via email: ${normalizedEmail}`);

    return res.status(200).json({
      merchantId:    tenant.id,
      apiKey:        tenant.apiKey,
      webhookSecret: webhookSecret,
      email:         tenant.email,
    });

  } catch (err) {
    logger.error('Auth connect error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;