const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'ChargeGuard API',
      version: '1.0.0',
      description: 'Fraud detection and card testing prevention API for WooCommerce',
    },
    servers: [
      {
        url: 'http://localhost:3000/api',
        description: 'Development server',
      },
      {
        url: 'https://Amr453-chargeguard-space.hf.space/api',
        description: 'Production server (Hugging Face)',
      },
    ],
    components: {
      securitySchemes: {
        apiKey: {
          type: 'apiKey',
          in: 'header',
          name: 'x-api-key',
          description: 'API key for authentication',
        },
      },
      schemas: {
        EvaluateRequest: {
          type: 'object',
          required: ['orderId', 'merchantId'],
          properties: {
            orderId: { type: 'string', example: 'order_123' },
            merchantId: { type: 'string', example: 'merchant_001' },
            email: { type: 'string', example: 'customer@example.com' },
            ipAddress: { type: 'string', example: '192.168.1.1' },
            deviceFingerprint: { type: 'string', example: 'fp_abc123' },
            amount: { type: 'number', example: 99.99 },
            billingCountry: { type: 'string', example: 'US' },
            shippingCountry: { type: 'string', example: 'US' },
            bin: { type: 'string', example: '424242' },
            customerLoginId: { type: 'string', example: 'user_456' },
            isNewCustomer: { type: 'boolean', example: false },
          },
        },
        EvaluateResponse: {
          type: 'object',
          properties: {
            orderId: { type: 'string' },
            score: { type: 'integer' },
            decision: { type: 'string', enum: ['approve', 'review', 'block'] },
            flags: { type: 'array', items: { type: 'object' } },
            connectedRisk: { type: 'integer' },
            cached: { type: 'boolean' },
          },
        },
        BlacklistEntry: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            merchantId: { type: 'string' },
            type: { type: 'string', enum: ['EMAIL', 'IP', 'DEVICE_FINGERPRINT'] },
            value: { type: 'string' },
            reason: { type: 'string' },
            expiresAt: { type: 'string', format: 'date-time', nullable: true },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
    security: [{ apiKey: [] }],
  },
  apis: ['./src/routes/*.js'],
};

module.exports = swaggerJsdoc(options);