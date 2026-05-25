# ------ مرحلة البناء (Builder) ------
FROM node:20-alpine AS builder
RUN apk add --no-cache openssl

WORKDIR /app

# نسخ ملفات تعريف الحزم أولاً للاستفادة من caching
COPY package*.json ./
RUN npm ci

# نسخ باقي الكود وتوليد Prisma Client
COPY . .
RUN npx prisma generate

# ------ مرحلة الإنتاج (Production) ------
FROM node:20-alpine

# إنشاء مستخدم غير جذر لأمان أعلى
RUN apk add --no-cache openssl
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

WORKDIR /app

# نسخ فقط الملفات الضرورية من مرحلة البناء
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma
COPY --from=builder --chown=nodejs:nodejs /app/src ./src

# متغيرات البيئة
ENV NODE_ENV=production

# تعريف مستخدم التشغيل
USER nodejs

# فتح المنفذ
EXPOSE 3000

# دورة حياة صحيحة - healthcheck (سطر واحد)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD node -e "require('http').get('http://localhost:3000/health', (r) => {r.statusCode === 200 ? process.exit(0) : process.exit(1)})"

# تشغيل التطبيق (صيغة JSON array الصحيحة)
# تشغيل مزامنة قاعدة البيانات ثم بدء التطبيق
CMD sh -c "npx prisma db push --skip-generate --accept-data-loss && node src/app.js"
