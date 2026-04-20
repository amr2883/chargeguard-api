---
title: ChargeGuard API
emoji: 🛡️
colorFrom: purple
colorTo: gray
sdk: docker
app_port: 7860
---
# ChargeGuard – نظام متقدم لمنع Card Testing في WooCommerce

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://www.docker.com/)
[![Node.js](https://img.shields.io/badge/node.js-20+-green)](https://nodejs.org/)

ChargeGuard هو نظام كشف ومنع احتيال متكامل، مصمم خصيصاً لحماية متاجر WooCommerce من هجمات **Card Testing** (اختبار البطاقات المسروقة). يعتمد على تقنيات متقدمة مثل **Identity Graph**، **Pattern Sharing** عبر التجار، **تحليل BIN/IP/Email**، **كشف السرعة (Velocity Detection)**، ومحرك اقتصادي لاتخاذ القرارات المالية.

---

## 📖 جدول المحتويات

- [الميزات الرئيسية](#-الميزات-الرئيسية)
- [المتطلبات الأساسية](#-المتطلبات-الأساسية)
- [التشغيل السريع (Docker)](#-التشغيل-السريع-docker)
- [الإعدادات والمتغيرات البيئية](#-الإعدادات-والمتغيرات-البيئية)
- [واجهة برمجة التطبيقات (API)](#-واجهة-برمجة-التطبيقات-api)
- [إدارة القائمة السوداء](#-إدارة-القائمة-السوداء)
- [حلقة التغذية الراجعة (Feedback Loop)](#-حلقة-التغذية-الراجعة-feedback-loop)
- [المراقبة (Prometheus + Grafana)](#-المراقبة-prometheus--grafana)
- [HTTPS والأمان](#-https-والأمان)
- [النشر على الإنترنت (Cloudflare Tunnel)](#-النشر-على-الإنترنت-cloudflare-tunnel)
- [الاختبارات](#-الاختبارات)
- [التطوير المحلي](#-التطوير-المحلي)
- [استكشاف الأخطاء وإصلاحها](#-استكشاف-الأخطاء-وإصلاحها)
- [الترخيص](#-الترخيص)

---

## ✨ الميزات الرئيسية

- **Identity Graph متقدم**: تتبع الأجهزة عبر 3 مستويات (full/config/hardware) باستخدام HMAC، مع اكتشاف الروابط بين البريد الإلكتروني، IP، العنوان، الجهاز.
- **Pattern Sharing عبر التجار**: مشاركة أنماط الاحتيال بين التجار دون الكشف عن معلومات تعريفية (PII)، مع تجميع الأنماط في مجموعات (clusters).
- **BIN Intelligence ذكي**: تحليل رقم BIN من 4 زوايا (prepaid، عدم تطابق الدولة، عدم تطابق ثلاثي، المخاطر الجغرافية) مع دمج العقوبات بطريقة إحصائية.
- **Email Intelligence متعدد الطبقات**: فحص DNS، قائمة النطاقات المؤقتة، الانتروبي، مع TTL ديناميكي وتخزين مؤقت LRU.
- **IP Intelligence**: تكامل مع IPQualityScore، كشف الـ VPN/Proxy/Tor/Datacenter، مع حساب احتمالي للخطر.
- **كشف السرعة (Velocity Detection)**: مراقبة IP والجهاز والبريد الإلكتروني، مع حظر تلقائي مؤقت عند تجاوز العتبات.
- **محرك اقتصادي (Economic Engine)**: تحويل القرار من "هل هذا احتيال؟" إلى "هل يستحق المخاطرة مالياً؟" باستخدام دالة sigmoid وعتبات ديناميكية.
- **ضوابط إرهاق المراجعة (Fatigue Management)**: رفع عتبة "Medium Risk" تلقائياً إذا زادت نسبة المراجعات.
- **مراقبة متكاملة**: Prometheus لجمع المقاييس + Grafana للوحات التحكم.
- **هندسة Fail-Secure**: رفض الطلب في حال فشل أي فحص أمني (اتصال قاعدة البيانات، API خارجي، إلخ).
- **دعم Docker Compose للإنتاج**: بنية متعددة الخدمات (app, db, nginx, prometheus, grafana, cloudflared).

---

## 🏗️ المتطلبات الأساسية

- **Docker** (الإصدار 20.10 أو أحدث) و **Docker Compose** (الإصدار 2.0+)
- **Node.js** (v20+) – فقط للتطوير المحلي بدون Docker
- **Git** (للاستنساخ)
- **4 GB RAM** على الأقل (موصى به 8 GB للإنتاج)

---

## 🚀 التشغيل السريع (Docker)

### 1. استنساخ المستودع

```bash
git clone https://github.com/your-repo/chargeguard-woocommerce-backend.git
cd chargeguard-woocommerce-backend