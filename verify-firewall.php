<?php
/**
 * اختبار تشخيصي لجدار الحماية الديناميكي
 * يثبت أن الأجهزة المحظورة يتم رفض وصولها.
 */

// كتم التحذيرات
error_reporting(0);
ini_set('display_errors', 0);

// تحميل بيئة ووردبريس
define('ABSPATH', '/var/www/html/');
require_once '/var/www/html/wp-load.php';

// تحميل ملفات ChargeGuard
require_once '/var/www/html/wp-content/plugins/chargeguard/includes/class-api-client.php';
require_once '/var/www/html/wp-content/plugins/chargeguard/includes/class-dynamic-firewall.php';

// بدء الاختبار
$firewall = new ChargeGuard_Dynamic_Firewall();
delete_option('chargeguard_device_blacklist');

// إضافة بصمة إلى القائمة السوداء
$fingerprint = 'fp_verify_test';
$firewall->add_device_to_blacklist($fingerprint);

// محاكاة كوكي المتصفح
$_COOKIE['chargeguard_fp'] = $fingerprint;

// محاولة الوصول
try {
    $firewall->check_device_blacklist();
    echo "[FAIL] Exception not thrown\n";
} catch (ChargeGuard_Blocked_Exception $e) {
    echo "[OK] Firewall working: " . $e->getMessage() . "\n";
}
echo "Done\n";