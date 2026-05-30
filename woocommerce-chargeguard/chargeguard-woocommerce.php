<?php
/**
 * Plugin Name: ChargeGuard for WooCommerce
 * Description: Advanced Card Testing prevention powered by ChargeGuard intelligence.
 * Version:     1.0.0
 * Author:      ChargeGuard
 * Author URI:  https://chargeguard.io
 * License:     GPLv2 or later
 * Text Domain: chargeguard-woocommerce
 */

defined('ABSPATH') || exit;
require_once __DIR__ . '/includes/class-api-client.php';
require_once __DIR__ . '/includes/class-admin-settings.php';
require_once __DIR__ . '/includes/class-stripe-webhook.php';
require_once __DIR__ . '/includes/class-paypal-webhook.php';
require_once __DIR__ . '/includes/class-dynamic-firewall.php';
require_once __DIR__ . '/vendor/stripe-php/init.php';

add_action('plugins_loaded', 'chargeguard_init');
function chargeguard_init() {
    if (!class_exists('WooCommerce')) { return; }
    if (is_admin()) { new ChargeGuard_Admin_Settings(); }
    new ChargeGuard_Stripe_Webhook();
new ChargeGuard_PayPal_Webhook();
    new ChargeGuard_Dynamic_Firewall();
    // إضافة بصمة الجهاز كحقل مخصص في الطلب وإرسالها عبر Webhook
add_action('woocommerce_checkout_create_order', 'chargeguard_add_device_fingerprint_to_order', 10, 2);
function chargeguard_add_device_fingerprint_to_order($order, $data) {
    if (isset($_COOKIE['chargeguard_fp'])) {
        $fingerprint = sanitize_text_field(wp_unslash($_COOKIE['chargeguard_fp']));
        $order->update_meta_data('_chargeguard_device_fingerprint', $fingerprint);
    }
}

add_filter('woocommerce_webhook_payload', 'chargeguard_add_fingerprint_to_webhook_payload', 10, 4);
function chargeguard_add_fingerprint_to_webhook_payload($payload, $resource, $resource_id, $webhook_id) {
    if ($resource === 'order' && isset($payload['id'])) {
        $order = wc_get_order($resource_id);
        if ($order) {
            $fingerprint = $order->get_meta('_chargeguard_device_fingerprint');
            if ($fingerprint) {
                $payload['device_fingerprint'] = $fingerprint;
            }
        }
    }
    return $payload;
}
}
