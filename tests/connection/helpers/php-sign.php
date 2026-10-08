<?php
// Test helper: signs ONE request with the REAL plugin code (no network, no WordPress).
// usage: php php-sign.php <request-id>   (request body is read from stdin)
function get_option($k) { return $k === 'chargeguard_webhook_secret' ? 'test-secret-123' : 'test-key'; }
function add_action($h, $c) {}
function home_url() { return 'https://Example-Store.com'; }
function wp_parse_url($u, $c = -1) { return parse_url($u, $c); }
class WP_Error {}
require __DIR__ . '/../../../woocommerce-chargeguard/includes/class-api-client.php';

$body = stream_get_contents(STDIN);
$rid  = $argv[1];
$client = new ChargeGuard_API_Client();
$m = new ReflectionMethod(ChargeGuard_API_Client::class, 'build_signed_headers');
echo json_encode(['headers' => $m->invoke($client, $body, $rid)]);