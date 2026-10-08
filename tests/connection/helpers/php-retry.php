<?php
// Test helper: drives the REAL ChargeGuard_API_Client::request_with_breaker() with a fake
// wp_remote_request (no network, no WordPress) and prints every attempt it made.
// usage: php php-retry.php <scenario> <METHOD> <timeout>   (request body is read from stdin)
// scenarios: ok | client_error | retry_503 | retry_wperror | both_503 | retry_500 | circuit
$GLOBALS['cg_t'] = [];
$GLOBALS['cg_calls'] = [];
$GLOBALS['cg_uuid_n'] = 0;
$GLOBALS['cg_scenario'] = $argv[1] ?? 'ok';

function get_option($k) { return $k === 'chargeguard_webhook_secret' ? 'test-secret-123' : 'test-key'; }
function update_option($k, $v, $a = null) { return true; }
function add_action($h, $c) {}
function home_url() { return 'https://Example-Store.com'; }
function wp_parse_url($u, $c = -1) { return parse_url($u, $c); }
function get_transient($k) { return $GLOBALS['cg_t'][$k] ?? false; }
function set_transient($k, $v, $e = 0) { $GLOBALS['cg_t'][$k] = $v; return true; }
function delete_transient($k) { unset($GLOBALS['cg_t'][$k]); return true; }
function wp_using_ext_object_cache() { return false; }
function apply_filters($tag, $value) { return $value; }
function wp_cache_increment($k, $o = 1, $g = '') { return false; }
// deterministic ids: a second call yields a DIFFERENT id, so "new id per attempt" is observable
function wp_generate_uuid4() { $GLOBALS['cg_uuid_n']++; return sprintf('00000000-0000-4000-8000-%012d', $GLOBALS['cg_uuid_n']); }
class WP_Error {
    public $c; public $m;
    function __construct($c = '', $m = '') { $this->c = $c; $this->m = $m; }
    function get_error_message() { return $this->m; }
}
function is_wp_error($t) { return $t instanceof WP_Error; }
function wp_remote_retrieve_response_code($r) { return is_array($r) ? ($r['response']['code'] ?? '') : ''; }
function wp_remote_request($url, $args) {
    $n = count($GLOBALS['cg_calls']) + 1;
    $GLOBALS['cg_calls'][] = [
        'url' => $url, 'method' => $args['method'] ?? null, 'headers' => $args['headers'] ?? null,
        'body' => $args['body'] ?? null, 'timeout' => $args['timeout'] ?? null,
    ];
    $s = $GLOBALS['cg_scenario'];
    // time() has 1s granularity: without this pause the retry lands in the same second and a
    // rebuilt timestamp/signature would be indistinguishable from a reused one.
    if ($n === 1 && in_array($s, ['retry_503', 'retry_wperror', 'both_503'], true)) { sleep(1); }
    if ($s === 'client_error') return ['response' => ['code' => 400], 'body' => '{}'];
    if ($s === 'retry_503')    return ['response' => ['code' => $n === 1 ? 503 : 200], 'body' => '{}'];
    if ($s === 'retry_wperror') return $n === 1 ? new WP_Error('http_request_failed', 'timeout') : ['response' => ['code' => 200], 'body' => '{}'];
    if ($s === 'retry_500') return ['response' => ['code' => $n === 1 ? 500 : 200], 'body' => '{}'];
    if ($s === 'flaky')     return ['response' => ['code' => $n === 5 ? 200 : 503], 'body' => '{}'];
    if ($s === 'circuit' || $s === 'both_503')     return ['response' => ['code' => 503], 'body' => '{}'];
    return ['response' => ['code' => 200], 'body' => '{}'];
}

require __DIR__ . '/../../../woocommerce-chargeguard/includes/class-api-client.php';
if (!defined('CHARGEGUARD_CIRCUIT_OPEN_SECONDS')) { define('CHARGEGUARD_CIRCUIT_OPEN_SECONDS', 300); }

$method  = $argv[2] ?? 'POST';
$timeout = (int) ($argv[3] ?? 5);
$body    = stream_get_contents(STDIN);
$client  = new ChargeGuard_API_Client();
$m = new ReflectionMethod(ChargeGuard_API_Client::class, 'request_with_breaker');
$reps = $GLOBALS['cg_scenario'] === 'circuit' ? 4 : ($GLOBALS['cg_scenario'] === 'flaky' ? 5 : 1);
$results = [];
for ($i = 0; $i < $reps; $i++) {
    $res = $m->invoke($client, 'https://api.example.test/risk/x', $method, $body, $timeout);
    $results[] = ['calls_total' => count($GLOBALS['cg_calls']), 'wp_error' => $res instanceof WP_Error, 'error_code' => $res instanceof WP_Error ? $res->c : null];
}
echo json_encode([
    'results'  => $results,
    'calls'    => $GLOBALS['cg_calls'],
    'wp_error' => $res instanceof WP_Error,
    'code'     => is_array($res) ? ($res['response']['code'] ?? null) : null,
]);
// END-OF-FILE-MARKER