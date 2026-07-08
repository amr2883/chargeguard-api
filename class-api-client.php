<?php
class ChargeGuard_API_Client {
    private $api_key;
    private $merchant_id;
    private $webhook_secret;
    private $base_url = 'https://Amr453-chargeguard-space.hf.space/api';

    public function __construct() {
        $this->api_key       = get_option('chargeguard_api_key');
        $this->merchant_id   = get_option('chargeguard_merchant_id');
        $this->webhook_secret = get_option('chargeguard_webhook_secret');
    }

    public function send_enrich($data) {
        $endpoint = '/risk/enrich';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode($data);
        $signature = $this->generate_hmac($body);
        $args = [
            'method'  => 'POST',
            'headers' => [
                'Content-Type'           => 'application/json',
                'X-API-Key'              => $this->api_key,
                'X-Merchant-Id'          => $this->merchant_id,
                'X-WC-Webhook-Signature' => $signature,
            ],
            'body'    => $body,
            'timeout' => 5,
        ];
        $response = wp_remote_post($url, $args);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            sleep(2);
            $response = wp_remote_post($url, $args);
        }
        if (is_wp_error($response)) { return $response; }
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if ($code >= 200 && $code < 300) { return $body; }
        return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
    }

    private function generate_hmac($raw_body) {
        return base64_encode(hash_hmac('sha256', $raw_body, $this->webhook_secret, true));
    }
}
