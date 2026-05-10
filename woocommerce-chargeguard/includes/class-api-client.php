<?php
/**
 * ChargeGuard API Client
 *
 * Handles authenticated communication with the ChargeGuard backend.
 *
 * @package ChargeGuard_WooCommerce
 */

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

    /**
     * الحصول على مفتاح API الحالي.
     *
     * @return string|null
     */
    public function get_api_key() {
        return $this->api_key;
    }

    /**
     * إرسال بيانات enrich إلى ChargeGuard.
     *
     * @param array $data يحتوي على orderId, bin, cardBrand, cardCountry, funding, issuer.
     * @return array|WP_Error نتيجة الاستدعاء.
     */
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

        // إعادة المحاولة مرة واحدة عند حدوث خطأ في الشبكة أو خطأ خادم
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            sleep(2);
            $response = wp_remote_post($url, $args);
        }

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }

    /**
     * فحص بصمة جهاز عبر ChargeGuard API.
     *
     * @param string $fingerprint بصمة الجهاز.
     * @return array|WP_Error
     */
    public function check_device($fingerprint) {
        $endpoint = '/risk/check-device';
        $url      = $this->base_url . $endpoint;
        $body     = json_encode(['fingerprint' => $fingerprint]);
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
            'timeout' => 3,
        ];

        $response = wp_remote_post($url, $args);

        // إعادة المحاولة مرة واحدة عند الفشل
        if (is_wp_error($response)) {
            sleep(1);
            $response = wp_remote_post($url, $args);
        }

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }

    /**
     * توليد توقيع HMAC-SHA256 مطابق لتوقيع WooCommerce webhook.
     *
     * @param string $raw_body الجسم الخام للطلب.
     * @return string التوقيع بصيغة base64.
     */
    private function generate_hmac($raw_body) {
        return base64_encode(hash_hmac('sha256', $raw_body, $this->webhook_secret, true));
    }

    /**
     * إرسال طلب تقييم مخاطر إلى ChargeGuard API.
     *
     * @param array $data بيانات الطلب.
     * @return array|WP_Error
     */
    public function evaluate_risk($data) {
        $endpoint = '/risk/evaluate';
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

        // إعادة المحاولة مرة واحدة عند فشل الشبكة أو خطأ خادم
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) >= 500) {
            sleep(2);
            $response = wp_remote_post($url, $args);
        }

        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }
}