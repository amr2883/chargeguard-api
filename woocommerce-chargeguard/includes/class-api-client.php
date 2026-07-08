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
    
    private $webhook_secret;
    private $base_url = 'https://chargeguard-api.onrender.com/api';

    public function __construct() {
        $this->api_key       = get_option('chargeguard_api_key');
        
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
        $body      = json_encode($data);
        $timestamp = (string) time();
        $signature = $this->generate_hmac($body, $timestamp);

        $args = [
            'method'  => 'POST',
            'headers' => [
                'Content-Type'              => 'application/json',
                'X-API-Key'                 => $this->api_key,
                'X-Store-Domain'            => wp_parse_url( home_url(), PHP_URL_HOST ),
                'X-ChargeGuard-Signature'   => $signature,
                'X-ChargeGuard-Timestamp'   => $timestamp,
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
        $body      = json_encode(['fingerprint' => $fingerprint]);
        $timestamp = (string) time();
        $signature = $this->generate_hmac($body, $timestamp);

        $args = [
            'method'  => 'POST',
            'headers' => [
                'Content-Type'              => 'application/json',
                'X-API-Key'                 => $this->api_key,
                'X-Store-Domain'            => wp_parse_url( home_url(), PHP_URL_HOST ),
                'X-ChargeGuard-Signature'   => $signature,
                'X-ChargeGuard-Timestamp'   => $timestamp,
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
     * Send feedback on a previous evaluation to the ChargeGuard backend.
     *
     * @param string $order_id The WooCommerce order ID.
     * @param bool   $is_fraud Whether the order was fraudulent.
     * @return array|WP_Error Result from the API.
     */
    public function send_feedback($order_id, $is_fraud) {
        $endpoint = '/risk/feedback';
        $url      = $this->base_url . $endpoint;
        $body      = json_encode([
            'orderId'  => (string) $order_id,
            'isFraud'  => (bool) $is_fraud,
        ]);
        $timestamp = (string) time();
        $signature = $this->generate_hmac($body, $timestamp);

        $args = [
            'method'  => 'POST',
            'headers' => [
                'Content-Type'              => 'application/json',
                'X-API-Key'                 => $this->api_key,
                'X-Store-Domain'            => wp_parse_url( home_url(), PHP_URL_HOST ),
                'X-ChargeGuard-Signature'   => $signature,
                'X-ChargeGuard-Timestamp'   => $timestamp,
            ],
            'body'    => $body,
            'timeout' => 5,
        ];

        $response = wp_remote_post($url, $args);

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
    private function generate_hmac($raw_body, $timestamp) {
        $signed_string = $timestamp . '.' . $raw_body;
        return 'v1=' . hash_hmac('sha256', $signed_string, $this->webhook_secret);
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
        $body      = json_encode($data);
        $timestamp = (string) time();
        $signature = $this->generate_hmac($body, $timestamp);

        $args = [
            'method'  => 'POST',
            'headers' => [
                'Content-Type'              => 'application/json',
                'X-API-Key'                 => $this->api_key,
                'X-Store-Domain'            => wp_parse_url( home_url(), PHP_URL_HOST ),
                'X-ChargeGuard-Signature'   => $signature,
                'X-ChargeGuard-Timestamp'   => $timestamp,
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