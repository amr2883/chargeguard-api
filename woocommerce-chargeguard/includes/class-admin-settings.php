<?php
class ChargeGuard_Admin_Settings {

    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_chargeguard_connect', [$this, 'ajax_connect']);
        add_action('wp_ajax_chargeguard_disconnect', [$this, 'ajax_disconnect']);
        add_action('wp_ajax_chargeguard_verify_key',  [$this, 'ajax_verify_key']);
        add_action('wp_ajax_chargeguard_whitelist_get',    [$this, 'ajax_whitelist_get']);
        add_action('wp_ajax_chargeguard_whitelist_add',    [$this, 'ajax_whitelist_add']);
        add_action('wp_ajax_chargeguard_whitelist_delete', [$this, 'ajax_whitelist_delete']);
        add_action('wp_ajax_chargeguard_blacklist_get',    [$this, 'ajax_blacklist_get']);
        add_action('wp_ajax_chargeguard_blacklist_add',    [$this, 'ajax_blacklist_add']);
        add_action('wp_ajax_chargeguard_blacklist_delete', [$this, 'ajax_blacklist_delete']);
        add_action('wp_ajax_chargeguard_webhook_save',     [$this, 'ajax_webhook_save']);
        add_action('wp_ajax_chargeguard_webhook_test',     [$this, 'ajax_webhook_test']);
        add_action('wp_ajax_chargeguard_webhook_status',        [$this, 'ajax_webhook_status']);
        add_action('wp_ajax_chargeguard_geo_overrides_get',     [$this, 'ajax_geo_overrides_get']);
        add_action('wp_ajax_chargeguard_geo_override_save',     [$this, 'ajax_geo_override_save']);
        add_action('wp_ajax_chargeguard_paypal_save',           [$this, 'ajax_paypal_save']);
        add_action('wp_ajax_chargeguard_paypal_test',           [$this, 'ajax_paypal_test']);
    }

    public function add_admin_menu() {
        add_submenu_page(
            'woocommerce',
            'ChargeGuard',
            'ChargeGuard',
            'manage_woocommerce',
            'chargeguard-settings',
            [$this, 'settings_page']
        );
    }

    public function register_settings() {
        register_setting('chargeguard_firewall_settings', 'chargeguard_enable_firewall', 'intval');
        register_setting('chargeguard_firewall_settings', 'chargeguard_firewall_block_duration', 'intval');
        // Trust Badge options
        register_setting( 'chargeguard_badge_settings', 'chargeguard_badge_enabled',  'sanitize_text_field' );
        register_setting( 'chargeguard_badge_settings', 'chargeguard_badge_location', 'sanitize_text_field' );
        register_setting( 'chargeguard_badge_settings', 'chargeguard_badge_color',    'sanitize_text_field' );
    }
    public function ajax_verify_key() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $api_key = get_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'No API key found.']);
        }

        $response = wp_remote_get('https://chargeguard-api.onrender.com/api/auth/verify', [
            'timeout' => 15,
            'headers' => ['x-api-key' => $api_key],
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code === 200) {
            wp_send_json_success(['message' => '✓ API key is valid.']);
        } else {
            wp_send_json_error(['message' => 'Invalid API key. Please reconnect your store.']);
        }
    }

    public function ajax_connect() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        $email = sanitize_email(wp_unslash($_POST['email'] ?? ''));
        if (!is_email($email)) {
            wp_send_json_error(['message' => 'Please enter a valid email address.']);
        }

        $site_url = get_site_url();

        $response = wp_remote_post('https://chargeguard-api.onrender.com/api/auth/connect', [
            'timeout' => 15,
            'headers' => [
                'Content-Type'   => 'application/json',
                'x-store-domain' => wp_parse_url( home_url(), PHP_URL_HOST ),
            ],
            'body'    => json_encode([
                'email'   => $email,
                'siteUrl' => $site_url,
            ]),
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard. Check your connection.']);
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($code !== 200) {
            $msg = $body['error'] ?? 'Connection failed. Please try again.';
            wp_send_json_error(['message' => $msg]);
        }

        // حفظ كل حاجة تلقائياً
        update_option('chargeguard_api_key',        sanitize_text_field($body['apiKey']));
        update_option('chargeguard_merchant_id',    sanitize_text_field($body['merchantId']));
        update_option('chargeguard_webhook_secret', sanitize_text_field($body['webhookSecret']));
        update_option('chargeguard_connected_email', sanitize_email($email));

        // إضافة الـ WooCommerce webhook تلقائياً
        $this->register_woocommerce_webhook($body['webhookSecret']);

        wp_send_json_success(['email' => $email]);
    }

    public function ajax_disconnect() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');

        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }

        delete_option('chargeguard_api_key');
        delete_option('chargeguard_merchant_id');
        delete_option('chargeguard_webhook_secret');
        delete_option('chargeguard_connected_email');

        // حذف الـ webhook
        $this->delete_woocommerce_webhook();

        wp_send_json_success();
    }

    public function ajax_whitelist_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $response = wp_remote_get(
            'https://chargeguard-api.onrender.com/api/risk/whitelist?merchantId=' . urlencode($merchant_id),
            ['timeout' => 15, 'headers' => ['x-api-key' => $api_key, 'x-merchant-id' => $merchant_id]]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!empty($body['success'])) {
            wp_send_json_success(['entries' => $body['entries'] ?? []]);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to fetch whitelist.']);
        }
    }

    public function ajax_whitelist_add() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $type   = sanitize_text_field(wp_unslash($_POST['type']   ?? ''));
        $value  = sanitize_text_field(wp_unslash($_POST['value']  ?? ''));
        $reason = sanitize_text_field(wp_unslash($_POST['reason'] ?? ''));
        if (!$type || !$value) {
            wp_send_json_error(['message' => 'Type and value are required.']);
        }
        $response = wp_remote_post(
            'https://chargeguard-api.onrender.com/api/risk/whitelist',
            [
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode([
                    'merchantId' => $merchant_id,
                    'type'       => $type,
                    'value'      => $value,
                    'reason'     => $reason ?: null,
                    'createdBy'  => get_option('chargeguard_connected_email'),
                ]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if ($code === 200 && !empty($body['success'])) {
            wp_send_json_success(['entry' => $body['entry'] ?? []]);
        } elseif ($code === 409) {
            wp_send_json_error(['message' => 'This entry already exists in the safe list.']);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to add entry.']);
        }
    }

    public function ajax_whitelist_delete() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        $id          = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$merchant_id || !$api_key || !$id) {
            wp_send_json_error(['message' => 'Missing required data.']);
        }
        $response = wp_remote_request(
            'https://chargeguard-api.onrender.com/api/risk/whitelist/' . rawurlencode($id),
            [
                'method'  => 'DELETE',
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode(['merchantId' => $merchant_id]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            wp_send_json_success();
        } else {
            wp_send_json_error(['message' => 'Failed to delete entry.']);
        }
    }

    public function ajax_blacklist_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $response = wp_remote_get(
            'https://chargeguard-api.onrender.com/api/risk/blacklist?merchantId=' . urlencode($merchant_id),
            ['timeout' => 15, 'headers' => ['x-api-key' => $api_key, 'x-merchant-id' => $merchant_id]]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!empty($body['success'])) {
            wp_send_json_success(['entries' => $body['entries'] ?? []]);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to fetch blacklist.']);
        }
    }

    public function ajax_blacklist_add() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $type   = sanitize_text_field(wp_unslash($_POST['type']   ?? ''));
        $value  = sanitize_text_field(wp_unslash($_POST['value']  ?? ''));
        $reason = sanitize_text_field(wp_unslash($_POST['reason'] ?? ''));
        if (!$type || !$value) {
            wp_send_json_error(['message' => 'Type and value are required.']);
        }
        $response = wp_remote_post(
            'https://chargeguard-api.onrender.com/api/risk/blacklist',
            [
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode([
                    'merchantId' => $merchant_id,
                    'type'       => $type,
                    'value'      => $value,
                    'reason'     => $reason ?: null,
                    'createdBy'  => get_option('chargeguard_connected_email'),
                ]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if ($code === 200 && !empty($body['success'])) {
            wp_send_json_success(['entry' => $body['entry'] ?? []]);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to add entry.']);
        }
    }

    public function ajax_blacklist_delete() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        $id          = sanitize_text_field(wp_unslash($_POST['id'] ?? ''));
        if (!$merchant_id || !$api_key || !$id) {
            wp_send_json_error(['message' => 'Missing required data.']);
        }
        $response = wp_remote_request(
            'https://chargeguard-api.onrender.com/api/risk/blacklist/' . rawurlencode($id),
            [
                'method'  => 'DELETE',
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode(['merchantId' => $merchant_id]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            wp_send_json_success();
        } else {
            wp_send_json_error(['message' => 'Failed to delete entry.']);
        }
    }

    public function ajax_webhook_save() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $webhook_url  = sanitize_text_field(wp_unslash($_POST['webhook_url']  ?? ''));
        $webhook_type = sanitize_text_field(wp_unslash($_POST['webhook_type'] ?? 'custom'));
        if (!in_array($webhook_type, ['slack', 'discord', 'custom'])) {
            $webhook_type = 'custom';
        }
        $response = wp_remote_post(
            'https://chargeguard-api.onrender.com/api/settings/webhook',
            [
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode(['webhookUrl' => $webhook_url, 'webhookType' => $webhook_type]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            wp_send_json_success();
        } else {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to save webhook settings.']);
        }
    }

    public function ajax_webhook_test() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $response = wp_remote_post(
            'https://chargeguard-api.onrender.com/api/settings/webhook/test',
            [
                'timeout' => 15,
                'headers' => ['Content-Type' => 'application/json', 'x-api-key' => $api_key, 'x-merchant-id' => $merchant_id],
                'body'    => json_encode([]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        if ($code === 200) {
            wp_send_json_success();
        } else {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            wp_send_json_error(['message' => $body['error'] ?? 'Test failed. Check your webhook URL.']);
        }
    }

    public function ajax_webhook_status() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $merchant_id = get_option('chargeguard_merchant_id');
        $api_key     = get_option('chargeguard_api_key');
        if (!$merchant_id || !$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $response = wp_remote_get(
            'https://chargeguard-api.onrender.com/api/settings/webhook',
            ['timeout' => 15, 'headers' => ['x-api-key' => $api_key, 'x-merchant-id' => $merchant_id]]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!empty($body['success'])) {
            wp_send_json_success(['webhookUrl' => $body['webhookUrl'] ?? '', 'webhookType' => $body['webhookType'] ?? '', 'webhookLastStatus' => $body['webhookLastStatus'] ?? '', 'webhookLastSentAt' => $body['webhookLastSentAt'] ?? '', 'webhookFailureCount' => $body['webhookFailureCount'] ?? 0]);
        } else {
            wp_send_json_error(['message' => 'Failed to fetch webhook status.']);
        }
    }

    private function register_woocommerce_webhook($secret) {
        $existing = get_option('chargeguard_webhook_id');
        if ($existing) return;

        $webhook_url = 'https://chargeguard-api.onrender.com/api/risk/woocommerce-webhook';

        $webhook = new WC_Webhook();
        $webhook->set_name('ChargeGuard Order Monitor');
        $webhook->set_topic('order.created');
        $webhook->set_delivery_url($webhook_url);
        $webhook->set_secret($secret);
        $webhook->set_status('active');
        $webhook->save();

        update_option('chargeguard_webhook_id', $webhook->get_id());
    }

    private function delete_woocommerce_webhook() {
        $webhook_id = get_option('chargeguard_webhook_id');
        if (!$webhook_id) return;

        $webhook = new WC_Webhook($webhook_id);
        $webhook->delete(true);
        delete_option('chargeguard_webhook_id');
    }

    public function ajax_geo_overrides_get() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = get_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $response = wp_remote_get(
            'https://chargeguard-api.onrender.com/api/settings/country-overrides',
            [
                'timeout' => 10,
                'headers' => ['x-api-key' => $api_key],
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (!empty($body['success'])) {
            wp_send_json_success([
                'countryOverrides'   => $body['countryOverrides']   ?? [],
                'availableCountries' => $body['availableCountries'] ?? [],
                'summary'            => $body['summary']            ?? [],
            ]);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to fetch geo settings.']);
        }
    }

    public function ajax_geo_override_save() {
        check_ajax_referer('chargeguard_connect_nonce', 'nonce');
        if (!current_user_can('manage_woocommerce')) {
            wp_send_json_error(['message' => 'Unauthorized'], 403);
        }
        $api_key = get_option('chargeguard_api_key');
        if (!$api_key) {
            wp_send_json_error(['message' => 'Store not connected.']);
        }
        $country_code = sanitize_text_field(wp_unslash($_POST['country_code'] ?? ''));
        $override     = sanitize_text_field(wp_unslash($_POST['override']      ?? ''));
        if (!$country_code || !$override) {
            wp_send_json_error(['message' => 'country_code and override are required.']);
        }
        $allowed_overrides = ['allow', 'escalate', 'smart'];
        if (!in_array($override, $allowed_overrides, true)) {
            wp_send_json_error(['message' => 'Invalid override value.']);
        }
        $response = wp_remote_post(
            'https://chargeguard-api.onrender.com/api/settings/country-overrides',
            [
                'method'  => 'PUT',
                'timeout' => 10,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'x-api-key'    => $api_key,
                ],
                'body' => json_encode([
                    'updates' => [
                        [
                            'countryCode' => strtoupper($country_code),
                            'override'    => $override,
                        ],
                    ],
                ]),
            ]
        );
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => 'Could not reach ChargeGuard server.']);
        }
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if ($code === 200 && !empty($body['success'])) {
            wp_send_json_success([
                'countryOverrides' => $body['countryOverrides'] ?? [],
                'warnings'         => $body['warnings']         ?? [],
            ]);
        } else {
            wp_send_json_error(['message' => $body['error'] ?? 'Failed to save override.']);
        }
    }

    public function ajax_paypal_save() {
        check_ajax_referer( 'chargeguard_connect_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'unauthorized' ], 403 );
        }

        $client_id     = sanitize_text_field( wp_unslash( $_post['client_id']     ?? '' ) );
        $client_secret = sanitize_text_field( wp_unslash( $_post['client_secret'] ?? '' ) );
        $webhook_id    = sanitize_text_field( wp_unslash( $_post['webhook_id']    ?? '' ) );
        $mode          = sanitize_text_field( wp_unslash( $_post['mode']          ?? 'sandbox' ) );
        $enabled       = sanitize_text_field( wp_unslash( $_post['enabled']       ?? '0' ) );

        if ( ! in_array( $mode, [ 'sandbox', 'live' ], true ) ) {
            $mode = 'sandbox';
        }

        update_option( 'chargeguard_paypal_client_id',  $client_id );
        if ( ! empty( $client_secret ) ) {
            update_option( 'chargeguard_paypal_client_secret', $client_secret );
        }
        update_option( 'chargeguard_paypal_webhook_id', $webhook_id );
        update_option( 'chargeguard_paypal_mode',          $mode );
        update_option( 'chargeguard_paypal_enabled',       $enabled === '1' ? '1' : '0' );

        // مسح access token المخزّن لإجبار التجديد بالبيانات الجديدة
        delete_transient( 'cg_paypal_access_token_' . md5( $client_id ) );

        wp_send_json_success( [ 'message' => 'paypal settings saved.' ] );
    }

    public function ajax_paypal_test() {
        check_ajax_referer( 'chargeguard_connect_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_woocommerce' ) ) {
            wp_send_json_error( [ 'message' => 'unauthorized' ], 403 );
        }

        $client_id     = get_option( 'chargeguard_paypal_client_id' );
        $client_secret = get_option( 'chargeguard_paypal_client_secret' );

        if ( ! $client_id || ! $client_secret ) {
            wp_send_json_error( [ 'message' => 'please save your paypal credentials first.' ] );
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/oauth2/token'
            : 'https://api-m.sandbox.paypal.com/v1/oauth2/token';

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'authorization' => 'basic ' . base64_encode( $client_id . ':' . $client_secret ),
                'content-type'  => 'application/x-www-form-urlencoded',
            ],
            'body' => 'grant_type=client_credentials',
        ] );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( [ 'message' => 'could not reach paypal servers.' ] );
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( $code === 200 && ! empty( $body['access_token'] ) ) {
            wp_send_json_success( [ 'message' => '✓ paypal credentials are valid.' ] );
        } else {
            $error = $body['error_description'] ?? 'invalid credentials.';
            wp_send_json_error( [ 'message' => $error ] );
        }
    }

    public function settings_page() {
        $is_connected = (bool) get_option('chargeguard_api_key');
        $connected_email = get_option('chargeguard_connected_email', '');
        $firewall_enabled = get_option('chargeguard_enable_firewall', 1);
        $block_duration   = get_option( 'chargeguard_firewall_block_duration', 24 );
        $badge_enabled    = get_option( 'chargeguard_badge_enabled', '1' );
        $badge_location   = get_option( 'chargeguard_badge_location', 'footer' );
        $badge_color      = get_option( 'chargeguard_badge_color', 'light' );
        $nonce = wp_create_nonce('chargeguard_connect_nonce');

        // IP المسؤول الحالي (مع دعم Proxies)
        $current_admin_ip = '';
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            $current_admin_ip = trim($ips[0]);
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $current_admin_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }
        ?>
        <div class="wrap" id="chargeguard-wrap">
        <style>
            #chargeguard-wrap { max-width: 680px; }
            .cg-card {
                background: #fff;
                border: 1px solid #e0e0e0;
                border-radius: 12px;
                padding: 28px 32px;
                margin-bottom: 20px;
                box-shadow: 0 1px 4px rgba(0,0,0,0.06);
            }
            .cg-status-badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 6px 14px;
                border-radius: 100px;
                font-size: 13px;
                font-weight: 600;
                margin-bottom: 20px;
            }
            .cg-status-badge.connected {
                background: #f0fdf4;
                color: #16a34a;
                border: 1px solid #bbf7d0;
            }
            .cg-status-badge.disconnected {
                background: #fafafa;
                color: #666;
                border: 1px solid #e0e0e0;
            }
            .cg-dot {
                width: 8px; height: 8px;
                border-radius: 50%;
            }
            .cg-dot.green { background: #16a34a; }
            .cg-dot.gray  { background: #999; }
            .cg-input {
                width: 100%;
                padding: 10px 14px;
                border: 1px solid #ddd;
                border-radius: 8px;
                font-size: 14px;
                margin-top: 6px;
                box-sizing: border-box;
            }
            .cg-input:focus { border-color: #f97316; outline: none; box-shadow: 0 0 0 3px rgba(249,115,22,0.15); }
            .cg-btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 10px 22px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                border: none;
                margin-top: 14px;
                transition: all 0.2s;
            }
            .cg-btn-primary { background: #f97316; color: #fff; }
            .cg-btn-primary:hover { background: #ea580c; }
            .cg-btn-danger { background: #fff; color: #dc2626; border: 1px solid #fecaca; }
            .cg-btn-danger:hover { background: #fef2f2; }
            .cg-steps {
                display: flex;
                gap: 0;
                margin-bottom: 24px;
            }
            .cg-step {
                flex: 1;
                text-align: center;
                padding: 10px 6px;
                font-size: 12px;
                color: #999;
                border-bottom: 2px solid #e0e0e0;
                position: relative;
            }
            .cg-step.active { color: #f97316; border-bottom-color: #f97316; font-weight: 600; }
            .cg-step.done { color: #16a34a; border-bottom-color: #16a34a; }
            .cg-message { padding: 12px 16px; border-radius: 8px; font-size: 13px; margin-top: 12px; display: none; }
            .cg-message.error { background: #fef2f2; border: 1px solid #fecaca; color: #dc2626; display: block; }
            .cg-message.success { background: #f0fdf4; border: 1px solid #bbf7d0; color: #16a34a; display: block; }
            .cg-info-row { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
            .cg-info-row:last-child { border-bottom: none; }
            .cg-info-label { color: #666; }
            .cg-info-value { font-weight: 600; color: #111; }
            .cg-spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.4); border-top-color: #fff; border-radius: 50%; animation: cg-spin 0.7s linear infinite; }
           @keyframes cg-spin { to { transform: rotate(360deg); } }

            /* Trust Badge Section */
            .cg-badge-preview-wrap {
                background: #f8fafc;
                border: 1px dashed #cbd5e1;
                border-radius: 8px;
                padding: 16px;
                text-align: center;
                margin-top: 12px;
            }
            .cg-badge-preview-label {
                font-size: 11px;
                color: #94a3b8;
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .cg-select {
                padding: 7px 10px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 13px;
                background: #fff;
            }
            .cg-toggle-wrap {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .cg-toggle {
                width: 36px; height: 20px;
                appearance: none;
                background: #cbd5e1;
                border-radius: 10px;
                cursor: pointer;
                position: relative;
                transition: background 0.2s;
            }
            .cg-toggle:checked { background: #16a34a; }
            .cg-toggle::after {
                content: '';
                position: absolute;
                width: 14px; height: 14px;
                background: #fff;
                border-radius: 50%;
                top: 3px; left: 3px;
                transition: left 0.2s;
                box-shadow: 0 1px 2px rgba(0,0,0,0.2);
            }
            .cg-toggle:checked::after { left: 19px; }
        </style>
        <h1 style="display:flex;align-items:center;gap:10px;margin-bottom:24px;">
            <span style="font-size:24px;">🛡️</span> ChargeGuard
        </h1>

        <?php if ($is_connected): ?>

            <!-- ✅ Connected State -->
            <div class="cg-card">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                    <div class="cg-status-badge connected" style="margin-bottom:0;">
                        <div class="cg-dot green"></div>
                        Active — Your store is protected
                    </div>
                    <button type="button" id="cg-verify-key-btn" class="button">
                        <?php esc_html_e( 'Verify Key', 'chargeguard-woocommerce' ); ?>
                    </button>
                </div>
                <div id="cg-key-status" style="display:none;font-size:12px;padding:6px 10px;border-radius:6px;margin-bottom:10px;"></div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Connected Account</span>
                    <span class="cg-info-value"><?php echo esc_html($connected_email); ?></span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Merchant ID</span>
                    <span class="cg-info-value" style="font-family:monospace;font-size:12px;"><?php echo esc_html(substr(get_option('chargeguard_merchant_id'), 0, 16) . '...'); ?></span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Webhook</span>
                    <span class="cg-info-value" style="color:#16a34a;">✓ Configured automatically</span>
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Firewall</span>
                    <span class="cg-info-value" style="color:#16a34a;">✓ Active</span>
                </div>
                <button class="cg-btn cg-btn-danger" id="cg-disconnect-btn">
                    Disconnect Store
                </button>
            </div>

        <?php else: ?>

            <!-- 🔌 Connect State -->
            <div class="cg-card">
                <div class="cg-status-badge disconnected">
                    <div class="cg-dot gray"></div>
                    Not Connected
                </div>

                <div class="cg-steps">
                    <div class="cg-step active" id="cg-step-1">① Enter Email</div>
                    <div class="cg-step" id="cg-step-2">② Connecting</div>
                    <div class="cg-step" id="cg-step-3">③ Protected</div>
                </div>

                <p style="color:#555;font-size:14px;margin-bottom:16px;">
                    Enter the email you used to register at ChargeGuard. Everything else is configured automatically.
                </p>

                <label style="font-size:13px;font-weight:600;color:#333;">
                    Your ChargeGuard Email
                </label>
                <input
                    type="email"
                    id="cg-email-input"
                    class="cg-input"
                    placeholder="you@yourstore.com"
                    autocomplete="email"
                />

                <button class="cg-btn cg-btn-primary" id="cg-connect-btn">
                    🔌 Connect ChargeGuard
                </button>

                <div class="cg-message" id="cg-message"></div>
            </div>

        <?php endif; ?>

        <?php if ($is_connected): ?>
        <!-- Access Control -->
        <div class="cg-card" id="cg-access-control">
            <h3 style="margin:0 0 4px;font-size:15px;">🔐 Access Control</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Trusted visitors always bypass security checks. Blocked visitors are always rejected.
            </p>

            <!-- Tab Switcher -->
            <div style="display:flex;gap:0;border-bottom:2px solid #e0e0e0;margin-bottom:20px;">
                <button class="cg-ac-tab cg-ac-active" data-tab="whitelist"
                    style="flex:1;padding:10px;border:none;background:none;cursor:pointer;
                           font-size:13px;font-weight:600;color:#16a34a;
                           border-bottom:2px solid #16a34a;margin-bottom:-2px;">
                    ✅ Always Allow
                </button>
                <button class="cg-ac-tab" data-tab="blacklist"
                    style="flex:1;padding:10px;border:none;background:none;cursor:pointer;
                           font-size:13px;font-weight:600;color:#999;
                           border-bottom:2px solid transparent;margin-bottom:-2px;">
                    🚫 Always Block
                </button>
            </div>

            <!-- Whitelist Panel -->
            <div id="cg-tab-whitelist">
                <!-- Onboarding Banner -->
                <?php if ($current_admin_ip): ?>
                <div id="cg-whitelist-onboarding"
                     style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;
                            padding:12px 16px;margin-bottom:16px;display:flex;
                            align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
                    <span style="font-size:13px;color:#16a34a;">
                        💡 <strong>Quick setup:</strong> Add your IP to never get blocked
                        <span style="font-family:monospace;background:#dcfce7;padding:2px 6px;
                                     border-radius:4px;font-size:12px;">
                            <?php echo esc_html($current_admin_ip); ?>
                        </span>
                    </span>
                    <button id="cg-add-my-ip" class="cg-btn cg-btn-primary"
                            style="margin:0;padding:6px 14px;font-size:12px;">
                        + Add My IP
                    </button>
                </div>
                <?php endif; ?>

                <!-- Add Form -->
                <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start;">
                    <select id="cg-wl-type" class="cg-select" style="min-width:110px;">
                        <option value="IP">IP Address</option>
                        <option value="EMAIL">Email</option>
                        <option value="BIN">Card BIN</option>
                    </select>
                    <input type="text" id="cg-wl-value" class="cg-input"
                           placeholder="e.g. 197.12.34.56"
                           style="flex:1;min-width:160px;margin:0;" />
                    <input type="text" id="cg-wl-reason" class="cg-input"
                           placeholder="Note (optional)"
                           style="flex:1;min-width:120px;margin:0;" />
                    <button id="cg-wl-add" class="cg-btn cg-btn-primary"
                            style="margin:0;white-space:nowrap;">
                        + Add to Safe List
                    </button>
                </div>
                <div id="cg-wl-message" class="cg-message"></div>
                <div id="cg-wl-table-wrap">
                    <p style="color:#999;font-size:13px;">Loading…</p>
                </div>
            </div>

            <!-- Blacklist Panel -->
            <div id="cg-tab-blacklist" style="display:none;">
                <!-- Add Form -->
                <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start;">
                    <select id="cg-bl-type" class="cg-select" style="min-width:130px;">
                        <option value="IP">IP Address</option>
                        <option value="EMAIL">Email</option>
                        <option value="BIN">Card BIN</option>
                        <option value="DEVICE_FINGERPRINT">Device ID</option>
                    </select>
                    <input type="text" id="cg-bl-value" class="cg-input"
                           placeholder="e.g. 45.33.32.156"
                           style="flex:1;min-width:160px;margin:0;" />
                    <input type="text" id="cg-bl-reason" class="cg-input"
                           placeholder="Reason (optional)"
                           style="flex:1;min-width:120px;margin:0;" />
                    <button id="cg-bl-add" class="cg-btn"
                            style="margin:0;background:#fef2f2;color:#dc2626;
                                   border:1px solid #fecaca;white-space:nowrap;">
                        🚫 Block This
                    </button>
                </div>
                <div id="cg-bl-message" class="cg-message"></div>
                <div id="cg-bl-table-wrap">
                    <p style="color:#999;font-size:13px;">Loading…</p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <?php if ($is_connected): ?>
        <!-- Geo Risk Intelligence -->
        <div class="cg-card" id="cg-geo-risk-controls">
            <h3 style="margin:0 0 4px;font-size:15px;">🌍 Geo Risk Intelligence</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Fine-tune how ChargeGuard handles transactions from specific regions.
                Smart defaults work for most stores — override only when you have specific business needs.
            </p>

            <!-- Summary Badge -->
            <div id="cg-geo-summary"
                 style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;
                        padding:12px 16px;margin-bottom:20px;
                        display:flex;align-items:center;justify-content:space-between;">
                <span style="font-size:13px;color:#475569;">
                    ✅ <strong>Smart Protection Active</strong> —
                    <span id="cg-override-count">Loading...</span>
                </span>
                <span style="font-size:11px;color:#94a3b8;">10 regions monitored</span>
            </div>

            <!-- Tier Groups Container -->
            <div id="cg-geo-tiers">
                <p style="color:#999;font-size:13px;">Loading country data...</p>
            </div>

            <!-- Impact Preview -->
            <div id="cg-geo-impact"
                 style="display:none;margin-top:16px;padding:14px 16px;
                        border-radius:8px;border:1px solid #fde68a;background:#fffbeb;">
                <div id="cg-geo-impact-text" style="font-size:13px;color:#92400e;"></div>
                <div style="display:flex;gap:8px;margin-top:10px;">
                    <button id="cg-geo-confirm" class="cg-btn cg-btn-primary"
                            style="margin:0;padding:7px 16px;font-size:13px;">
                        ✓ Apply Change
                    </button>
                    <button id="cg-geo-cancel" class="cg-btn"
                            style="margin:0;padding:7px 16px;font-size:13px;
                                   background:#fff;border:1px solid #ddd;color:#666;">
                        Cancel
                    </button>
                </div>
            </div>

            <div id="cg-geo-message" class="cg-message"></div>
        </div>
        <?php endif; ?>

        <!-- Firewall Settings -->
        <div class="cg-card">
            <h3 style="margin:0 0 16px;font-size:15px;">⚙️ Firewall Settings</h3>
            <form method="post" action="options.php">
                <?php settings_fields('chargeguard_firewall_settings'); ?>
                <div class="cg-info-row">
                    <span class="cg-info-label">Enable Firewall</span>
                    <input type="checkbox" name="chargeguard_enable_firewall" value="1" <?php checked(1, $firewall_enabled); ?> />
                </div>
                <div class="cg-info-row">
                    <span class="cg-info-label">Block Duration (hours)</span>
                    <input type="number" name="chargeguard_firewall_block_duration" value="<?php echo esc_attr($block_duration); ?>" style="width:70px;padding:4px 8px;border:1px solid #ddd;border-radius:6px;" />
                </div>
                <?php submit_button('Save Settings', 'secondary', 'submit', false, ['style' => 'margin-top:14px;']); ?>
            </form>
        </div>

        <!-- Trust Badge Settings -->
        <div class="cg-card">
            <h3 style="margin:0 0 4px;font-size:15px;">🛡️ <?php esc_html_e( 'Trust Badge', 'chargeguard-woocommerce' ); ?></h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                <?php esc_html_e( 'Show your visitors that your store is protected. The badge increases buyer trust and helps spread ChargeGuard — enabled by default.', 'chargeguard-woocommerce' ); ?>
            </p>

            <form method="post" action="options.php">
                <?php settings_fields( 'chargeguard_badge_settings' ); ?>

                <!-- تفعيل/تعطيل -->
                <div class="cg-info-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Show Badge', 'chargeguard-woocommerce' ); ?></span>
                    <div class="cg-toggle-wrap">
                        <input
                            type="checkbox"
                            class="cg-toggle"
                            name="chargeguard_badge_enabled"
                            id="cg-badge-toggle"
                            value="1"
                            <?php checked( '1', $badge_enabled ); ?>
                        />
                        <label for="cg-badge-toggle" style="font-size:12px;color:#64748b;">
                            <?php esc_html_e( 'Enabled', 'chargeguard-woocommerce' ); ?>
                        </label>
                    </div>
                </div>

                <!-- الموقع -->
                <div class="cg-info-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Badge Location', 'chargeguard-woocommerce' ); ?></span>
                    <select name="chargeguard_badge_location" class="cg-select">
                        <option value="footer"   <?php selected( $badge_location, 'footer' ); ?>>
                            <?php esc_html_e( 'Footer only', 'chargeguard-woocommerce' ); ?>
                        </option>
                        <option value="checkout" <?php selected( $badge_location, 'checkout' ); ?>>
                            <?php esc_html_e( 'Checkout only', 'chargeguard-woocommerce' ); ?>
                        </option>
                        <option value="both"     <?php selected( $badge_location, 'both' ); ?>>
                            <?php esc_html_e( 'Footer & Checkout', 'chargeguard-woocommerce' ); ?>
                        </option>
                    </select>
                </div>

                <!-- نظام الألوان -->
                <div class="cg-info-row">
                    <span class="cg-info-label"><?php esc_html_e( 'Color Scheme', 'chargeguard-woocommerce' ); ?></span>
                    <select name="chargeguard_badge_color" class="cg-select">
                        <option value="light" <?php selected( $badge_color, 'light' ); ?>>
                            <?php esc_html_e( 'Light (white background)', 'chargeguard-woocommerce' ); ?>
                        </option>
                        <option value="dark"  <?php selected( $badge_color, 'dark' ); ?>>
                            <?php esc_html_e( 'Dark (for dark themes)', 'chargeguard-woocommerce' ); ?>
                        </option>
                    </select>
                </div>

                <?php submit_button( __( 'Save Badge Settings', 'chargeguard-woocommerce' ), 'secondary', 'submit', false, array( 'style' => 'margin-top:14px;' ) ); ?>
            </form>

            <!-- معاينة حية -->
            <div class="cg-badge-preview-wrap" style="margin-top:16px;">
                <div class="cg-badge-preview-label"><?php esc_html_e( 'Badge Preview', 'chargeguard-woocommerce' ); ?></div>
                <?php echo chargeguard_get_badge_html(); // phpcs:ignore WordPress.Security.EscapeOutput ?>
            </div>
        </div>

        <!-- PayPal Integration -->
        <?php if ($is_connected): ?>
        <?php
        $pp_enabled    = get_option('chargeguard_paypal_enabled', '0');
        $pp_client_id  = get_option('chargeguard_paypal_client_id', '');
        $pp_webhook_id = get_option('chargeguard_paypal_webhook_id', '');
        $pp_mode       = get_option('chargeguard_paypal_mode', 'sandbox');
        $pp_webhook_url = str_replace( 'http://', 'https://', get_rest_url( null, 'chargeguard/v1/paypal-webhook' ) );
        ?>
        <div class="cg-card" id="cg-paypal-integration">
            <h3 style="margin:0 0 4px;font-size:15px;">🅿️ PayPal Integration</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Extend ChargeGuard protection to payments made via PayPal.
                Connect your PayPal app to monitor card testing attempts across all payment gateways.
            </p>

            <!-- Status Badge -->
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
                <div class="cg-status-badge <?php echo $pp_enabled === '1' ? 'connected' : 'disconnected'; ?>"
                     style="margin-bottom:0;">
                    <div class="cg-dot <?php echo $pp_enabled === '1' ? 'green' : 'gray'; ?>"></div>
                    <?php echo $pp_enabled === '1' ? 'PayPal Protection Active' : 'Not Configured'; ?>
                </div>
                <?php if ($pp_enabled === '1'): ?>
                <span style="font-size:11px;color:#94a3b8;background:#f8fafc;padding:3px 8px;border-radius:4px;border:1px solid #e2e8f0;">
                    <?php echo $pp_mode === 'live' ? '🟢 Live' : '🟡 Sandbox'; ?>
                </span>
                <?php endif; ?>
            </div>

            <!-- Webhook URL (للتاجر لنسخه في PayPal Dashboard) -->
            <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px 16px;margin-bottom:20px;">
                <div style="font-size:12px;font-weight:600;color:#475569;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.5px;">
                    Your Webhook URL
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <code style="flex:1;font-size:12px;background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:8px 12px;color:#1e293b;word-break:break-all;">
                        <?php echo esc_html($pp_webhook_url); ?>
                    </code>
                    <button id="cg-pp-copy-url" class="button" title="Copy URL"
                            style="flex-shrink:0;">
                        📋 Copy
                    </button>
                </div>
                <p style="font-size:11px;color:#94a3b8;margin:8px 0 0;">
                    Paste this URL in your <strong>PayPal Developer Dashboard</strong> → Apps & Credentials → Webhooks.
                </p>
            </div>

            <!-- Inline Setup Guide -->
            <details id="cg-pp-guide" style="margin-bottom:20px;">
                <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#f97316;
                                list-style:none;display:flex;align-items:center;gap:6px;
                                padding:10px 14px;background:#fff7ed;border:1px solid #fed7aa;
                                border-radius:8px;user-select:none;">
                    <span id="cg-pp-guide-arrow" style="transition:transform 0.2s;display:inline-block;">▶</span>
                    📖 How to get your PayPal credentials <span style="font-weight:400;color:#94a3b8;font-size:12px;margin-left:4px;">3 steps · ~2 min</span>
                </summary>
                <div style="border:1px solid #fed7aa;border-top:none;border-radius:0 0 8px 8px;
                            padding:16px 18px;background:#fffbf7;">
                    <div style="display:flex;flex-direction:column;gap:14px;">

                        <!-- Step 1 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">1</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Create a PayPal App
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    Go to
                                    <a href="https://developer.paypal.com/dashboard/applications" target="_blank"
                                       style="color:#f97316;text-decoration:none;font-weight:600;">
                                        PayPal Developer Dashboard ↗
                                    </a>
                                    → <strong>Apps & Credentials</strong> → <strong>Create App</strong>.
                                    Choose <em>Merchant</em> as the app type.
                                </div>
                            </div>
                        </div>

                        <!-- Step 2 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">2</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Copy your Client ID & Secret
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    Inside your app page, copy the <strong>Client ID</strong> and
                                    <strong>Secret</strong> from the credentials section.
                                    Use <em>Sandbox</em> for testing, <em>Live</em> for production.
                                </div>
                            </div>
                        </div>

                        <!-- Step 3 -->
                        <div style="display:flex;gap:12px;align-items:flex-start;">
                            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;
                                        background:#f97316;color:#fff;font-size:12px;font-weight:700;
                                        display:flex;align-items:center;justify-content:center;">3</div>
                            <div>
                                <div style="font-size:13px;font-weight:600;color:#1e293b;margin-bottom:3px;">
                                    Add a Webhook & get the Webhook ID
                                </div>
                                <div style="font-size:12px;color:#64748b;line-height:1.5;">
                                    In the same app page → <strong>Webhooks</strong> → <strong>Add Webhook</strong>.
                                    Paste your Webhook URL above, select these events:
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        PAYMENT.CAPTURE.COMPLETED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        PAYMENT.CAPTURE.DENIED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        CHECKOUT.ORDER.APPROVED
                                    </code>
                                    <code style="background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:11px;">
                                        RISK.DISPUTE.CREATED
                                    </code>.
                                    After saving, copy the <strong>Webhook ID</strong> shown on the webhook page.
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </details>

            <!-- Fields -->
            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Environment</span>
                <div style="display:flex;gap:0;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
                    <button class="cg-pp-mode-btn <?php echo $pp_mode === 'sandbox' ? 'active' : ''; ?>"
                            data-mode="sandbox"
                            style="padding:7px 16px;border:none;cursor:pointer;font-size:13px;font-weight:600;
                                   background:<?php echo $pp_mode === 'sandbox' ? '#f0fdf4' : '#fff'; ?>;
                                   color:<?php echo $pp_mode === 'sandbox' ? '#16a34a' : '#999'; ?>;">
                        Sandbox
                    </button>
                    <button class="cg-pp-mode-btn <?php echo $pp_mode === 'live' ? 'active' : ''; ?>"
                            data-mode="live"
                            style="padding:7px 16px;border:none;cursor:pointer;font-size:13px;font-weight:600;
                                   background:<?php echo $pp_mode === 'live' ? '#f0fdf4' : '#fff'; ?>;
                                   color:<?php echo $pp_mode === 'live' ? '#16a34a' : '#999'; ?>;
                                   border-left:1px solid #ddd;">
                        Live
                    </button>
                </div>
                <input type="hidden" id="cg-pp-mode" value="<?php echo esc_attr($pp_mode); ?>" />
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Client ID</span>
                <input type="text" id="cg-pp-client-id" class="cg-input"
                       value="<?php echo esc_attr($pp_client_id); ?>"
                       placeholder="AYour_PayPal_Client_ID"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    Found in your PayPal App → Credentials
                </span>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Client Secret</span>
                <input type="password" id="cg-pp-client-secret" class="cg-input"
                       value=""
                       placeholder="<?php echo $pp_client_id ? '••••••••••••••••' : 'EYour_PayPal_Client_Secret'; ?>"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    <?php echo $pp_client_id ? 'Leave blank to keep your current secret' : 'Found in your PayPal App → Credentials'; ?>
                </span>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:130px;">Webhook ID</span>
                <input type="text" id="cg-pp-webhook-id" class="cg-input"
                       value="<?php echo esc_attr($pp_webhook_id); ?>"
                       placeholder="Get this from PayPal Developer Dashboard"
                       style="flex:1;min-width:200px;margin:0;" />
                <span style="font-size:11px;color:#94a3b8;width:100%;padding-left:138px;">
                    Found on your Webhook page after saving it in PayPal
                </span>
            </div>

            <div class="cg-info-row">
                <span class="cg-info-label">Enable Protection</span>
                <div class="cg-toggle-wrap">
                    <input type="checkbox" class="cg-toggle" id="cg-pp-enabled"
                           <?php checked('1', $pp_enabled); ?> />
                    <label for="cg-pp-enabled" style="font-size:12px;color:#64748b;">Active</label>
                </div>
            </div>

            <div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap;">
                <button id="cg-pp-save" class="cg-btn cg-btn-primary" style="margin:0;">
                    💾 Save PayPal Settings
                </button>
                <button id="cg-pp-test" class="cg-btn"
                        style="margin:0;background:#fff;color:#f97316;border:1px solid #f97316;">
                    🔗 Test Connection
                </button>
            </div>
            <div id="cg-pp-message" class="cg-message" style="margin-top:10px;"></div>
        </div>
        <?php endif; ?>

        <!-- Notification Channels -->
        <?php if ($is_connected): ?>
        <div class="cg-card" id="cg-notification-channels">
            <h3 style="margin:0 0 4px;font-size:15px;">📢 Notification Channels</h3>
            <p style="margin:0 0 16px;font-size:13px;color:#64748b;">
                Receive attack alerts in Slack or Discord alongside email notifications.
            </p>

            <div class="cg-info-row">
                <span class="cg-info-label">Email Notifications</span>
                <span class="cg-info-value" style="color:#16a34a;">✅ Always Active</span>
            </div>

            <div style="border-top:1px solid #f0f0f0;padding-top:14px;margin-top:4px;">
                <label style="font-size:13px;font-weight:600;color:#333;">Webhook Platform</label>
                <div style="display:flex;gap:0;margin:10px 0 16px;border:1px solid #ddd;border-radius:8px;overflow:hidden;">
                    <button class="cg-webhook-tab cg-webhook-active" data-type="slack"
                        style="flex:1;padding:10px;border:none;background:#f0fdf4;cursor:pointer;font-size:13px;font-weight:600;color:#16a34a;">
                        Slack
                    </button>
                    <button class="cg-webhook-tab" data-type="discord"
                        style="flex:1;padding:10px;border:none;background:#fff;cursor:pointer;font-size:13px;font-weight:600;color:#999;border-left:1px solid #ddd;">
                        Discord
                    </button>
                    <button class="cg-webhook-tab" data-type="custom"
                        style="flex:1;padding:10px;border:none;background:#fff;cursor:pointer;font-size:13px;font-weight:600;color:#999;border-left:1px solid #ddd;">
                        Custom
                    </button>
                </div>
                <p id="cg-webhook-guide" style="font-size:12px;color:#94a3b8;margin:0 0 12px;">
                    Create an <strong>Incoming Webhook</strong> in Slack → paste the URL below.
                </p>
            </div>

            <div class="cg-info-row" style="flex-wrap:wrap;gap:8px;">
                <span class="cg-info-label" style="min-width:100px;">Webhook URL</span>
                <input type="url" id="cg-webhook-url" class="cg-input"
                       placeholder="https://hooks.slack.com/services/..."
                       style="flex:1;min-width:220px;margin:0;" />
            </div>

            <div style="display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap;">
                <button id="cg-webhook-save" class="cg-btn cg-btn-primary" style="margin:0;">
                    💾 Save Webhook
                </button>
                <button id="cg-webhook-test" class="cg-btn" style="margin:0;background:#fff;color:#f97316;border:1px solid #f97316;">
                    📤 Send Test Notification
                </button>
                <div id="cg-webhook-status" style="font-size:12px;color:#94a3b8;display:flex;align-items:center;gap:6px;">
                    <span id="cg-webhook-status-dot" style="display:none;width:8px;height:8px;border-radius:50%;"></span>
                    <span id="cg-webhook-status-text">Not configured</span>
                </div>
            </div>
            <div id="cg-webhook-message" class="cg-message" style="margin-top:10px;"></div>
        </div>
        <?php endif; ?>

        </div>

        <script>        (function($) {
            const nonce          = '<?php echo esc_js($nonce); ?>';
            const cgCurrentIp    = '<?php echo esc_js($current_admin_ip); ?>';
            const cgMerchantId   = '<?php echo esc_js(get_option("chargeguard_merchant_id")); ?>';

            // ── Helper: HTML Escape ──────────────────────────────────
            function escHtml(str) {
                return String(str)
                    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
                    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            }

            // ── Helper: Render Table ─────────────────────────────────
            function renderTable(entries, wrapId, listType) {
                const $wrap = $('#' + wrapId);
                if (!entries || entries.length === 0) {
                    $wrap.html('<p style="color:#999;font-size:13px;text-align:center;padding:20px 0;">No entries yet.</p>');
                    return;
                }
                let html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">' +
                    '<thead><tr style="border-bottom:2px solid #f0f0f0;">' +
                    '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;width:80px;">Type</th>' +
                    '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Value</th>' +
                    '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;">Note</th>' +
                    '<th style="text-align:left;padding:8px 4px;color:#666;font-weight:600;width:90px;">Added</th>' +
                    '<th style="width:32px;"></th></tr></thead><tbody>';

                entries.forEach(function(e) {
                    const isExpired = e.expiresAt && new Date(e.expiresAt) < new Date();
                    const dateStr   = new Date(e.createdAt).toLocaleDateString('en-GB', { day:'2-digit', month:'short' });
                    const valStyle  = isExpired ? 'color:#999;text-decoration:line-through;' : 'font-family:monospace;';
                    html += '<tr style="border-bottom:1px solid #f8f8f8;">' +
                        '<td style="padding:9px 4px;"><span style="background:#f1f5f9;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600;color:#475569;">' + escHtml(e.type) + '</span></td>' +
                        '<td style="padding:9px 4px;' + valStyle + '">' + escHtml(e.value) + (isExpired ? ' <span style="color:#f59e0b;font-size:11px;">(expired)</span>' : '') + '</td>' +
                        '<td style="padding:9px 4px;color:#94a3b8;">' + (e.reason ? escHtml(e.reason) : '—') + '</td>' +
                        '<td style="padding:9px 4px;color:#94a3b8;">' + dateStr + '</td>' +
                        '<td style="padding:9px 4px;text-align:center;"><button class="cg-delete-entry" data-id="' + escHtml(e.id) + '" data-list="' + listType + '" title="Remove" style="background:none;border:none;cursor:pointer;color:#fca5a5;font-size:16px;padding:2px 6px;border-radius:4px;" onmouseover="this.style.background=\'#fef2f2\'" onmouseout="this.style.background=\'none\'">×</button></td>' +
                        '</tr>';
                });
                html += '</tbody></table>';
                $wrap.html(html);
            }

            // ── Load Whitelist ───────────────────────────────────────
            function loadWhitelist() {
                $('#cg-wl-table-wrap').html('<p style="color:#999;font-size:13px;">Loading…</p>');
                $.post(ajaxurl, {
                    action: 'chargeguard_whitelist_get',
                    nonce:  nonce,
                    merchantId: cgMerchantId,
                }, function(res) {
                    if (res.success) {
                        renderTable(res.data.entries, 'cg-wl-table-wrap', 'whitelist');
                        if (res.data.entries && res.data.entries.length > 0) {
                            $('#cg-whitelist-onboarding').hide();
                        }
                    }
                });
            }

            // ── Load Blacklist ───────────────────────────────────────
            function loadBlacklist() {
                $('#cg-bl-table-wrap').html('<p style="color:#999;font-size:13px;">Loading…</p>');
                $.post(ajaxurl, {
                    action: 'chargeguard_blacklist_get',
                    nonce:  nonce,
                    merchantId: cgMerchantId,
                }, function(res) {
                    if (res.success) {
                        renderTable(res.data.entries, 'cg-bl-table-wrap', 'blacklist');
                    }
                });
            }

            // ── Tab Switcher ─────────────────────────────────────────
            $(document).on('click', '.cg-ac-tab', function() {
                const tab = $(this).data('tab');
                $('.cg-ac-tab').css({ color:'#999', borderBottomColor:'transparent' });
                $(this).css({
                    color: tab === 'whitelist' ? '#16a34a' : '#dc2626',
                    borderBottomColor: tab === 'whitelist' ? '#16a34a' : '#dc2626'
                });
                $('#cg-tab-whitelist, #cg-tab-blacklist').hide();
                $('#cg-tab-' + tab).show();
                if (tab === 'whitelist') loadWhitelist();
                else loadBlacklist();
            });

            // ── Add My IP ────────────────────────────────────────────
            $('#cg-add-my-ip').on('click', function() {
                const $btn = $(this);
                $btn.prop('disabled', true).text('Adding…');
                $.post(ajaxurl, {
                    action: 'chargeguard_whitelist_add',
                    nonce:  nonce,
                    type:   'IP',
                    value:  cgCurrentIp,
                    reason: 'My admin IP — added automatically',
                }, function(res) {
                    if (res.success) {
                        $('#cg-whitelist-onboarding').slideUp(300);
                        loadWhitelist();
                    } else {
                        $btn.prop('disabled', false).text('+ Add My IP');
                    }
                });
            });

            // ── Dynamic Placeholder ──────────────────────────────────
            const wlPlaceholders = { IP:'e.g. 197.12.34.56', EMAIL:'e.g. john@mystore.com', BIN:'e.g. 411111 (first 6 digits)' };
            const blPlaceholders = { IP:'e.g. 45.33.32.156', EMAIL:'e.g. fraud@example.com', BIN:'e.g. 411111 (first 6 digits)', DEVICE_FINGERPRINT:'Device fingerprint ID' };
            $('#cg-wl-type').on('change', function() { $('#cg-wl-value').attr('placeholder', wlPlaceholders[$(this).val()] || ''); });
            $('#cg-bl-type').on('change', function() { $('#cg-bl-value').attr('placeholder', blPlaceholders[$(this).val()] || ''); });

            // ── Add to Whitelist ─────────────────────────────────────
            $('#cg-wl-add').on('click', function() {
                const type   = $('#cg-wl-type').val();
                const value  = $('#cg-wl-value').val().trim();
                const reason = $('#cg-wl-reason').val().trim();
                const $msg   = $('#cg-wl-message');
                if (!value) {
                    $msg.removeClass('success').addClass('error').text('Please enter a value.').show();
                    return;
                }
                $(this).prop('disabled', true).text('Adding…');
                $msg.hide().removeClass('error success');
                $.post(ajaxurl, {
                    action: 'chargeguard_whitelist_add',
                    nonce, type, value, reason,
                }, function(res) {
                    if (res.success) {
                        $('#cg-wl-value, #cg-wl-reason').val('');
                        $msg.removeClass('error').addClass('success').text('✓ Added to safe list.').show();
                        loadWhitelist();
                        setTimeout(function() { $msg.fadeOut(); }, 3000);
                    } else {
                        $msg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to add. Try again.').show();
                    }
                    $('#cg-wl-add').prop('disabled', false).text('+ Add to Safe List');
                });
            });

            // ── Add to Blacklist ─────────────────────────────────────
            $('#cg-bl-add').on('click', function() {
                const type   = $('#cg-bl-type').val();
                const value  = $('#cg-bl-value').val().trim();
                const reason = $('#cg-bl-reason').val().trim();
                const $msg   = $('#cg-bl-message');
                if (!value) {
                    $msg.removeClass('success').addClass('error').text('Please enter a value.').show();
                    return;
                }
                if (type === 'IP' && value === cgCurrentIp) {
                    if (!window.confirm('⚠️ Warning\n\nThis is your current admin IP address.\nBlocking it may disrupt your store\'s connection to ChargeGuard.\n\nAre you absolutely sure?')) return;
                }
                $(this).prop('disabled', true).text('Blocking…');
                $msg.hide().removeClass('error success');
                $.post(ajaxurl, {
                    action: 'chargeguard_blacklist_add',
                    nonce, type, value, reason,
                }, function(res) {
                    if (res.success) {
                        $('#cg-bl-value, #cg-bl-reason').val('');
                        $msg.removeClass('error').addClass('success').text('✓ Added to blocked list.').show();
                        loadBlacklist();
                        setTimeout(function() { $msg.fadeOut(); }, 3000);
                    } else {
                        $msg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to add. Try again.').show();
                    }
                    $('#cg-bl-add').prop('disabled', false).text('🚫 Block This');
                });
            });

            // ── Delete Entry ─────────────────────────────────────────
            $(document).on('click', '.cg-delete-entry', function() {
                const id       = $(this).data('id');
                const listType = $(this).data('list');
                const action   = listType === 'whitelist' ? 'chargeguard_whitelist_delete' : 'chargeguard_blacklist_delete';
                const $row     = $(this).closest('tr');
                $row.fadeOut(200, function() { $(this).remove(); });
                $.post(ajaxurl, { action, nonce, id }, function(res) {
                    if (!res.success) {
                        if (listType === 'whitelist') loadWhitelist();
                        else loadBlacklist();
                    }
                });
            });

            // ── تحميل تلقائي عند فتح الصفحة ─────────────────────────
            <?php if ($is_connected): ?>
            loadWhitelist();
            <?php endif; ?>

            // ── Connect ──────────────────────────────────────────────
            $('#cg-connect-btn').on('click', function() {
                const email = $('#cg-email-input').val().trim();
                const $btn  = $(this);
                const $msg  = $('#cg-message');

                if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                    $msg.removeClass('success').addClass('error').text('Please enter a valid email address.').show();
                    return;
                }

                // Step 2
                $('#cg-step-1').removeClass('active').addClass('done');
                $('#cg-step-2').addClass('active');
                $btn.prop('disabled', true).html('<span class="cg-spinner"></span> Connecting…');
                $msg.hide().removeClass('error success');

                $.post(ajaxurl, {
                    action: 'chargeguard_connect',
                    nonce:  nonce,
                    email:  email,
                }, function(res) {
                    if (res.success) {
                        // Step 3
                        $('#cg-step-2').removeClass('active').addClass('done');
                        $('#cg-step-3').addClass('active done');
                        $msg.removeClass('error').addClass('success')
                            .text('✅ Connected successfully! Reloading…').show();
                        setTimeout(() => location.reload(), 1500);
                    } else {
                        $('#cg-step-2').removeClass('active');
                        $('#cg-step-1').removeClass('done').addClass('active');
                        $msg.removeClass('success').addClass('error').text(res.data.message).show();
                        $btn.prop('disabled', false).html('🔌 Connect ChargeGuard');
                    }
                }).fail(function() {
                    $msg.removeClass('success').addClass('error')
                        .text('Connection failed. Please try again.').show();
                    $btn.prop('disabled', false).html('🔌 Connect ChargeGuard');
                });
            });

            // ── Verify Key ───────────────────────────────────────────────
            $('#cg-verify-key-btn').on('click', function() {
                const $btn    = $(this);
                const $status = $('#cg-key-status');

                $btn.prop('disabled', true).text('Verifying…');
                $status.hide().css({ background: '', border: '', color: '' });

                $.post(ajaxurl, {
                    action: 'chargeguard_verify_key',
                    nonce:  nonce,
                }, function(res) {
                    if (res.success) {
                        $status.css({
                            background: '#f0fdf4',
                            border:     '1px solid #bbf7d0',
                            color:      '#16a34a',
                        }).text('✓ API key is valid and active.').show();
                    } else {
                        $status.css({
                            background: '#fef2f2',
                            border:     '1px solid #fecaca',
                            color:      '#dc2626',
                        }).text('✗ ' + (res.data.message || 'Invalid API key. Please reconnect.')).show();
                    }
                }).fail(function() {
                    $status.css({
                        background: '#fef2f2',
                        border:     '1px solid #fecaca',
                        color:      '#dc2626',
                    }).text('✗ Could not reach server. Try again.').show();
                }).always(function() {
                    $btn.prop('disabled', false).text('Verify Key');
                });
            });

            // ── Disconnect ───────────────────────────────────────────────
            $('#cg-disconnect-btn').on('click', function() {
                if (!confirm('Are you sure you want to disconnect ChargeGuard?')) return;
                const $btn = $(this);
                $btn.prop('disabled', true).text('Disconnecting…');

                $.post(ajaxurl, {
                    action: 'chargeguard_disconnect',
                    nonce:  nonce,
                }, function(res) {
                    if (res.success) location.reload();
                });
            });

            // ── Webhook ────────────────────────────────────────────────
            const $webhookUrl    = $('#cg-webhook-url');
            const $webhookMsg    = $('#cg-webhook-message');
            const $webhookStatus = $('#cg-webhook-status-text');
            const $webhookDot    = $('#cg-webhook-status-dot');
            let currentType      = 'slack';

            // Tab switcher
            $('.cg-webhook-tab').on('click', function() {
                currentType = $(this).data('type');
                $('.cg-webhook-tab').css({ background:'#fff', color:'#999' });
                $(this).css({ background:'#f0fdf4', color:'#16a34a' });
                // Update guide text
                const guides = {
                    slack:  'Create an <strong>Incoming Webhook</strong> in Slack → paste the URL below.',
                    discord: 'Create an <strong>Incoming Webhook</strong> in Discord → paste the URL below.',
                    custom: 'Enter any HTTPS URL that accepts JSON POST requests.'
                };
                $('#cg-webhook-guide').html(guides[currentType] || guides.custom);
            });

            // Load saved settings on page load
            $.post(ajaxurl, { action: 'chargeguard_webhook_status', nonce }, function(res) {
                if (res.success) {
                    const d = res.data;
                    if (d.webhookUrl) {
                        $webhookUrl.val(d.webhookUrl);
                        currentType = d.webhookType || 'custom';
                        $('.cg-webhook-tab').css({ background:'#fff', color:'#999' });
                        const $tab = $('.cg-webhook-tab[data-type="' + currentType + '"]');
                        if ($tab.length) $tab.css({ background:'#f0fdf4', color:'#16a34a' });
                        else { currentType = 'custom'; $('.cg-webhook-tab[data-type="custom"]').css({ background:'#f0fdf4', color:'#16a34a' }); }
                    }
                    if (d.webhookLastStatus === 'success') {
                        $webhookStatus.text('Last test: successful');
                        $webhookDot.css({ background:'#16a34a' }).show();
                    } else if (d.webhookLastStatus === 'failed') {
                        $webhookStatus.text('Last test: failed (' + (d.webhookFailureCount || 0) + ' attempts)');
                        $webhookDot.css({ background:'#dc2626' }).show();
                    } else if (d.webhookUrl) {
                        $webhookStatus.text('Saved — not tested yet');
                        $webhookDot.css({ background:'#f59e0b' }).show();
                    }
                }
            });

            // Save webhook
            $('#cg-webhook-save').on('click', function() {
                const url   = $webhookUrl.val().trim();
                const $btn  = $(this);
                if (!url) {
                    $webhookMsg.removeClass('success').addClass('error').text('Please enter a webhook URL.').show();
                    return;
                }
                if (!url.startsWith('https://')) {
                    $webhookMsg.removeClass('success').addClass('error').text('Only HTTPS URLs are allowed.').show();
                    return;
                }
                $btn.prop('disabled', true).text('Saving…');
                $webhookMsg.hide().removeClass('error success');
                $.post(ajaxurl, {
                    action:       'chargeguard_webhook_save',
                    nonce:        nonce,
                    webhook_url:  url,
                    webhook_type: currentType,
                }, function(res) {
                    if (res.success) {
                        $webhookMsg.removeClass('error').addClass('success').text('✓ Webhook saved.').show();
                        $webhookStatus.text('Saved — not tested yet');
                        $webhookDot.css({ background:'#f59e0b' }).show();
                        setTimeout(function() { $webhookMsg.fadeOut(); }, 3000);
                    } else {
                        $webhookMsg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Failed to save.').show();
                    }
                    $btn.prop('disabled', false).text('💾 Save Webhook');
                });
            });

            // Test webhook
            $('#cg-webhook-test').on('click', function() {
                const $btn = $(this);
                $btn.prop('disabled', true).text('Testing…');
                $webhookMsg.hide().removeClass('error success');
                $.post(ajaxurl, {
                    action: 'chargeguard_webhook_test',
                    nonce:  nonce,
                }, function(res) {
                    if (res.success) {
                        $webhookMsg.removeClass('error').addClass('success').text('✓ Test notification sent! Check your channel.').show();
                        $webhookStatus.text('Last test: successful');
                        $webhookDot.css({ background:'#16a34a' }).show();
                    } else {
                        $webhookMsg.removeClass('success').addClass('error').text((res.data && res.data.message) || 'Test failed. Check your webhook URL.').show();
                        $webhookStatus.text('Last test: failed');
                        $webhookDot.css({ background:'#dc2626' }).show();
                    }
                    $btn.prop('disabled', false).text('📤 Send Test Notification');
                });
            });

        // ── PayPal Integration ────────────────────────────────────────
            let cgPpMode = $('#cg-pp-mode').val() || 'sandbox';

            // Guide arrow animation
            $('#cg-pp-guide').on('toggle', function() {
                $('#cg-pp-guide-arrow').css(
                    'transform',
                    this.open ? 'rotate(90deg)' : 'rotate(0deg)'
                );
            });

            // Mode toggle
            $(document).on('click', '.cg-pp-mode-btn', function() {
                cgPpMode = $(this).data('mode');
                $('#cg-pp-mode').val(cgPpMode);
                $('.cg-pp-mode-btn').css({ background: '#fff', color: '#999' });
                $(this).css({ background: '#f0fdf4', color: '#16a34a' });
            });

            // Copy Webhook URL
            $('#cg-pp-copy-url').on('click', function() {
                const url = $('code', '#cg-paypal-integration').first().text().trim();
                navigator.clipboard.writeText(url).then(function() {
                    $('#cg-pp-copy-url').text('✓ Copied!');
                    setTimeout(function() { $('#cg-pp-copy-url').text('📋 Copy'); }, 2000);
                });
            });

            // Save PayPal Settings
            $('#cg-pp-save').on('click', function() {
                const $btn    = $(this);
                const $msg    = $('#cg-pp-message');
                const secret  = $('#cg-pp-client-secret').val().trim();

                $btn.prop('disabled', true).text('Saving…');
                $msg.hide().removeClass('error success');

                const postData = {
                    action:        'chargeguard_paypal_save',
                    nonce:         nonce,
                    client_id:     $('#cg-pp-client-id').val().trim(),
                    webhook_id:    $('#cg-pp-webhook-id').val().trim(),
                    mode:          cgPpMode,
                    enabled:       $('#cg-pp-enabled').is(':checked') ? '1' : '0',
                };
                if (secret) postData.client_secret = secret;

                $.post(ajaxurl, postData, function(res) {
                    if (res.success) {
                        $msg.removeClass('error').addClass('success')
                            .text('✓ PayPal settings saved.').show();
                        $('#cg-pp-client-secret').val('').attr('placeholder', '••••••••••••••••');
                        setTimeout(function() { $msg.fadeOut(); }, 3000);
                    } else {
                        $msg.removeClass('success').addClass('error')
                            .text((res.data && res.data.message) || 'Failed to save.').show();
                    }
                    $btn.prop('disabled', false).text('💾 Save PayPal Settings');
                });
            });

            // Test PayPal Connection
            $('#cg-pp-test').on('click', function() {
                const $btn = $(this);
                const $msg = $('#cg-pp-message');
                $btn.prop('disabled', true).text('Testing…');
                $msg.hide().removeClass('error success');

                $.post(ajaxurl, {
                    action: 'chargeguard_paypal_test',
                    nonce:  nonce,
                }, function(res) {
                    if (res.success) {
                        $msg.removeClass('error').addClass('success')
                            .text((res.data && res.data.message) || '✓ Connected.').show();
                    } else {
                        $msg.removeClass('success').addClass('error')
                            .text((res.data && res.data.message) || 'Connection failed.').show();
                    }
                    $btn.prop('disabled', false).text('🔗 Test Connection');
                });
            });

            // ── Geo Risk Intelligence ─────────────────────────────────────
            const TIER_CONFIG = {
                critical: { emoji: '🛑', label: 'Extreme Risk',   color: '#dc2626', bg: '#fef2f2' },
                high:     { emoji: '⚠️', label: 'High Risk',      color: '#ea580c', bg: '#fff7ed' },
                medium:   { emoji: '🟡', label: 'Moderate Risk',  color: '#ca8a04', bg: '#fefce8' },
                elevated: { emoji: '🔵', label: 'Monitored',      color: '#2563eb', bg: '#eff6ff' },
            };

            const OVERRIDE_CONFIG = {
                smart:    { label: '● Smart',    color: '#16a34a', desc: 'Use ChargeGuard default' },
                allow:    { label: '○ Allow',    color: '#2563eb', desc: 'Remove country penalty'  },
                escalate: { label: '○ Escalate', color: '#ea580c', desc: 'Double country penalty'  },
            };

            let cgGeoCountries    = [];
            let cgPendingChange   = null;

            function cgGetEffectivePenalty(basePenalty, override) {
                if (override === 'allow')    return 0;
                if (override === 'escalate') return Math.min(basePenalty * 2, 20);
                return basePenalty;
            }

            function cgBuildImpactText(change) {
                const c        = change.country;
                const tierConf = TIER_CONFIG[c.tier] || TIER_CONFIG.elevated;
                const newPenalty = cgGetEffectivePenalty(c.basePenalty, change.newOverride);
                const oldPenalty = cgGetEffectivePenalty(c.basePenalty, change.currentOverride);

                if (change.newOverride === 'allow') {
                    return tierConf.emoji + ' Removing the +' + c.basePenalty +
                        ' pt risk penalty for <strong>' + escHtml(c.name) + '</strong>. ' +
                        'All other fraud signals still apply.' +
                        (c.tier === 'critical' ? ' <strong style="color:#dc2626;">⚠️ High-risk region — monitor chargebacks closely.</strong>' : '');
                }
                if (change.newOverride === 'escalate') {
                    return '⬆️ Escalating <strong>' + escHtml(c.name) + '</strong> penalty from ' +
                        oldPenalty + ' to <strong>' + newPenalty + ' pts</strong>. ' +
                        'Transactions from this region will be scored more strictly.';
                }
                return '↩️ Restoring <strong>' + escHtml(c.name) +
                    '</strong> to Smart default (' + c.basePenalty + ' pts).';
            }

            function cgRenderTierGroups(countries) {
                const byTier = {};
                countries.forEach(function(c) {
                    if (!byTier[c.tier]) byTier[c.tier] = [];
                    byTier[c.tier].push(c);
                });

                const tierOrder = ['critical', 'high', 'medium', 'elevated'];
                let html = '';

                tierOrder.forEach(function(tier) {
                    if (!byTier[tier] || !byTier[tier].length) return;
                    const tc = TIER_CONFIG[tier];
                    html += '<div style="margin-bottom:16px;">';
                    html += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;">';
                    html += '<span style="font-size:13px;font-weight:700;color:' + tc.color + ';">' +
                            tc.emoji + ' ' + tc.label + '</span>';
                    html += '</div>';

                    byTier[tier].forEach(function(c) {
                        const cur = c.currentOverride || 'smart';
                        html += '<div style="display:flex;align-items:center;justify-content:space-between;' +
                                'padding:10px 12px;border-radius:8px;background:' + tc.bg + ';' +
                                'border:1px solid ' + tc.color + '22;margin-bottom:6px;flex-wrap:wrap;gap:8px;">';

                        // اسم الدولة + penalty
                        html += '<div style="display:flex;align-items:center;gap:8px;min-width:140px;">';
                        html += '<span style="font-size:14px;">' + cgGetFlag(c.code) + '</span>';
                        html += '<span style="font-size:13px;font-weight:600;color:#1e293b;">' +
                                escHtml(c.name) + '</span>';
                        html += '<span id="cg-penalty-' + c.code + '" ' +
                                'style="font-size:11px;color:' + tc.color + ';background:' + tc.color + '15;' +
                                'padding:2px 6px;border-radius:4px;font-weight:600;">' +
                                '-' + cgGetEffectivePenalty(c.basePenalty, cur) + ' pts</span>';
                        html += '</div>';

                        // Radio buttons
                        html += '<div style="display:flex;gap:6px;">';
                        ['smart', 'allow', 'escalate'].forEach(function(ov) {
                            const isActive = cur === ov;
                            const ovConf   = OVERRIDE_CONFIG[ov];
                            const btnColor = isActive ? ovConf.color : '#94a3b8';
                            const btnBg    = isActive ? ovConf.color + '15' : '#fff';
                            const border   = isActive ? ovConf.color : '#e2e8f0';
                            html += '<button class="cg-geo-radio" ' +
                                    'data-code="' + escHtml(c.code) + '" ' +
                                    'data-override="' + ov + '" ' +
                                    'title="' + escHtml(ovConf.desc) + '" ' +
                                    'style="padding:5px 10px;border-radius:6px;font-size:12px;font-weight:600;' +
                                    'cursor:pointer;border:1px solid ' + border + ';' +
                                    'background:' + btnBg + ';color:' + btnColor + ';">' +
                                    (isActive ? '● ' : '○ ') + ov.charAt(0).toUpperCase() + ov.slice(1) +
                                    '</button>';
                        });
                        html += '</div>';
                        html += '</div>';
                    });

                    html += '</div>';
                });

                $('#cg-geo-tiers').html(html);
            }

            function cgGetFlag(code) {
                try {
                    return code.toUpperCase().replace(/./g, function(c) {
                        return String.fromCodePoint(c.charCodeAt(0) + 127397);
                    });
                } catch(e) { return '🌐'; }
            }

            function cgUpdateSummary(countries) {
                const modified = countries.filter(function(c) { return c.currentOverride !== 'smart'; }).length;
                if (modified === 0) {
                    $('#cg-override-count').text('All regions using Smart defaults');
                } else {
                    $('#cg-override-count').text(modified + ' region' + (modified > 1 ? 's' : '') + ' customized');
                }
            }

            // تحميل البيانات
            <?php if ($is_connected): ?>
            $.post(ajaxurl, {
                action: 'chargeguard_geo_overrides_get',
                nonce:  nonce,
            }, function(res) {
                if (res.success) {
                    cgGeoCountries = res.data.availableCountries || [];
                    cgRenderTierGroups(cgGeoCountries);
                    cgUpdateSummary(cgGeoCountries);
                } else {
                    $('#cg-geo-tiers').html('<p style="color:#dc2626;font-size:13px;">Failed to load geo settings.</p>');
                }
            });
            <?php endif; ?>

            // Radio button click
            $(document).on('click', '.cg-geo-radio', function() {
                const code        = $(this).data('code');
                const newOverride = $(this).data('override');
                const country     = cgGeoCountries.find(function(c) { return c.code === code; });
                if (!country) return;

                const currentOverride = country.currentOverride || 'smart';
                if (currentOverride === newOverride) return;

                cgPendingChange = { code, newOverride, currentOverride, country };

                $('#cg-geo-impact-text').html(cgBuildImpactText(cgPendingChange));
                $('#cg-geo-impact').show();
                $('#cg-geo-message').hide().removeClass('error success');
            });

            // Apply Change
            $('#cg-geo-confirm').on('click', function() {
                if (!cgPendingChange) return;
                const $btn = $(this);
                $btn.prop('disabled', true).text('Saving…');

                $.post(ajaxurl, {
                    action:       'chargeguard_geo_override_save',
                    nonce:        nonce,
                    country_code: cgPendingChange.code,
                    override:     cgPendingChange.newOverride,
                }, function(res) {
                    if (res.success) {
                        // تحديث البيانات المحلية
                        const country = cgGeoCountries.find(function(c) {
                            return c.code === cgPendingChange.code;
                        });
                        if (country) {
                            country.currentOverride  = cgPendingChange.newOverride;
                            country.effectivePenalty = cgGetEffectivePenalty(
                                country.basePenalty,
                                cgPendingChange.newOverride
                            );
                        }

                        // تحديث الـ UI
                        cgRenderTierGroups(cgGeoCountries);
                        cgUpdateSummary(cgGeoCountries);
                        $('#cg-geo-impact').hide();
                        cgPendingChange = null;

                        // Warning لو وُجد
                        const warnings = res.data.warnings || [];
                        if (warnings.length > 0) {
                            $('#cg-geo-message')
                                .removeClass('error').addClass('success')
                                .html('✓ Saved. ⚠️ ' + escHtml(warnings[0].message))
                                .show();
                        } else {
                            $('#cg-geo-message')
                                .removeClass('error').addClass('success')
                                .text('✓ Override saved successfully.')
                                .show();
                        }
                        setTimeout(function() { $('#cg-geo-message').fadeOut(); }, 4000);
                    } else {
                        $('#cg-geo-message')
                            .removeClass('success').addClass('error')
                            .text((res.data && res.data.message) || 'Failed to save. Try again.')
                            .show();
                    }
                    $btn.prop('disabled', false).text('✓ Apply Change');
                });
            });

            // Cancel
            $('#cg-geo-cancel').on('click', function() {
                cgPendingChange = null;
                $('#cg-geo-impact').hide();
            });

        })(jQuery);
        </script>
        <?php
    }
}