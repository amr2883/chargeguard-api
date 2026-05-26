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

        })(jQuery);
        </script>
        <?php
    }
}