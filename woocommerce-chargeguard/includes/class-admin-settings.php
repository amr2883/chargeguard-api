<?php
class ChargeGuard_Admin_Settings {

    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_chargeguard_connect', [$this, 'ajax_connect']);
        add_action('wp_ajax_chargeguard_disconnect', [$this, 'ajax_disconnect']);
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
        register_setting('chargeguard_settings', 'chargeguard_api_key', 'sanitize_text_field');
        register_setting('chargeguard_settings', 'chargeguard_merchant_id', 'sanitize_text_field');
        register_setting('chargeguard_settings', 'chargeguard_webhook_secret', 'sanitize_text_field');
        register_setting('chargeguard_settings', 'chargeguard_stripe_webhook_secret', 'sanitize_text_field');
        register_setting('chargeguard_settings', 'chargeguard_enable_firewall', 'intval');
        register_setting('chargeguard_settings', 'chargeguard_firewall_block_duration', 'intval');

        // Trust Badge options
        register_setting( 'chargeguard_settings', 'chargeguard_badge_enabled',  'sanitize_text_field' );
        register_setting( 'chargeguard_settings', 'chargeguard_badge_location', 'sanitize_text_field' );
        register_setting( 'chargeguard_settings', 'chargeguard_badge_color',    'sanitize_text_field' );
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
                <div class="cg-status-badge connected">
                    <div class="cg-dot green"></div>
                    Active — Your store is protected
                </div>
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

        <!-- Firewall Settings -->
        <div class="cg-card">
            <h3 style="margin:0 0 16px;font-size:15px;">⚙️ Firewall Settings</h3>
            <form method="post" action="options.php">
                <?php settings_fields('chargeguard_settings'); ?>
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
                <?php settings_fields( 'chargeguard_settings' ); ?>

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
            const nonce = '<?php echo esc_js($nonce); ?>';

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

            // ── Disconnect ───────────────────────────────────────────
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