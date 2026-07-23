<?php
/**
 * ChargeGuard - Remote Config Viewer (read-only)
 *
 * Exposes a small, explicitly allow-listed subset of plugin settings over
 * a REST route so ChargeGuard support can diagnose proxy/firewall/auto-block
 * misconfigurations without asking the merchant to screen-share or read
 * settings aloud. Read-only, allow-listed, and gated by a dedicated shared
 * secret — never the merchant's chargeguard_api_key (that authenticates
 * the OUTBOUND plugin→backend direction and must not double as an inbound
 * credential), and never a raw wp_options dump (which would leak
 * chargeguard_api_key, chargeguard_webhook_secret, Stripe/PayPal
 * credentials, etc. alongside the intentionally-exposed settings).
 *
 * @package ChargeGuard_WooCommerce
 */

defined('ABSPATH') || exit;

class ChargeGuard_Remote_Config {

    const ADMIN_CONFIG_KEY_OPTION = 'chargeguard_admin_config_key';

    /**
     * Explicit allow-list of option names this endpoint may ever return.
     * Anything not in this list — including every secret/credential option
     * in this plugin — is structurally unreachable through this class,
     * regardless of future edits elsewhere. Keep this list in sync with
     * the "Key settings" list in the ChargeGuard admin gap report; it is
     * not meant to grow to "everything."
     *
     * @var string[]
     */
    const ALLOWED_OPTIONS = [
        'chargeguard_enable_firewall',
        'chargeguard_firewall_block_duration',
        'chargeguard_trust_proxy_headers',      // legacy toggle, may still exist on older installs
        'chargeguard_proxy_trust_mode',
        'chargeguard_trusted_proxy_cidrs',
        'chargeguard_auto_block',
        'chargeguard_auto_refund',
        'chargeguard_api_down_behavior',
        'chargeguard_api_down_rate_limit',
        'chargeguard_block_min_amount',
    ];

    public function __construct() {
        add_action('rest_api_init', [$this, 'register_routes']);
        add_action('admin_init', [$this, 'maybe_generate_admin_config_key']);
        add_action('admin_notices', [$this, 'maybe_show_config_key_notice']);
    }

    public function register_routes() {
        register_rest_route('chargeguard/v1', '/admin/settings', [
            'methods'             => 'GET',
            'callback'            => [$this, 'handle_get_settings'],
            'permission_callback' => [$this, 'check_admin_config_key'],
        ]);
    }

    /**
     * Auto-generates a random per-install secret the first time this file
     * loads on an admin request, so there is never a "please set this up"
     * manual step before the feature can be used at all — only before it
     * can be used from the ChargeGuard admin dashboard specifically
     * (which needs the merchant/support to copy this value over once).
     */
    public function maybe_generate_admin_config_key() {
        if (!get_option(self::ADMIN_CONFIG_KEY_OPTION)) {
            update_option(self::ADMIN_CONFIG_KEY_OPTION, wp_generate_password(40, false, false), false);
        }
    }

    /**
     * One-time-visible-ish admin notice surfacing the key so a merchant or
     * support agent can copy it into the ChargeGuard admin dashboard's
     * "Set Config Key" action. Shown only to capable users, only while the
     * key has not yet plausibly been copied — there's no way to know that
     * for certain from the plugin side, so this stays visible (not
     * dismissible-forever) but is low-noise: a single-line notice, not a
     * blocking modal.
     */
    public function maybe_show_config_key_notice() {
        if (!is_admin() || !current_user_can('manage_woocommerce')) {
            return;
        }
        $key = get_option(self::ADMIN_CONFIG_KEY_OPTION);
        if (!$key) {
            return;
        }
        ?>
        <div class="notice notice-info">
            <p>
                <strong>ChargeGuard Remote Config Key:</strong>
                <code><?php echo esc_html($key); ?></code>
                — share this with ChargeGuard support (once) to enable the read-only
                "View Config" diagnostic tool in the ChargeGuard admin dashboard.
                It grants read-only access to a small set of non-secret settings only.
            </p>
        </div>
        <?php
    }

    /**
     * Constant-time comparison against the Authorization header, exactly
     * mirroring the timing-attack-safe pattern already used by the
     * backend's own authAdmin middleware (see src/routes/admin.js).
     */
    public function check_admin_config_key(\WP_REST_Request $request) {
        $expected = get_option(self::ADMIN_CONFIG_KEY_OPTION);
        if (!$expected) {
            return new \WP_Error('chargeguard_not_configured', 'Remote config key not set up.', ['status' => 503]);
        }

        $auth = $request->get_header('authorization');
        $provided = '';
        if ($auth && stripos($auth, 'Bearer ') === 0) {
            $provided = trim(substr($auth, 7));
        }

        $valid = strlen($provided) === strlen($expected) && hash_equals($expected, $provided);
        if (!$valid) {
            return new \WP_Error('chargeguard_forbidden', 'Invalid or missing remote config key.', ['status' => 403]);
        }
        return true;
    }

    /**
     * Returns only the allow-listed settings, each with a WordPress
     * default matching the value already used elsewhere in this plugin
     * (e.g. get_option('chargeguard_enable_firewall', 1) in the firewall
     * constructor) — so a merchant who has never touched a setting still
     * sees the value actually in effect, not a missing/null field.
     */
    public function handle_get_settings(\WP_REST_Request $request) {
        $defaults = [
            'chargeguard_enable_firewall'         => 1,
            'chargeguard_firewall_block_duration'  => 24,
            'chargeguard_trust_proxy_headers'      => 0,
            'chargeguard_proxy_trust_mode'         => null,
            'chargeguard_trusted_proxy_cidrs'      => '',
            'chargeguard_auto_block'               => 1,
            'chargeguard_auto_refund'               => 0,
            'chargeguard_api_down_behavior'        => 'local_checks',
            'chargeguard_api_down_rate_limit'      => 3,
            'chargeguard_block_min_amount'         => 0,
        ];

        $settings = [];
        foreach (self::ALLOWED_OPTIONS as $option_name) {
            $default = array_key_exists($option_name, $defaults) ? $defaults[$option_name] : null;
            $settings[$option_name] = get_option($option_name, $default);
        }

        return new \WP_REST_Response([
            'success'          => true,
            'settings'         => $settings,
            'pluginVersion'    => defined('CHARGEGUARD_VERSION') ? CHARGEGUARD_VERSION : null,
            'fetchedAtServer'  => gmdate('c'),
        ], 200);
    }
}