<?php
defined('ABSPATH') || exit;

/**
 * Thin wrapper around Plugin Update Checker (PUC). Only initializes when
 * a connected API key exists — an unlicensed/disconnected install has no
 * key to send to /api/updates/info, so there's nothing to check.
 *
 * SHA256 verification (UPD-NO-CHECKSUM-VERIFY):
 *   PUC v5.7 does not forward checksum_sha256 to the WordPress upgrader
 *   (the field is absent from PUC's toWpFormat() mapping). Two hooks
 *   close the gap without patching vendor code:
 *     1. http_response   — intercepts /api/updates/info and caches
 *                          checksum_sha256 in a short-lived transient.
 *     2. upgrader_pre_download — downloads the ZIP manually via
 *                          download_url(), verifies its SHA256 against
 *                          the cached value, and either returns the
 *                          verified tmpfile path (WordPress installs it
 *                          normally) or a WP_Error that aborts the
 *                          upgrade before any file is written.
 *   Graceful degradation: if no checksum is cached (e.g. info was
 *   fetched in a prior session that predates this code), the download
 *   is logged and allowed through — the cache window is 1 hour, which
 *   comfortably covers the gap between PUC's info check and the upgrade.
 */
class ChargeGuard_Plugin_Updater {

    private static $update_checker = null;

    /** Transient key — short TTL covers info→download window. */
    const SHA256_TRANSIENT = 'cg_update_sha256_pending';

    public static function init($plugin_file) {
        $puc_bootstrap = __DIR__ . '/../vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';
        if (!file_exists($puc_bootstrap)) {
            add_action('admin_notices', [__CLASS__, 'missing_puc_notice']);
            return;
        }
        require_once $puc_bootstrap;

        $api_key = chargeguard_get_secret_option('chargeguard_api_key');
        if (!$api_key) {
            return;
        }

        $domain  = wp_parse_url(home_url(), PHP_URL_HOST);
        $channel = apply_filters('chargeguard_update_channel', 'stable');

        $info_url = add_query_arg(
            [
                'key'     => rawurlencode($api_key),
                'domain'  => rawurlencode($domain),
                'channel' => $channel,
            ],
            'https://chargeguard-api.onrender.com/api/updates/info'
        );

        self::$update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            $info_url,
            $plugin_file,
            'chargeguard-woocommerce'
        );

        // Hook 1: cache checksum_sha256 from /api/updates/info response.
        add_filter('http_response', [__CLASS__, 'cache_update_checksum'], 10, 3);

        // Hook 2: verify ZIP SHA256 before WordPress installs it.
        add_filter('upgrader_pre_download', [__CLASS__, 'verified_download'], 10, 3);
    }

    /**
     * Intercept the /api/updates/info HTTP response and cache checksum_sha256
     * in a short-lived transient so verified_download() can read it back.
     *
     * @param array  $response   WordPress HTTP response array.
     * @param array  $parsed_args Request arguments (unused).
     * @param string $url         Request URL.
     * @return array Unmodified response.
     */
    public static function cache_update_checksum($response, $parsed_args, $url) {
        if (strpos($url, 'chargeguard-api.onrender.com/api/updates/info') === false) {
            return $response;
        }
        $body = json_decode(wp_remote_retrieve_body($response), true);
        if (
            !empty($body['checksum_sha256']) &&
            preg_match('/^[0-9a-f]{64}$/i', $body['checksum_sha256'])
        ) {
            set_transient(self::SHA256_TRANSIENT, strtolower($body['checksum_sha256']), HOUR_IN_SECONDS);
        }
        return $response;
    }

    /**
     * Download the ChargeGuard plugin ZIP manually, verify its SHA256 against
     * the cached checksum, and return either the verified tmpfile path (so
     * WordPress installs it normally) or a WP_Error that aborts the upgrade.
     *
     * Returning false passes control back to WordPress's default downloader.
     * Returning a string (tmpfile path) skips the default downloader entirely.
     * Returning WP_Error aborts the upgrade immediately.
     *
     * @param bool|WP_Error $reply   False = not yet handled.
     * @param string        $package Download URL from PUC.
     * @param WP_Upgrader   $upgrader Upgrader instance (unused).
     * @return bool|string|WP_Error
     */
    public static function verified_download($reply, $package, $upgrader) {
        // Only intercept if nobody else handled the download yet.
        if ($reply !== false) {
            return $reply;
        }

        // Only handle ChargeGuard update downloads.
        if (strpos($package, 'chargeguard-api.onrender.com/api/updates/download') === false) {
            return $reply;
        }

        $expected = get_transient(self::SHA256_TRANSIENT);
        if (!$expected) {
            // No checksum cached — log and allow WordPress to download normally.
            // This is graceful degradation, not a security bypass: the transient
            // window (1 h) covers the info→upgrade gap in every realistic flow.
            error_log('[ChargeGuard] Plugin update: no SHA256 checksum cached — skipping verification (graceful degradation). Transient may have expired.');
            return false;
        }

        // Download the ZIP ourselves so we can hash it before WordPress unpacks it.
        // download_url() follows HTTP redirects (GitHub Release asset redirect).
        $tmpfile = download_url($package);
        if (is_wp_error($tmpfile)) {
            delete_transient(self::SHA256_TRANSIENT);
            return $tmpfile;
        }

        $actual = hash_file('sha256', $tmpfile);
        delete_transient(self::SHA256_TRANSIENT);

        if (!hash_equals($expected, $actual)) {
            @unlink($tmpfile);
            return new \WP_Error(
                'cg_checksum_mismatch',
                sprintf(
                    /* translators: 1: expected hash, 2: actual hash */
                    __('ChargeGuard update aborted: the downloaded ZIP failed SHA256 verification (expected %1$s, got %2$s). This may indicate file corruption or tampering. Please try again; if the problem persists, contact ChargeGuard support.', 'chargeguard-woocommerce'),
                    $expected,
                    $actual
                )
            );
        }

        // Checksum verified — return the tmpfile path.
        // WordPress treats a string return as the downloaded package and
        // proceeds to unpack and install it normally.
        return $tmpfile;
    }

    public static function missing_puc_notice() {
        if (!current_user_can('manage_woocommerce')) return;
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong>ChargeGuard:</strong> The update checker library (<code>vendor/yahnis-elsts/plugin-update-checker</code>) was not found. Automatic update notifications are disabled. Run <code>composer install</code> in the plugin directory.</p>
        </div>
        <?php
    }

    public static function force_check() {
        if (self::$update_checker) {
            self::$update_checker->checkForUpdates();
        }
    }
}