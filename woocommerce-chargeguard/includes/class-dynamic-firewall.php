<?php
/**
 * ChargeGuard - Dynamic Firewall
 *
 * يمنع الأجهزة المحظورة من الوصول إلى صفحة الدفع،
 * ويضيف طبقة حماية عبر رمز جلسة آمنة.
 *
 * @package ChargeGuard_WooCommerce
 */

defined('ABSPATH') || exit;

class ChargeGuard_Blocked_Exception extends \Exception {}

class ChargeGuard_Dynamic_Firewall {

    /**
     * عميل API للتواصل مع ChargeGuard.
     *
     * @var ChargeGuard_API_Client|null
     */
    private $api_client;

    /**
     * اسم الخيار في قاعدة البيانات لتخزين القائمة السوداء المحلية.
     *
     * @var string
     */
    private $blacklist_option = 'chargeguard_device_blacklist';

    /**
     * مفتاح الجلسة لحفظ رمز الأمان.
     *
     * @var string
     */
    private $session_token_key = 'chargeguard_checkout_token';

    /**
     * تهيئة الخطافات المطلوبة.
     */
    public function __construct() {
        // احترام إعدادات التفعيل
        if (!get_option('chargeguard_enable_firewall', 1)) {
            return;
        }
        error_log('ChargeGuard Dynamic Firewall loaded');

        // تحميل عميل API إن كان موجودًا
        if (class_exists('ChargeGuard_API_Client')) {
            $this->api_client = new ChargeGuard_API_Client();
        }

        // 1. طبقة الجلسة
        add_action('woocommerce_before_checkout_form', [$this, 'inject_session_token']);
        add_action('woocommerce_checkout_process', [$this, 'validate_session_token']);

        // 2. طبقة البصمة
        add_action('wp_enqueue_scripts', [$this, 'enqueue_firewall_assets']);
        add_action('woocommerce_before_checkout_form', [$this, 'handle_checkout_access']);

        // 3. Ajax للفحص
        add_action('wp_ajax_chargeguard_check_fp', [$this, 'ajax_check_fingerprint']);
        add_action('wp_ajax_nopriv_chargeguard_check_fp', [$this, 'ajax_check_fingerprint']);

        // 4. خطاف لتسجيل بصمة ضارة
        add_action('chargeguard_mark_device_fraud', [$this, 'add_device_to_blacklist']);

        // 5. فحص المخاطر قبل معالجة الطلب
        add_action('woocommerce_checkout_process', [$this, 'intercept_checkout']);
    }

    // ─────────────────────────────────────────────
    // 1. طبقة الجلسة (Session Token)
    // ─────────────────────────────────────────────

    /**
     * إنشاء رمز عشوائي وحقنه في نموذج الدفع.
     */
    public function inject_session_token() {
        if (!WC()->session) {
            return;
        }

        $token = bin2hex(random_bytes(32));
        WC()->session->set($this->session_token_key, $token);

        echo '<input type="hidden" name="chargeguard_session_token" value="' . esc_attr($token) . '" />';
    }

    /**
     * التحقق من صحة الرمز عند تقديم الطلب.
     *
     * @param array $checkout_data بيانات الدفع (غير مستخدمة هنا).
     */
    public function validate_session_token($checkout_data) {
        if (!WC()->session) {
            return;
        }

        $submitted = isset($_POST['chargeguard_session_token'])
            ? sanitize_text_field(wp_unslash($_POST['chargeguard_session_token']))
            : '';

        $stored = WC()->session->get($this->session_token_key);

        // رفض الطلب إذا كان الرمز مفقودًا أو غير مطابق
        if (empty($stored) || empty($submitted) || !hash_equals($stored, $submitted)) {
            wc_add_notice(
                __('خطأ في التحقق الأمني. يرجى تحديث الصفحة والمحاولة مرة أخرى.', 'chargeguard-woocommerce'),
                'error'
            );
            WC()->session->__unset($this->session_token_key);
        }
    }

    // ─────────────────────────────────────────────
    // 2. طبقة البصمة (Device Fingerprint)
    // ─────────────────────────────────────────────

    /**
     * تحميل ملفات JavaScript الخاصة بالبصمة على صفحة الدفع فقط.
     */
    public function enqueue_firewall_assets() {
        if (!is_checkout()) {
            return;
        }

        wp_enqueue_script(
            'chargeguard-firewall',
            plugin_dir_url(__FILE__) . '../assets/js/chargeguard-firewall.js',
            ['jquery'],
            '1.0.0',
            true
        );

        wp_localize_script('chargeguard-firewall', 'chargeguard_fw', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('chargeguard_fw_nonce'),
        ]);
    }

    /**
     * التحقق من القائمة السوداء قبل عرض صفحة الدفع.
     * إذا كانت البصمة محظورة، يتم منع الوصول.
     */
    public function handle_checkout_access() {
        try {
            $this->check_device_blacklist();
        } catch (ChargeGuard_Blocked_Exception $e) {
            wp_die(
                $e->getMessage(),
                esc_html__('تم تقييد الوصول', 'chargeguard-woocommerce'),
                ['response' => 403]
            );
        }
    }

    public function check_device_blacklist() {
        if (!isset($_COOKIE['chargeguard_fp'])) {
            return;
        }

        $fingerprint = sanitize_text_field(wp_unslash($_COOKIE['chargeguard_fp']));
        if (empty($fingerprint)) {
            return;
        }

        // الفحص المحلي مع احترام مدة الصلاحية
        $local_blacklist = get_option($this->blacklist_option, []);
        if (is_array($local_blacklist)) {
            // تنظيف تلقائي للحظر المنتهي
            $now = time();
            foreach ($local_blacklist as $fp => $expires) {
                if ($expires < $now) {
                    unset($local_blacklist[$fp]);
                }
            }
            update_option($this->blacklist_option, $local_blacklist);

            if (isset($local_blacklist[$fingerprint]) && $local_blacklist[$fingerprint] > $now) {
                $this->block_access();
            }
        }

        // الفحص عبر API (اختياري)
        if ($this->api_client && $this->api_client->get_api_key()) {
            $response = $this->api_client->check_device($fingerprint);
            if (!is_wp_error($response) && isset($response['blocked']) && $response['blocked']) {
                // حفظ في القائمة المحلية للسرعة
                $this->add_device_to_blacklist($fingerprint);
                $this->block_access();
            }
        }
    }

    /**
     * إضافة بصمة جهاز إلى القائمة السوداء المحلية.
     *
     * @param string $fingerprint بصمة الجهاز.
     */
    public function add_device_to_blacklist($fingerprint) {
        $blacklist = get_option($this->blacklist_option, []);
        if (!is_array($blacklist)) {
            $blacklist = [];
        }

        // استخدام مدة الحظر من الإعدادات (بالساعات)
        $duration_hours = (int) get_option('chargeguard_firewall_block_duration', 24);
        $expires_at     = time() + ($duration_hours * 3600);

        // تخزين البصمة مع وقت الانتهاء
        $blacklist[$fingerprint] = $expires_at;
        update_option($this->blacklist_option, $blacklist);
    }

    /**
     * إيقاف عرض الصفحة مع رسالة شفافة.
     */
    private function block_access() {
        throw new ChargeGuard_Blocked_Exception(
            esc_html__('نعتذر، لا يمكن معالجة طلبك في الوقت الحالي. يرجى التواصل مع الدعم.', 'chargeguard-woocommerce')
        );
    }

    // ─────────────────────────────────────────────
    // 3. Ajax: فحص البصمة من JavaScript
    // ─────────────────────────────────────────────

    /**
     * معالج Ajax لفحص بصمة الجهاز.
     */
    public function ajax_check_fingerprint() {
        check_ajax_referer('chargeguard_fw_nonce', 'nonce');

        $fingerprint = isset($_POST['fingerprint'])
            ? sanitize_text_field(wp_unslash($_POST['fingerprint']))
            : '';

        $blocked = false;

        // فحص محلي
        $blacklist = get_option($this->blacklist_option, []);
        if (is_array($blacklist) && in_array($fingerprint, $blacklist, true)) {
            $blocked = true;
        }

        // فحص API
        if (!$blocked && $this->api_client && $this->api_client->get_api_key()) {
            $response = $this->api_client->check_device($fingerprint);
            if (!is_wp_error($response) && isset($response['blocked']) && $response['blocked']) {
                $blocked = true;
                $this->add_device_to_blacklist($fingerprint);
            }
        }

        wp_send_json_success(['blocked' => $blocked]);
    }
        // تحميل عميل API إن كان موجودًا
    /**
     * اعتراض عملية الدفع واستشارة ChargeGuard API.
     */
    public function intercept_checkout() {
        // لا تفعل شيئًا إذا لم يكن هناك عميل API أو مفتاح
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }

        // تجهيز البيانات
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $email = isset($_POST['billing_email']) ? sanitize_email($_POST['billing_email']) : '';
        $device_fp = isset($_COOKIE['chargeguard_fp']) ? sanitize_text_field($_COOKIE['chargeguard_fp']) : '';
        $amount = WC()->cart ? WC()->cart->total : 0;
        $billing_country = isset($_POST['billing_country']) ? sanitize_text_field($_POST['billing_country']) : '';
        $shipping_country = isset($_POST['shipping_country']) ? sanitize_text_field($_POST['shipping_country']) : '';

        $order_data = [
            'orderId'         => 'pre_' . uniqid(),
            'email'           => $email,
            'ipAddress'       => $ip,
            'deviceFingerprint' => $device_fp,
            'amount'          => (float)$amount,
            'billingCountry'  => $billing_country,
            'shippingCountry' => $shipping_country,
            'merchantId'      => get_option('chargeguard_merchant_id', ''),
        ];

        $result = $this->api_client->evaluate_risk($order_data);

        // إذا فشل الاتصال، نترك الطلب يمر لأسباب أمان
        error_log('ChargeGuard API raw response: ' . print_r($result, true));
        if (is_wp_error($result)) {
            error_log('ChargeGuard API error: ' . $result->get_error_message());
            return;
        }

        $decision = isset($result['decision']) ? $result['decision'] : '';

        // حظر الطلب إذا كان القرار "block"
        if ($decision === 'block') {
            $message = __('نعتذر، لا يمكن معالجة طلبك حاليًا. يرجى المحاولة لاحقًا.', 'chargeguard-woocommerce');
            wc_add_notice($message, 'error');
        }
    }
}