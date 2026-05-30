<?php
/**
 * ChargeGuard PayPal Webhook Handler
 *
 * يستقبل Webhook من PayPal، يستخرج بيانات الدفع، ويرسلها إلى ChargeGuard.
 *
 * @package ChargeGuard_WooCommerce
 */

class ChargeGuard_PayPal_Webhook {

    private $api_client;

    public function __construct() {
        $this->api_client = new ChargeGuard_API_Client();
        add_action( 'rest_api_init', [ $this, 'register_rest_route' ] );
    }

    /**
     * تسجيل REST API endpoint لاستقبال PayPal Webhook.
     */
    public function register_rest_route() {
        register_rest_route( 'chargeguard/v1', '/paypal-webhook', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'handle_webhook' ],
            'permission_callback' => '__return_true',
        ] );
    }

    /**
     * معالجة PayPal Webhook الوارد.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @return WP_REST_Response
     */
    public function handle_webhook( $request ) {

        // ── 1. التحقق من أن التكامل مفعّل ──────────────────────────
        if ( get_option( 'chargeguard_paypal_enabled', '0' ) !== '1' ) {
            return new WP_REST_Response( [ 'status' => 'disabled' ], 200 );
        }

        // ── 2. Idempotency — منع معالجة نفس الحدث مرتين ────────────
        $transmission_id = $request->get_header( 'paypal_transmission_id' );
        $cache_key       = $transmission_id
            ? 'cg_pp_processed_' . md5( $transmission_id )
            : null;

        if ( $cache_key && get_transient( $cache_key ) ) {
            return new WP_REST_Response( [ 'status' => 'already_processed' ], 200 );
        }

        // ── 3. قراءة الـ payload ─────────────────────────────────────
        $payload_raw = $request->get_body();
        $payload     = json_decode( $payload_raw, true );

        if ( empty( $payload ) || ! isset( $payload['event_type'] ) ) {
            return new WP_REST_Response( [ 'error' => 'Invalid payload' ], 400 );
        }

        // ── 4. فلترة الأحداث — نعالج فقط ما يهمنا ──────────────────
        $supported_events = [
            'PAYMENT.CAPTURE.COMPLETED',
            'PAYMENT.CAPTURE.DENIED',
            'CHECKOUT.ORDER.APPROVED',
            'PAYMENT.AUTHORIZATION.CREATED',
            'RISK.DISPUTE.CREATED',
        ];

        if ( ! in_array( $payload['event_type'], $supported_events, true ) ) {
            return new WP_REST_Response( [ 'status' => 'ignored', 'event' => $payload['event_type'] ], 200 );
        }

        // ── 5. التحقق من توقيع PayPal (Remote Verification) ─────────
        $verified = $this->verify_webhook_signature( $request, $payload_raw );
        if ( ! $verified ) {
            return new WP_REST_Response( [ 'error' => 'Invalid signature' ], 403 );
        }

        // ── 6. تسجيل Idempotency بعد التحقق ─────────────────────────
        if ( $cache_key ) {
            set_transient( $cache_key, 1, 48 * HOUR_IN_SECONDS );
        }

        // ── 7. استخراج البيانات من الـ payload ──────────────────────
        $extracted = $this->extract_payment_data( $payload );

        if ( ! $extracted ) {
            // حدث لا يحتوي على بيانات دفع قابلة للمعالجة (مثل RISK.DISPUTE.CREATED)
            $this->handle_dispute_event( $payload );
            return new WP_REST_Response( [ 'status' => 'handled', 'event' => $payload['event_type'] ], 200 );
        }

        // ── 8. الرد على PayPal فوراً قبل أي استدعاء خارجي ──────────
        // PayPal ينتظر 30 ثانية فقط — لا نخاطر بالتأخير
        // نُكمل المعالجة بعد الإرسال
        $response = new WP_REST_Response( [ 'status' => 'received' ], 200 );

        // ── 9. ربط الـ WooCommerce Order ─────────────────────────────
        $order_id = $this->find_order_id( $extracted, $payload );

        // ── 10. بناء بيانات enrich وإرسالها ─────────────────────────
        $enrich_data = [
            'orderId'     => $order_id ? (string) $order_id : $this->generate_paypal_order_id( $payload ),
            'bin'         => $extracted['bin'] ?? null,
            'last4'       => $extracted['last4'] ?? null,
            'expMonth'    => $extracted['exp_month'] ?? null,
            'expYear'     => $extracted['exp_year'] ?? null,
            'brand'       => $extracted['brand'] ?? null,
            'cardBrand'   => $extracted['brand'] ?? null,
            'cardCountry' => $extracted['card_country'] ?? null,
            'funding'     => $extracted['funding'] ?? null,
            'issuer'      => null,
            'source'      => 'paypal',
            'paypalTxnId' => $extracted['txn_id'] ?? null,
            'eventType'   => $payload['event_type'],
        ];

        // نرسل فقط إذا كان هناك BIN أو last4 (بيانات بطاقة حقيقية)
        $has_card_data = ! empty( $enrich_data['bin'] ) || ! empty( $enrich_data['last4'] );

        if ( $has_card_data ) {
            $result = $this->api_client->send_enrich( $enrich_data );

            // إذا كان القرار block وكانت الـ auto-block مفعلة وعندنا order_id
            if ( $order_id && ! is_wp_error( $result ) ) {
                $this->maybe_block_order( $result, $order_id );
            }
        } elseif ( ! empty( $extracted['payer_email'] ) ) {
            // PayPal Balance payment — لا بطاقة، لكن نُسجّل الحدث للـ velocity tracking
            // نرسل للـ enrich بدون bin — سيُخزَّن كـ pendingEnrichment إذا لم يُوجد الطلب
            if ( $order_id ) {
                $enrich_data['orderId'] = (string) $order_id;
                $this->api_client->send_enrich( $enrich_data );
            }
        }

        return $response;
    }

    /**
     * التحقق من توقيع PayPal Webhook عبر Remote Verification API.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @param string          $payload_raw الجسم الخام للطلب.
     * @return bool
     */
    private function verify_webhook_signature( $request, $payload_raw ) {
        $client_id     = get_option( 'chargeguard_paypal_client_id' );
        $client_secret = get_option( 'chargeguard_paypal_client_secret' );
        $webhook_id    = get_option( 'chargeguard_paypal_webhook_id' );

        // إذا لم تكن الإعدادات مكتملة، نتجاوز التحقق في البيئة التطويرية فقط
        if ( ! $client_id || ! $client_secret || ! $webhook_id ) {
            if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
                return true; // تطوير فقط
            }
            return false;
        }

        // الحصول على Access Token (مخزّن في Transient لـ 8 ساعات)
        $access_token = $this->get_paypal_access_token( $client_id, $client_secret );
        if ( ! $access_token ) {
            return false;
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/notifications/verify-webhook-signature'
            : 'https://api-m.sandbox.paypal.com/v1/notifications/verify-webhook-signature';

        $verify_body = [
            'auth_algo'         => $request->get_header( 'paypal_auth_algo' ),
            'cert_url'          => $request->get_header( 'paypal_cert_url' ),
            'transmission_id'   => $request->get_header( 'paypal_transmission_id' ),
            'transmission_sig'  => $request->get_header( 'paypal_transmission_sig' ),
            'transmission_time' => $request->get_header( 'paypal_transmission_time' ),
            'webhook_id'        => $webhook_id,
            'webhook_event'     => json_decode( $payload_raw, true ),
        ];

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $access_token,
            ],
            'body' => json_encode( $verify_body ),
        ] );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        return isset( $body['verification_status'] ) && $body['verification_status'] === 'SUCCESS';
    }

    /**
     * الحصول على PayPal Access Token مع caching.
     *
     * @param string $client_id
     * @param string $client_secret
     * @return string|null
     */
    private function get_paypal_access_token( $client_id, $client_secret ) {
        $cache_key = 'cg_paypal_access_token_' . md5( $client_id );
        $cached    = get_transient( $cache_key );
        if ( $cached ) {
            return $cached;
        }

        $mode    = get_option( 'chargeguard_paypal_mode', 'sandbox' );
        $api_url = ( $mode === 'live' )
            ? 'https://api-m.paypal.com/v1/oauth2/token'
            : 'https://api-m.sandbox.paypal.com/v1/oauth2/token';

        $response = wp_remote_post( $api_url, [
            'timeout' => 10,
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode( $client_id . ':' . $client_secret ),
                'Content-Type'  => 'application/x-www-form-urlencoded',
            ],
            'body' => 'grant_type=client_credentials',
        ] );

        if ( is_wp_error( $response ) ) {
            return null;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body['access_token'] ) ) {
            return null;
        }

        // نخزن لـ 8 ساعات (PayPal token صالح لـ 9 ساعات)
        set_transient( $cache_key, $body['access_token'], 8 * HOUR_IN_SECONDS );
        return $body['access_token'];
    }

    /**
     * استخراج بيانات الدفع من PayPal payload.
     * يعالج كلاً من بطاقات الائتمان ومدفوعات PayPal Balance.
     *
     * @param array $payload
     * @return array|null
     */
    private function extract_payment_data( $payload ) {
        $resource = $payload['resource'] ?? null;
        if ( ! $resource ) {
            return null;
        }

        $extracted = [
            'txn_id'      => $resource['id'] ?? null,
            'payer_email' => null,
            'amount'      => null,
            'currency'    => null,
            'bin'         => null,
            'last4'       => null,
            'exp_month'   => null,
            'exp_year'    => null,
            'brand'       => null,
            'card_country'=> null,
            'funding'     => null,
        ];

        // ── استخراج بيانات البطاقة ───────────────────────────────────
        // المسار 1: payment_source.card (PayPal Advanced / Braintree)
        $card = $resource['payment_source']['card'] ?? null;
        if ( $card ) {
            // PayPal يرسل BIN في حقل bin أو أول 6 أرقام من number
            $extracted['bin']      = $card['bin'] ?? null;
            $extracted['last4']    = $card['last_digits'] ?? null;
            $extracted['brand']    = strtolower( $card['brand'] ?? '' ) ?: null;
            $extracted['funding']  = strtolower( $card['type'] ?? '' ) ?: null; // CREDIT/DEBIT

            // استخراج الشهر والسنة من expiry (صيغة: YYYY-MM)
            if ( ! empty( $card['expiry'] ) ) {
                $parts = explode( '-', $card['expiry'] );
                if ( count( $parts ) === 2 ) {
                    $extracted['exp_year']  = (int) $parts[0];
                    $extracted['exp_month'] = (int) $parts[1];
                }
            }

            // بعض استجابات PayPal تحتوي على billing_address.country_code
            $extracted['card_country'] = $card['billing_address']['country_code'] ?? null;
        }

        // المسار 2: payer.email_address (PayPal Balance أو أي دفع)
        $payer = $resource['payer'] ?? null;
        if ( $payer ) {
            $extracted['payer_email'] = $payer['email_address'] ?? null;
        }

        // المسار 3: amount
        $amount_data = $resource['amount'] ?? $resource['purchase_units'][0]['amount'] ?? null;
        if ( $amount_data ) {
            $extracted['amount']   = $amount_data['value'] ?? null;
            $extracted['currency'] = $amount_data['currency_code'] ?? null;
        }

        // إذا لم يكن هناك أي بيانات مفيدة، نتجاوز
        if ( ! $extracted['txn_id'] && ! $extracted['payer_email'] ) {
            return null;
        }

        return $extracted;
    }

    /**
     * البحث عن WooCommerce Order ID المرتبط بمعاملة PayPal.
     *
     * @param array $extracted البيانات المستخرجة.
     * @param array $payload   الـ payload الكامل.
     * @return int|null
     */
    private function find_order_id( $extracted, $payload ) {
        $resource = $payload['resource'] ?? [];

        // المسار 1: custom_id في purchase_units (WooCommerce يضع order_id هنا)
        $custom_id = $resource['purchase_units'][0]['custom_id']
                  ?? $resource['custom_id']
                  ?? null;
        if ( $custom_id && is_numeric( $custom_id ) ) {
            $order = wc_get_order( (int) $custom_id );
            if ( $order ) {
                return $order->get_id();
            }
        }

        // المسار 2: invoice_id
        $invoice_id = $resource['purchase_units'][0]['invoice_id'] ?? null;
        if ( $invoice_id && is_numeric( $invoice_id ) ) {
            $order = wc_get_order( (int) $invoice_id );
            if ( $order ) {
                return $order->get_id();
            }
        }

        // المسار 3: البحث بـ PayPal transaction ID في meta
        if ( ! empty( $extracted['txn_id'] ) ) {
            $orders = wc_get_orders( [
                'limit'      => 1,
                'meta_key'   => '_transaction_id',
                'meta_value' => $extracted['txn_id'],
                'return'     => 'ids',
            ] );
            if ( ! empty( $orders ) ) {
                return $orders[0];
            }
        }

        return null;
    }

    /**
     * توليد معرف افتراضي للمعاملات التي لم يُربط بها طلب WooCommerce.
     *
     * @param array $payload
     * @return string
     */
    private function generate_paypal_order_id( $payload ) {
        $txn_id = $payload['resource']['id'] ?? uniqid( 'pp_', true );
        return 'paypal_' . $txn_id;
    }

    /**
     * معالجة أحداث النزاعات لتغذية الـ Feedback Loop.
     *
     * @param array $payload
     */
    private function handle_dispute_event( $payload ) {
        $resource = $payload['resource'] ?? [];
        $txn_id   = $resource['disputed_transactions'][0]['seller_transaction_id'] ?? null;

        if ( ! $txn_id ) {
            return;
        }

        // البحث عن الطلب المرتبط بهذه المعاملة
        $orders = wc_get_orders( [
            'limit'      => 1,
            'meta_key'   => '_transaction_id',
            'meta_value' => $txn_id,
            'return'     => 'ids',
        ] );

        if ( empty( $orders ) ) {
            return;
        }

        $order_id = $orders[0];

        // إرسال feedback للـ ChargeGuard Backend (isFraud = true)
        $api_key     = get_option( 'chargeguard_api_key' );
        $merchant_id = get_option( 'chargeguard_merchant_id' );

        if ( ! $api_key || ! $merchant_id ) {
            return;
        }

        wp_remote_post( 'https://chargeguard-api.onrender.com/api/risk/feedback', [
            'timeout' => 5,
            'headers' => [
                'Content-Type'   => 'application/json',
                'x-api-key'      => $api_key,
                'x-merchant-id'  => $merchant_id,
            ],
            'body' => json_encode( [
                'orderId' => (string) $order_id,
                'isFraud' => true,
            ] ),
        ] );
    }

    /**
     * إلغاء الطلب تلقائياً إذا كان القرار block وكانت الميزة مفعلة.
     *
     * @param array $result  نتيجة enrich من ChargeGuard.
     * @param int   $order_id معرف الطلب في WooCommerce.
     */
    private function maybe_block_order( $result, $order_id ) {
        $auto_block = get_option( 'chargeguard_auto_block', 'no' );
        if ( $auto_block !== 'yes' ) {
            return;
        }

        $decision = $result['newDecision'] ?? $result['decision'] ?? '';
        if ( strtolower( $decision ) !== 'block' ) {
            return;
        }

        $order = wc_get_order( $order_id );
        if ( ! $order ) {
            return;
        }

        $min_amount = (float) get_option( 'chargeguard_block_min_amount', 0 );
        if ( $min_amount > 0 && $order->get_total() < $min_amount ) {
            return;
        }

        $order->update_status(
            'failed',
            __( 'Blocked by ChargeGuard: Suspicious PayPal payment detected.', 'chargeguard-woocommerce' )
        );
        $order->add_order_note(
            'ChargeGuard PayPal decision: block. Flags: ' . json_encode( $result['flags'] ?? [] )
        );
    }
}