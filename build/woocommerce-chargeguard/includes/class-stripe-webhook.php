<?php
/**
 * ChargeGuard Stripe Webhook Handler
 *
 * يستقبل Webhook من Stripe، يستخرج BIN، ويرسله إلى ChargeGuard.
 *
 * @package ChargeGuard_WooCommerce
 */

class ChargeGuard_Stripe_Webhook {

    use ChargeGuard_Auto_Block_Trait;

    private $api_client;

    public function __construct() {
        $this->api_client = new ChargeGuard_API_Client();
        add_action('rest_api_init', [$this, 'register_rest_route']);

        // Consumes any enrichment data queued by handle_webhook() when the
        // Stripe webhook raced ahead of order creation. Hooked on payment
        // completion (rather than order creation) because that's the
        // earliest point a Stripe payment intent ID is reliably available
        // as order meta.
        add_action('woocommerce_payment_complete', [$this, 'consume_pending_enrichment']);
    }

    /**
     * تسجيل REST API endpoint لاستقبال Stripe Webhook.
     */
    public function register_rest_route() {
        register_rest_route('chargeguard/v1', '/stripe-webhook', [
            'methods'             => 'POST',
            'callback'            => [$this, 'handle_webhook'],
            'permission_callback' => '__return_true', // سيتم التحقق من توقيع Stripe داخل الدالة
        ]);
    }

    /**
     * معالجة Webhook Stripe الوارد.
     *
     * @param WP_REST_Request $request الطلب الوارد.
     * @return WP_REST_Response
     */
    public function handle_webhook($request) {
        // ── Confirm the integration is enabled ──────────────────────────
        // Mirrors the PayPal handler's pattern: if the merchant has
        // disabled (or never enabled, or disconnected) Stripe enrichment,
        // stop here before touching the Stripe SDK, verifying signatures,
        // or forwarding any card data downstream.
        if (get_option('chargeguard_stripe_enabled', '0') !== '1') {
            return new \WP_REST_Response(['status' => 'disabled'], 200);
        }

        $stripe_init = __DIR__ . '/../vendor/stripe-php/init.php';
        if (file_exists($stripe_init)) {
            require_once $stripe_init;
        } else {
            error_log('[ChargeGuard] Stripe webhook received but vendor/stripe-php/init.php is missing — run composer install.');
            return new \WP_REST_Response(['error' => 'Unable to process webhook'], 500);
        }

        // Must be set before any Stripe API call in this request (Charge::retrieve()
        // below requires it). constructEvent() itself only does a local signature
        // check and doesn't need the key, but setting it here fails fast if Stripe
        // hasn't been configured yet in the ChargeGuard settings page.
        $stripe_secret_key = chargeguard_get_secret_option('chargeguard_stripe_secret_key');
        if (!$stripe_secret_key) {
            error_log('[ChargeGuard] Stripe webhook received but no chargeguard_stripe_secret_key is configured.');
            return new \WP_REST_Response(['error' => 'Unable to process webhook'], 500);
        }
        \Stripe\Stripe::setApiKey($stripe_secret_key);

        $payload   = $request->get_body();
        $sig_header = $request->get_header('stripe_signature');
        $endpoint_secret = chargeguard_get_secret_option('chargeguard_stripe_webhook_secret');

        // التحقق من توقيع Stripe
        try {
            $event = \Stripe\Webhook::constructEvent($payload, $sig_header, $endpoint_secret);
        } catch (\Exception $e) {
            return new \WP_REST_Response(['error' => 'Invalid signature'], 403);
        }

        // معالجة حدث payment_intent.succeeded فقط
        if ($event->type !== 'payment_intent.succeeded') {
            return new \WP_REST_Response(['status' => 'ignored'], 200);
        }

        // ── Idempotency — منع معالجة نفس الحدث مرتين ────────────
        // Mirrors the PayPal handler's transient-based guard, keyed on
        // Stripe's own event ID (unique per delivery attempt group).
        $cache_key = 'cg_stripe_processed_' . md5($event->id);
        if (get_transient($cache_key)) {
            return new \WP_REST_Response(['status' => 'already_processed'], 200);
        }

        // NOTE: the "processed" marker is intentionally NOT set here.
        // Stripe redelivers an event until it receives a 2xx response, and
        // that retry is exactly what we want for transient failures (a
        // network blip to the ChargeGuard backend, a slow/failing Stripe
        // API call). Marking the event as processed before we know the
        // outcome would cause every subsequent retry to be silently
        // swallowed by the already_processed check above, even though
        // nothing was actually enriched. The marker is set individually
        // below, only at points where processing has genuinely concluded
        // (successfully enriched, successfully queued as pending, or
        // failed for a reason a retry cannot fix) — never at points where
        // a retry could plausibly succeed.

        $payment_intent = $event->data->object;

        try {
            $charge = $this->get_latest_charge($payment_intent);
        } catch (\Exception $e) {
            error_log('[ChargeGuard] Stripe charge retrieval failed for ' . $payment_intent->id . ': ' . $e->getMessage());
            return new \WP_REST_Response(['error' => 'Charge retrieval failed'], 500);
        }

        if (!$charge) {
            // Deterministic given this event's payload — a retry will see
            // the same payment intent with no charges every time, so mark
            // processed to stop Stripe retrying a call that cannot succeed.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No charges found'], 400);
        }

        $card = $charge->payment_method_details->card ?? null;

        if (!$card) {
            // Deterministic — the charge will never gain card details on
            // retry, so mark processed to stop further redelivery attempts.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No card details found'], 400);
        }

        $iin     = $card->iin ?? null;
        $brand   = $card->brand ?? null;
        $country = $card->country ?? null;
        $funding = $card->funding ?? null;
        $last4   = $card->last4 ?? null;
        $expMonth = $card->exp_month ?? null;
        $expYear  = $card->exp_year ?? null;

        if (!$iin) {
            // Deterministic — the same card data will lack an IIN on retry too.
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['error' => 'No IIN found'], 400);
        }

        // البحث عن الطلب المرتبط بـ payment_intent_id
        $orders = wc_get_orders([
            'limit'       => 1,
            'meta_key'    => '_chargeguard_payment_intent_id',
            'meta_value'  => $payment_intent->id,
            'return'      => 'ids',
        ]);

        $order_id = !empty($orders) ? $orders[0] : $payment_intent->metadata->order_id ?? null;

        // If we resolved the order via the Stripe metadata fallback rather
        // than our own meta key, persist that meta now so future lookups
        // (including the deferred-enrichment consumer below) don't need to
        // rely on the fallback again.
        if ($order_id && empty($orders)) {
            $existing_order = wc_get_order($order_id);
            if ($existing_order && !$existing_order->get_meta('_chargeguard_payment_intent_id')) {
                $existing_order->update_meta_data('_chargeguard_payment_intent_id', $payment_intent->id);
                $existing_order->save_meta_data();
            }
        }

        if (!$order_id) {
            // تخزين مؤقت للبيانات حتى يصل Webhook الطلب
            set_transient('chargeguard_pending_enrich_' . $payment_intent->id, [
                'orderId'     => null,
                'paymentIntentId' => $payment_intent->id,
                'bin'         => $iin,
                'cardBrand'   => $brand,
                'cardCountry' => $country,
                'funding'     => $funding,
                'issuer'      => $charge->payment_method_details->card->issuer ?? null,
                'last4'       => $last4,
                'expMonth'    => $expMonth,
                'expYear'     => $expYear,
                'brand'       => $brand,
            ], HOUR_IN_SECONDS);
            // Data is now safely persisted for the deferred consumer to
            // pick up — this delivery has concluded successfully, so mark
            // it processed now (not before, per the note above).
            set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);
            return new \WP_REST_Response(['status' => 'pending', 'message' => 'Order not found, enrichment queued locally.'], 202);
        }

        // إرسال enrich إلى ChargeGuard
        $enrich_data = [
            'orderId'         => (string) $order_id,
            'paymentIntentId' => $payment_intent->id,
            'source'          => 'stripe',
            'bin'             => $iin,
            'cardBrand'       => $brand,
            'cardCountry'     => $country,
            'funding'         => $funding,
            'issuer'          => $charge->payment_method_details->card->issuer ?? null,
            'last4'           => $last4,
            'expMonth'        => $expMonth,
            'expYear'         => $expYear,
            'brand'           => $brand,
        ];

        $result = $this->api_client->send_enrich($enrich_data);

        if (is_wp_error($result)) {
            // Do NOT mark processed — this is exactly the transient-failure
            // case (network blip, backend 5xx) that Stripe's retry exists
            // for. Leaving the marker unset lets the next redelivery
            // attempt try send_enrich() again instead of being silently
            // swallowed by the already_processed check.
            return new \WP_REST_Response(['error' => $result->get_error_message()], 500);
        }

        // Enrichment succeeded — this delivery has genuinely concluded, so
        // mark it processed now.
        set_transient($cache_key, 1, 48 * HOUR_IN_SECONDS);

        // إذا كان القرار block، نقوم بإلغاء الطلب تلقائيًا إذا كان التاجر قد فعّل الميزة
        $this->chargeguard_maybe_block_order(
            $result,
            $order_id,
            __('Blocked by ChargeGuard: Card Testing detected.', 'chargeguard-woocommerce')
        );

        return new \WP_REST_Response(['status' => 'enriched', 'result' => $result], 200);
    }

    /**
     * Consume any enrichment data queued by handle_webhook() for a Stripe
     * payment intent that arrived before its order existed.
     *
     * Fires on woocommerce_payment_complete rather than
     * woocommerce_checkout_order_created because the payment intent ID is
     * not reliably present as order meta at order-creation time — it's
     * written by the payment gateway (or by handle_webhook() itself, see
     * above) once payment has actually been processed.
     *
     * At-least-once semantics: if this fires more than once for the same
     * order (e.g. a payment-complete hook firing twice), the transient is
     * deleted on first consumption, so subsequent calls are safe no-ops.
     *
     * If the transient has already expired (1 hour TTL) or was never set
     * (the common case — most Stripe webhooks arrive after order
     * creation and are handled directly in handle_webhook()), this
     * silently returns; that is expected, not an error condition.
     *
     * @param int $order_id
     * @return void
     */
    public function consume_pending_enrichment($order_id) {
        $order = wc_get_order($order_id);
        if (!$order) {
            return;
        }

        $payment_intent_id = $order->get_meta('_chargeguard_payment_intent_id');

        // Fall back to common WooCommerce Stripe gateway meta keys — nothing
        // in ChargeGuard's own checkout flow writes this meta before the
        // gateway has actually created a payment intent, so on first pass
        // this key normally comes from the gateway itself.
        if (!$payment_intent_id) {
            $payment_intent_id = $order->get_meta('_stripe_intent_id')
                ?: $order->get_meta('_payment_intent_id')
                ?: $order->get_meta('_intent_id');

            if ($payment_intent_id) {
                $order->update_meta_data('_chargeguard_payment_intent_id', $payment_intent_id);
                $order->save_meta_data();
            }
        }

        if (!$payment_intent_id) {
            return;
        }

        $transient_key = 'chargeguard_pending_enrich_' . $payment_intent_id;
        $pending = get_transient($transient_key);

        if ($pending === false) {
            return;
        }

        // Delete before the API call so a slow/failed send_enrich() can't
        // cause this to be reprocessed on a subsequent payment-complete
        // fire for the same order.
        delete_transient($transient_key);

        $pending['orderId'] = (string) $order_id;

        $result = $this->api_client->send_enrich($pending);

        if (is_wp_error($result)) {
            error_log('[ChargeGuard] Deferred enrichment failed for order ' . $order_id . ': ' . $result->get_error_message());
            return;
        }

        $this->chargeguard_maybe_block_order(
            $result,
            $order_id,
            __('Blocked by ChargeGuard: Card Testing detected.', 'chargeguard-woocommerce')
        );
    }

    /**
     * استرجاع كائن Charge الكامل من PaymentIntent، مع دعم للتوافق العكسي.
     *
     * Backward compatible: on older Stripe API versions the legacy
     * `charges.data` list may still be populated on the webhook payload
     * itself, so we prefer that (no extra API call) when present. On
     * newer API versions `charges` is absent/null and we fall back to
     * `latest_charge`, which webhook payloads only ever send as a bare
     * ID — Stripe does not auto-expand nested objects on event payloads,
     * so a separate retrieve() call is required to get payment_method_details.
     *
     * @param \Stripe\PaymentIntent $payment_intent
     * @return \Stripe\Charge|null
     * @throws \Stripe\Exception\ApiErrorException
     */
    private function get_latest_charge($payment_intent) {
        // Legacy path (older API versions): charges.data still populated inline.
        if (!empty($payment_intent->charges) && !empty($payment_intent->charges->data)) {
            return $payment_intent->charges->data[0];
        }

        // Current path: resolve latest_charge (ID only) via a separate API call.
        if (!empty($payment_intent->latest_charge)) {
            $charge_id = is_string($payment_intent->latest_charge)
                ? $payment_intent->latest_charge
                : $payment_intent->latest_charge->id;

            return \Stripe\Charge::retrieve($charge_id);
        }

        return null;
    }

    }