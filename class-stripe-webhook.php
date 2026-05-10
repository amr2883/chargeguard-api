<?php
class ChargeGuard_Stripe_Webhook {
    private $api_client;
    public function __construct() {
        $this->api_client = new ChargeGuard_API_Client();
        add_action("rest_api_init", [$this, "register_rest_route"]);
    }
    public function register_rest_route() {
        register_rest_route("chargeguard/v1", "/stripe-webhook", [
            "methods"             => "POST",
            "callback"            => [$this, "handle_webhook"],
            "permission_callback" => "__return_true",
        ]);
    }
    public function handle_webhook($request) {
        $payload   = $request->get_body();
        $sig_header = $request->get_header("stripe_signature");
        $endpoint_secret = get_option("chargeguard_stripe_webhook_secret");
        try {
            $event = \Stripe\Webhook::constructEvent($payload, $sig_header, $endpoint_secret);
        } catch (\Exception $e) {
            return new \WP_REST_Response(["error" => "Invalid signature"], 403);
        }
        if ($event->type !== "payment_intent.succeeded") {
            return new \WP_REST_Response(["status" => "ignored"], 200);
        }
        $payment_intent = $event->data->object;
        $charges = $payment_intent->charges->data;
        if (empty($charges)) {
            return new \WP_REST_Response(["error" => "No charges found"], 400);
        }
        $charge = $charges[0];
        $card = $charge->payment_method_details->card ?? null;
        if (!$card) {
            return new \WP_REST_Response(["error" => "No card details found"], 400);
        }
        $iin     = $card->iin ?? null;
        $brand   = $card->brand ?? null;
        $country = $card->country ?? null;
        $funding = $card->funding ?? null;
        if (!$iin) {
            return new \WP_REST_Response(["error" => "No IIN found"], 400);
        }
        $orders = wc_get_orders([
            "limit"       => 1,
            "meta_key"    => "_chargeguard_payment_intent_id",
            "meta_value"  => $payment_intent->id,
            "return"      => "ids",
        ]);
        $order_id = !empty($orders) ? $orders[0] : $payment_intent->metadata->order_id ?? null;
        if (!$order_id) {
            set_transient("chargeguard_pending_enrich_" . $payment_intent->id, [
                "orderId"     => null,
                "paymentIntentId" => $payment_intent->id,
                "bin"         => $iin,
                "cardBrand"   => $brand,
                "cardCountry" => $country,
                "funding"     => $funding,
                "issuer"      => $charge->payment_method_details->card->issuer ?? null,
            ], HOUR_IN_SECONDS);
            return new \WP_REST_Response(["status" => "pending", "message" => "Order not found, enrichment queued locally."], 202);
        }
        $enrich_data = [
            "orderId"         => (string) $order_id,
            "paymentIntentId" => $payment_intent->id,
            "bin"             => $iin,
            "cardBrand"       => $brand,
            "cardCountry"     => $country,
            "funding"         => $funding,
            "issuer"          => $charge->payment_method_details->card->issuer ?? null,
        ];
        $result = $this->api_client->send_enrich($enrich_data);
        if (is_wp_error($result)) {
            return new \WP_REST_Response(["error" => $result->get_error_message()], 500);
        }
        $this->maybe_block_order($result, $order_id);
        return new \WP_REST_Response(["status" => "enriched", "result" => $result], 200);
    }
    private function maybe_block_order($result, $order_id) {
        $auto_block = get_option("chargeguard_auto_block", "no");
        if ($auto_block !== "yes") { return; }
        $decision = $result["newDecision"] ?? $result["decision"] ?? "";
        if (strtolower($decision) !== "block") { return; }
        $order = wc_get_order($order_id);
        if (!$order) { return; }
        $min_amount = (float) get_option("chargeguard_block_min_amount", 0);
        if ($min_amount > 0 && $order->get_total() < $min_amount) { return; }
        $order->update_status("failed", __("Blocked by ChargeGuard: Card Testing detected.", "chargeguard-woocommerce"));
        $order->add_order_note("ChargeGuard decision: block. Flags: " . json_encode($result["flags"] ?? []));
    }
}
