<?php
/**
 * Shared auto-block logic for ChargeGuard webhook handlers.
 *
 * Used by both the Stripe and PayPal webhook handlers so the
 * auto-block decision logic exists in exactly one place.
 *
 * @package ChargeGuard_WooCommerce
 */

trait ChargeGuard_Auto_Block_Trait {

    /**
     * Fail the order automatically if the ChargeGuard decision is "block"
     * and the merchant has explicitly enabled auto-block.
     *
     * IMPORTANT: this fires from a post-capture webhook. Marking the order
     * "failed" does NOT refund the payment on Stripe/PayPal — merchants
     * must review and issue a manual refund. See admin settings warning.
     *
     * @param array  $result   Enrich result from ChargeGuard.
     * @param int    $order_id WooCommerce order ID.
     * @param string $reason   Order-note / status-change reason, gateway-specific.
     */
    private function chargeguard_maybe_block_order( $result, $order_id, $reason = '' ) {
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

        // Idempotency guard: if this order was already marked failed by a
        // previous call to this method, skip re-applying the status
        // transition and note. Protects every caller of this shared trait
        // method, not just the Stripe deferred-enrichment path that
        // originally surfaced the duplicate-call risk.
        if ( $order->has_status( 'failed' ) ) {
            return;
        }

        $min_amount = (float) get_option( 'chargeguard_block_min_amount', 0 );
        if ( $min_amount > 0 && $order->get_total() < $min_amount ) {
            return;
        }

        if ( '' === $reason ) {
            $reason = __( 'Blocked by ChargeGuard: fraud decision received.', 'chargeguard-woocommerce' );
        }

        $order->update_status( 'failed', $reason );
        $order->add_order_note( 'ChargeGuard decision: block. Flags: ' . json_encode( $result['flags'] ?? [] ) );
    }
}