content = open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'r', encoding='utf-8').read()

old = "    public function intercept_checkout() {"

new = """    public function intercept_checkout_block($order, $request) {
        if (!$this->api_client || !$this->api_client->get_api_key()) {
            return;
        }
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $email = $order->get_billing_email();
        $device_fp = isset($_COOKIE['chargeguard_fp']) ? sanitize_text_field($_COOKIE['chargeguard_fp']) : '';
        $amount = $order->get_total();
        $billing_country = $order->get_billing_country();

        $order_data = [
            'orderId' => 'pre_' . uniqid(),
            'email' => $email,
            'ipAddress' => $ip,
            'deviceFingerprint' => $device_fp,
            'amount' => (float)$amount,
            'billingCountry' => $billing_country,
            'merchantId' => get_option('chargeguard_merchant_id', ''),
        ];

        $result = $this->api_client->evaluate_risk($order_data);

        if (is_wp_error($result)) {
            return;
        }

        $decision = isset($result['decision']) ? $result['decision'] : '';

        if ($decision === 'block') {
            throw new \\Exception(__('Sorry, your order cannot be processed.', 'chargeguard-woocommerce'));
        }
    }

    public function intercept_checkout() {"""

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'w', encoding='utf-8').write(content)
    print("Done!")
else:
    print("Pattern NOT FOUND")
