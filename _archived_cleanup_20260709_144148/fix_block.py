content = open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'r', encoding='utf-8').read()

old = "        // 5. فحص المخاطر قبل معالجة الطلب\n        add_action('woocommerce_checkout_process', [$this, 'intercept_checkout']);"

new = "        // 5. فحص المخاطر قبل معالجة الطلب\n        add_action('woocommerce_checkout_process', [$this, 'intercept_checkout']);\n        add_action('woocommerce_store_api_checkout_update_order_from_request', [$this, 'intercept_checkout_block'], 10, 2);"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'w', encoding='utf-8').write(content)
    print("Done!")
else:
    print("Pattern NOT FOUND")
