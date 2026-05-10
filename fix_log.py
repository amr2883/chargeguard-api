content = open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'r', encoding='utf-8').read()

old = "        // لا تفعل شيئًا إذا لم يكن هناك عميل API أو مفتاح\n        if (!$this->api_client || !$this->api_client->get_api_key()) {\n            return;\n        }"

new = "        // لا تفعل شيئًا إذا لم يكن هناك عميل API أو مفتاح\n        error_log('ChargeGuard intercept_checkout called. API client: ' . ($this->api_client ? 'YES' : 'NO') . ' Key: ' . ($this->api_client ? ($this->api_client->get_api_key() ? 'YES' : 'NO') : 'N/A'));\n        if (!$this->api_client || !$this->api_client->get_api_key()) {\n            error_log('ChargeGuard: No API client or key, returning early');\n            return;\n        }"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-dynamic-firewall.php', 'w', encoding='utf-8').write(content)
    print("Done!")
else:
    print("Pattern NOT FOUND")
