content = open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-api-client.php', 'r', encoding='utf-8').read()

old = """        if ($code >= 200 && $code < 300) {
            return $body;
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }
}"""

new = """        if ($code >= 200 && $code < 300) {
            return $body;
        } elseif ($code === 403) {
            return ['decision' => 'block', 'score' => 100, 'flags' => []];
        } else {
            return new WP_Error('api_error', $body['error'] ?? 'Unknown error');
        }
    }
}"""

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-api-client.php', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND')
