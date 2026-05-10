content = open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-api-client.php', 'r', encoding='utf-8').read()

old = "private $base_url = 'https://Amr453-chargeguard-space.hf.space/api';"
new = "private $base_url = 'https://chargeguard-api.onrender.com/api';"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-new\app\public\wp-content\plugins\chargeguard-1.0.0\includes\class-api-client.php', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND')
