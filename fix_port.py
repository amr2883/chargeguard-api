import json

with open(r'C:\Users\Future\AppData\Roaming\Local\sites.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for site_id, site in data.items():
    if site.get('name') == 'chargeguard-lab':
        site['services']['mysql']['ports']['MYSQL'] = [10005]
        print('Changed port to 10005')

with open(r'C:\Users\Future\AppData\Roaming\Local\sites.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
    print('Done!')
