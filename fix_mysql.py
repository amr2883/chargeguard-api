content = open(r'C:\Users\Future\Local Sites\chargeguard-lab\conf\mysql\my.cnf.hbs', 'r', encoding='utf-8').read()

old = "host = {{clientAddress}}"
new = "host = 127.0.0.1"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\Local Sites\chargeguard-lab\conf\mysql\my.cnf.hbs', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND')
