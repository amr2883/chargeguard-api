content = open(r'C:\Users\Future\AppData\Local\Programs\Local\resources\extraResources\lightning-services\mysql-8.0.35+4\conf\my.cnf.hbs', 'r', encoding='utf-8').read()

old = "host = {{clientAddress}}"
new = "host = 127.0.0.1"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\AppData\Local\Programs\Local\resources\extraResources\lightning-services\mysql-8.0.35+4\conf\my.cnf.hbs', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND - showing content:')
    print(content)
