content = open(r'C:\Users\Future\AppData\Local\Programs\Local\resources\extraResources\lightning-services\mysql-8.0.35+4\lib\MysqlService.js', 'r', encoding='utf-8').read()

old = "clientAddress: '::1',"
new = "clientAddress: '127.0.0.1',"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\AppData\Local\Programs\Local\resources\extraResources\lightning-services\mysql-8.0.35+4\lib\MysqlService.js', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND')
