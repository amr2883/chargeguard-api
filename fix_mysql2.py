content = open(r'C:\Users\Future\AppData\Roaming\Local\run\fm7c2xsx_\conf\mysql\my.cnf', 'r', encoding='utf-8').read()

old = "host = ::1"
new = "host = 127.0.0.1"

if old in content:
    content = content.replace(old, new)
    open(r'C:\Users\Future\AppData\Roaming\Local\run\fm7c2xsx_\conf\mysql\my.cnf', 'w', encoding='utf-8').write(content)
    print('Done!')
else:
    print('Pattern NOT FOUND')
