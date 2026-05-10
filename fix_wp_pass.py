import subprocess
hash_val = '$2y$10$rmL3oIC23ZBbFM/uP8X38.tZV1hO1ixcYW8OhUKDFCuWHcKCvz6Rq'
sql = 'USE local; UPDATE wp_users SET user_pass="' + hash_val + '" WHERE user_login="admin";'
cmd = [
    r'C:\Users\Future\AppData\Roaming\Local\lightning-services\mysql-8.0.35+4\bin\win64\bin\mysql.exe',
    '-u', 'root', '-proot', '-h', '127.0.0.1', '-P', '10012',
    '-e', sql
]
result = subprocess.run(cmd, capture_output=True, text=True)
print('stderr:', result.stderr)
print('Done')
