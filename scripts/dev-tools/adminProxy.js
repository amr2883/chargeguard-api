const http = require('http');
const https = require('https');

const ADMIN_KEY = process.env.ADMIN_KEY_LOCAL;
const TARGET_HOST = 'chargeguard-api.onrender.com';
const PORT = 9000;

if (!ADMIN_KEY) {
  console.error('ERROR: ADMIN_KEY_LOCAL environment variable is not set.');
  process.exit(1);
}

const server = http.createServer((req, res) => {
  const headers = { ...req.headers, host: TARGET_HOST, 'x-admin-key': ADMIN_KEY };

  const proxyReq = https.request(
    { hostname: TARGET_HOST, port: 443, path: req.url, method: req.method, headers },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    }
  );

  req.pipe(proxyReq, { end: true });

  proxyReq.on('error', (err) => {
    res.writeHead(502);
    res.end('Proxy error: ' + err.message);
  });
});

server.listen(PORT, () => {
  console.log(`✅ Local admin proxy running — open: http://localhost:${PORT}/admin`);
});