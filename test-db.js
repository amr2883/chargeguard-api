const p = require('./chargeguard-space/src/lib/db');
p.$connect()
  .then(() => {
    console.log('DB_CONNECTION: OK');
    process.exit(0);
  })
  .catch(e => {
    console.error('DB_CONNECTION: FAILED', e.message);
    process.exit(1);
  });
