'use strict';
const https = require('https');
const tls   = require('tls');

const HOST = 'test.example.com';
const IP   = '127.0.0.1';
const PORT = 8443;

console.log('='.repeat(66));
console.log(' Node ' + process.version + '  (' + process.platform + ')');
console.log(' vulnerable if < v22.23.4 / v24.22.1 / v26.12.1');
console.log(' this build:', process.version, '-> patched if >= that line');
console.log('='.repeat(66));

function run(label, extra) {
  return new Promise((resolve) => {
    const opts = {
      host: IP,
      port: PORT,
      servername: HOST,
      path: '/',
      method: 'GET',
      headers: { Host: HOST },
      // force validation of the cert against HOST, not IP:
      checkServerIdentity: (h, cert) => tls.checkServerIdentity(HOST, cert),
      ...extra,
    };
    const req = https.request(opts, (res) => {
      console.log(`  [${label}] VULNERABLE — HTTP ${res.statusCode} from forged cert`);
      res.resume();
      res.on('end', () => resolve(true));
    });
    req.on('error', (e) => {
      const code = e.code || '';
      const msg  = (e.message || '').split('\n')[0];
      if (/CERT|TLS|SSL|UNABLE|SELF_SIGNED|ALTNAME/i.test(code)) {
        console.log(`  [${label}] PROTECTED — ${code}: ${msg}`);
      } else {
        console.log(`  [${label}] ERROR — ${code || '(no code)'}: ${msg}`);
      }
      resolve(false);
    });
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

(async () => {
  const r1 = await run('default', {});

  // also test with rejectUnauthorized=false to prove the network path works
  const r2 = await run('unverified', { rejectUnauthorized: false });

  console.log('');
  if (r2 && !r1) {
    console.log(' RESULT: network path OK, cert rejected by trust check');
    console.log('         -> Node is PROTECTED (fix applied)');
    console.log('         Any package / script on this Node is not exposed to');
    console.log('         the eMudhra forgery.');
  } else if (r1) {
    console.log(' RESULT: Node accepts the forged cert -> VULNERABLE.');
    console.log('         Upgrade to >= v22.23.4 / v24.22.1 / v26.12.1.');
  } else {
    console.log(' RESULT: both tests failed — is the server running in WSL on 8443?');
    console.log('         Try: curl -k https://localhost:8443/');
  }
  console.log('='.repeat(66));
  process.exit(r1 ? 0 : 1);
})();