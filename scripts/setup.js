import { existsSync,writeFileSync,mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
if(!existsSync('.env')) writeFileSync('.env',`NODE_ENV=development\nAPP_ORIGIN=https://localhost:3443\nPORT=3443\nJWT_SECRET=${randomBytes(48).toString('base64url')}\nDATABASE_PATH=./data/gateway.sqlite\nSEED_DEMO=true\nGITHUB_CLIENT_ID=\nGITHUB_CLIENT_SECRET=\n`);
mkdirSync('certs',{recursive:true});
if(!existsSync('certs/localhost.pem')) {
 const result=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout','certs/localhost-key.pem','-out','certs/localhost.pem','-days','30','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],{stdio:'inherit'});
 if(result.status!==0) { console.error('Install OpenSSL (Git for Windows includes it), or use mkcert localhost and rename the certificate files as documented.'); process.exit(1); }
}
console.log('Setup ready. Run npm start; open https://localhost:3443.');
