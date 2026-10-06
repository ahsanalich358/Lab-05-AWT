import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { getConfig } from './config.js';
import { openDatabase } from './db.js';
import { createApp } from './app.js';
import { seedDemo } from './seed.js';
const cfg=getConfig(), db=openDatabase(cfg.dbPath);
if(process.env.SEED_DEMO === 'true') await seedDemo(db);
const app=createApp(db,cfg), port=Number(process.env.PORT || 3443);
const server=cfg.production ? app.listen(port,'0.0.0.0') : createServer({key:readFileSync('./certs/localhost-key.pem'),cert:readFileSync('./certs/localhost.pem')},app).listen(port);
console.log(`Gateway listening; public origin: ${cfg.origin}`);
// Retain used tokens until their family expires so replay detection remains effective.
const cleanup=setInterval(()=>{
  db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());
  db.prepare('DELETE FROM login_attempts WHERE until<?').run(Date.now());
  db.prepare('DELETE FROM oauth_states WHERE expires<?').run(Date.now());
},3600000); cleanup.unref();
for(const signal of ['SIGTERM','SIGINT']) process.on(signal,()=>server.close(()=>{clearInterval(cleanup);db.close();process.exit(0);}));
