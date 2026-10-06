import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const DAY = 86400000;
const hash = value => createHash('sha256').update(value).digest('hex');
const random = () => randomBytes(32).toString('base64url');
const cookieName = '__Host-refresh';
const cookie = { httpOnly: true, secure: true, sameSite: 'strict', path: '/' };
const oauthCookie = { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 600000 };
const email = z.string().trim().toLowerCase().email().max(254);
const slug = z.string().regex(/^[a-z0-9-]{3,40}$/);
const password = z.string().min(12).refine(v => Buffer.byteLength(v) <= 72, 'Maximum 72 UTF-8 bytes');
const plainName = z.string().trim().min(2).max(80).regex(/^[\p{L}\p{N} .'-]+$/u);
const loginSchema = z.object({ tenant: slug, email, password: z.string().min(1).max(1000) }).strict();
const registerSchema = z.object({ tenant: slug, email, password, name: plainName }).strict();
function invalid(status, message) { return Object.assign(new Error(message), { status }); }
function validate(schema, input) { const r = schema.safeParse(input); if (!r.success) throw invalid(400, 'Invalid input or unexpected fields'); return r.data; }
function safeObject(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (key.startsWith('$') || key.includes('.') || ['__proto__','constructor','prototype'].includes(key)) throw invalid(400, 'Unsafe input key');
    safeObject(child);
  }
}
export function createApp(db, cfg, fetcher = fetch) {
  const app = express();
  app.disable('x-powered-by'); app.set('trust proxy', cfg.trustProxy || false);
  app.use(helmet({ referrerPolicy: { policy: 'no-referrer' } }));
  app.use(cors({ origin(origin, cb) { cb(origin && origin !== cfg.origin ? invalid(403, 'Origin denied') : null, !!origin); }, credentials: true, methods: ['GET','POST','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
  app.use('/api', (req,res,next) => { res.set('Cache-Control','no-store'); next(); });
  app.use(express.json({ limit: '16kb' }), cookieParser());
  app.use((req,res,next) => { safeObject(req.body); safeObject(req.query); next(); });
  app.use('/api', rateLimit({ windowMs: 60000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }));
  // Browser mutations must be same-origin. Origin-less API clients use JSON;
  // browsers cannot submit cross-origin JSON without passing the CORS preflight.
  app.use('/api', (req,res,next) => {
    if (['POST','DELETE'].includes(req.method)) {
      if (req.get('sec-fetch-site') === 'cross-site') throw invalid(403, 'Cross-site mutation denied');
      if (!req.is('application/json')) throw invalid(415, 'Use application/json');
    }
    next();
  });
  const audit = (user, action, resource = null) => db.prepare('INSERT INTO audit(tenant_id,actor_id,action,resource_id) VALUES(?,?,?,?)').run(user?.tenant_id || null,user?.id || null,action,resource);
  const publicUser = u => ({ id:u.id, name:u.name, email:u.email, tenant:u.tenant_id, role:u.role });
  function access(user, sid) { return jwt.sign({ sid, tenant:user.tenant_id }, cfg.secret, { algorithm:'HS256', subject:user.id, issuer:cfg.origin, audience:'gateway-api', expiresIn:'15m' }); }
  function issue(user, res) {
    const sid = randomUUID(), token = random(), expires = Date.now() + 7 * DAY;
    db.transaction(() => {
      db.prepare('INSERT INTO sessions(id,user_id,expires) VALUES(?,?,?)').run(sid,user.id,expires);
      db.prepare('INSERT INTO refresh_tokens(hash,session_id) VALUES(?,?)').run(hash(token),sid);
    })();
    res.cookie(cookieName, token, { ...cookie, maxAge:7 * DAY });
    return { accessToken:access(user,sid), expiresIn:900, user:publicUser(user) };
  }
  function authenticate(req,res,next) {
    try {
      const header = req.get('authorization') || '';
      if (!header.startsWith('Bearer ')) throw Error();
      const p = jwt.verify(header.slice(7),cfg.secret,{ algorithms:['HS256'], issuer:cfg.origin, audience:'gateway-api' });
      const s = db.prepare('SELECT * FROM sessions WHERE id=? AND user_id=? AND revoked=0 AND expires>?').get(p.sid,p.sub,Date.now());
      const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.sub);
      if (!s || !u || u.tenant_id !== p.tenant) throw Error();
      req.user=u; req.sid=s.id; next();
    } catch { next(invalid(401,'Authentication required')); }
  }
  const checkRole = roles => (req,res,next) => {
    if (!roles.includes(req.user.role)) { audit(req.user,'rbac.denied'); return next(invalid(403,'Insufficient role')); }
    next();
  };
  // Synchronous reservation is atomic even when bcrypt calls overlap. The fifth
  // failed attempt is permitted; subsequent attempts are blocked for the window.
  function reserveAttempt(key) {
    return db.transaction(() => {
      const now = Date.now();
      let row = db.prepare('SELECT * FROM login_attempts WHERE key=?').get(key);
      if (!row || row.until <= now) {
        db.prepare('INSERT OR REPLACE INTO login_attempts VALUES(?,0,?)').run(key,now+900000);
        row={ count:0, until:now+900000 };
      }
      if (row.count >= 5) return Math.ceil((row.until-now)/1000);
      db.prepare('UPDATE login_attempts SET count=count+1 WHERE key=?').run(key);
      return 0;
    })();
  }
  const dummyHash = bcrypt.hashSync(random(),12);
  app.get('/api/v1/health', (req,res) => { db.prepare('SELECT 1').get(); res.json({ status:'ok' }); });
  app.get('/api/v1/config', (req,res) => res.json({ githubEnabled:!!(cfg.githubClientId && cfg.githubClientSecret) }));
  app.post('/api/v1/auth/register', rateLimit({windowMs:900000,limit:10}), async(req,res) => {
    const v=validate(registerSchema,req.body);
    if(v.tenant.startsWith('github-')) throw invalid(400,'Reserved workspace prefix');
    const passwordHash=await bcrypt.hash(v.password,12);
    // Registration creates a NEW workspace only: never self-join an existing tenant.
    const user={ id:randomUUID(), tenant_id:v.tenant, email:v.email, name:v.name, role:'Employee' };
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO tenants VALUES(?,?)').run(v.tenant,v.tenant);
        db.prepare('INSERT INTO users(id,tenant_id,email,name,password_hash,role) VALUES(?,?,?,?,?,?)').run(user.id,user.tenant_id,user.email,user.name,passwordHash,user.role);
        audit(user,'register');
      })();
    } catch(e) { if(e.code?.startsWith('SQLITE_CONSTRAINT')) throw invalid(409,'Workspace unavailable'); throw e; }
    res.status(201).json(issue(user,res));
  });
  app.post('/api/v1/auth/login', async(req,res) => {
    const v=validate(loginSchema,req.body), key=hash(v.tenant+'\0'+v.email);
    const wait=reserveAttempt(key);
    if(wait) { res.set('Retry-After',String(wait)); throw invalid(429,'Too many attempts. Try after 15 minutes.'); }
    const u=db.prepare('SELECT * FROM users WHERE tenant_id=? AND email=?').get(v.tenant,v.email);
    const ok=await bcrypt.compare(v.password,u?.password_hash || dummyHash);
    if(!ok || !u?.password_hash) { audit(null,'login.failed'); throw invalid(401,'Invalid credentials'); }
    db.prepare('DELETE FROM login_attempts WHERE key=?').run(key);
    audit(u,'login'); res.json(issue(u,res));
  });
  app.post('/api/v1/auth/refresh', (req,res) => {
    const token=req.cookies[cookieName];
    if(typeof token !== 'string' || token.length > 200) throw invalid(401,'Refresh required');
    const result=db.transaction(() => {
      const row=db.prepare('SELECT r.*,s.user_id,s.revoked,s.expires FROM refresh_tokens r JOIN sessions s ON s.id=r.session_id WHERE r.hash=?').get(hash(token));
      if(!row || row.revoked || row.expires <= Date.now()) return null;
      if(row.used) {
        db.prepare('UPDATE sessions SET revoked=1 WHERE id=?').run(row.session_id);
        audit(null,'refresh.reuse',row.session_id); return null;
      }
      const u=db.prepare('SELECT * FROM users WHERE id=?').get(row.user_id);
      if(!u) return null;
      const next=random();
      db.prepare('UPDATE refresh_tokens SET used=1 WHERE hash=?').run(hash(token));
      db.prepare('INSERT INTO refresh_tokens VALUES(?,?,0)').run(hash(next),row.session_id);
      audit(u,'refresh.rotated',row.session_id);
      return { user:u, token:next, sid:row.session_id, expires:row.expires };
    })();
    if(!result) { res.clearCookie(cookieName,cookie); throw invalid(401,'Invalid, expired, or reused refresh token'); }
    res.cookie(cookieName,result.token,{...cookie,maxAge:result.expires-Date.now()});
    res.json({accessToken:access(result.user,result.sid),expiresIn:900,user:publicUser(result.user)});
  });
  app.post('/api/v1/auth/logout', (req,res) => {
    const token=req.cookies[cookieName];
    if(typeof token === 'string') {
      const row=db.prepare('SELECT session_id FROM refresh_tokens WHERE hash=?').get(hash(token));
      if(row) db.prepare('UPDATE sessions SET revoked=1 WHERE id=?').run(row.session_id);
    }
    res.clearCookie(cookieName,cookie); res.status(204).end();
  });
  app.get('/api/v1/employee/profile',authenticate,(req,res)=>res.json(publicUser(req.user)));
  app.get('/api/v1/users',authenticate,checkRole(['SuperAdmin']),(req,res)=>res.json(db.prepare('SELECT id,name,email,role FROM users WHERE tenant_id=?').all(req.user.tenant_id)));
  app.get('/api/v1/payroll',authenticate,(req,res)=>res.json(db.prepare('SELECT * FROM payroll WHERE tenant_id=?').all(req.user.tenant_id)));
  app.post('/api/v1/payroll/approve',authenticate,checkRole(['Manager','SuperAdmin']),(req,res)=>{
    const {payrollId}=validate(z.object({payrollId:z.string().uuid()}).strict(),req.body);
    const result=db.prepare("UPDATE payroll SET status='Approved',approved_by=? WHERE id=? AND tenant_id=? AND status='Pending'").run(req.user.id,payrollId,req.user.tenant_id);
    if(!result.changes) throw invalid(404,'Pending payroll not found in your workspace');
    audit(req.user,'payroll.approved',payrollId); res.json({message:'Payroll approved',payrollId});
  });
  app.delete('/api/v1/users/:id',authenticate,checkRole(['SuperAdmin']),(req,res)=>{
    const id=validate(z.string().uuid(),req.params.id);
    if(id===req.user.id) throw invalid(400,'Cannot delete your own account');
    db.transaction(()=>{
      const target=db.prepare('SELECT * FROM users WHERE id=? AND tenant_id=?').get(id,req.user.tenant_id);
      if(!target) throw invalid(404,'User not found in your workspace');
      db.prepare('DELETE FROM users WHERE id=? AND tenant_id=?').run(id,req.user.tenant_id);
      audit(req.user,'user.deleted',id);
    })(); res.status(204).end();
  });
  app.get('/api/v1/auth/github', (req,res)=>{
    if(!cfg.githubClientId || !cfg.githubClientSecret) throw invalid(503,'Configure GitHub OAuth credentials first');
    const state=random(),verifier=random();
    db.prepare('DELETE FROM oauth_states WHERE expires<?').run(Date.now());
    db.prepare('INSERT INTO oauth_states VALUES(?,?,?)').run(hash(state),verifier,Date.now()+600000);
    res.cookie('__Host-oauth-state',state,oauthCookie);
    const p=new URLSearchParams({client_id:cfg.githubClientId,redirect_uri:cfg.origin+'/api/v1/auth/github/callback',scope:'read:user user:email',state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
    res.redirect('https://github.com/login/oauth/authorize?'+p);
  });
  app.get('/api/v1/auth/github/callback', async(req,res)=>{
    const { code, state } = validate(
  z.object({
    code: z.string().min(1).max(512),
    state: z.string().min(1).max(200),
    iss: z.literal('https://github.com/login/oauth').optional()
  }).strict(),
  req.query
);
    const bound=req.cookies['__Host-oauth-state'];
    res.clearCookie('__Host-oauth-state',oauthCookie);
    if(typeof bound!=='string' || !timingSafeEqual(Buffer.from(hash(state)),Buffer.from(hash(bound)))) throw invalid(400,'OAuth state mismatch');
    const saved=db.prepare('DELETE FROM oauth_states WHERE hash=? AND expires>? RETURNING *').get(hash(state),Date.now());
    if(!saved) throw invalid(400,'OAuth state expired or already used');
    async function github(url,options) {
      const r=await fetcher(url,{...options,signal:AbortSignal.timeout(10000)});
      if(!r.ok) throw invalid(502,'OAuth provider unavailable');
      return r.json();
    }
    const token=await github('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({client_id:cfg.githubClientId,client_secret:cfg.githubClientSecret,code,code_verifier:saved.verifier,redirect_uri:cfg.origin+'/api/v1/auth/github/callback'})});
    if(!token.access_token) throw invalid(401,'OAuth exchange failed');
    const headers={Authorization:'Bearer '+token.access_token,Accept:'application/vnd.github+json','User-Agent':'CSC337-Gateway'};
    const profile=await github('https://api.github.com/user',{headers});
    const emails=await github('https://api.github.com/user/emails',{headers});
    const verified=Array.isArray(emails) && emails.find(e=>e.primary && e.verified);
    if(!verified || !Number.isSafeInteger(profile.id)) throw invalid(403,'A verified primary GitHub email is required');
    const address=validate(email,verified.email), githubId=String(profile.id);
    // Never link by email: provider subject is the stable identity.
    const u=db.transaction(()=>{
      let user=db.prepare('SELECT * FROM users WHERE github_id=?').get(githubId);
      const name=String(profile.name || profile.login).replace(/[<>\x00-\x1f]/g,'').slice(0,80);
      if(!user) {
        const tenant='github-'+githubId;
        db.prepare('INSERT INTO tenants VALUES(?,?)').run(tenant,'GitHub workspace');
        db.prepare('INSERT INTO users(id,tenant_id,email,name,github_id,role) VALUES(?,?,?,?,?,?)').run(randomUUID(),tenant,address,name,githubId,'Employee');
      } else db.prepare('UPDATE users SET email=?,name=? WHERE id=?').run(address,name,user.id);
      user=db.prepare('SELECT * FROM users WHERE github_id=?').get(githubId);
      audit(user,'oauth.login'); return user;
    })();
    issue(u,res); // Only refresh cookie leaves callback; no credentials in URL.
    res.redirect('/?oauth=success');
  });
  app.use(express.static(fileURLToPath(new URL('../public',import.meta.url))));
  app.use((req,res)=>res.status(404).json({error:'Not found'}));
  app.use((err,req,res,next)=>{
    const status=err.status || 500;
    if(status>=500) console.error('Request failed:',err.code || err.name); // Never log credentials or URLs.
    res.status(status).json({error:status>=500?'Service unavailable':err.message});
  });
  return app;
}
