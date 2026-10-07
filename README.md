# CSC337 Lab 05 — Enterprise Multi-Tenant Security Gateway by Ahsan Ali (SP24-BSE-004)

A complete, runnable teaching implementation of hybrid authentication, rotating refresh credentials, tenant-scoped RBAC and OWASP defenses. The responsive Sentinel dashboard and Express API are served from the same HTTPS origin.

**Delivery status:** source code and automated tests are complete. No public GitHub repository or live deployment has been created by this package. Real GitHub OAuth must be configured and tested before claiming the submission checklist is complete. This is a security-focused lab reference, not an independently audited enterprise product.

## 1. Stack and design

- Node.js 24, Express 5, plain HTML/CSS/JavaScript frontend.
- SQLite with parameterized queries, foreign keys and WAL; persistent disk required in deployment.
- Bcrypt (cost 12), Zod validation, Helmet, exact-origin CORS, express-rate-limit.
- Local sign-in and GitHub OAuth authorization code + PKCE + one-time state.
- JWT access credentials: 15 minutes, Authorization Bearer, browser memory only.
- Random opaque refresh credentials: SHA-256 hashes at rest; `__Host-refresh` cookie only, `HttpOnly; Secure; SameSite=Strict; Path=/`.
- Seven-day absolute session lifetime. Rotation does not extend the session indefinitely.
- One Express process and one persistent database. Horizontal scaling requires a shared database and shared rate-limit store.

## 2. Quick start (Windows / macOS / Linux)

Install Node.js 24 and OpenSSL. Git for Windows includes OpenSSL; run these commands in Git Bash if OpenSSL is unavailable in PowerShell.

```bash
npm ci
npm run setup
npm start
```

Open **https://localhost:3443**. Setup creates a random JWT secret in `.env` and a self-signed local certificate. Accept the certificate warning only for this local development app. For a trusted local certificate, use mkcert and place the generated files at `certs/localhost.pem` and `certs/localhost-key.pem`.

Do not switch the URL to HTTP or disable Secure cookies. GitHub login is hidden until the two OAuth variables are configured. The rest of the local application works independently.

```bash
npm test
npm run check
```

## 3. Required sample login accounts

With `SEED_DEMO=true`, these accounts are created on startup. **Workspace: `acme`**.

| Role | Email | Password |
|---|---|---|
| SuperAdmin | admin@acme.test | Lab05!DemoPass2026 |
| Manager | manager@acme.test | Lab05!DemoPass2026 |
| Employee | employee@acme.test | Lab05!DemoPass2026 |

A second tenant, **`globex`**, contains `admin@globex.test`, `manager@globex.test`, and `employee@globex.test`, with the same demo password. This makes tenant isolation demonstrable. Each stored password has an independently salted bcrypt hash. The README and seed fixture contain public lab credentials intentionally; the database never stores plaintext passwords.

Use public sample accounts only with synthetic lab data. Before real deployment with real users, remove the seeded accounts and turn off `SEED_DEMO`. Turning the flag off alone does not delete existing accounts. Seed is idempotent for existing users, but restarting with it enabled recreates deleted demo users.

## 4. GitHub OAuth setup

1. In GitHub, open Settings → Developer settings → OAuth Apps → New OAuth App.
2. For local testing, set Homepage URL to `https://localhost:3443`.
3. Set Authorization callback URL to `https://localhost:3443/api/v1/auth/github/callback`.
4. Copy the Client ID and generate a Client Secret. Put them in `.env` as `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`. Do not commit or share the secret.
5. Restart the server, click Continue with GitHub, and authorize the application.
6. For deployment, create a separate OAuth app or change the callback and homepage to the exact live HTTPS origin.

The flow uses PKCE S256, a browser-bound one-time state cookie, verified primary email, and GitHub's immutable user ID. GitHub users receive an isolated Employee workspace. Local and GitHub accounts are **not automatically linked by email**, preventing account takeover. Existing GitHub profiles are synchronized on subsequent sign-ins without replacing their role or tenant.
# Output

<img width="904" height="439" alt="git" src="https://github.com/user-attachments/assets/fecd3509-acf4-45fa-b323-0ebccac59fad" />

<img width="671" height="433" alt="hub" src="https://github.com/user-attachments/assets/d1f0ac9b-f58d-4861-b4e1-4e7d67b2b023" />

<img width="661" height="367" alt="repo" src="https://github.com/user-attachments/assets/2e8eeebd-1624-4480-9f7f-47f5c74d68a4" />

<img width="704" height="145" alt="abcfd" src="https://github.com/user-attachments/assets/057464dd-54f8-42de-a8bb-f1834ba8b3ce" />


## 5. API contract

Base URL: `https://localhost:3443/api/v1` locally; replace with your live origin after deployment.

All POST and DELETE requests use `Content-Type: application/json`. Empty mutations send `{}`. Protected routes use `Authorization: Bearer <accessToken>`.

| Method | Path | Access / request |
|---|---|---|
| POST | /auth/register | `{ "tenant":"new-team", "name":"Ahsan Ali", "email":"user@example.com", "password":"A-LongPassword!2026" }` |
| POST | /auth/login | `{ "tenant":"acme", "email":"employee@acme.test", "password":"Lab05!DemoPass2026" }` |
| GET | /auth/github | Browser OAuth redirect |
| GET | /auth/github/callback | Provider callback; code + state |
| POST | /auth/refresh | Refresh cookie, body `{}` |
| POST | /auth/logout | Refresh cookie, body `{}`; returns 204 |
| GET | /employee/profile | All authenticated roles |
| GET | /payroll | Tenant's payroll rows; all authenticated roles |
| POST | /payroll/approve | Manager or SuperAdmin; `{ "payrollId":"UUID" }` |
| GET | /users | SuperAdmin; own tenant only |
| DELETE | /users/:id | SuperAdmin; own tenant only; cannot delete self |
| GET | /health | Health check |
| GET | /config | Whether GitHub OAuth is configured; no secrets |

Register only creates a **new** workspace with an Employee. It cannot join an existing tenant or choose a role. `github-` is reserved. Manager and SuperAdmin provisioning is intentionally not exposed as public registration; the lab roles are supplied by the controlled seed. A real deployment would add a verified invitation and audited administrative provisioning flow.

## 6. RBAC matrix

| Route | Employee | Manager | SuperAdmin |
|---|---|---|---|
| GET /employee/profile | 200 | 200 | 200 |
| POST /payroll/approve | 403 | 200* | 200* |
| DELETE /users/:id | 403 | 403 | 204* |

`*` Valid, eligible resource in the same tenant required. Missing/cross-tenant resources return 404; already-approved payroll is not approved twice. Deleting yourself returns 400. Authentication failure returns 401. Roles are read from the database on every request, so an old JWT cannot preserve revoked privileges.

“SuperAdmin” is tenant-scoped in this implementation. It is not a cross-tenant platform operator.

## 7. Rotation, replay and logout

1. Login creates a session family and a 256-bit random refresh credential.
2. Only its SHA-256 hash is stored; the raw credential goes in the secure cookie.
3. Refresh transaction marks the old credential used and creates a new credential atomically.
4. Reuse of an old credential revokes the entire family, including its newest refresh token.
5. Logout revokes the family. Authentication checks the session database, so previously issued access tokens are rejected immediately too.
6. Expired session records are cleaned hourly. Used tokens remain until family expiry for replay detection.

The frontend coalesces refresh calls within one tab. Simultaneous refresh from different tabs can trigger the strict replay defense and require signing in again. This conservative lab behavior is documented rather than silently allowing a replay grace period.

## 8. OWASP defenses and practical limits

- Bcrypt cost 12; registration requires at least 12 characters and at most 72 UTF-8 bytes, avoiding bcrypt truncation.
- Persistent account-keyed lockout: five failed attempts within a 15-minute window; the next attempt returns 429 + Retry-After, including a correct password during the lock window. Unknown accounts receive equivalent password hashing work. Concurrent requests reserve attempts atomically; successful login resets the account counter.
- General API/IP rate limit of 120 requests/minute; registration 10/15 minutes. These IP counters are in-process and reset on restart; account lockout is stored in SQLite and persists.
- Strict JSON schemas reject extra fields, role injection, object-shaped credentials, `$` operators and prototype-related keys. Display names allow plain text only.
- Parameter binding, not string concatenation, prevents SQL injection. No dynamic NoSQL query construction exists.
- Passwords are not HTML-sanitized or silently modified. XSS prevention combines input validation, Helmet CSP and `textContent` output rendering; submitted text is never inserted with innerHTML.
- Exact-origin CORS, strict refresh cookies, JSON-only mutations and cross-site Fetch Metadata checks protect cookie mutation routes from browser CSRF. Origin-less Postman requests are allowed; CORS is not API authentication.
- Helmet security headers, no credential response caching, bounded JSON bodies, no tokens in URLs, generic authentication errors.
- Audit events contain no passwords, refresh credentials or provider tokens.
- SQLite persistence is suitable for this single-instance lab. 
## 9. Deploy on Render with HTTPS

This package includes `render.yaml`. **It selects a paid Starter web service with a persistent disk. Review Render's pricing before creating it.** Render's free ephemeral filesystem is not suitable for this SQLite deployment because it loses sessions/users across restarts or redeploys. A free serverless/Vercel deployment is not a drop-in target for this project; migrate storage to managed PostgreSQL first if choosing that approach.

1. Create a public GitHub repository, for example `LabAssignment05AWT`. Upload all project source files, `package.json`, `package-lock.json`, `render.yaml`, README and docs. Do not upload `node_modules`, `.env`, `certs`, `data`, or database files.
2. In Render create a Blueprint from that repository, or create a Node Web Service manually.
3. Use build command `npm ci --omit=dev`, start command `npm start`, and health path `/api/v1/health`.
4. Attach a persistent disk mounted at `/var/data`. Keep the service to one instance.
5. Configure the variables below. Render supplies `PORT`; do not hardcode the production port.
6. Set your OAuth app's homepage and callback to the exact live URL. Deploy/redeploy after changing environment settings.
7. Test the live dashboard, API health, all three demo roles, real GitHub login, rotation, replay and logout.

| Variable | Production value |
|---|---|
| NODE_ENV | production |
| APP_ORIGIN | Exact `https://YOUR-SERVICE.onrender.com` URL, no trailing slash |
| JWT_SECRET | Strong random secret, at least 32 bytes; Blueprint generates one |
| DATABASE_PATH | /var/data/gateway.sqlite |
| TRUST_PROXY_HOPS | 1 for this Render topology; never blindly trust arbitrary proxies |
| SEED_DEMO | true for synthetic assessment demo only |
| GITHUB_CLIENT_ID | Your OAuth app client ID |
| GITHUB_CLIENT_SECRET | Your OAuth app client secret |

Render terminates public TLS; production Node listens on the platform's internal HTTP port. Browser-facing transport stays HTTPS and cookies stay Secure. Only set production mode behind a trusted HTTPS reverse proxy.

### Upload with Git

Run from the project directory, replacing `YOUR_USERNAME` with your actual account:

```bash
git init
git add .
git commit -m "Implement CSC337 Lab 05 security gateway"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/LabAssignment05AWT.git
git push -u origin main
```

Create the empty repository in GitHub first. Do not pre-create a remote README if following these commands. Authenticate using GitHub's normal credential manager; never paste a personal token into source code.

## Outputs:

<img width="611" height="416" alt="58" src="https://github.com/user-attachments/assets/e06751c1-2fc1-4267-bd59-30b8158d84ed" />

<img width="611" height="416" alt="57" src="https://github.com/user-attachments/assets/1d5a06c5-f87b-4595-937e-b851f94e9d33" />

<img width="613" height="417" alt="56" src="https://github.com/user-attachments/assets/253a8378-1075-4aa2-81b7-6358f8b1f29f" />

<img width="596" height="416" alt="55" src="https://github.com/user-attachments/assets/6128f6f6-d78d-43a1-963d-b8d9deca57b2" />

<img width="623" height="354" alt="54" src="https://github.com/user-attachments/assets/d2866d4a-d553-40fc-80ce-6ef64010aa24" />

<img width="593" height="413" alt="53" src="https://github.com/user-attachments/assets/d2baff52-e9e7-452d-8f4b-3f31328e0d89" />

<img width="663" height="378" alt="52" src="https://github.com/user-attachments/assets/19a322c8-aa2d-4e9f-aa7b-ca5746cbcb44" />

<img width="679" height="416" alt="51" src="https://github.com/user-attachments/assets/c4a11c6e-8e6b-4b69-88ae-49da02efaa02" />



