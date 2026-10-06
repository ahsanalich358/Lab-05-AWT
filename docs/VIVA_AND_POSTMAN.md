# Lab 05 — Viva and Postman Demonstration

## Import and prepare

Import `Lab05.postman_collection.json`. Set `baseUrl` to `https://localhost:3443/api/v1` or your live HTTPS API base. Set `origin` to the matching origin without `/api/v1`. The collection defaults to the local values.

For the local self-signed certificate only, trust it in Postman or disable SSL verification for the local test. Keep certificate verification enabled for public deployments. Postman keeps the refresh token in its cookie jar automatically; never place it in the Authorization header.

## Recommended live demo order

1. **Employee login:** run Login Employee. Its script stores `accessToken` in the collection environment. Profile returns 200. List Payroll captures a real `payrollId`. Approve Payroll returns **403**.
2. **Manager login:** run Login Manager, then List Payroll and Approve Payroll. Expect **200** on a Pending record. Once approved, repeating returns 404 by design.
3. **Manager rejection:** List Users returns **403**. Delete User (with a valid target ID) also returns 403.
4. **SuperAdmin:** run Login SuperAdmin and List Users. Copy an Employee ID into `userId`, then Delete User; expect **204**. Perform destructive demo last, or use a disposable account/tenant. Self-delete returns 400. Restart with demo seeding enabled to recreate deleted demo users.
5. **Tenant isolation:** sign in as Globex SuperAdmin and List Payroll to record its payroll ID. Sign in as Acme Manager and submit the Globex ID to Approve Payroll; expect **404** even though the record exists. Refresh List Payroll after switching users so you do not accidentally use stale IDs in normal demonstrations.
6. **Refresh rotation:** log in again. In Postman's cookie jar, observe `__Host-refresh`. Run Refresh. The cookie changes; response contains a new 15-minute access token, with no refresh token in JSON. Check HttpOnly, Secure, SameSite=Strict and Path=/ in browser DevTools or Set-Cookie headers.
7. **Replay detection:** save the old refresh-cookie value privately before rotating. Use a separate request with the cookie jar disabled and manually send `Cookie: __Host-refresh=OLD_VALUE`. POST Refresh returns **401**. Restoring the newer value also returns 401 because the family is revoked. Do not include token values in submitted screenshots.
8. **Logout:** log in, run Logout, then call Profile with the old access token and Refresh with the old cookie. Both return **401**.
9. **Lockout:** run Wrong Password five times for the same tenant/email. These return **401**. The sixth request, including correct credentials, returns **429** with Retry-After. Wait for the 15-minute window. Demonstrate this after other role tests so it does not block them.
10. **OAuth in browser:** click Continue with GitHub, authorize, return to the dashboard. Open Profile and show the GitHub Employee workspace. This must be a real provider sign-in; mocked automated tests are not proof of live OAuth.

When replay testing, Postman may override a manually entered Cookie header with its cookie jar. Disable the jar for the replay request or use a separate client. In real browsers the application cannot read an httpOnly cookie; DevTools/Postman inspection is for your viva demonstration only.

## Short viva answers (Roman Urdu + technical terms)

**Authentication aur authorization mein farq?** Authentication check karta hai aap kaun hain. Authorization check karta hai aap ko kaunsa action karne ki permission hai.

**Bcrypt kyun?** Password ko slow, salted hash mein convert karta hai. Database leak ho to original password seedha nahin milta. Login par bcrypt.compare use hota hai; password decrypt nahin hota.

**JWT encrypted hai?** Nahin. Is project ka JWT signed hai; payload readable hai. Signature tampering detect karti hai. Is liye secret data JWT mein nahin rakhte.

**Access token 15 minutes kyun?** Chori hone par token ki useful lifetime kam hoti hai. Is project mein session revocation check bhi hai, is liye logout ke baad token foran reject hota hai.

**Refresh token kyun?** User ko har 15 minutes password dobara type nahin karna padta. Secure cookie se new access token mil jata hai.

**Rotation kya hai?** Har refresh par old token used mark hota hai aur naya random token milta hai. Purana token dobara aaye to poori session family revoke hoti hai.

**httpOnly, Secure aur SameSite?** httpOnly JavaScript ko cookie read karne se rokta hai; Secure cookie HTTPS par bhejta hai; SameSite=Strict cross-site requests mein refresh cookie bhejne se rokta hai. HttpOnly akela har XSS action ko nahin rokta; CSP aur safe rendering bhi zaroori hain.

**OAuth state aur PKCE?** State browser login request ko callback se bind karta hai aur login CSRF se protect karta hai. PKCE code verifier prove karta hai ke authorization flow start karne wala client hi code exchange kar raha hai.

**GitHub callback cookie Lax kyun?** Provider se wapas aana cross-site top-level navigation hai. Temporary state cookie Lax hai; assignment ka refresh cookie hamesha Strict hai.

**RBAC kahan enforce hota hai?** Backend authenticate middleware ke baad checkRole allowed roles compare karta hai. Sirf frontend button hide karna security nahin hai.

**Multi-tenant ka matlab?** Ek app mein multiple organizations. Resource queries authenticated user ke tenant_id se scope hoti hain. Client apni marzi se tenant change nahin kar sakta.

**401, 403, 404, 429?** 401 invalid/missing authentication; 403 authenticated user ko permission nahin; 404 current tenant mein resource nahin milta; 429 request/attempt limit cross hui.

**CORS kya authentication hai?** Nahin. Yeh browser origin policy hai. Postman CORS se protected nahin hota; JWT aur RBAC API ko protect karte hain.

**SQL injection se kaise bachaya?** Prepared statements aur bound parameters. NoSQL operators aur unexpected payload shapes validation se reject hote hain.

**XSS se kaise bachaya?** Plain-text validation, frontend textContent, aur Helmet CSP. Password ko sanitize karke change nahin karte.

**SQLite kyun?** Single-instance lab ko persistent, transactional storage deta hai. Multiple instances ke liye managed database aur shared rate-limit store chahiye.

**Registration se admin kyun nahin ban sakte?** Role choose karna privilege escalation hota. Public registration sirf naya Employee workspace banati hai; privileged roles controlled provisioning se milte hain.
