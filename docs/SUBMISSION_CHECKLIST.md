# Lab 05 — Complete only after live verification

Do not submit placeholders or check an item without testing it.

| Form field | Your entry |
|---|---|
| Official name / registration number | Select your own official record |
| WhatsApp / phone | Your active number |
| Live application URL | https://YOUR-SERVICE.onrender.com |
| Live backend/API base | https://YOUR-SERVICE.onrender.com/api/v1 |
| Public GitHub repository | https://github.com/YOUR_USERNAME/LabAssignment05AWT |
| OAuth provider | GitHub |

## Final checks

- [ ] Public repository opens while logged out.
- [ ] README contains all three test accounts.
- [ ] Live HTTPS dashboard and API health endpoint load.
- [ ] Local accounts use bcrypt hashes in the database.
- [ ] Real GitHub login works with the live callback URL.
- [ ] Access token is 15 minutes; refresh session is 7 days.
- [ ] Refresh cookie is HttpOnly, Secure and SameSite=Strict.
- [ ] Refresh rotates; replay revokes the family.
- [ ] Logout revokes refresh and access use for that session.
- [ ] Employee approval and Manager deletion are rejected.
- [ ] Cross-tenant resources cannot be accessed, including by SuperAdmin.
- [ ] Sixth failed-login-window attempt receives 429.
- [ ] Helmet, validation and exact-origin CORS are active.
- [ ] Persistent data survives a service restart.
- [ ] I can explain the implementation and demonstrate it in the viva.

Evidence to capture: successful role logins, Employee 403, Manager 403, SuperAdmin action, OAuth profile, cookie attributes with values redacted, refresh rotation, replay 401, lockout 429, public repository and live application. Never expose .env, client secrets, passwords for real accounts, or active token values.

Assignment inconsistency: it says public repositories are mandatory but another line references private sharing with an instructor email. Use public visibility per the main requirement and clarify any additional invitation with the instructor.
