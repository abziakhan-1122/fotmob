# FotMob

Secure authentication foundation for the football data platform.

## Implemented

- Email/password registration and login.
- Argon2id password hashing; plaintext passwords are never persisted.
- Opaque random session tokens stored only as HMAC-SHA256 hashes in PostgreSQL.
- HttpOnly + SameSite=Lax session cookie; Secure in production.
- 30-day server-side sessions with expiry and revocation.
- Password reset tokens are random, hashed at rest, single-use, and expire after 30 minutes.
- Login rate limiting: 10 failed attempts per 15 minutes per hashed IP/email key.
- Origin validation for state-changing auth requests.
- RBAC roles: SUPER_ADMIN, ADMIN, EDITOR, AMBASSADOR, USER.
- Granular ambassador permissions.
- Server-side requireUser, requireRole, and requirePermission guards.
- Audit logging for registration/login/logout with hashed IP data.
- Admin and ambassador API boundaries.
- Bootstrap admin seeding through environment variables.

## Setup

1. Copy .env.example to .env.local.
2. Set a PostgreSQL DATABASE_URL.
3. Set a strong, unique SESSION_SECRET with at least 32 characters.
4. Run npm install.
5. Run npm run db:push.
6. Optionally set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD, then run npm run db:seed.
7. Start with npm run dev.

Production password reset delivery requires RESEND_API_KEY, MAIL_FROM, and APP_URL.

## Request flow

POST /api/auth/login
→ validate with Zod
→ rate limit
→ normalized email lookup
→ Argon2id verification
→ random opaque session token
→ only HMAC-SHA256 token hash stored in PostgreSQL
→ HttpOnly/SameSite cookie
→ server-side session + role/permission resolution.

The browser never supplies roles or permissions. Authorization is derived from PostgreSQL.

## Authorization

Every sensitive server action/API handler should call requireUser, requireRole, or requirePermission. For university/league features, permission checks are necessary but not sufficient: service-layer code must also verify that an ambassador is assigned to the target university/league before mutation.

## Security

- Never store credentials, password hashes, session tokens, or reset tokens in localStorage.
- Use HTTPS in production.
- Keep DATABASE_URL and SESSION_SECRET server-only.
- Rotate/revoke sessions after password changes.
- Add email verification, MFA, CAPTCHA/edge rate limiting, and account-recovery policy before exposing the platform at scale.
- Keep admin endpoints server-protected; hiding admin links is not authorization.
