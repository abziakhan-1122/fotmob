# Authentication Architecture

## Components

- lib/auth.ts: password hashing, opaque sessions, current-user lookup, RBAC guards.
- lib/security.ts: login throttling, origin checks, request-key hashing.
- lib/validation.ts: Zod request schemas.
- lib/audit.ts: security audit events.
- lib/mail.ts: password reset delivery.
- prisma/schema.prisma: users, roles, permissions, sessions, reset tokens, login attempts and audit logs.
- app/api/auth/*: authentication API routes.
- app/api/admin/*: administrator authorization example.
- app/api/ambassador/*: granular ambassador authorization example.

## Credential lifecycle

Passwords are received only by the server over HTTPS and are passed to Argon2id; only the resulting hash is persisted.

A session starts with a cryptographically random opaque value. The raw value is placed in an HttpOnly cookie; PostgreSQL stores only its HMAC-SHA256 digest.

Password reset uses a random single-use token, stores only its digest, expires after 30 minutes, and revokes all existing sessions after a successful reset.

## Authorization flow

1. Resolve the session from the HttpOnly cookie.
2. Reject expired, revoked, or suspended sessions.
3. Load roles and permissions from PostgreSQL.
4. Enforce role/permission in the server handler.
5. For domain mutations, enforce university/league resource scope in the service layer.
6. Audit security-sensitive operations.

## Production hardening

Add email verification, MFA/WebAuthn for administrators, secret rotation, CAPTCHA/edge rate limiting, centralized session cleanup, security headers/CSP, strict HTTPS, and monitoring/alerting before production scale.
