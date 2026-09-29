import "server-only";
import argon2 from "argon2";
import crypto from "node:crypto";
import { cookies, headers } from "next/headers";
import { db } from "@/lib/db";
import type { RoleName } from "@prisma/client";

export const SESSION_COOKIE = "fotmob_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

function secret(): string {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters");
  return value;
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function hashToken(token: string): string {
  return crypto.createHmac("sha256", secret()).update(token).digest("hex");
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1
  });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  return argon2.verify(hash, password);
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function createSession(userId: string, request?: Request): Promise<void> {
  const raw = randomToken(32);
  const tokenHash = hashToken(raw);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  const h = request ? new Headers(request.headers) : await headers();

  await db.session.create({
    data: {
      tokenHash,
      userId,
      expiresAt,
      ipHash: hashToken((h.get("x-forwarded-for") ?? h.get("x-real-ip") ?? "unknown").split(",")[0].trim()),
      userAgent: h.get("user-agent")?.slice(0, 512)
    }
  });

  const jar = await cookies();
  jar.set(SESSION_COOKIE, raw, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS
  });
}

export async function destroySession(): Promise<void> {
  const jar = await cookies();
  const raw = jar.get(SESSION_COOKIE)?.value;
  if (raw) await db.session.deleteMany({ where: { tokenHash: hashToken(raw) } });
  jar.delete(SESSION_COOKIE);
}

export async function getCurrentUser() {
  const raw = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!raw) return null;

  const session = await db.session.findUnique({
    where: { tokenHash: hashToken(raw) },
    include: { user: { include: { roles: { include: { role: true } }, ambassador: true } } }
  });

  if (!session) return null;
  if (session.expiresAt <= new Date() || session.user.status !== "ACTIVE") {
    await db.session.delete({ where: { id: session.id } }).catch(() => undefined);
    return null;
  }

  await db.session.update({ where: { id: session.id }, data: { lastUsedAt: new Date() } }).catch(() => undefined);

  const roles = session.user.roles.map((r) => r.role.name);
  const permissions = session.user.roles.flatMap((r) => r.role.permissions.map((p) => p.permission.key));

  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    status: session.user.status,
    roles,
    permissions: [...new Set(permissions)],
    ambassador: session.user.ambassador
  };
}

export async function requireUser() {
  const user = await getCurrentUser();
  if (!user) throw new AuthError("UNAUTHENTICATED", "Authentication required");
  return user;
}

export async function requireRole(...allowed: RoleName[]) {
  const user = await requireUser();
  if (!user.roles.some((role) => allowed.includes(role as RoleName))) {
    throw new AuthError("FORBIDDEN", "Insufficient role");
  }
  return user;
}

export async function requirePermission(permission: string) {
  const user = await requireUser();
  if (!user.permissions.includes(permission)) {
    throw new AuthError("FORBIDDEN", "Missing permission");
  }
  return user;
}

export async function findUserByEmail(email: string) {
  return db.user.findUnique({ where: { email: normalizeEmail(email) } });
}

export { normalizeEmail };

export class AuthError extends Error {
  constructor(public code: "UNAUTHENTICATED" | "FORBIDDEN", message: string) {
    super(message);
  }
}