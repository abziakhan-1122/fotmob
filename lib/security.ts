import "server-only";
import crypto from "node:crypto";
import { db } from "@/lib/db";
import { hashToken } from "@/lib/auth";

const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;

export function clientKey(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return hashToken(forwarded || request.headers.get("x-real-ip") || "unknown");
}

export async function enforceLoginRateLimit(request: Request, email: string) {
  const key = hashToken("login:" + clientKey(request) + ":" + email.trim().toLowerCase());
  const since = new Date(Date.now() - WINDOW_MS);
  const failures = await db.loginAttempt.count({ where: { key, success: false, createdAt: { gt: since } } });
  if (failures >= MAX_FAILURES) {
    throw new Error("Too many login attempts. Please try again later.");
  }
  return key;
}

export async function recordLoginAttempt(key: string, success: boolean) {
  await db.loginAttempt.create({ data: { key, success } });
}

export function assertSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return;
  const expected = new URL(process.env.APP_URL || request.url).origin;
  if (origin !== expected) throw new Error("Invalid request origin");
}

export function secureRandomHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}