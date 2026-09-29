import "server-only";
import { db } from "@/lib/db";
import { hashToken } from "@/lib/auth";

export async function audit(input: {
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
  request?: Request;
}) {
  const ip = input.request?.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  await db.auditLog.create({
    data: {
      actorId: input.actorId,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      metadata: input.metadata,
      ipHash: hashToken(ip)
    }
  });
}