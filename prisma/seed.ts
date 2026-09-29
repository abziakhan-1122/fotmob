import { PrismaClient, RoleName } from "@prisma/client";
import argon2 from "argon2";

const db = new PrismaClient();

const permissions = [
  ["VIEW_MATCHES", "View matches"],
  ["EDIT_MATCHES", "Edit matches"],
  ["ADD_EVENTS", "Add match events"],
  ["EDIT_EVENTS", "Edit match events"],
  ["CREATE_NEWS", "Create news"],
  ["EDIT_NEWS", "Edit news"],
  ["UPLOAD_MEDIA", "Upload media"],
  ["MANAGE_ASSIGNED_LEAGUES", "Manage assigned leagues"]
];

const rolePermissions: Record<RoleName, string[]> = {
  SUPER_ADMIN: permissions.map(([key]) => key),
  ADMIN: permissions.map(([key]) => key),
  EDITOR: ["VIEW_MATCHES", "EDIT_MATCHES", "ADD_EVENTS", "EDIT_EVENTS", "CREATE_NEWS", "EDIT_NEWS", "UPLOAD_MEDIA"],
  AMBASSADOR: ["VIEW_MATCHES", "EDIT_MATCHES", "ADD_EVENTS", "EDIT_EVENTS", "CREATE_NEWS", "EDIT_NEWS", "UPLOAD_MEDIA", "MANAGE_ASSIGNED_LEAGUES"],
  USER: ["VIEW_MATCHES"]
};

async function main() {
  for (const [key, description] of permissions) {
    await db.permission.upsert({ where: { key }, update: { description }, create: { key, description } });
  }

  for (const name of Object.values(RoleName)) {
    const role = await db.role.upsert({
      where: { name },
      update: {},
      create: { name, description: name.replaceAll("_", " ") }
    });
    for (const key of rolePermissions[name]) {
      const permission = await db.permission.findUniqueOrThrow({ where: { key } });
      await db.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId: permission.id } },
        update: {},
        create: { roleId: role.id, permissionId: permission.id }
      });
    }
  }

  const email = process.env.BOOTSTRAP_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (email && password) {
    const role = await db.role.findUniqueOrThrow({ where: { name: "SUPER_ADMIN" } });
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const user = await db.user.upsert({
      where: { email },
      update: { passwordHash, status: "ACTIVE", emailVerifiedAt: new Date() },
      create: { email, passwordHash, name: "Super Admin", emailVerifiedAt: new Date() }
    });
    await db.userRole.upsert({
      where: { userId_roleId: { userId: user.id, roleId: role.id } },
      update: {},
      create: { userId: user.id, roleId: role.id }
    });
  }
}

main().finally(() => db.$disconnect());