import { z } from "zod";

export const registerSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(12).max(128)
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(1).max(128)
});

export const forgotPasswordSchema = z.object({
  email: z.string().trim().toLowerCase().email().max(254)
});

export const resetPasswordSchema = z.object({
  token: z.string().min(40).max(200),
  password: z.string().min(12).max(128)
});