import { Request, Response } from "express";
import { z } from "zod";
import { env } from "~/env";
import { UnauthorizedError, ZodValidationError } from "~/lib/http";
import { sign } from "~/lib/jwt";

export const permissions = ["read", "write", "delete"] as const;
export type Permissions = (typeof permissions)[number];

const TokenRequestSchema = z.object({
  expiresIn: z
    .string()
    .regex(/^\d+[smhdy]$/, "expiresIn must be a valid duration")
    .default("1y"),

  permissions: z.array(z.enum(permissions)).default(["read", "write"]),
});

export const keys = {
  header: "x-media-access-token",
  cookie: "__media_access_token__",
} as const;

export async function createAccessToken(req: Request, res: Response) {
  const secret = req.headers["x-secret"];
  if (secret !== env.SECRET_KEY) throw new UnauthorizedError("Permission denied");

  const result = TokenRequestSchema.safeParse(req.body);
  if (!result.success) throw new ZodValidationError(result.error);
  const token = await sign(result.data.permissions, { expiresIn: result.data.expiresIn });

  res.json({
    token,
    expiresIn: result.data.expiresIn,
    permissions: result.data.permissions,
    keys,
  });
}
