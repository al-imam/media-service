import axios from "axios";
import { IncomingHttpHeaders } from "http";
import z from "zod";
import { env } from "~/env";

export interface ValidationRequest {
  id: string;
  permissions: string[];
}

export const ValidationResponseSchema = z.object({
  success: z.boolean(),
  allowed: z.boolean(),
  message: z.string().optional(),
});

export async function validateAccess({
  id,
  headers,
  permissions,
  ...rest
}: {
  id: string;
  permissions: string[];
  headers: IncomingHttpHeaders;
  [key: string]: unknown;
}): Promise<boolean> {
  if (!env.VALIDATION_URI) throw new Error("Validation URI is not configured");

  try {
    const response = await axios.post<z.infer<typeof ValidationResponseSchema>>(
      env.VALIDATION_URI,
      { ...rest, id, permissions },
      { headers: { ...headers, host: undefined }, withCredentials: true, timeout: 5000 }
    );

    const result = ValidationResponseSchema.parse(response.data);
    return result.success && result.allowed === true;
  } catch {
    return false;
  }
}
