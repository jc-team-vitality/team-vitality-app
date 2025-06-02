import { z } from 'zod';

// Base schema for common fields, used for creation
export const IdentityProviderConfigCreateSchema = z.object({
  name: z.string().min(1, "Name cannot be empty."),
  issuer_uri: z.string().url("Invalid Issuer URI format."),
  well_known_uri: z.string().url("Invalid .well-known URI format."),
  client_id: z.string().min(1, "Client ID cannot be empty."),
  client_secret_name: z.string().min(1, "Client secret name cannot be empty."),
  scopes: z.string().min(1, "Scopes cannot be empty."),
  is_active: z.boolean().optional().default(true),
  supports_refresh_token: z.boolean(),
});
export type IdentityProviderConfigCreateDto = z.infer<typeof IdentityProviderConfigCreateSchema>;

// Schema for updating, all fields optional
export const IdentityProviderConfigUpdateSchema = IdentityProviderConfigCreateSchema.partial();
export type IdentityProviderConfigUpdateDto = z.infer<typeof IdentityProviderConfigUpdateSchema>;

// Schema for responses, including read-only fields like id and timestamps
export const IdentityProviderConfigSchema = IdentityProviderConfigCreateSchema.extend({
  id: z.string().uuid(), // Assuming UUIDs are strings from the DB/API response
  created_at: z.preprocess((arg) => {
    if (typeof arg == "string" || arg instanceof Date) return new Date(arg);
  }, z.date()),
  updated_at: z.preprocess((arg) => {
    if (typeof arg == "string" || arg instanceof Date) return new Date(arg);
  }, z.date()),
});
export type IdentityProviderConfigDto = z.infer<typeof IdentityProviderConfigSchema>;
