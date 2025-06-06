-- Flyway Migration V2: Create Auth Tables for TeamVitality
-- This migration defines tables for OIDC identity providers, application users, and their relationships.

-- Table: identity_providers
-- Stores configuration for each supported OIDC Identity Provider (IdP).
CREATE TABLE identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL, -- Common name (e.g., 'google', 'facebook')
    issuer_uri TEXT UNIQUE NOT NULL, -- OIDC issuer URI
    well_known_uri TEXT NOT NULL, -- .well-known/openid-configuration URI
    client_id TEXT NOT NULL, -- OIDC client ID
    client_secret_name TEXT NOT NULL, -- Name of secret in GCP Secret Manager
    scopes TEXT NOT NULL, -- Space-separated OIDC scopes (e.g., 'openid email profile')
    is_active BOOLEAN NOT NULL DEFAULT TRUE, -- Whether this IdP is enabled
    supports_refresh_token BOOLEAN NOT NULL, -- Should app request/store refresh tokens for this IdP
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table: app_users
-- Stores application user accounts.
CREATE TABLE app_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL, -- User's email address
    first_name TEXT, -- Optional first name
    last_name TEXT, -- Optional last name
    roles TEXT[] NOT NULL DEFAULT ARRAY['User']::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Add a comment to the app_users.roles column to clarify its purpose
COMMENT ON COLUMN app_users.roles IS 'Array of roles assigned to the user, e.g., {User, Admin}. Defaults to {User}.';

-- Table: user_provider_links
-- Many-to-many join table linking users to their authenticated identity providers.
CREATE TABLE user_provider_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE, -- Linked user
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE, -- Linked IdP
    provider_user_id TEXT NOT NULL, -- Unique user identifier from IdP (e.g., 'sub' claim)
    encrypted_refresh_token BYTEA, -- refresh token encrypted with KMS
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, provider_user_id) -- Ensure unique link per IdP account
);

-- Insert initial data for Google OIDC Identity Provider
INSERT INTO identity_providers (
    name,
    issuer_uri,
    well_known_uri,
    client_id,
    client_secret_name,
    scopes,
    supports_refresh_token
) VALUES (
    'google',
    'https://accounts.google.com',
    'https://accounts.google.com/.well-known/openid-configuration',
    '63554064837-l4jksh58sqoo7c9a983dcplfjp3c5djo.apps.googleusercontent.com',
    'oidc_client_secret_google',
    'openid email profile',
    TRUE
);
