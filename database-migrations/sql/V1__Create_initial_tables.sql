-- This is a placeholder for the initial schema setup.
-- It creates a users table and a table for linking identity providers.
CREATE TABLE app_users (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
email VARCHAR(255) UNIQUE NOT NULL,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_identity_providers (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
provider_name VARCHAR(50) NOT NULL,
provider_user_id VARCHAR(255) NOT NULL,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
UNIQUE (provider_name, provider_user_id)
);
