-- Flyway Migration V2: Add roles to app_users table
ALTER TABLE app_users
ADD COLUMN roles TEXT[] NOT NULL DEFAULT ARRAY['User']::TEXT[];

COMMENT ON COLUMN app_users.roles IS 'Array of roles assigned to the user, e.g., {User, Admin}. Defaults to {User}.';
