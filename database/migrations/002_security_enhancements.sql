-- Security Enhancement Migration for Existing Database
-- This migration adds security columns to existing users and sessions tables
-- Run this AFTER backing up your existing data

-- ===================================================================
-- STEP 1: Backup existing data (manual step - see instructions below)
-- ===================================================================

-- Before running this migration, backup your existing data:
-- wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT * FROM users;" > users_backup.json
-- wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT * FROM sessions;" > sessions_backup.json

-- ===================================================================
-- STEP 2: Add new security columns to users table
-- ===================================================================

-- Add security tracking columns to users table
ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;
ALTER TABLE users ADD COLUMN last_login_at TEXT;
ALTER TABLE users ADD COLUMN last_login_ip TEXT;
ALTER TABLE users ADD COLUMN password_changed_at TEXT;

-- ===================================================================
-- STEP 3: Recreate sessions table with enhanced security
-- ===================================================================

-- Create new sessions table with enhanced security features
CREATE TABLE sessions_new (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,
    is_revoked BOOLEAN NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoked_reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Migrate existing session data (if any)
-- Note: Old sessions will lose some data but will remain functional
INSERT INTO sessions_new (id, user_id, expires_at, created_at, last_used_at, access_token, refresh_token)
SELECT 
    id, 
    user_id, 
    expires_at, 
    created_at,
    created_at as last_used_at,
    'legacy_' || id as access_token,
    'legacy_refresh_' || id as refresh_token
FROM sessions;

-- Drop old sessions table and rename new one
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

-- ===================================================================
-- STEP 4: Create enhanced security indexes
-- ===================================================================

-- User security indexes
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_users_security ON users(failed_login_attempts, locked_until);

-- Enhanced session indexes
CREATE INDEX idx_sessions_security ON sessions(user_id, is_revoked, ip_address);
CREATE INDEX idx_sessions_device ON sessions(device_fingerprint);
CREATE INDEX idx_sessions_activity ON sessions(last_used_at DESC);
CREATE INDEX idx_sessions_active ON sessions(user_id, is_revoked, expires_at) WHERE is_revoked = 0;

-- ===================================================================
-- STEP 5: Update existing user data
-- ===================================================================

-- Set password_changed_at for existing users
UPDATE users 
SET password_changed_at = created_at 
WHERE password_changed_at IS NULL;

-- ===================================================================
-- STEP 6: Verification queries
-- ===================================================================

-- Verify the migration worked correctly
-- These should return data without errors:

-- Check users table structure
-- PRAGMA table_info(users);

-- Check sessions table structure  
-- PRAGMA table_info(sessions);

-- Count records
-- SELECT 'users' as table_name, COUNT(*) as count FROM users
-- UNION ALL
-- SELECT 'sessions' as table_name, COUNT(*) as count FROM sessions;

-- ===================================================================
-- MIGRATION NOTES
-- ===================================================================

-- 1. This migration is designed to be safe and preserve existing data
-- 2. Existing users will need to log in again after this migration
-- 3. All existing sessions will be marked as legacy but will work
-- 4. New security features will apply to all new authentications
-- 5. Consider running VACUUM after migration to optimize database

-- To run this migration:
-- wrangler d1 execute teachinspire-prompt-builder-db --file=./database/migrations/002_security_enhancements.sql

-- Post-migration cleanup (optional):
-- wrangler d1 execute teachinspire-prompt-builder-db --command="VACUUM;"