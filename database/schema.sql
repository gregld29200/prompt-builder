-- Teachinspire Prompt Builder D1 Database Schema
-- Optimized for edge distribution and eventual consistency

-- Users table for authentication with enhanced security
CREATE TABLE users (
    id TEXT PRIMARY KEY, -- UUID for global uniqueness across edge locations
    email TEXT NOT NULL UNIQUE COLLATE NOCASE, -- Case-insensitive email
    password_hash TEXT NOT NULL, -- bcrypt hashed password
    email_verified BOOLEAN NOT NULL DEFAULT 0, -- SQLite uses 0/1 for boolean
    is_active BOOLEAN NOT NULL DEFAULT 1, -- Account status
    failed_login_attempts INTEGER NOT NULL DEFAULT 0, -- Security: Track failed attempts
    locked_until TEXT, -- Security: Account lockout timestamp
    last_login_at TEXT, -- Security: Track last login
    last_login_ip TEXT, -- Security: Track login IP
    password_changed_at TEXT, -- Security: Track password changes
    created_at TEXT NOT NULL DEFAULT (datetime('now')), -- ISO 8601 timestamp
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Prompts table for storing user-generated prompts
CREATE TABLE prompts (
    id TEXT PRIMARY KEY, -- UUID for global uniqueness
    user_id TEXT NOT NULL,
    title TEXT NOT NULL CHECK(length(title) <= 100), -- Max 100 chars as requested
    raw_request TEXT NOT NULL, -- Original user input
    generated_prompt TEXT NOT NULL, -- AI-generated prompt
    prompt_type TEXT NOT NULL CHECK(prompt_type IN ('MVP', 'AGENTIC')),
    domain TEXT NOT NULL CHECK(domain IN ('education', 'technical', 'creative', 'analysis', 'other')),
    language TEXT NOT NULL CHECK(language IN ('fr', 'en')),
    output_length TEXT NOT NULL CHECK(output_length IN ('short', 'medium', 'long')),
    expert_role TEXT, -- Optional field
    mission TEXT, -- Optional field
    constraints TEXT, -- Optional field
    is_favorite BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Enhanced sessions table with comprehensive security tracking
CREATE TABLE sessions (
    id TEXT PRIMARY KEY, -- UUID for session identification
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL, -- JWT access token
    refresh_token TEXT NOT NULL, -- JWT refresh token
    expires_at TEXT NOT NULL, -- ISO 8601 timestamp
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT NOT NULL DEFAULT (datetime('now')), -- Security: Track activity
    ip_address TEXT, -- Security: Track IP changes
    user_agent TEXT, -- Security: Device identification
    device_fingerprint TEXT, -- Security: Enhanced tracking
    is_revoked BOOLEAN NOT NULL DEFAULT 0, -- Security: Session revocation
    revoked_at TEXT, -- Security: When session was revoked
    revoked_reason TEXT, -- Security: Why session was revoked
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Performance indexes for efficient queries
-- User lookup by email (login)
CREATE INDEX idx_users_email ON users(email);

-- User verification and account status lookup
CREATE INDEX idx_users_email_verified ON users(email_verified);
CREATE INDEX idx_users_active ON users(is_active);

-- Security: Failed login attempts and account lockout
CREATE INDEX idx_users_security ON users(failed_login_attempts, locked_until);

-- User's prompts lookup (most common query)
CREATE INDEX idx_prompts_user_id ON prompts(user_id);

-- Recent prompts lookup
CREATE INDEX idx_prompts_created_at ON prompts(created_at DESC);

-- User's recent prompts (compound index for optimal performance)
CREATE INDEX idx_prompts_user_created ON prompts(user_id, created_at DESC);

-- Favorite prompts lookup
CREATE INDEX idx_prompts_favorite ON prompts(user_id, is_favorite) WHERE is_favorite = 1;

-- Prompts by type and domain for analytics
CREATE INDEX idx_prompts_type_domain ON prompts(prompt_type, domain);

-- Enhanced session management indexes with security features
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_user_expires ON sessions(user_id, expires_at);

-- Security: Session revocation and activity tracking
CREATE INDEX idx_sessions_security ON sessions(user_id, is_revoked, ip_address);
CREATE INDEX idx_sessions_device ON sessions(device_fingerprint);
CREATE INDEX idx_sessions_activity ON sessions(last_used_at DESC);

-- Security: Active sessions lookup
CREATE INDEX idx_sessions_active ON sessions(user_id, is_revoked, expires_at) WHERE is_revoked = 0;

-- Create triggers for automatic updated_at timestamps
CREATE TRIGGER update_users_updated_at 
    AFTER UPDATE ON users
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER update_prompts_updated_at 
    AFTER UPDATE ON prompts
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE prompts SET updated_at = datetime('now') WHERE id = NEW.id;
END;