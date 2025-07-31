-- Migration: 001_initial_schema
-- Description: Create initial database schema for users, prompts, and sessions
-- Date: 2025-07-31

-- Users table for authentication
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Prompts table for storing user-generated prompts
CREATE TABLE prompts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL CHECK(length(title) <= 100),
    raw_request TEXT NOT NULL,
    generated_prompt TEXT NOT NULL,
    prompt_type TEXT NOT NULL CHECK(prompt_type IN ('MVP', 'AGENTIC')),
    domain TEXT NOT NULL CHECK(domain IN ('education', 'technical', 'creative', 'analysis', 'other')),
    language TEXT NOT NULL CHECK(language IN ('fr', 'en')),
    output_length TEXT NOT NULL CHECK(output_length IN ('short', 'medium', 'long')),
    expert_role TEXT,
    mission TEXT,
    constraints TEXT,
    is_favorite BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sessions table for authentication management
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Performance indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_verified ON users(email_verified);
CREATE INDEX idx_prompts_user_id ON prompts(user_id);
CREATE INDEX idx_prompts_created_at ON prompts(created_at DESC);
CREATE INDEX idx_prompts_user_created ON prompts(user_id, created_at DESC);
CREATE INDEX idx_prompts_favorite ON prompts(user_id, is_favorite) WHERE is_favorite = 1;
CREATE INDEX idx_prompts_type_domain ON prompts(prompt_type, domain);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_user_expires ON sessions(user_id, expires_at);

-- Automatic timestamp triggers
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