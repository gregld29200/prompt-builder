-- Migration: Add password reset tokens table
-- Purpose: Support "forgot password" functionality with secure token management
-- Date: 2025-08-03

-- Create password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_password_reset_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id);

-- Create partial index for active tokens only (performance optimization)
CREATE INDEX IF NOT EXISTS idx_password_reset_active ON password_reset_tokens(token, expires_at) 
WHERE used = 0;

-- Cleanup trigger to automatically remove expired tokens (optional, for maintenance)
CREATE TRIGGER IF NOT EXISTS cleanup_expired_reset_tokens
AFTER INSERT ON password_reset_tokens
BEGIN
  DELETE FROM password_reset_tokens 
  WHERE expires_at < datetime('now') OR used = 1;
END;