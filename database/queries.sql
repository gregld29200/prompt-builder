-- Common queries for the Teachinspire Prompt Builder
-- This file contains frequently used SQL queries for reference and testing

-- USER MANAGEMENT QUERIES --

-- Get user by email (for login)
SELECT id, email, password_hash, email_verified, created_at 
FROM users 
WHERE email = ? COLLATE NOCASE;

-- Create new user
INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) 
VALUES (?, ?, ?, 0, datetime('now'), datetime('now'));

-- Update user email verification status
UPDATE users 
SET email_verified = 1, updated_at = datetime('now') 
WHERE id = ?;

-- Get user profile
SELECT id, email, email_verified, created_at, updated_at 
FROM users 
WHERE id = ?;

-- SESSION MANAGEMENT QUERIES --

-- Create new session
INSERT INTO sessions (id, user_id, expires_at, created_at) 
VALUES (?, ?, ?, datetime('now'));

-- Get valid session
SELECT s.id, s.user_id, s.expires_at, u.email, u.email_verified
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.id = ? AND s.expires_at > datetime('now');

-- Delete session (logout)
DELETE FROM sessions WHERE id = ?;

-- Delete expired sessions (cleanup job)
DELETE FROM sessions WHERE expires_at <= datetime('now');

-- Delete all user sessions (logout from all devices)
DELETE FROM sessions WHERE user_id = ?;

-- PROMPT MANAGEMENT QUERIES --

-- Get user's prompts (paginated, most recent first)
SELECT id, title, raw_request, generated_prompt, prompt_type, domain, 
       language, output_length, expert_role, mission, constraints, 
       is_favorite, created_at, updated_at
FROM prompts 
WHERE user_id = ? 
ORDER BY created_at DESC 
LIMIT ? OFFSET ?;

-- Get user's favorite prompts
SELECT id, title, raw_request, generated_prompt, prompt_type, domain, 
       language, output_length, expert_role, mission, constraints, 
       is_favorite, created_at, updated_at
FROM prompts 
WHERE user_id = ? AND is_favorite = 1 
ORDER BY created_at DESC;

-- Create new prompt
INSERT INTO prompts (id, user_id, title, raw_request, generated_prompt, 
                    prompt_type, domain, language, output_length, 
                    expert_role, mission, constraints, is_favorite, 
                    created_at, updated_at) 
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'));

-- Update prompt (toggle favorite)
UPDATE prompts 
SET is_favorite = ?, updated_at = datetime('now') 
WHERE id = ? AND user_id = ?;

-- Delete prompt
DELETE FROM prompts WHERE id = ? AND user_id = ?;

-- Get single prompt by ID
SELECT id, title, raw_request, generated_prompt, prompt_type, domain, 
       language, output_length, expert_role, mission, constraints, 
       is_favorite, created_at, updated_at
FROM prompts 
WHERE id = ? AND user_id = ?;

-- Search prompts by title or content
SELECT id, title, raw_request, generated_prompt, prompt_type, domain, 
       language, output_length, expert_role, mission, constraints, 
       is_favorite, created_at, updated_at
FROM prompts 
WHERE user_id = ? AND (
    title LIKE ? OR 
    raw_request LIKE ? OR 
    generated_prompt LIKE ?
)
ORDER BY created_at DESC
LIMIT ?;

-- Filter prompts by domain and type
SELECT id, title, raw_request, generated_prompt, prompt_type, domain, 
       language, output_length, expert_role, mission, constraints, 
       is_favorite, created_at, updated_at
FROM prompts 
WHERE user_id = ? AND domain = ? AND prompt_type = ?
ORDER BY created_at DESC;

-- ANALYTICS QUERIES --

-- User prompt statistics
SELECT 
    COUNT(*) as total_prompts,
    COUNT(CASE WHEN is_favorite = 1 THEN 1 END) as favorite_prompts,
    COUNT(CASE WHEN prompt_type = 'MVP' THEN 1 END) as mvp_prompts,
    COUNT(CASE WHEN prompt_type = 'AGENTIC' THEN 1 END) as agentic_prompts
FROM prompts 
WHERE user_id = ?;

-- Prompts by domain (for user dashboard)
SELECT domain, COUNT(*) as count
FROM prompts 
WHERE user_id = ?
GROUP BY domain
ORDER BY count DESC;

-- Recent activity (last 30 days)
SELECT DATE(created_at) as date, COUNT(*) as prompts_created
FROM prompts 
WHERE user_id = ? AND created_at >= datetime('now', '-30 days')
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- MAINTENANCE QUERIES --

-- Database statistics
SELECT 
    (SELECT COUNT(*) FROM users) as total_users,
    (SELECT COUNT(*) FROM users WHERE email_verified = 1) as verified_users,
    (SELECT COUNT(*) FROM prompts) as total_prompts,
    (SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')) as active_sessions;

-- Cleanup expired sessions (run periodically)
DELETE FROM sessions WHERE expires_at <= datetime('now');

-- Find inactive users (no prompts in last 90 days)
SELECT u.id, u.email, u.created_at, MAX(p.created_at) as last_prompt
FROM users u
LEFT JOIN prompts p ON u.id = p.user_id
GROUP BY u.id, u.email, u.created_at
HAVING last_prompt IS NULL OR last_prompt < datetime('now', '-90 days')
ORDER BY u.created_at;