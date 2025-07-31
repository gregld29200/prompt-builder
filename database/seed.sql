-- Seed data for development and testing
-- This file contains sample data for testing the Teachinspire Prompt Builder

-- Note: In production, you'll generate UUIDs programmatically
-- These are example UUIDs for development purposes

-- Sample users
INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at) VALUES
    ('550e8400-e29b-41d4-a716-446655440001', 'demo@teachinspire.com', '$2b$10$K7J8QXqJ2yXqZrG4K7J8QXqJ2yXqZrG4K7J8QXqJ2yXqZrG4K7J8QO', 1, datetime('now', '-30 days'), datetime('now', '-1 days')),
    ('550e8400-e29b-41d4-a716-446655440002', 'teacher@example.com', '$2b$10$L8K9RYrK3zYrAsH5L8K9RYrK3zYrAsH5L8K9RYrK3zYrAsH5L8K9RP', 1, datetime('now', '-15 days'), datetime('now', '-2 days')),
    ('550e8400-e29b-41d4-a716-446655440003', 'student@example.com', '$2b$10$M9L0SZsL4aZsBtI6M9L0SZsL4aZsBtI6M9L0SZsL4aZsBtI6M9L0SQ', 0, datetime('now', '-7 days'), datetime('now', '-7 days'));

-- Sample prompts
INSERT INTO prompts (id, user_id, title, raw_request, generated_prompt, prompt_type, domain, language, output_length, expert_role, mission, constraints, is_favorite, created_at, updated_at) VALUES
    ('650e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440001', 'Math Problem Solver', 'Help students solve algebra problems step by step', 'You are an expert mathematics tutor specializing in algebra. Your mission is to guide students through problem-solving processes step-by-step, ensuring they understand each stage of the solution. When a student presents an algebra problem, break down the solution into clear, logical steps. Explain the reasoning behind each step, highlight common mistakes to avoid, and encourage questions. Always verify the final answer and suggest similar practice problems when appropriate.', 'MVP', 'education', 'en', 'medium', 'Mathematics Tutor', 'Guide students through algebra problem-solving', 'Must show step-by-step work, explain reasoning', 1, datetime('now', '-5 days'), datetime('now', '-5 days')),
    
    ('650e8400-e29b-41d4-a716-446655440002', '550e8400-e29b-41d4-a716-446655440001', 'Creative Writing Assistant', 'Aide à la rédaction créative pour les étudiants', 'Vous êtes un assistant d''écriture créative expérimenté, spécialisé dans l''accompagnement des étudiants francophones. Votre mission est d''inspirer et de guider les étudiants dans leurs projets d''écriture créative, en les aidant à développer leur style personnel et à structurer leurs idées. Lorsqu''un étudiant vous présente un projet d''écriture, posez des questions ouvertes pour comprendre sa vision, proposez des techniques narratives adaptées, et donnez des conseils constructifs. Encouragez l''originalité tout en respectant les contraintes académiques.', 'AGENTIC', 'creative', 'fr', 'long', 'Assistant d''écriture créative', 'Inspirer et guider les étudiants en écriture', 'Respecter les contraintes académiques, encourager l''originalité', 0, datetime('now', '-3 days'), datetime('now', '-3 days')),
    
    ('650e8400-e29b-41d4-a716-446655440003', '550e8400-e29b-41d4-a716-446655440002', 'Code Review Assistant', 'Help review JavaScript code for best practices', 'You are a senior software engineer with expertise in JavaScript and modern web development practices. Your mission is to conduct thorough code reviews focusing on best practices, performance optimization, and maintainability. When reviewing code, examine: 1) Code structure and organization, 2) Performance implications, 3) Security considerations, 4) Adherence to modern JavaScript standards, 5) Readability and documentation. Provide specific, actionable feedback with examples of improvements. Always explain the reasoning behind your suggestions and offer alternative approaches when applicable.', 'MVP', 'technical', 'en', 'long', 'Senior Software Engineer', 'Conduct thorough JavaScript code reviews', 'Focus on best practices, performance, security', 1, datetime('now', '-1 day'), datetime('now', '-1 day'));

-- Sample sessions (active sessions for testing)
INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES
    ('750e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440001', datetime('now', '+7 days'), datetime('now', '-1 hour')),
    ('750e8400-e29b-41d4-a716-446655440002', '550e8400-e29b-41d4-a716-446655440002', datetime('now', '+7 days'), datetime('now', '-2 hours'));