# Teachinspire Prompt Builder - Database Documentation

This directory contains the complete D1 database schema and setup for the Teachinspire Prompt Builder application.

## Quick Start

1. **Install Dependencies**
   ```bash
   npm install -g wrangler
   wrangler login
   ```

2. **Setup Database**
   ```bash
   cd database
   ./setup.sh
   ```

3. **Set Environment Variables**
   ```bash
   wrangler secret put JWT_SECRET
   ```

## Files Overview

### Schema Files
- **`schema.sql`** - Complete database schema with all tables, indexes, and triggers
- **`migrations/001_initial_schema.sql`** - Initial migration file
- **`seed.sql`** - Sample data for development and testing
- **`queries.sql`** - Common SQL queries for reference

### Setup Files
- **`setup.sh`** - Automated database setup script
- **`README.md`** - This documentation file

## Database Schema

### Tables

#### `users`
Stores user authentication and profile information.
- `id` (TEXT, PK) - UUID for global uniqueness
- `email` (TEXT, UNIQUE) - User email (case-insensitive)
- `password_hash` (TEXT) - bcrypt hashed password
- `email_verified` (BOOLEAN) - Email verification status
- `created_at`, `updated_at` (TEXT) - ISO 8601 timestamps

#### `prompts`
Stores user-generated AI prompts and metadata.
- `id` (TEXT, PK) - UUID for global uniqueness
- `user_id` (TEXT, FK) - References users.id
- `title` (TEXT) - Auto-generated from raw_request (max 100 chars)
- `raw_request` (TEXT) - Original user input
- `generated_prompt` (TEXT) - AI-generated prompt
- `prompt_type` (TEXT) - 'MVP' or 'AGENTIC'
- `domain` (TEXT) - 'education', 'technical', 'creative', 'analysis', 'other'
- `language` (TEXT) - 'fr' or 'en'
- `output_length` (TEXT) - 'short', 'medium', 'long'
- `expert_role` (TEXT) - Optional expert role
- `mission` (TEXT) - Optional mission statement
- `constraints` (TEXT) - Optional constraints
- `is_favorite` (BOOLEAN) - Favorite flag
- `created_at`, `updated_at` (TEXT) - ISO 8601 timestamps

#### `sessions`
Manages user authentication sessions.
- `id` (TEXT, PK) - UUID for session identification
- `user_id` (TEXT, FK) - References users.id
- `expires_at` (TEXT) - Session expiration timestamp
- `created_at` (TEXT) - Session creation timestamp

### Indexes

Performance indexes are strategically placed for:
- User lookup by email (login)
- User's prompts retrieval (most common query)
- Recent prompts sorting
- Favorite prompts filtering
- Session management and cleanup
- Analytics queries by type and domain

### Design Decisions

#### Edge-First Architecture
- **UUIDs for Primary Keys**: Ensures global uniqueness across distributed edge locations
- **TEXT Timestamps**: ISO 8601 format for consistency across time zones
- **Strategic Indexing**: Optimized for read-heavy workloads common in edge environments

#### Data Integrity
- **Foreign Key Constraints**: Maintain referential integrity with CASCADE deletes
- **Check Constraints**: Validate enum-like fields at database level
- **Automatic Timestamps**: Triggers maintain updated_at timestamps

#### Performance Optimization
- **Compound Indexes**: `(user_id, created_at DESC)` for efficient user prompt queries
- **Partial Indexes**: `WHERE is_favorite = 1` for memory efficiency
- **Case-Insensitive Email**: `COLLATE NOCASE` for user-friendly login

## Usage with Cloudflare Workers

### Binding Configuration
The database is bound as `env.DB` in your Workers/Pages Functions:

```javascript
export default {
  async fetch(request, env, ctx) {
    // Access your D1 database
    const db = env.DB;
    
    // Example query
    const users = await db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ).bind(email).first();
    
    return new Response(JSON.stringify(users));
  }
};
```

### Prepared Statements
Always use prepared statements for security and performance:

```javascript
// Good: Prepared statement
const stmt = db.prepare("SELECT * FROM prompts WHERE user_id = ?");
const prompts = await stmt.bind(userId).all();

// Bad: String concatenation (vulnerable to SQL injection)
const query = `SELECT * FROM prompts WHERE user_id = '${userId}'`;
```

### Batch Operations
Use batch operations for multiple inserts/updates:

```javascript
const batch = [
  db.prepare("INSERT INTO prompts (...) VALUES (...)").bind(...values1),
  db.prepare("INSERT INTO prompts (...) VALUES (...)").bind(...values2)
];
await db.batch(batch);
```

## Maintenance

### Session Cleanup
Run periodically to remove expired sessions:
```sql
DELETE FROM sessions WHERE expires_at <= datetime('now');
```

### Database Statistics
Monitor usage with:
```sql
SELECT 
  (SELECT COUNT(*) FROM users) as total_users,
  (SELECT COUNT(*) FROM prompts) as total_prompts,
  (SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')) as active_sessions;
```

## Development

### Local Testing
1. Use the seed data: `wrangler d1 execute teachinspire-prompt-builder-db --file=database/seed.sql`
2. Test queries: `wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT * FROM users;"`

### Adding Migrations
1. Create new migration file: `database/migrations/002_description.sql`
2. Apply migration: `wrangler d1 execute teachinspire-prompt-builder-db --file=database/migrations/002_description.sql`

### Common Queries
Refer to `queries.sql` for examples of:
- User authentication flows
- Prompt CRUD operations
- Session management
- Analytics queries
- Maintenance tasks

## Security Considerations

- All passwords are bcrypt hashed
- Sessions have expiration timestamps
- Foreign key constraints prevent orphaned data
- Prepared statements prevent SQL injection
- Email verification workflow supported

## Performance Notes

- Indexes are optimized for read-heavy workloads
- Compound indexes support common query patterns
- Partial indexes reduce memory usage
- Automatic timestamp updates via triggers
- UUID primary keys support distributed architecture