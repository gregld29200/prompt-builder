# Project Duplication & Rebranding Plan

## Overview
Cloning the existing TeachInspire Prompt Builder and rebranding it as a new application with fresh Cloudflare databases.

## Current Project Analysis
**Tech Stack:**
- Frontend: React 19 (CDN-based) + Tailwind CSS
- Backend: Cloudflare Workers (TypeScript)
- Database: D1 + Workers KV
- Deployment: Cloudflare Pages

**Key Components:**
- Authentication system with JWT
- Prompt generation using Gemini API
- User management and favorites
- Rate limiting via KV
- Database migrations in `/database/migrations/`

**Current Database Configuration:**
- D1 Database: `teachinspire-prompt-builder-db` (ID: 2eb75f37-06b7-486a-a2e0-138ea1fb0574)
- KV Namespace: `RATE_LIMITER` (ID: 341d4109a4044a3a88cb3ccea2797278)

## Duplication Strategy

### Phase 1: Repository Setup
- [ ] Create new repository/directory structure
- [ ] Copy all source files (excluding .git, node_modules)
- [ ] Initialize new git repository
- [ ] Update package.json metadata

### Phase 2: Cloudflare Infrastructure Setup
- [ ] Create new D1 database
- [ ] Create new KV namespace for rate limiting
- [ ] Update wrangler.toml configuration
- [ ] Run database migrations on new D1 instance

### Phase 3: Branding Implementation
- [ ] Update application name and descriptions
- [ ] Replace branding colors and styling
- [ ] Update meta tags and SEO content
- [ ] Replace logos and favicon
- [ ] Update email templates and user-facing text

### Phase 4: Configuration Updates
- [ ] Update environment variables
- [ ] Set new Cloudflare secrets
- [ ] Update API endpoints if needed
- [ ] Configure new domain (if applicable)

### Phase 5: Testing & Deployment
- [ ] Test database connections
- [ ] Verify authentication flow
- [ ] Test prompt generation functionality
- [ ] Deploy to Cloudflare Pages
- [ ] Verify production deployment

## Questions for User
1. What is the new application name?
2. What are the new brand colors?
3. Do you have new logo assets ready?
4. What domain will this be deployed to?
5. Should we preserve any existing data or start fresh?

## Step-by-Step Implementation Commands

### Repository Duplication
```bash
# 1. Create new directory
mkdir my-new-prompt-app
cd my-new-prompt-app

# 2. Copy files (excluding git)
cp -r ../prompt-builder/* .
cp ../prompt-builder/.gitignore .

# 3. Initialize new git
rm -rf .git
git init
git add .
git commit -m "Initial commit - rebranded application"
```

### Database Setup
```bash
# 1. Create new D1 database
wrangler d1 create my-new-app-db

# 2. Create new KV namespace
wrangler kv:namespace create "RATE_LIMITER"
wrangler kv:namespace create "RATE_LIMITER" --preview

# 3. Run migrations
wrangler d1 execute my-new-app-db --file=./database/migrations/001_initial_schema.sql
wrangler d1 execute my-new-app-db --file=./database/migrations/002_security_enhancements.sql
wrangler d1 execute my-new-app-db --file=./database/migrations/003_password_reset_tokens.sql
```

### Configuration Update
Update `wrangler.toml` with new database IDs:
```toml
name = "my-new-app"
[[d1_databases]]
binding = "DB"
database_name = "my-new-app-db"
database_id = "NEW_DATABASE_ID_HERE"

[[kv_namespaces]]
binding = "RATE_LIMITER"
id = "NEW_KV_ID_HERE"
```

### Secrets Setup
```bash
wrangler secret put JWT_SECRET
wrangler secret put API_KEY
wrangler secret put RESEND_API_KEY
```

## Todo Checklist
- [ ] Analyze current project structure
- [ ] Create duplication plan
- [ ] Set up new databases
- [ ] Update configuration
- [ ] Implement rebranding
- [ ] Test and deploy