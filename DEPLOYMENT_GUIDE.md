# 🚀 Teachinspire Prompt Builder - Deployment Guide

## Quick Deployment Checklist

Follow these steps to deploy your enhanced Teachinspire Prompt Builder with authentication and cloud storage.

## 📋 Pre-Deployment Requirements

- ✅ Cloudflare account with Pages access
- ✅ Domain or subdomain (optional)
- ✅ Google Gemini API key
- ✅ Git repository connected to Cloudflare Pages

## 🛠️ Step 1: Database Setup

### Create D1 Database
```bash
# Create the database
wrangler d1 create teachinspire-prompt-builder-db

# Copy the database_id from output and update wrangler.toml
# Example output: database_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### Update wrangler.toml
```toml
[[d1_databases]]
binding = "DB"
database_name = "teachinspire-prompt-builder-db"
database_id = "YOUR_DATABASE_ID_HERE"  # ← Update this!
```

### Run Database Migration
```bash
# Apply the schema
wrangler d1 execute teachinspire-prompt-builder-db --file=./database/schema.sql

# Verify tables were created
wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT name FROM sqlite_master WHERE type='table';"
```

## 🔑 Step 2: KV Storage Setup

### Create KV Namespace
```bash
# Create KV namespace for rate limiting
wrangler kv:namespace create "KV"

# Copy the id from output and update wrangler.toml
# Example output: id = "a1b2c3d4e5f67890abcdef1234567890"
```

### Update wrangler.toml
```toml
[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_ID_HERE"  # ← Update this!
```

## 🔐 Step 3: Environment Variables

### Set JWT Secret
```bash
# Generate a secure JWT secret
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"

# Set the secret
wrangler secret put JWT_SECRET
# Paste the generated secret when prompted
```

### Set Gemini API Key
```bash
# Set your existing Gemini API key
wrangler secret put API_KEY
# Paste your Gemini API key when prompted
```

## 🌐 Step 4: Cloudflare Pages Deployment

### Method 1: GitHub Integration (Recommended)
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com) → Pages
2. Click "Create a project" → "Connect to Git"
3. Select your repository
4. Configure build settings:
   - **Build command**: Leave empty (static site)
   - **Build output directory**: `./`
   - **Root directory**: Leave empty

### Method 2: Direct Upload
```bash
# Deploy directly via CLI
wrangler pages deploy ./ --project-name teachinspire-prompt-builder
```

## ⚙️ Step 5: Pages Environment Configuration

### In Cloudflare Dashboard:
1. Go to Pages → Your Project → Settings → Environment variables
2. Add these variables for **Production**:
   - `JWT_SECRET`: (your generated secret)
   - `API_KEY`: (your Gemini API key)

### Bind D1 Database:
1. Go to Pages → Your Project → Settings → Functions
2. Add D1 database binding:
   - **Variable name**: `DB`
   - **Database**: Select your created database

### Bind KV Namespace:
1. In the same Functions settings
2. Add KV namespace binding:
   - **Variable name**: `KV`
   - **KV namespace**: Select your created namespace

## 🧪 Step 6: Test Deployment

### Basic Health Check
```bash
# Test if the site loads
curl https://your-deployment-url.pages.dev

# Test API endpoint (should return 401 without auth)
curl https://your-deployment-url.pages.dev/api/prompts
```

### Full Functionality Test
1. **Registration**: Create a new account
2. **Login**: Sign in with credentials
3. **Prompt Creation**: Generate and save a prompt
4. **Migration**: Test with localStorage data (if applicable)
5. **Logout**: Verify session cleanup

## 📊 Step 7: Monitoring Setup

### Configure Custom Domain (Optional)
1. Pages → Your Project → Custom domains
2. Add your domain
3. Configure DNS records as instructed

### Set Up Analytics
1. Enable Web Analytics in Cloudflare
2. Add analytics code to index.html if desired

## 🚨 Troubleshooting Common Issues

### Database Connection Issues
```bash
# Check database exists
wrangler d1 list

# Check database binding in wrangler.toml
grep -A 3 "d1_databases" wrangler.toml

# Test database connection
wrangler d1 execute your-db-name --command="SELECT 1;"
```

### Authentication Errors
```bash
# Verify JWT secret is set
wrangler secret list

# Check if API key is set
curl -X POST "https://your-domain.com/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!"}'
```

### API Endpoint Issues
```bash
# Check Functions deployment
wrangler pages functions list

# Verify all API endpoints exist
find functions/api -name "*.ts" -type f
```

## 📈 Performance Optimization

### Enable Caching
Add to your Pages deployment:
```javascript
// In functions/_middleware.ts (if you add one)
export function onRequest(context) {
  return context.next();
}
```

### Optimize Database Queries
- Monitor query performance in Cloudflare Analytics
- Use the included indexes for optimal performance
- Consider adding more indexes if needed

## 🔒 Security Checklist

- [ ] JWT_SECRET is strong and secure (64+ characters)
- [ ] API_KEY is properly secured
- [ ] Database has proper constraints and indexes
- [ ] Rate limiting is functional
- [ ] CORS is properly configured
- [ ] All API endpoints require authentication
- [ ] Input validation is working

## 📋 Post-Deployment Tasks

### User Communication
1. **Announcement**: Notify users about new authentication requirement
2. **Migration Guide**: Provide instructions for existing users
3. **Support**: Set up support channel for migration issues

### Monitoring
1. **Error Tracking**: Monitor authentication failures
2. **Performance**: Track API response times
3. **Usage**: Monitor user adoption rates
4. **Migration**: Track localStorage migration success rates

## 🚨 Emergency Procedures

### Rollback Plan
If issues occur:
1. **Disable new deployment** in Pages dashboard
2. **Revert to previous deployment**
3. **Communicate with users** about temporary issues
4. **Debug and fix** issues before re-deploying

### Database Recovery
```bash
# Create backup before major changes
wrangler d1 backup create teachinspire-prompt-builder-db

# Restore if needed
wrangler d1 backup restore teachinspire-prompt-builder-db backup-id
```

## ✅ Success Metrics

Your deployment is successful when:
- [ ] Users can register and login without issues
- [ ] Prompts are saved and retrieved correctly
- [ ] Migration works for existing localStorage users
- [ ] No security vulnerabilities detected
- [ ] Performance meets expectations (<500ms API responses)
- [ ] Error rates are minimal (<1%)

## 📞 Support Resources

- **Cloudflare Docs**: https://developers.cloudflare.com/pages/
- **D1 Documentation**: https://developers.cloudflare.com/d1/
- **Workers Documentation**: https://developers.cloudflare.com/workers/
- **API Testing**: Use provided TESTING_GUIDE.md

---

**🎉 Congratulations! Your enhanced Teachinspire Prompt Builder is now live with authentication and cloud storage!**