# Teachinspire Prompt Builder - Testing Guide

## 🧪 Comprehensive Testing Plan

This guide provides a systematic approach to testing all components of the enhanced Teachinspire Prompt Builder before production deployment.

## 📋 Pre-Testing Setup

### Environment Setup
```bash
# 1. Create D1 database
wrangler d1 create teachinspire-prompt-builder-db

# 2. Update database ID in wrangler.toml
# Copy the database_id from the create command output

# 3. Create KV namespace
wrangler kv:namespace create "KV"

# 4. Set environment variables
wrangler secret put JWT_SECRET  # Use: node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
wrangler secret put API_KEY     # Your existing Gemini API key

# 5. Run database migrations
wrangler d1 execute teachinspire-prompt-builder-db --file=./database/schema.sql

# 6. Deploy for testing
wrangler pages deploy
```

## 🔐 Authentication Testing

### 1. User Registration
**Test Cases:**
- [ ] Valid registration (email + strong password)
- [ ] Invalid email format rejection
- [ ] Weak password rejection
- [ ] Duplicate email handling
- [ ] Rate limiting (3 attempts per hour)
- [ ] French/English form validation

**Manual Test Steps:**
1. Open app → Should show login/register screen
2. Click "Register" → Form appears
3. Test invalid emails: `test`, `test@`, `@test.com`
4. Test weak passwords: `123`, `password`, `abc123`
5. Test valid registration: `test@example.com` + `SecurePass123!`
6. Verify success message and automatic login

### 2. User Login
**Test Cases:**
- [ ] Valid login credentials
- [ ] Invalid email/password combinations
- [ ] Account lockout after 5 failed attempts
- [ ] Rate limiting (5 attempts per 15 minutes)
- [ ] Automatic token refresh
- [ ] Remember login across browser sessions

**Manual Test Steps:**
1. Logout if logged in
2. Test wrong password → Should show error
3. Test correct credentials → Should login successfully
4. Close browser → Reopen → Should still be logged in
5. Wait for token expiry (15min) → Should auto-refresh

### 3. Session Management
**Test Cases:**
- [ ] Logout single device
- [ ] Logout all devices
- [ ] Session cleanup on logout
- [ ] Token invalidation
- [ ] Concurrent login handling

## 📝 Prompts Management Testing

### 1. Prompt Creation
**Test Cases:**
- [ ] Create MVP prompt
- [ ] Create AGENTIC prompt
- [ ] Auto-title generation
- [ ] Field validation
- [ ] Save to backend successfully

**Manual Test Steps:**
1. Login and navigate to prompt builder
2. Create new prompt with all fields
3. Generate prompt → Should call Gemini API
4. Save prompt → Should appear in library
5. Verify prompt data in backend

### 2. Prompt Library
**Test Cases:**
- [ ] Load user's prompts on login
- [ ] Pagination (if >20 prompts)
- [ ] Search functionality
- [ ] Filter by domain/type/language
- [ ] Sort by date/title/favorites
- [ ] No access to other users' prompts

**Manual Test Steps:**
1. Create multiple prompts with different domains
2. Test search: partial titles, content search
3. Test filters: education, technical, French, English
4. Test sorting: newest first, title A-Z
5. Verify pagination if many prompts

### 3. Prompt Operations
**Test Cases:**
- [ ] Edit prompt (title, favorites)
- [ ] Delete prompt
- [ ] Toggle favorite status
- [ ] Load prompt from library
- [ ] Export prompt to file

**Manual Test Steps:**
1. Edit a prompt → Save → Verify changes
2. Toggle favorite → Check star indicator
3. Delete prompt → Confirm removal
4. Load old prompt → Should populate form
5. Export prompt → Download file

## 🔄 Migration Testing

### 1. localStorage Migration
**Test Cases:**
- [ ] Detect existing localStorage prompts
- [ ] Convert format to API format
- [ ] Batch upload to backend
- [ ] Progress indication
- [ ] Error handling and retry
- [ ] Clear localStorage after success

**Manual Test Steps:**
1. Add test data to localStorage:
```javascript
localStorage.setItem('teachinspire-prompts', JSON.stringify([
  {
    id: 'test1',
    timestamp: Date.now(),
    rawRequest: 'Test prompt 1',
    generatedPrompt: 'Generated test prompt',
    type: 'MVP',
    domain: 'education',
    language: 'en'
  }
]));
```
2. Login → Should show migration dialog
3. Start migration → Watch progress
4. Verify prompts appear in library
5. Check localStorage is cleared

## 🛡️ Security Testing

### 1. Authentication Security
**Test Cases:**
- [ ] JWT token validation
- [ ] Token expiration handling
- [ ] Rate limiting enforcement
- [ ] Password hashing verification
- [ ] Session security

**API Test Commands:**
```bash
# Test unauthenticated access (should fail)
curl -X GET "https://your-domain.com/api/prompts"

# Test with expired token (should fail)
curl -X GET "https://your-domain.com/api/prompts" \
  -H "Authorization: Bearer expired_token"

# Test rate limiting (make 6+ requests rapidly)
for i in {1..10}; do
  curl -X POST "https://your-domain.com/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"wrong@test.com","password":"wrong"}'
done
```

### 2. API Security
**Test Cases:**
- [ ] Input sanitization (XSS prevention)
- [ ] SQL injection prevention
- [ ] Authorization checks (own prompts only)
- [ ] CORS configuration
- [ ] Security headers

**API Test Examples:**
```bash
# Test XSS in prompt creation
curl -X POST "https://your-domain.com/api/prompts" \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{"rawRequest":"<script>alert(1)</script>","promptType":"MVP"}'

# Test accessing other user's prompts (should fail)
curl -X GET "https://your-domain.com/api/prompts/other_user_prompt_id" \
  -H "Authorization: Bearer your_token"
```

## 🌐 Frontend Testing

### 1. UI Component Testing
**Test Cases:**
- [ ] Responsive design (mobile, tablet, desktop)
- [ ] Bilingual switching (FR/EN)
- [ ] Loading states
- [ ] Error messages
- [ ] Form validation
- [ ] Navigation flows

**Manual Test Steps:**
1. Test on different screen sizes
2. Switch between French/English
3. Test all form validations
4. Verify loading spinners appear
5. Check error message clarity

### 2. Integration Testing
**Test Cases:**
- [ ] API service error handling
- [ ] Network failure recovery
- [ ] Offline behavior
- [ ] Token refresh flow
- [ ] State persistence

## 📊 Performance Testing

### 1. API Performance
**Test Cases:**
- [ ] Response times <500ms
- [ ] Pagination performance with large datasets
- [ ] Concurrent user handling
- [ ] Database query optimization

**Test Commands:**
```bash
# Test API response times
time curl -X GET "https://your-domain.com/api/prompts" \
  -H "Authorization: Bearer your_token"

# Test pagination performance
curl -X GET "https://your-domain.com/api/prompts?page=1&limit=50" \
  -H "Authorization: Bearer your_token"
```

### 2. Frontend Performance
**Test Cases:**
- [ ] Initial load time
- [ ] Authentication check speed
- [ ] Migration performance
- [ ] Prompt library load time

## ✅ Deployment Readiness Checklist

### Database & Infrastructure
- [ ] D1 database created and migrated
- [ ] KV namespace configured
- [ ] Environment variables set (JWT_SECRET, API_KEY)
- [ ] wrangler.toml properly configured

### Security Configuration
- [ ] Strong JWT secret configured
- [ ] Rate limiting functional
- [ ] CORS properly configured
- [ ] Security headers in place

### Functionality Verification
- [ ] Complete registration flow works
- [ ] Login/logout functionality works
- [ ] Prompt CRUD operations work
- [ ] Migration utility functional
- [ ] API security enforced

### User Experience
- [ ] Bilingual support working
- [ ] Responsive design verified
- [ ] Error handling user-friendly
- [ ] Loading states implemented
- [ ] Migration UX smooth

### Documentation
- [ ] API endpoints documented
- [ ] Setup instructions complete
- [ ] Security guidelines provided
- [ ] User migration guide ready

## 🚨 Critical Tests Before Go-Live

1. **End-to-End User Journey:**
   - Register → Login → Create Prompt → Save → Logout → Login → Access Saved Prompts

2. **Migration Test:**
   - Add localStorage data → Login → Verify migration → Check data integrity

3. **Security Validation:**
   - Attempt unauthorized access → Verify rejection
   - Test rate limiting → Verify enforcement

4. **Multi-User Test:**
   - Create 2+ accounts → Verify data isolation

5. **Performance Test:**
   - Load test with multiple concurrent users
   - Verify response times acceptable

## 📞 Support & Monitoring

### Post-Deployment Monitoring
- [ ] Authentication success/failure rates
- [ ] API response times
- [ ] Error rates and types
- [ ] Migration completion rates
- [ ] User adoption metrics

### Emergency Procedures
- [ ] Rollback plan documented
- [ ] Database backup strategy
- [ ] Incident response contacts
- [ ] Performance threshold alerts

---

**Execute all tests systematically before production deployment. Each section should be completed and signed off before proceeding to the next phase.**