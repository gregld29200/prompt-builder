# Manual Testing Checklist
## Teachinspire Prompt Builder - Pre-Deployment Validation

### Overview
This checklist provides step-by-step manual testing procedures to validate all critical functionality before deployment. Each test should be performed and documented with results.

---

## 🔐 Authentication Flow Testing

### User Registration
- [ ] **Test ID: AUTH-001** - Valid User Registration  
  **Steps:**
  1. Navigate to registration page
  2. Enter valid email: `test-[timestamp]@teachinspire.com`
  3. Enter strong password: `SecurePass123!`
  4. Submit form
  
  **Expected Result:** User registered successfully, redirected to main app, authentication state updated
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-002** - Duplicate Email Registration  
  **Steps:**
  1. Try to register with an already registered email
  2. Submit form
  
  **Expected Result:** Error message displayed, registration prevented
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-003** - Invalid Email Validation  
  **Steps:**
  1. Try registration with invalid emails: `notanemail`, `@domain.com`, `test@`
  2. Submit each form
  
  **Expected Result:** Email validation errors displayed
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-004** - Weak Password Validation  
  **Steps:**
  1. Try registration with weak passwords: `123456`, `password`, `short`
  2. Submit each form
  
  **Expected Result:** Password strength errors displayed
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### User Login
- [ ] **Test ID: AUTH-005** - Valid Login  
  **Steps:**
  1. Enter valid registered email and password
  2. Submit login form
  
  **Expected Result:** Successful login, user authenticated, redirected to app
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-006** - Invalid Credentials Login  
  **Steps:**
  1. Enter wrong password for valid email
  2. Enter non-existent email
  3. Submit forms
  
  **Expected Result:** Generic error message, login prevented
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-007** - Account Lockout  
  **Steps:**
  1. Attempt login with wrong password 5+ times consecutively
  2. Try login with correct password
  
  **Expected Result:** Account locked message, correct password temporarily rejected
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Session Management
- [ ] **Test ID: AUTH-008** - Token Persistence  
  **Steps:**
  1. Login successfully
  2. Refresh browser page
  3. Close and reopen browser tab
  
  **Expected Result:** User remains authenticated across page refreshes
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-009** - Automatic Token Refresh  
  **Steps:**
  1. Login and wait for token to near expiration (check dev tools)
  2. Make API call that triggers refresh
  
  **Expected Result:** Token automatically refreshed, API call successful
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: AUTH-010** - Logout Functionality  
  **Steps:**
  1. Login successfully
  2. Click logout button
  3. Try to access protected pages
  
  **Expected Result:** User logged out, redirected to login, protected pages inaccessible
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 📝 Prompts Management Testing

### Prompt Creation
- [ ] **Test ID: PROMPTS-001** - Create Basic Prompt  
  **Steps:**
  1. Login as authenticated user
  2. Navigate to prompt creation
  3. Fill all required fields:
     - Raw Request: "Create a lesson plan for Python basics"
     - Generated Prompt: [Generated content]
     - Type: MVP
     - Domain: Education
     - Language: English
     - Output Length: Medium
  4. Save prompt
  
  **Expected Result:** Prompt created successfully, appears in prompt list
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-002** - Create Prompt with All Fields  
  **Steps:**
  1. Create prompt with all optional fields filled
  2. Include title, expert role, mission, constraints
  3. Save prompt
  
  **Expected Result:** All fields saved correctly, prompt displays complete information
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-003** - Prompt Validation  
  **Steps:**
  1. Try to save prompt with missing required fields
  2. Try to save with invalid enum values
  3. Try to save with excessively long text (>5000 chars)
  
  **Expected Result:** Validation errors displayed, save prevented
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Prompt Retrieval and Display
- [ ] **Test ID: PROMPTS-004** - View Prompts List  
  **Steps:**
  1. Navigate to prompts list page
  2. Verify all user's prompts are displayed
  
  **Expected Result:** All created prompts visible, proper metadata displayed
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-005** - Pagination Testing  
  **Steps:**
  1. Create 25+ prompts
  2. Navigate through pagination controls
  3. Test different page sizes
  
  **Expected Result:** Pagination works correctly, proper page navigation
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-006** - Search Functionality  
  **Steps:**
  1. Use search box to find prompts by keywords
  2. Test partial matches
  3. Test no results scenario
  
  **Expected Result:** Search returns relevant prompts, handles edge cases properly
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-007** - Filtering  
  **Steps:**
  1. Filter by domain (education, technical, etc.)
  2. Filter by prompt type (MVP, AGENTIC)
  3. Filter by language (French, English)
  4. Filter by favorites
  
  **Expected Result:** Filters work correctly, can be combined, clear properly
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-008** - Sorting  
  **Steps:**
  1. Sort by creation date (newest/oldest)
  2. Sort by title (A-Z, Z-A)
  3. Sort by favorite status
  
  **Expected Result:** Sorting works correctly for all options
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Prompt Management
- [ ] **Test ID: PROMPTS-009** - View Single Prompt  
  **Steps:**
  1. Click on a prompt to view details
  2. Verify all fields are displayed correctly
  
  **Expected Result:** Full prompt details displayed, proper formatting
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-010** - Edit Prompt  
  **Steps:**
  1. Open prompt for editing
  2. Modify title, favorite status, and other fields
  3. Save changes
  
  **Expected Result:** Changes saved successfully, reflected in display
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-011** - Toggle Favorite  
  **Steps:**
  1. Mark prompt as favorite
  2. Unmark favorite
  3. Check favorite filter functionality
  
  **Expected Result:** Favorite status updates correctly, filtering works
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: PROMPTS-012** - Delete Prompt  
  **Steps:**
  1. Select prompt for deletion
  2. Confirm deletion in dialog
  3. Verify prompt removed from list
  
  **Expected Result:** Confirmation dialog shown, prompt deleted successfully
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 🔄 Migration System Testing

### Migration Detection
- [ ] **Test ID: MIGRATION-001** - Detect localStorage Prompts  
  **Steps:**
  1. Add test prompts to localStorage (use browser dev tools)
  2. Login or register new user
  3. Check for migration prompt
  
  **Expected Result:** Migration dialog appears, prompts detected correctly
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: MIGRATION-002** - No Migration Needed  
  **Steps:**
  1. Ensure localStorage has no prompts
  2. Login as user
  
  **Expected Result:** No migration dialog, normal app flow
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Migration Process
- [ ] **Test ID: MIGRATION-003** - Successful Migration  
  **Steps:**
  1. Ensure localStorage has test prompts
  2. Login and start migration
  3. Monitor progress dialog
  4. Wait for completion
  
  **Expected Result:** Progress shown, all prompts migrated, localStorage cleared
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: MIGRATION-004** - Migration Progress Tracking  
  **Steps:**
  1. Start migration with multiple prompts
  2. Monitor progress indicators
  3. Verify batch processing feedback
  
  **Expected Result:** Real-time progress updates, batch completion notifications
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: MIGRATION-005** - Migration Error Handling  
  **Steps:**
  1. Simulate network interruption during migration
  2. Include invalid prompt data in localStorage
  3. Observe error handling
  
  **Expected Result:** Partial migration completes, errors reported, retry options available
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: MIGRATION-006** - Skip Migration  
  **Steps:**
  1. When migration dialog appears, choose skip
  2. Verify localStorage prompts remain
  3. Check that migration can be triggered later
  
  **Expected Result:** Migration skipped, localStorage preserved, option to migrate later
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 🔒 Security Testing

### Input Security
- [ ] **Test ID: SECURITY-001** - XSS Prevention  
  **Steps:**
  1. Try entering XSS payloads in all input fields:
     - `<script>alert('xss')</script>`
     - `<img src=x onerror=alert('xss')>`
     - `javascript:alert('xss')`
  2. Save and view the data
  
  **Expected Result:** No script execution, inputs properly sanitized/escaped
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: SECURITY-002** - SQL Injection Prevention  
  **Steps:**
  1. Try SQL injection payloads in login and form fields:
     - `'; DROP TABLE users; --`
     - `' OR '1'='1`
     - `admin'--`
  
  **Expected Result:** No database errors, payloads treated as literal strings
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Authentication Security
- [ ] **Test ID: SECURITY-003** - Unauthorized Access  
  **Steps:**
  1. Logout from application
  2. Try to access protected URLs directly
  3. Try API calls without authentication
  
  **Expected Result:** Redirected to login, API returns 401 Unauthorized
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: SECURITY-004** - Cross-User Data Access  
  **Steps:**
  1. Login as User A, note prompt IDs
  2. Login as User B
  3. Try to access User A's prompt URLs directly
  
  **Expected Result:** Access denied, only own prompts accessible
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: SECURITY-005** - Password Security  
  **Steps:**
  1. Register user and check database (if accessible)
  2. Verify passwords are hashed
  3. Test password strength requirements
  
  **Expected Result:** Passwords stored as bcrypt hashes, strength enforced
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 🌐 User Interface Testing

### Responsive Design
- [ ] **Test ID: UI-001** - Mobile Responsiveness  
  **Steps:**
  1. Test on mobile devices (320px-768px)
  2. Check all major functionality
  3. Verify touch interactions work
  
  **Expected Result:** App fully functional on mobile, proper layout
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: UI-002** - Tablet Responsiveness  
  **Steps:**
  1. Test on tablet devices (768px-1024px)
  2. Check landscape and portrait modes
  
  **Expected Result:** Proper layout adaptation, all features accessible
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: UI-003** - Desktop Responsiveness  
  **Steps:**
  1. Test on various desktop screen sizes
  2. Check ultra-wide and high-DPI displays
  
  **Expected Result:** Optimal layout on all desktop sizes
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Language Support
- [ ] **Test ID: UI-004** - French Language  
  **Steps:**
  1. Switch language to French
  2. Navigate through all major features
  3. Check error messages in French
  
  **Expected Result:** Complete French translation, proper formatting
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: UI-005** - English Language  
  **Steps:**
  1. Switch language to English
  2. Navigate through all major features
  3. Check error messages in English
  
  **Expected Result:** Complete English translation, proper formatting
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Error Handling
- [ ] **Test ID: UI-006** - Network Error Handling  
  **Steps:**
  1. Disconnect network while using app
  2. Try various operations
  3. Reconnect network
  
  **Expected Result:** Graceful error messages, retry functionality, recovery
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

- [ ] **Test ID: UI-007** - Loading States  
  **Steps:**
  1. Monitor loading indicators during API calls
  2. Check spinner/skeleton states
  3. Verify proper loading feedback
  
  **Expected Result:** Clear loading feedback, no UI blocking
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 🌍 Browser Compatibility Testing

### Chrome Testing
- [ ] **Test ID: BROWSER-001** - Chrome Latest  
  **Browser Version:** ____________  
  **All core functionality working:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Firefox Testing
- [ ] **Test ID: BROWSER-002** - Firefox Latest  
  **Browser Version:** ____________  
  **All core functionality working:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Safari Testing
- [ ] **Test ID: BROWSER-003** - Safari Latest  
  **Browser Version:** ____________  
  **All core functionality working:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Edge Testing
- [ ] **Test ID: BROWSER-004** - Edge Latest  
  **Browser Version:** ____________  
  **All core functionality working:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## ⚡ Performance Testing

### Load Times
- [ ] **Test ID: PERF-001** - Initial Page Load  
  **Steps:**
  1. Clear browser cache
  2. Load application homepage
  3. Measure load time
  
  **Target:** < 3 seconds  
  **Actual Time:** ____________  
  **Result:** ✅ Pass / ❌ Fail

- [ ] **Test ID: PERF-002** - Authenticated Page Load  
  **Steps:**
  1. Login and navigate to main app
  2. Measure time to interactive
  
  **Target:** < 2 seconds  
  **Actual Time:** ____________  
  **Result:** ✅ Pass / ❌ Fail

### Migration Performance
- [ ] **Test ID: PERF-003** - Migration with 50+ Prompts  
  **Steps:**
  1. Create 50+ localStorage prompts
  2. Time complete migration process
  
  **Target:** < 60 seconds  
  **Actual Time:** ____________  
  **Result:** ✅ Pass / ❌ Fail

---

## 🚀 Deployment Readiness

### Environment Configuration
- [ ] **Test ID: DEPLOY-001** - Environment Variables  
  **Check all required environment variables are set:**
  - [ ] JWT_SECRET
  - [ ] API_KEY
  - [ ] D1 Database configured
  - [ ] KV Namespace configured
  - [ ] CORS origins set
  
  **Result:** ✅ Pass / ❌ Fail

- [ ] **Test ID: DEPLOY-002** - Database Schema  
  **Steps:**
  1. Verify all tables exist with correct schema
  2. Check indexes are created
  3. Verify constraints and relationships
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

### Production Testing
- [ ] **Test ID: DEPLOY-003** - Production Environment  
  **Steps:**
  1. Deploy to production environment
  2. Run smoke tests on critical functionality
  3. Verify performance metrics
  
  **Result:** ✅ Pass / ❌ Fail  
  **Notes:** ____________________

---

## 📋 Testing Summary

**Testing Date:** ________________  
**Tester Name:** ________________  
**Environment:** ________________  

**Overall Results:**
- Total Tests: ______
- Passed: ______
- Failed: ______
- Success Rate: ______%

**Critical Issues Found:**
_________________________________
_________________________________
_________________________________

**Recommendations:**
_________________________________
_________________________________
_________________________________

**Deployment Recommendation:**
✅ Ready for deployment  
❌ Not ready - issues must be resolved  
⚠️ Ready with minor issues to be addressed post-deployment

**Sign-off:**
Tester: ________________ Date: ________  
Tech Lead: _____________ Date: ________