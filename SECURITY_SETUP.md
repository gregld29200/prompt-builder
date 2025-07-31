# 🛡️ Security Implementation Guide

This guide provides step-by-step instructions for deploying your secure Cloudflare Workers authentication system.

## 🚨 CRITICAL: Deploy These Security Fixes Immediately

Your application had several **critical security vulnerabilities** that have been fixed:

1. **Unprotected API endpoint** - The main `/api/generate-prompt` endpoint was completely exposed
2. **Missing authentication** - Anyone could consume your Gemini API quota
3. **No rate limiting** - Vulnerable to abuse and DoS attacks
4. **Weak password hashing** - Exponential iteration calculation could cause DoS

**These issues have been resolved with this implementation.**

## 📋 Prerequisites

- Cloudflare account with Workers/Pages enabled
- Wrangler CLI installed and authenticated
- Node.js and npm/yarn installed

## 🔧 Installation & Configuration

### Step 1: Database Setup

1. **Create D1 Database:**
```bash
# Create the database
wrangler d1 create teachinspire-prompt-builder-db

# Copy the database_id from the output and update wrangler.toml
```

2. **Apply Database Schema:**
```bash
# Run the schema migration
wrangler d1 execute teachinspire-prompt-builder-db --file=./database/schema.sql

# Verify tables were created
wrangler d1 execute teachinspire-prompt-builder-db --command="SELECT name FROM sqlite_master WHERE type='table';"
```

### Step 2: KV Namespace Setup

1. **Create KV Namespace:**
```bash
# Create KV namespace for rate limiting
wrangler kv:namespace create "KV"

# Create preview namespace
wrangler kv:namespace create "KV" --preview

# Copy the IDs and update wrangler.toml
```

### Step 3: Secrets Configuration

1. **Generate JWT Secret:**
```bash
# Generate a secure 64-byte JWT secret
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
```

2. **Set Secrets:**
```bash
# Set JWT secret (paste the generated secret when prompted)
wrangler secret put JWT_SECRET

# Set Gemini API key
wrangler secret put API_KEY

# Optional: Set environment
wrangler secret put ENVIRONMENT
# Enter: "production" or "development"
```

### Step 4: Environment Variables

Update `wrangler.toml` with your actual domains:

```toml
[vars]
ENVIRONMENT = "production"
ALLOWED_ORIGINS = "https://yourdomain.com,https://www.yourdomain.com"
```

### Step 5: Deploy Application

```bash
# Deploy to Cloudflare Pages
wrangler pages deploy

# Or if using Workers
wrangler publish
```

## 🔐 Authentication Flow

### User Registration

**Endpoint:** `POST /api/auth/register`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "confirmPassword": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Registration successful",
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "isActive": true,
    "emailVerified": false
  },
  "tokens": {
    "accessToken": "jwt-access-token",
    "refreshToken": "jwt-refresh-token",
    "expiresAt": 1640995200000
  }
}
```

### User Login

**Endpoint:** `POST /api/auth/login`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "isActive": true
  },
  "tokens": {
    "accessToken": "jwt-access-token",
    "refreshToken": "jwt-refresh-token",
    "expiresAt": 1640995200000
  }
}
```

### Token Refresh

**Endpoint:** `POST /api/auth/refresh`

**Request:**
```json
{
  "refreshToken": "jwt-refresh-token"
}
```

**Response:**
```json
{
  "success": true,
  "tokens": {
    "accessToken": "new-jwt-access-token",
    "refreshToken": "new-jwt-refresh-token",
    "expiresAt": 1640995200000
  },
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "isActive": true
  }
}
```

### Authenticated API Calls

**All API calls now require authentication:**

```javascript
// Include JWT token in Authorization header
const response = await fetch('/api/generate-prompt', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    rawRequest: "Create a lesson plan for teaching Python",
    promptType: "MVP",
    domain: "education",
    language: "en",
    outputLength: "medium",
    expertRole: "Education Specialist",
    mission: "create engaging learning experiences",
    constraints: "30 minute lesson\nBeginner level"
  })
});
```

## 🛡️ Security Features

### Password Security
- **Minimum 12 characters** (OWASP compliant)
- **Required complexity:** uppercase, lowercase, numbers, special characters
- **Secure hashing:** Edge-optimized PBKDF2 with 100k iterations cap
- **Timing-safe comparison** to prevent timing attacks

### JWT Security
- **Short-lived access tokens** (15 minutes)
- **Longer refresh tokens** (7 days)  
- **Token rotation** on refresh for enhanced security
- **Secure signing** using HMAC-SHA256

### Rate Limiting
- **Login attempts:** 5 per IP per 15 minutes
- **Registration:** 3 per IP per hour
- **API calls:** 100 per IP per minute
- **Token refresh:** 10 per IP per 5 minutes

### Session Management
- **IP tracking** for suspicious activity detection
- **Device fingerprinting** capability
- **Session revocation** on new login
- **Automatic cleanup** of expired sessions

### Input Validation
- **Comprehensive sanitization** of all inputs
- **Length limits** to prevent DoS attacks
- **XSS prevention** through HTML entity encoding
- **SQL injection prevention** through parameterized queries

### Security Headers
- **Strict Transport Security** (HSTS)
- **Content Security Policy** (CSP)
- **X-Frame-Options** (Clickjacking protection)
- **X-Content-Type-Options** (MIME sniffing protection)

## 📊 Security Monitoring

### Security Events Logged
- Authentication attempts (success/failure)
- Rate limit violations
- Suspicious IP changes
- API access patterns
- Input validation failures

### Log Format
```json
{
  "type": "security_event",
  "event": "login_failure",
  "timestamp": 1640995200000,
  "userId": "user-uuid",
  "ipAddress": "192.168.1.1",
  "userAgent": "Mozilla/5.0...",
  "severity": "medium",
  "reason": "Invalid password"
}
```

## 🔍 Testing Your Security

### 1. Test Authentication Flow
```bash
# Test registration
curl -X POST https://your-domain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePassword123!","confirmPassword":"SecurePassword123!"}'

# Test login
curl -X POST https://your-domain.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePassword123!"}'

# Save the access token from response and test protected endpoint
curl -X POST https://your-domain.com/api/generate-prompt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{"rawRequest":"Test prompt","promptType":"MVP","domain":"education","language":"en","outputLength":"short"}'
```

### 2. Test Rate Limiting
```bash
# Try to hit the same endpoint multiple times quickly
for i in {1..10}; do
  curl -X POST https://your-domain.com/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
```

### 3. Test Security Headers
```bash
# Check security headers
curl -I https://your-domain.com/api/generate-prompt
```

## 🚨 Security Alerts

### Immediate Actions Required

1. **Update wrangler.toml** with your actual domain names
2. **Generate and set JWT_SECRET** immediately
3. **Set strong API_KEY** for Gemini
4. **Configure ALLOWED_ORIGINS** for your domains
5. **Deploy immediately** to fix critical vulnerabilities

### Monitoring Recommendations

1. **Set up log monitoring** for security events
2. **Monitor rate limit violations** for potential attacks
3. **Track failed authentication attempts** by IP
4. **Alert on unusual API usage patterns**
5. **Regular security audits** of authentication flows

## 🔧 Frontend Integration

You'll need to update your frontend React application to handle authentication:

### 1. Authentication Context
```javascript
// Create AuthContext for managing authentication state
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [tokens, setTokens] = useState(null);
  
  // Load tokens from localStorage on app start
  useEffect(() => {
    const savedTokens = localStorage.getItem('authTokens');
    if (savedTokens) {
      setTokens(JSON.parse(savedTokens));
    }
  }, []);
  
  const login = async (email, password) => {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    if (data.success) {
      setUser(data.user);
      setTokens(data.tokens);
      localStorage.setItem('authTokens', JSON.stringify(data.tokens));
    }
    return data;
  };
  
  return (
    <AuthContext.Provider value={{ user, tokens, login }}>
      {children}
    </AuthContext.Provider>
  );
};
```

### 2. Protected API Calls
```javascript
// Utility function for authenticated API calls
const authenticatedFetch = async (url, options = {}) => {
  const tokens = JSON.parse(localStorage.getItem('authTokens') || '{}');
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${tokens.accessToken}`,
      ...options.headers
    }
  });
  
  if (response.status === 401) {
    // Token expired, try to refresh
    const refreshResponse = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: tokens.refreshToken })
    });
    
    if (refreshResponse.ok) {
      const newTokens = await refreshResponse.json();
      localStorage.setItem('authTokens', JSON.stringify(newTokens.tokens));
      
      // Retry original request with new token
      return fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${newTokens.tokens.accessToken}`,
          ...options.headers
        }
      });
    } else {
      // Refresh failed, redirect to login
      localStorage.removeItem('authTokens');
      window.location.href = '/login';
    }
  }
  
  return response;
};
```

## 📚 Additional Resources

- [OWASP Authentication Guide](https://owasp.org/www-project-authentication-cheat-sheet/)
- [Cloudflare Workers Security](https://developers.cloudflare.com/workers/platform/security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [D1 Database Documentation](https://developers.cloudflare.com/d1/)

## 🆘 Support

If you encounter issues during deployment:

1. **Check Cloudflare Dashboard** for deployment logs
2. **Verify environment variables** are set correctly
3. **Test database connectivity** with simple queries
4. **Review security logs** for authentication failures
5. **Check CORS configuration** for frontend integration

---

**⚠️ IMPORTANT:** This implementation fixes critical security vulnerabilities. Deploy immediately to protect your application and prevent unauthorized access to your Gemini API quota.