# 🔐 Authentication & Security Library

This directory contains the core security and authentication utilities for the Cloudflare Workers application. All modules are designed to be:

- **Edge-compatible** (no Node.js dependencies)
- **Security-first** (following OWASP guidelines) 
- **Performance-optimized** for distributed edge computing
- **Type-safe** with comprehensive error handling

## 📂 Module Overview

### 🛡️ `auth-utils.ts` - Core Authentication Utilities

**Main Classes:**
- `EdgeBcrypt` - Edge-optimized password hashing using PBKDF2
- `JWTManager` - Secure JWT token generation and verification
- `PasswordValidator` - OWASP-compliant password strength validation
- `InputValidator` - Comprehensive input validation and sanitization
- `SessionManager` - Secure session creation and management
- `AuthUtils` - General authentication utilities

**Key Features:**
- **Secure Password Hashing:** Edge-optimized PBKDF2 with timing-safe comparisons
- **JWT Security:** HMAC-SHA256 signed tokens with proper expiration handling
- **Input Sanitization:** XSS and injection attack prevention
- **Session Management:** Secure session ID generation and tracking

### 🛡️ `security.ts` - Security Middleware & Validation

**Main Classes:**
- `EdgeRateLimiter` - Distributed rate limiting with KV storage
- `CORSHandler` - Secure CORS handling with origin validation
- `RequestValidator` - HTTP request validation and sanitization
- `SecurityHeadersManager` - Comprehensive security headers
- `AuthMiddleware` - JWT authentication middleware
- `SecurityLogger` - Structured security event logging
- `SecurityMiddleware` - Complete security middleware stack

**Key Features:**
- **Rate Limiting:** Distributed edge-compatible rate limiting
- **CORS Security:** Strict origin validation with development support
- **Security Headers:** Complete OWASP-recommended security headers
- **Request Validation:** Size limits, content type validation, method validation
- **Security Logging:** Structured logging for security events

## 🚀 Quick Start

### Basic Authentication Flow

```typescript
import { 
  EdgeBcrypt, 
  JWTManager, 
  InputValidator,
  AuthUtils 
} from './auth-utils';

import { 
  SecurityMiddleware,
  RATE_LIMIT_CONFIGS 
} from './security';

// 1. Validate user input
const validation = InputValidator.validateLoginRequest(requestData);
if (!validation.isValid) {
  return AuthUtils.createErrorResponse(/* error */);
}

// 2. Verify password
const isValid = await EdgeBcrypt.compare(password, storedHash);
if (!isValid) {
  return AuthUtils.createErrorResponse(/* error */);
}

// 3. Generate JWT tokens
const tokens = await JWTManager.generateTokens(user, jwtSecret);

// 4. Return secure response
return AuthUtils.createSuccessResponse({ tokens });
```

### Security Middleware Usage

```typescript
// Initialize security middleware
const security = new SecurityMiddleware(kvNamespace, jwtSecret);

// Apply comprehensive security checks
const securityResult = await security.applySecurityChecks(request, {
  rateLimitConfig: RATE_LIMIT_CONFIGS.API,
  requireAuth: true,
  allowedMethods: ['POST'],
  endpoint: 'generate-prompt'
});

if (!securityResult.allowed) {
  return security.wrapResponse(securityResult.response!, request);
}

// Process authenticated request
const userId = securityResult.userId;
```

## 🔑 Security Configuration

### Password Requirements (OWASP Compliant)
```typescript
const PASSWORD_RULES = {
  minLength: 12,           // Minimum 12 characters
  requireUppercase: true,  // At least one uppercase letter
  requireLowercase: true,  // At least one lowercase letter  
  requireNumbers: true,    // At least one number
  requireSpecialChars: true, // At least one special character
  maxLength: 128          // Prevent DoS attacks
};
```

### JWT Configuration
```typescript
const JWT_CONFIG = {
  ACCESS_EXPIRES_IN: 15 * 60,        // 15 minutes
  REFRESH_EXPIRES_IN: 7 * 24 * 60 * 60, // 7 days
  ALGORITHM: 'HS256'                 // HMAC-SHA256
};
```

### Rate Limiting Configuration
```typescript
const RATE_LIMITS = {
  LOGIN: {
    windowMs: 15 * 60 * 1000,  // 15 minutes
    maxRequests: 5             // 5 attempts per IP
  },
  API: {
    windowMs: 60 * 1000,       // 1 minute  
    maxRequests: 100           // 100 requests per IP
  }
};
```

## 🛡️ Security Features

### ✅ Password Security
- **PBKDF2 Hashing:** Edge-optimized with 100k iteration cap
- **Timing-Safe Comparison:** Prevents timing attacks
- **Salt Generation:** Cryptographically secure random salts
- **Strength Validation:** OWASP password guidelines

### ✅ JWT Security  
- **HMAC-SHA256 Signing:** Industry standard algorithm
- **Token Rotation:** Refresh tokens for enhanced security
- **Expiration Validation:** Automatic token expiry checking
- **Type Validation:** Access vs refresh token verification

### ✅ Input Security
- **XSS Prevention:** HTML entity encoding
- **Length Limits:** DoS attack prevention
- **Email Validation:** RFC 5322 compliant regex
- **SQL Injection Prevention:** Parameterized queries only

### ✅ Session Security
- **Secure Session IDs:** 32-byte random generation
- **IP Tracking:** Suspicious activity detection
- **Session Revocation:** Immediate session invalidation
- **Activity Tracking:** Last used timestamps

### ✅ Request Security
- **Rate Limiting:** Distributed edge-compatible
- **CORS Validation:** Strict origin checking
- **Size Limits:** Request/payload size restrictions
- **Method Validation:** HTTP method whitelisting

### ✅ Response Security
- **Security Headers:** Complete OWASP header set
- **Error Information:** No sensitive data exposure
- **CORS Headers:** Proper cross-origin handling
- **Content Type:** Strict content type enforcement

## ⚡ Performance Optimizations

### Edge-Specific Optimizations
- **Web Crypto API:** Native browser cryptography
- **No Node.js Dependencies:** Pure web standard APIs
- **Memory Efficient:** Minimal object allocation
- **Async Operations:** Non-blocking crypto operations

### Cloudflare Optimizations
- **KV Storage:** Distributed rate limiting state
- **CF Headers:** Real IP extraction from CF-Connecting-IP
- **Edge Caching:** Session and rate limit data caching
- **Worker Memory:** Optimized for 128MB limit

## 🔍 Security Monitoring

### Events Logged
```typescript
// Authentication events
SecurityLogger.logAuthEvent('login_success', {
  userId: 'user-123',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...'
});

// Security events  
SecurityLogger.logSecurityEvent('rate_limit_exceeded', {
  endpoint: '/api/login',
  ipAddress: '192.168.1.1',
  severity: 'medium'
});
```

### Log Structure
```json
{
  "type": "security_event",
  "event": "login_failure", 
  "timestamp": 1640995200000,
  "userId": "user-123",
  "ipAddress": "192.168.1.1",
  "severity": "medium",
  "reason": "Invalid password"
}
```

## 🧪 Testing

### Unit Tests
```typescript
// Test password hashing
const hash = await EdgeBcrypt.hash('password123');
const isValid = await EdgeBcrypt.compare('password123', hash);
assert(isValid === true);

// Test JWT tokens
const tokens = await JWTManager.generateTokens(user, secret);
const payload = await JWTManager.verify(tokens.accessToken, secret);
assert(payload.userId === user.id);
```

### Security Tests
```typescript
// Test rate limiting
for (let i = 0; i < 10; i++) {
  const result = await rateLimiter.checkRateLimit('127.0.0.1', 'login', config);
  if (i >= 5) assert(result.allowed === false);
}

// Test input validation
const result = InputValidator.validateEmail('<script>alert(1)</script>@test.com');
assert(result.isValid === false);
```

## 🚨 Security Considerations

### Critical Security Practices
1. **Never log passwords** or sensitive data
2. **Always validate input** before processing
3. **Use parameterized queries** for database operations
4. **Implement proper error handling** without information disclosure
5. **Set secure headers** on all responses
6. **Rate limit all endpoints** to prevent abuse
7. **Validate JWT tokens** on every protected request
8. **Use HTTPS only** in production
9. **Implement session timeout** and cleanup
10. **Monitor security events** for suspicious activity

### Environment Variables
```bash
# Required secrets (set via wrangler secret put)
JWT_SECRET=<64-byte-base64-encoded-secret>
API_KEY=<gemini-api-key>

# Optional configuration
ENVIRONMENT=production
ALLOWED_ORIGINS=https://yourdomain.com
```

## 📚 References

- [OWASP Authentication Cheat Sheet](https://owasp.org/www-project-authentication-cheat-sheet/)
- [JWT Best Practices RFC 8725](https://tools.ietf.org/html/rfc8725)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Cloudflare Workers Runtime APIs](https://developers.cloudflare.com/workers/runtime-apis/)

---

**⚠️ SECURITY NOTICE:** This library implements production-ready security measures. Always review and test thoroughly before deploying to production. Follow the security setup guide for proper configuration.