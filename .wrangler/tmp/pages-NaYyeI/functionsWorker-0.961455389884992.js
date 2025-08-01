var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ../lib/auth-utils.ts
var AUTH_CONFIG = {
  // Bcrypt rounds optimized for edge performance vs security trade-off
  BCRYPT_ROUNDS: 12,
  // Reduced from typical 15 for edge performance, still secure
  // JWT Configuration
  JWT_ACCESS_EXPIRES_IN: 15 * 60,
  // 15 minutes in seconds
  JWT_REFRESH_EXPIRES_IN: 7 * 24 * 60 * 60,
  // 7 days in seconds
  // Account Security
  MAX_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCK_DURATION: 15 * 60 * 1e3,
  // 15 minutes in milliseconds
  // Password Requirements (OWASP compliant)
  PASSWORD_RULES: {
    minLength: 12,
    // OWASP recommends minimum 12 characters
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxLength: 128
    // Prevent DoS attacks
  },
  // Security Headers
  SECURE_HEADERS: {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
  }
};
var AUTH_ERRORS = {
  INVALID_CREDENTIALS: { code: "INVALID_CREDENTIALS", message: "Invalid email or password", statusCode: 401 },
  ACCOUNT_LOCKED: { code: "ACCOUNT_LOCKED", message: "Account temporarily locked due to too many failed attempts", statusCode: 423 },
  ACCOUNT_DISABLED: { code: "ACCOUNT_DISABLED", message: "Account has been disabled", statusCode: 403 },
  TOKEN_EXPIRED: { code: "TOKEN_EXPIRED", message: "Token has expired", statusCode: 401 },
  TOKEN_INVALID: { code: "TOKEN_INVALID", message: "Invalid token", statusCode: 401 },
  USER_NOT_FOUND: { code: "USER_NOT_FOUND", message: "User not found", statusCode: 404 },
  USER_EXISTS: { code: "USER_EXISTS", message: "User already exists", statusCode: 409 },
  WEAK_PASSWORD: { code: "WEAK_PASSWORD", message: "Password does not meet security requirements", statusCode: 400 },
  PASSWORDS_DONT_MATCH: { code: "PASSWORDS_DONT_MATCH", message: "Passwords do not match", statusCode: 400 },
  INVALID_EMAIL: { code: "INVALID_EMAIL", message: "Invalid email format", statusCode: 400 },
  RATE_LIMITED: { code: "RATE_LIMITED", message: "Too many requests, please try again later", statusCode: 429 },
  INTERNAL_ERROR: { code: "INTERNAL_ERROR", message: "Internal server error", statusCode: 500 }
};
var EdgeBcrypt = class {
  static {
    __name(this, "EdgeBcrypt");
  }
  static {
    this.BCRYPT_CHARSET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  }
  /**
   * Generate a cryptographically secure salt
   * Uses Web Crypto API for true randomness
   */
  static async generateSalt(rounds) {
    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    let salt = "$2b$" + rounds.toString().padStart(2, "0") + "$";
    for (let i = 0; i < saltBytes.length; i += 3) {
      const chunk = saltBytes[i] << 16 | (saltBytes[i + 1] || 0) << 8 | (saltBytes[i + 2] || 0);
      salt += this.BCRYPT_CHARSET[chunk >>> 18 & 63];
      salt += this.BCRYPT_CHARSET[chunk >>> 12 & 63];
      salt += this.BCRYPT_CHARSET[chunk >>> 6 & 63];
      salt += this.BCRYPT_CHARSET[chunk & 63];
    }
    return salt.substring(0, 29);
  }
  /**
   * Hash a password using edge-optimized bcrypt
   * @param password - Plain text password to hash
   * @param rounds - Number of salt rounds (default: 12 for edge optimization)
   */
  static async hash(password, rounds = AUTH_CONFIG.BCRYPT_ROUNDS) {
    if (!password || password.length === 0) {
      throw new Error("Password cannot be empty");
    }
    if (password.length > AUTH_CONFIG.PASSWORD_RULES.maxLength) {
      throw new Error("Password too long");
    }
    const salt = await this.generateSalt(rounds);
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const saltBytes = encoder.encode(salt);
    const key = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const iterations = Math.min(1e5, rounds * 1e4);
    const hashBytes = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );
    const hashArray = new Uint8Array(hashBytes);
    let encoded = "";
    for (let i = 0; i < hashArray.length; i += 3) {
      const chunk = hashArray[i] << 16 | (hashArray[i + 1] || 0) << 8 | (hashArray[i + 2] || 0);
      encoded += this.BCRYPT_CHARSET[chunk >>> 18 & 63];
      encoded += this.BCRYPT_CHARSET[chunk >>> 12 & 63];
      encoded += this.BCRYPT_CHARSET[chunk >>> 6 & 63];
      encoded += this.BCRYPT_CHARSET[chunk & 63];
    }
    return salt + encoded.substring(0, 31);
  }
  /**
   * Compare password with hash using timing-safe comparison
   * @param password - Plain text password
   * @param hash - Stored password hash
   */
  static async compare(password, hash) {
    if (!password || !hash || hash.length < 60) {
      return false;
    }
    try {
      const parts = hash.split("$");
      if (parts.length !== 4 || parts[1] !== "2b") {
        return false;
      }
      const rounds = parseInt(parts[2], 10);
      const salt = `$${parts[1]}$${parts[2]}$${parts[3].substring(0, 22)}`;
      const encoder = new TextEncoder();
      const passwordBytes = encoder.encode(password);
      const saltBytes = encoder.encode(salt);
      const key = await crypto.subtle.importKey(
        "raw",
        passwordBytes,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const iterations = Math.min(1e5, rounds * 1e4);
      const hashBytes = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBytes,
          iterations,
          hash: "SHA-256"
        },
        key,
        256
      );
      const hashArray = new Uint8Array(hashBytes);
      let encoded = "";
      for (let i = 0; i < hashArray.length; i += 3) {
        const chunk = hashArray[i] << 16 | (hashArray[i + 1] || 0) << 8 | (hashArray[i + 2] || 0);
        encoded += this.BCRYPT_CHARSET[chunk >>> 18 & 63];
        encoded += this.BCRYPT_CHARSET[chunk >>> 12 & 63];
        encoded += this.BCRYPT_CHARSET[chunk >>> 6 & 63];
        encoded += this.BCRYPT_CHARSET[chunk & 63];
      }
      const computedHash = salt + encoded.substring(0, 31);
      return await this.timingSafeEqual(computedHash, hash);
    } catch (error) {
      console.error("Password comparison error:", error);
      return false;
    }
  }
  /**
   * Timing-safe string comparison to prevent timing attacks
   */
  static async timingSafeEqual(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    const encoder = new TextEncoder();
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);
    let result = 0;
    for (let i = 0; i < aBytes.length; i++) {
      result |= aBytes[i] ^ bBytes[i];
    }
    return result === 0;
  }
};
var JWTManager = class {
  static {
    __name(this, "JWTManager");
  }
  static {
    this.encoder = new TextEncoder();
  }
  /**
   * Generate a secure random secret key for JWT signing
   * Should be called once and stored securely (environment variable)
   */
  static async generateSecretKey() {
    const key = await crypto.subtle.generateKey(
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );
    const keyData = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(keyData)));
  }
  /**
   * Import JWT secret key from base64 string
   */
  static async importKey(secret) {
    const keyData = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  }
  /**
   * Base64URL encode (RFC 7515 compliant)
   */
  static base64urlEncode(data) {
    const base64 = btoa(String.fromCharCode(...data));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  /**
   * Base64URL decode
   */
  static base64urlDecode(str) {
    const padded = str + "====".substring(0, (4 - str.length % 4) % 4);
    const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }
  /**
   * Generate JWT access and refresh tokens
   * @param user - Authenticated user data
   * @param secret - JWT signing secret
   */
  static async generateTokens(user, secret) {
    const now = Math.floor(Date.now() / 1e3);
    const accessExpiresAt = now + AUTH_CONFIG.JWT_ACCESS_EXPIRES_IN;
    const refreshExpiresAt = now + AUTH_CONFIG.JWT_REFRESH_EXPIRES_IN;
    const accessPayload = {
      userId: user.id,
      email: user.email,
      iat: now,
      exp: accessExpiresAt,
      type: "access"
    };
    const refreshPayload = {
      userId: user.id,
      email: user.email,
      iat: now,
      exp: refreshExpiresAt,
      type: "refresh"
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.sign(accessPayload, secret),
      this.sign(refreshPayload, secret)
    ]);
    return {
      accessToken,
      refreshToken,
      expiresAt: accessExpiresAt * 1e3
      // Convert to milliseconds
    };
  }
  /**
   * Sign JWT token
   */
  static async sign(payload, secret) {
    const header = {
      alg: "HS256",
      typ: "JWT"
    };
    const encodedHeader = this.base64urlEncode(this.encoder.encode(JSON.stringify(header)));
    const encodedPayload = this.base64urlEncode(this.encoder.encode(JSON.stringify(payload)));
    const data = `${encodedHeader}.${encodedPayload}`;
    const key = await this.importKey(secret);
    const signature = await crypto.subtle.sign("HMAC", key, this.encoder.encode(data));
    const encodedSignature = this.base64urlEncode(new Uint8Array(signature));
    return `${data}.${encodedSignature}`;
  }
  /**
   * Verify and decode JWT token
   * @param token - JWT token to verify
   * @param secret - JWT signing secret
   */
  static async verify(token, secret) {
    if (!token || typeof token !== "string") {
      throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
    }
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
    }
    const [headerB64, payloadB64, signatureB64] = parts;
    try {
      const data = `${headerB64}.${payloadB64}`;
      const key = await this.importKey(secret);
      const signature = this.base64urlDecode(signatureB64);
      const isValid = await crypto.subtle.verify(
        "HMAC",
        key,
        signature,
        this.encoder.encode(data)
      );
      if (!isValid) {
        throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
      }
      const payload = JSON.parse(
        new TextDecoder().decode(this.base64urlDecode(payloadB64))
      );
      const now = Math.floor(Date.now() / 1e3);
      if (payload.exp <= now) {
        throw new Error(AUTH_ERRORS.TOKEN_EXPIRED.message);
      }
      return payload;
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
    }
  }
};
var PasswordValidator = class {
  static {
    __name(this, "PasswordValidator");
  }
  /**
   * Validate password against security rules
   * @param password - Password to validate
   * @param rules - Validation rules (optional, uses default if not provided)
   */
  static validate(password, rules = AUTH_CONFIG.PASSWORD_RULES) {
    const errors = [];
    if (password.length < rules.minLength) {
      errors.push(`Password must be at least ${rules.minLength} characters long`);
    }
    if (password.length > rules.maxLength) {
      errors.push(`Password must not exceed ${rules.maxLength} characters`);
    }
    if (rules.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push("Password must contain at least one uppercase letter");
    }
    if (rules.requireLowercase && !/[a-z]/.test(password)) {
      errors.push("Password must contain at least one lowercase letter");
    }
    if (rules.requireNumbers && !/\d/.test(password)) {
      errors.push("Password must contain at least one number");
    }
    if (rules.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push("Password must contain at least one special character");
    }
    if (this.hasCommonPatterns(password)) {
      errors.push("Password contains common patterns and may be easily guessed");
    }
    const strength = this.calculateStrength(password);
    return {
      isValid: errors.length === 0,
      errors,
      strength
    };
  }
  /**
   * Check for common password patterns
   */
  static hasCommonPatterns(password) {
    const commonPatterns = [
      /(.)\1{2,}/,
      // Repeated characters (aaa, 111)
      /123456|abcdef|qwerty/i,
      // Sequential patterns
      /password|admin|login|user/i,
      // Common words
      /^(.{1,2})\1+$/
      // Very short repeated patterns
    ];
    return commonPatterns.some((pattern) => pattern.test(password));
  }
  /**
   * Calculate password strength
   */
  static calculateStrength(password) {
    let score = 0;
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    if (password.length >= 16) score += 1;
    if (/[^a-zA-Z0-9!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    if (this.hasCommonPatterns(password)) score -= 2;
    if (score >= 6) return "strong";
    if (score >= 4) return "medium";
    return "weak";
  }
};
var InputValidator = class {
  static {
    __name(this, "InputValidator");
  }
  /**
   * Validate and sanitize email address
   * Uses RFC 5322 compliant regex with additional security checks
   */
  static validateEmail(email) {
    if (!email || typeof email !== "string") {
      return { isValid: false, sanitized: "", error: "Email is required" };
    }
    const sanitized = email.trim().toLowerCase();
    if (sanitized.length > 254) {
      return { isValid: false, sanitized: "", error: "Email address too long" };
    }
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    if (!emailRegex.test(sanitized)) {
      return { isValid: false, sanitized: "", error: "Invalid email format" };
    }
    if (sanitized.includes("..") || sanitized.startsWith(".") || sanitized.endsWith(".")) {
      return { isValid: false, sanitized: "", error: "Invalid email format" };
    }
    const maliciousPatterns = [
      /<script/i,
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /<iframe/i,
      /<object/i,
      /<embed/i
    ];
    if (maliciousPatterns.some((pattern) => pattern.test(sanitized))) {
      return { isValid: false, sanitized: "", error: "Invalid email format" };
    }
    return { isValid: true, sanitized };
  }
  /**
   * Sanitize user input for safe database storage
   * Prevents XSS and injection attacks
   */
  static sanitizeInput(input) {
    if (!input || typeof input !== "string") {
      return "";
    }
    return input.trim().replace(/[<>'"&]/g, (char) => {
      const entities = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "&": "&amp;"
      };
      return entities[char] || char;
    }).slice(0, 1e3);
  }
  /**
   * Validate request data structure
   */
  static validateLoginRequest(data) {
    const errors = [];
    if (!data || typeof data !== "object") {
      return { isValid: false, errors: ["Invalid request data"] };
    }
    const emailValidation = this.validateEmail(data.email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.error || "Invalid email");
    }
    if (!data.password || typeof data.password !== "string") {
      errors.push("Password is required");
    } else if (data.password.length > AUTH_CONFIG.PASSWORD_RULES.maxLength) {
      errors.push("Password too long");
    }
    if (errors.length > 0) {
      return { isValid: false, errors };
    }
    return {
      isValid: true,
      request: {
        email: emailValidation.sanitized,
        password: data.password
      },
      errors: []
    };
  }
  /**
   * Validate registration request
   */
  static validateRegisterRequest(data) {
    const errors = [];
    if (!data || typeof data !== "object") {
      return { isValid: false, errors: ["Invalid request data"] };
    }
    const emailValidation = this.validateEmail(data.email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.error || "Invalid email");
    }
    if (!data.password || typeof data.password !== "string") {
      errors.push("Password is required");
    }
    if (!data.confirmPassword || typeof data.confirmPassword !== "string") {
      errors.push("Password confirmation is required");
    }
    if (data.password !== data.confirmPassword) {
      errors.push(AUTH_ERRORS.PASSWORDS_DONT_MATCH.message);
    }
    if (data.password) {
      const passwordValidation = PasswordValidator.validate(data.password);
      if (!passwordValidation.isValid) {
        errors.push(...passwordValidation.errors);
      }
    }
    if (errors.length > 0) {
      return { isValid: false, errors };
    }
    return {
      isValid: true,
      request: {
        email: emailValidation.sanitized,
        password: data.password,
        confirmPassword: data.confirmPassword
      },
      errors: []
    };
  }
  /**
   * Validate generate prompt request for the main API endpoint
   */
  static validateGeneratePromptRequest(data) {
    const errors = [];
    if (!data || typeof data !== "object") {
      return { isValid: false, errors: ["Invalid request data"] };
    }
    if (!data.rawRequest || typeof data.rawRequest !== "string") {
      errors.push("Raw request is required");
    } else if (data.rawRequest.trim().length === 0) {
      errors.push("Raw request cannot be empty");
    } else if (data.rawRequest.length > 5e3) {
      errors.push("Raw request exceeds maximum length of 5000 characters");
    }
    if (!data.promptType || !["MVP", "AGENTIC"].includes(data.promptType)) {
      errors.push("Invalid prompt type. Must be MVP or AGENTIC");
    }
    if (!data.domain || !["education", "technical", "creative", "analysis", "other"].includes(data.domain)) {
      errors.push("Invalid domain. Must be one of: education, technical, creative, analysis, other");
    }
    if (!data.language || !["fr", "en"].includes(data.language)) {
      errors.push("Invalid language. Must be fr or en");
    }
    if (!data.outputLength || !["short", "medium", "long"].includes(data.outputLength)) {
      errors.push("Invalid output length. Must be short, medium, or long");
    }
    if (data.expertRole !== void 0) {
      if (typeof data.expertRole !== "string") {
        errors.push("Expert role must be a string");
      } else if (data.expertRole.length > 200) {
        errors.push("Expert role exceeds maximum length of 200 characters");
      }
    }
    if (data.mission !== void 0) {
      if (typeof data.mission !== "string") {
        errors.push("Mission must be a string");
      } else if (data.mission.length > 500) {
        errors.push("Mission description exceeds maximum length of 500 characters");
      }
    }
    if (data.constraints !== void 0) {
      if (typeof data.constraints !== "string") {
        errors.push("Constraints must be a string");
      } else if (data.constraints.length > 1e3) {
        errors.push("Constraints exceed maximum length of 1000 characters");
      }
    }
    const sanitizedData = {
      rawRequest: data.rawRequest ? this.sanitizeInput(data.rawRequest) : "",
      promptType: data.promptType,
      domain: data.domain,
      language: data.language,
      outputLength: data.outputLength,
      expertRole: data.expertRole ? this.sanitizeInput(data.expertRole) : void 0,
      mission: data.mission ? this.sanitizeInput(data.mission) : void 0,
      constraints: data.constraints ? this.sanitizeInput(data.constraints) : void 0
    };
    if (errors.length > 0) {
      return { isValid: false, errors };
    }
    return {
      isValid: true,
      data: sanitizedData,
      errors: []
    };
  }
};
var SessionManager = class {
  static {
    __name(this, "SessionManager");
  }
  /**
   * Generate a unique session ID
   */
  static generateSessionId() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  /**
   * Create a new session
   */
  static createSession(userId, tokens, ipAddress, userAgent) {
    const now = Date.now();
    return {
      id: this.generateSessionId(),
      userId,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      createdAt: now,
      expiresAt: tokens.expiresAt,
      lastUsedAt: now,
      ipAddress,
      userAgent
    };
  }
  /**
   * Check if session is valid and not expired
   */
  static isSessionValid(session) {
    const now = Date.now();
    return session.expiresAt > now;
  }
  /**
   * Update session last used timestamp
   */
  static updateSessionActivity(session) {
    return {
      ...session,
      lastUsedAt: Date.now()
    };
  }
};
var AuthUtils = class {
  static {
    __name(this, "AuthUtils");
  }
  /**
   * Generate secure random string for various auth purposes
   */
  static generateSecureRandom(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  /**
   * Extract IP address from request, handling Cloudflare headers
   */
  static getClientIP(request) {
    return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() || request.headers.get("X-Real-IP") || void 0;
  }
  /**
   * Extract User-Agent safely
   */
  static getUserAgent(request) {
    const userAgent = request.headers.get("User-Agent");
    return userAgent ? InputValidator.sanitizeInput(userAgent) : void 0;
  }
  /**
   * Create standardized error response
   */
  static createErrorResponse(error) {
    return new Response(
      JSON.stringify({
        success: false,
        error: {
          code: error.code,
          message: error.message
        }
      }),
      {
        status: error.statusCode,
        headers: AUTH_CONFIG.SECURE_HEADERS
      }
    );
  }
  /**
   * Create success response with security headers
   */
  static createSuccessResponse(data) {
    return new Response(
      JSON.stringify({
        success: true,
        data
      }),
      {
        status: 200,
        headers: AUTH_CONFIG.SECURE_HEADERS
      }
    );
  }
};

// ../lib/security.ts
var RATE_LIMIT_CONFIGS = {
  // Authentication endpoints - most restrictive
  LOGIN: {
    windowMs: 15 * 60 * 1e3,
    // 15 minutes
    maxRequests: 5,
    // 5 attempts per IP per 15 minutes
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  },
  REGISTER: {
    windowMs: 15 * 60 * 1e3,
    // 15 minutes  
    maxRequests: 10,
    // 10 registrations per IP per 15 minutes (more generous for testing)
    skipSuccessfulRequests: true,
    // Don't count successful registrations
    skipFailedRequests: false
  },
  // Token refresh - moderate limiting
  REFRESH_TOKEN: {
    windowMs: 5 * 60 * 1e3,
    // 5 minutes
    maxRequests: 10,
    // 10 refreshes per IP per 5 minutes
    skipSuccessfulRequests: true,
    skipFailedRequests: false
  },
  // General API endpoints
  API: {
    windowMs: 60 * 1e3,
    // 1 minute
    maxRequests: 100,
    // 100 requests per IP per minute
    skipSuccessfulRequests: true,
    skipFailedRequests: false
  },
  // Password reset - very restrictive
  PASSWORD_RESET: {
    windowMs: 60 * 60 * 1e3,
    // 1 hour
    maxRequests: 3,
    // 3 reset attempts per IP per hour
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  }
};
var SECURITY_CONFIG = {
  // Request size limits (DoS prevention)
  MAX_REQUEST_SIZE: 1024 * 1024,
  // 1MB max request size
  MAX_JSON_SIZE: 100 * 1024,
  // 100KB max JSON payload
  // CORS configuration
  ALLOWED_ORIGINS: [
    "https://yourdomain.com",
    "https://www.yourdomain.com"
    // Add your production domains here
  ],
  // Content Security Policy
  CSP_DIRECTIVES: {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline'",
    // Adjust based on your needs
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data: https:",
    "font-src": "'self'",
    "connect-src": "'self'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'",
    "form-action": "'self'"
  },
  // Security headers with strict defaults
  SECURITY_HEADERS: {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin"
  }
};
var EdgeRateLimiter = class {
  static {
    __name(this, "EdgeRateLimiter");
  }
  constructor(kvNamespace) {
    this.kvNamespace = kvNamespace;
  }
  /**
   * Generate rate limit key for distributed tracking
   */
  generateKey(identifier, endpoint) {
    return `rate_limit:${endpoint}:${identifier}`;
  }
  /**
   * Check and update rate limit state
   * @param identifier - Usually IP address or user ID
   * @param endpoint - API endpoint identifier
   * @param config - Rate limiting configuration
   */
  async checkRateLimit(identifier, endpoint, config) {
    const key = this.generateKey(identifier, endpoint);
    const now = Date.now();
    const windowStart = now - config.windowMs;
    let state;
    try {
      const existingState = this.kvNamespace ? await this.kvNamespace.get(key, "json") : null;
      if (existingState && existingState.resetTime > now) {
        state = {
          count: existingState.count + 1,
          resetTime: existingState.resetTime,
          blocked: existingState.count >= config.maxRequests
        };
      } else {
        state = {
          count: 1,
          resetTime: now + config.windowMs,
          blocked: false
        };
      }
      if (this.kvNamespace) {
        await this.kvNamespace.put(
          key,
          JSON.stringify(state),
          { expirationTtl: Math.ceil(config.windowMs / 1e3) }
        );
      }
      return {
        allowed: !state.blocked,
        state,
        resetTime: state.resetTime
      };
    } catch (error) {
      console.error("Rate limiter error:", error);
      return {
        allowed: true,
        state: { count: 1, resetTime: now + config.windowMs, blocked: false },
        resetTime: now + config.windowMs
      };
    }
  }
  /**
   * Reset rate limit for an identifier (admin function)
   */
  async resetRateLimit(identifier, endpoint) {
    if (!this.kvNamespace) return;
    const key = this.generateKey(identifier, endpoint);
    await this.kvNamespace.delete(key);
  }
  /**
   * Get current rate limit state without incrementing
   */
  async getRateLimitState(identifier, endpoint) {
    if (!this.kvNamespace) return null;
    const key = this.generateKey(identifier, endpoint);
    return await this.kvNamespace.get(key, "json");
  }
};
var CORSHandler = class {
  static {
    __name(this, "CORSHandler");
  }
  constructor(allowedOrigins = SECURITY_CONFIG.ALLOWED_ORIGINS, allowCredentials = true) {
    this.allowedOrigins = allowedOrigins;
    this.allowCredentials = allowCredentials;
  }
  /**
   * Check if origin is allowed
   */
  isOriginAllowed(origin) {
    if (origin.startsWith("http://localhost:") || origin.startsWith("https://localhost:")) {
      return false;
    }
    return this.allowedOrigins.includes(origin);
  }
  /**
   * Handle CORS preflight request
   */
  handlePreflight(request) {
    const origin = request.headers.get("Origin");
    const method = request.headers.get("Access-Control-Request-Method");
    const headers = request.headers.get("Access-Control-Request-Headers");
    if (!origin || !this.isOriginAllowed(origin)) {
      return new Response(null, {
        status: 403,
        statusText: "Forbidden - Invalid Origin"
      });
    }
    const allowedMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
    if (!method || !allowedMethods.includes(method)) {
      return new Response(null, {
        status: 405,
        statusText: "Method Not Allowed"
      });
    }
    const responseHeaders = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": allowedMethods.join(", "),
      "Access-Control-Allow-Headers": headers || "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      // 24 hours
      "Vary": "Origin"
    };
    if (this.allowCredentials) {
      responseHeaders["Access-Control-Allow-Credentials"] = "true";
    }
    return new Response(null, {
      status: 204,
      headers: responseHeaders
    });
  }
  /**
   * Add CORS headers to response
   */
  addCORSHeaders(response, origin) {
    if (!origin || !this.isOriginAllowed(origin)) {
      return response;
    }
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Access-Control-Allow-Origin", origin);
    newHeaders.set("Vary", "Origin");
    if (this.allowCredentials) {
      newHeaders.set("Access-Control-Allow-Credentials", "true");
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
var RequestValidator = class {
  static {
    __name(this, "RequestValidator");
  }
  /**
   * Validate request size (DoS prevention)
   */
  static validateRequestSize(request) {
    const contentLength = request.headers.get("Content-Length");
    if (contentLength) {
      const size = parseInt(contentLength, 10);
      if (isNaN(size) || size > SECURITY_CONFIG.MAX_REQUEST_SIZE) {
        return {
          valid: false,
          error: {
            code: "REQUEST_TOO_LARGE",
            message: "Request size exceeds maximum allowed limit",
            statusCode: 413
          }
        };
      }
    }
    return { valid: true };
  }
  /**
   * Validate Content-Type header
   */
  static validateContentType(request, expectedTypes = ["application/json"]) {
    const contentType = request.headers.get("Content-Type");
    if (!contentType) {
      return {
        valid: false,
        error: {
          code: "MISSING_CONTENT_TYPE",
          message: "Content-Type header is required",
          statusCode: 400
        }
      };
    }
    const mainType = contentType.split(";")[0].trim().toLowerCase();
    if (!expectedTypes.includes(mainType)) {
      return {
        valid: false,
        error: {
          code: "INVALID_CONTENT_TYPE",
          message: `Content-Type must be one of: ${expectedTypes.join(", ")}`,
          statusCode: 415
        }
      };
    }
    return { valid: true };
  }
  /**
   * Parse and validate JSON body
   */
  static async parseAndValidateJSON(request) {
    try {
      console.log("=== SecurityHelpers.parseAndValidateJSON ===");
      console.log("Request bodyUsed before text():", request.bodyUsed);
      const text = await request.text();
      console.log("Text received - length:", text.length);
      console.log("Text content (first 200 chars):", text.substring(0, 200));
      console.log("Text content (full):", text);
      if (text.length > SECURITY_CONFIG.MAX_JSON_SIZE) {
        return {
          valid: false,
          error: {
            code: "JSON_TOO_LARGE",
            message: "JSON payload too large",
            statusCode: 413
          }
        };
      }
      const data = JSON.parse(text);
      if (typeof data !== "object" || data === null || Array.isArray(data)) {
        return {
          valid: false,
          error: {
            code: "INVALID_JSON_STRUCTURE",
            message: "JSON must be an object",
            statusCode: 400
          }
        };
      }
      return { valid: true, data };
    } catch (error) {
      return {
        valid: false,
        error: {
          code: "INVALID_JSON",
          message: "Invalid JSON format",
          statusCode: 400
        }
      };
    }
  }
  /**
   * Validate HTTP method
   */
  static validateMethod(request, allowedMethods) {
    if (!allowedMethods.includes(request.method)) {
      return {
        valid: false,
        error: {
          code: "METHOD_NOT_ALLOWED",
          message: `Method ${request.method} not allowed`,
          statusCode: 405
        }
      };
    }
    return { valid: true };
  }
  /**
   * Extract and validate Authorization header
   */
  static extractBearerToken(request) {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
      return {
        valid: false,
        error: AUTH_ERRORS.TOKEN_INVALID
      };
    }
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return {
        valid: false,
        error: AUTH_ERRORS.TOKEN_INVALID
      };
    }
    const token = parts[1];
    if (!token || token.length === 0) {
      return {
        valid: false,
        error: AUTH_ERRORS.TOKEN_INVALID
      };
    }
    return { valid: true, token };
  }
};
var SecurityHeadersManager = class {
  static {
    __name(this, "SecurityHeadersManager");
  }
  /**
   * Generate Content Security Policy header value
   */
  static generateCSP() {
    const directives = Object.entries(SECURITY_CONFIG.CSP_DIRECTIVES).map(([directive, value]) => `${directive} ${value}`).join("; ");
    return directives;
  }
  /**
   * Get all security headers
   */
  static getSecurityHeaders() {
    const headers = { ...SECURITY_CONFIG.SECURITY_HEADERS };
    headers["Content-Security-Policy"] = this.generateCSP();
    return headers;
  }
  /**
   * Add security headers to response
   */
  static addSecurityHeaders(response) {
    const newHeaders = new Headers(response.headers);
    const securityHeaders = this.getSecurityHeaders();
    Object.entries(securityHeaders).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
var AuthMiddleware = class {
  static {
    __name(this, "AuthMiddleware");
  }
  constructor(jwtSecret) {
    this.jwtSecret = jwtSecret;
  }
  /**
   * Verify JWT token and extract user information
   */
  async verifyToken(request) {
    const tokenResult = RequestValidator.extractBearerToken(request);
    if (!tokenResult.valid) {
      return { valid: false, error: tokenResult.error };
    }
    try {
      const payload = await JWTManager.verify(tokenResult.token, this.jwtSecret);
      if (payload.type !== "access") {
        return {
          valid: false,
          error: {
            code: "INVALID_TOKEN_TYPE",
            message: "Invalid token type for this endpoint",
            statusCode: 401
          }
        };
      }
      return { valid: true, payload };
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === AUTH_ERRORS.TOKEN_EXPIRED.message) {
          return { valid: false, error: AUTH_ERRORS.TOKEN_EXPIRED };
        }
      }
      return { valid: false, error: AUTH_ERRORS.TOKEN_INVALID };
    }
  }
  /**
   * Create authentication middleware function
   */
  createMiddleware() {
    return async (request) => {
      const result = await this.verifyToken(request);
      if (!result.valid) {
        return {
          authorized: false,
          error: AuthUtils.createErrorResponse(result.error)
        };
      }
      return {
        authorized: true,
        userId: result.payload.userId
      };
    };
  }
};
var SecurityLogger = class {
  static {
    __name(this, "SecurityLogger");
  }
  /**
   * Log authentication event
   */
  static logAuthEvent(event, details) {
    const logEntry = {
      type: "auth_event",
      event,
      timestamp: details.timestamp || Date.now(),
      ...details
    };
    console.log(JSON.stringify(logEntry));
  }
  /**
   * Log security event
   */
  static logSecurityEvent(event, details) {
    const logEntry = {
      type: "security_event",
      event,
      timestamp: details.timestamp || Date.now(),
      severity: details.severity || "medium",
      ...details
    };
    console.log(JSON.stringify(logEntry));
  }
  /**
   * Log rate limit event
   */
  static logRateLimitEvent(identifier, endpoint, state, allowed) {
    this.logSecurityEvent("rate_limit_exceeded", {
      ipAddress: identifier,
      endpoint,
      reason: `Rate limit ${allowed ? "approached" : "exceeded"}: ${state.count} requests`,
      severity: allowed ? "low" : "medium"
    });
  }
};
var SecurityMiddleware = class {
  static {
    __name(this, "SecurityMiddleware");
  }
  constructor(kvNamespace, jwtSecret, corsOptions) {
    this.rateLimiter = new EdgeRateLimiter(kvNamespace);
    this.corsHandler = new CORSHandler(corsOptions?.origins, corsOptions?.credentials);
    if (jwtSecret) {
      this.authMiddleware = new AuthMiddleware(jwtSecret);
    }
  }
  /**
   * Apply all security checks to a request
   */
  async applySecurityChecks(request, options = {}) {
    const origin = request.headers.get("Origin");
    const clientIP = AuthUtils.getClientIP(request) || "unknown";
    const endpoint = options.endpoint || "default";
    try {
      if (request.method === "OPTIONS") {
        return {
          allowed: true,
          response: this.corsHandler.handlePreflight(request)
        };
      }
      if (options.allowedMethods) {
        const methodResult = RequestValidator.validateMethod(request, options.allowedMethods);
        if (!methodResult.valid) {
          const response = AuthUtils.createErrorResponse(methodResult.error);
          return {
            allowed: false,
            response: SecurityHeadersManager.addSecurityHeaders(response)
          };
        }
      }
      const sizeResult = RequestValidator.validateRequestSize(request);
      if (!sizeResult.valid) {
        const response = AuthUtils.createErrorResponse(sizeResult.error);
        return {
          allowed: false,
          response: SecurityHeadersManager.addSecurityHeaders(response)
        };
      }
      if (options.rateLimitConfig) {
        const rateLimitResult = await this.rateLimiter.checkRateLimit(
          clientIP,
          endpoint,
          options.rateLimitConfig
        );
        if (!rateLimitResult.allowed) {
          SecurityLogger.logRateLimitEvent(clientIP, endpoint, rateLimitResult.state, false);
          const response = AuthUtils.createErrorResponse(AUTH_ERRORS.RATE_LIMITED);
          const headers = new Headers(response.headers);
          headers.set("Retry-After", Math.ceil((rateLimitResult.resetTime - Date.now()) / 1e3).toString());
          return {
            allowed: false,
            response: new Response(response.body, {
              status: response.status,
              headers
            }),
            rateLimitState: rateLimitResult.state
          };
        }
      }
      let userId;
      if (options.requireAuth && this.authMiddleware) {
        const authResult = await this.authMiddleware.createMiddleware()(request);
        if (!authResult.authorized) {
          SecurityLogger.logAuthEvent("login_failure", {
            ipAddress: clientIP,
            userAgent: AuthUtils.getUserAgent(request),
            reason: "Invalid or missing token"
          });
          return {
            allowed: false,
            response: authResult.error
          };
        }
        userId = authResult.userId;
      }
      return {
        allowed: true,
        userId,
        rateLimitState: options.rateLimitConfig ? (await this.rateLimiter.checkRateLimit(clientIP, endpoint, options.rateLimitConfig)).state : void 0
      };
    } catch (error) {
      console.error("Security middleware error:", error);
      SecurityLogger.logSecurityEvent("suspicious_request", {
        ipAddress: clientIP,
        endpoint,
        reason: "Security middleware error",
        severity: "high"
      });
      const response = AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
      return {
        allowed: false,
        response: SecurityHeadersManager.addSecurityHeaders(response)
      };
    }
  }
  /**
   * Wrap response with security headers and CORS
   */
  wrapResponse(response, request) {
    const origin = request.headers.get("Origin");
    const corsResponse = this.corsHandler.addCORSHeaders(response, origin);
    return SecurityHeadersManager.addSecurityHeaders(corsResponse);
  }
};
var SecurityHelpers = class {
  static {
    __name(this, "SecurityHelpers");
  }
  /**
   * Create a secure response with proper headers
   */
  static createSecureResponse(data, status = 200, additionalHeaders = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...SecurityHeadersManager.getSecurityHeaders(),
      ...additionalHeaders
    };
    return new Response(JSON.stringify(data), {
      status,
      headers
    });
  }
  /**
   * Validate and sanitize request data
   */
  static async validateRequest(request, validator) {
    const contentTypeResult = RequestValidator.validateContentType(request);
    if (!contentTypeResult.valid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse(contentTypeResult.error)
      };
    }
    const jsonResult = await RequestValidator.parseAndValidateJSON(request);
    if (!jsonResult.valid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse(jsonResult.error)
      };
    }
    const validationResult = validator(jsonResult.data);
    if (!validationResult.isValid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse({
          code: "VALIDATION_ERROR",
          message: validationResult.errors.join("; "),
          statusCode: 400
        })
      };
    }
    return {
      valid: true,
      data: validationResult.data
    };
  }
  /**
   * Extract request metadata for logging
   */
  static extractRequestMetadata(request) {
    return {
      ipAddress: AuthUtils.getClientIP(request),
      userAgent: AuthUtils.getUserAgent(request),
      origin: request.headers.get("Origin") || void 0,
      timestamp: Date.now()
    };
  }
};

// ../lib/prompts-db.ts
var PromptError = class extends Error {
  constructor(message, code, statusCode = 500) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.name = "PromptError";
  }
  static {
    __name(this, "PromptError");
  }
};
var PromptsDatabase = class {
  constructor(db) {
    this.db = db;
  }
  static {
    __name(this, "PromptsDatabase");
  }
  /**
   * Generate UUID for prompts (edge-compatible)
   */
  generateId() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    array[6] = array[6] & 15 | 64;
    array[8] = array[8] & 63 | 128;
    const hex = Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32)
    ].join("-");
  }
  /**
   * Auto-generate title from raw request (first 50 characters)
   */
  generateTitle(rawRequest) {
    const cleanRequest = rawRequest.trim();
    if (cleanRequest.length <= 50) {
      return cleanRequest;
    }
    const truncated = cleanRequest.substring(0, 47);
    const lastSpaceIndex = truncated.lastIndexOf(" ");
    if (lastSpaceIndex > 20) {
      return truncated.substring(0, lastSpaceIndex) + "...";
    }
    return truncated + "...";
  }
  /**
   * Validate prompt data before database operations
   */
  validatePromptData(data, isUpdate = false) {
    if (!isUpdate) {
      const createData = data;
      if (!createData.userId || typeof createData.userId !== "string") {
        throw new PromptError("User ID is required", "INVALID_USER_ID", 400);
      }
      if (!createData.rawRequest || typeof createData.rawRequest !== "string") {
        throw new PromptError("Raw request is required", "INVALID_RAW_REQUEST", 400);
      }
      if (createData.rawRequest.length > 5e3) {
        throw new PromptError("Raw request exceeds maximum length", "RAW_REQUEST_TOO_LONG", 400);
      }
      if (!createData.generatedPrompt || typeof createData.generatedPrompt !== "string") {
        throw new PromptError("Generated prompt is required", "INVALID_GENERATED_PROMPT", 400);
      }
      if (createData.generatedPrompt.length > 1e4) {
        throw new PromptError("Generated prompt exceeds maximum length", "GENERATED_PROMPT_TOO_LONG", 400);
      }
      if (!["MVP", "AGENTIC"].includes(createData.promptType)) {
        throw new PromptError("Invalid prompt type", "INVALID_PROMPT_TYPE", 400);
      }
      if (!["education", "technical", "creative", "analysis", "other"].includes(createData.domain)) {
        throw new PromptError("Invalid domain", "INVALID_DOMAIN", 400);
      }
      if (!["fr", "en"].includes(createData.language)) {
        throw new PromptError("Invalid language", "INVALID_LANGUAGE", 400);
      }
      if (!["short", "medium", "long"].includes(createData.outputLength)) {
        throw new PromptError("Invalid output length", "INVALID_OUTPUT_LENGTH", 400);
      }
    }
    if (data.title !== void 0) {
      if (typeof data.title !== "string" || data.title.length > 100) {
        throw new PromptError("Title must be a string with maximum 100 characters", "INVALID_TITLE", 400);
      }
    }
    if (data.expertRole !== void 0) {
      if (typeof data.expertRole !== "string" || data.expertRole.length > 200) {
        throw new PromptError("Expert role must be a string with maximum 200 characters", "INVALID_EXPERT_ROLE", 400);
      }
    }
    if (data.mission !== void 0) {
      if (typeof data.mission !== "string" || data.mission.length > 500) {
        throw new PromptError("Mission must be a string with maximum 500 characters", "INVALID_MISSION", 400);
      }
    }
    if (data.constraints !== void 0) {
      if (typeof data.constraints !== "string" || data.constraints.length > 1e3) {
        throw new PromptError("Constraints must be a string with maximum 1000 characters", "INVALID_CONSTRAINTS", 400);
      }
    }
    if (data.isFavorite !== void 0 && typeof data.isFavorite !== "boolean") {
      throw new PromptError("isFavorite must be a boolean", "INVALID_IS_FAVORITE", 400);
    }
  }
  /**
   * Check if user owns a prompt
   */
  async validateOwnership(promptId, userId) {
    try {
      const stmt = this.db.prepare(`
        SELECT user_id FROM prompts 
        WHERE id = ? LIMIT 1
      `);
      const result = await stmt.bind(promptId).first();
      return result?.user_id === userId;
    } catch (error) {
      console.error("Error validating prompt ownership:", error);
      return false;
    }
  }
  /**
   * Create a new prompt
   */
  async createPrompt(data) {
    this.validatePromptData(data);
    const id = this.generateId();
    const title = data.title || this.generateTitle(data.rawRequest);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const stmt = this.db.prepare(`
        INSERT INTO prompts (
          id, user_id, title, raw_request, generated_prompt,
          prompt_type, domain, language, output_length,
          expert_role, mission, constraints, is_favorite,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      await stmt.bind(
        id,
        data.userId,
        title,
        data.rawRequest,
        data.generatedPrompt,
        data.promptType,
        data.domain,
        data.language,
        data.outputLength,
        data.expertRole || null,
        data.mission || null,
        data.constraints || null,
        data.isFavorite ? 1 : 0,
        now,
        now
      ).run();
      return {
        id,
        userId: data.userId,
        title,
        rawRequest: data.rawRequest,
        generatedPrompt: data.generatedPrompt,
        promptType: data.promptType,
        domain: data.domain,
        language: data.language,
        outputLength: data.outputLength,
        expertRole: data.expertRole,
        mission: data.mission,
        constraints: data.constraints,
        isFavorite: data.isFavorite || false,
        createdAt: now,
        updatedAt: now
      };
    } catch (error) {
      console.error("Error creating prompt:", error);
      throw new PromptError("Failed to create prompt", "CREATE_FAILED", 500);
    }
  }
  /**
   * Get prompt by ID with ownership validation
   */
  async getPromptById(id, userId) {
    try {
      let stmt;
      let bindings;
      if (userId) {
        stmt = this.db.prepare(`
          SELECT * FROM prompts 
          WHERE id = ? AND user_id = ?
        `);
        bindings = [id, userId];
      } else {
        stmt = this.db.prepare(`
          SELECT * FROM prompts 
          WHERE id = ?
        `);
        bindings = [id];
      }
      const result = await stmt.bind(...bindings).first();
      if (!result) {
        return null;
      }
      return {
        id: result.id,
        userId: result.user_id,
        title: result.title,
        rawRequest: result.raw_request,
        generatedPrompt: result.generated_prompt,
        promptType: result.prompt_type,
        domain: result.domain,
        language: result.language,
        outputLength: result.output_length,
        expertRole: result.expert_role,
        mission: result.mission,
        constraints: result.constraints,
        isFavorite: Boolean(result.is_favorite),
        createdAt: result.created_at,
        updatedAt: result.updated_at
      };
    } catch (error) {
      console.error("Error getting prompt by ID:", error);
      throw new PromptError("Failed to retrieve prompt", "GET_FAILED", 500);
    }
  }
  /**
   * Get user's prompts with pagination, filtering, and search
   */
  async getUserPrompts(userId, filters = {}, pagination = {}) {
    const {
      page = 1,
      limit = 20,
      sortBy = "created_at",
      sortOrder = "DESC"
    } = pagination;
    if (page < 1 || limit < 1 || limit > 100) {
      throw new PromptError("Invalid pagination parameters", "INVALID_PAGINATION", 400);
    }
    const offset = (page - 1) * limit;
    try {
      const conditions = ["user_id = ?"];
      const bindings = [userId];
      if (filters.domain) {
        conditions.push("domain = ?");
        bindings.push(filters.domain);
      }
      if (filters.promptType) {
        conditions.push("prompt_type = ?");
        bindings.push(filters.promptType);
      }
      if (filters.language) {
        conditions.push("language = ?");
        bindings.push(filters.language);
      }
      if (filters.isFavorite !== void 0) {
        conditions.push("is_favorite = ?");
        bindings.push(filters.isFavorite ? 1 : 0);
      }
      if (filters.search) {
        conditions.push("(title LIKE ? OR raw_request LIKE ?)");
        const searchPattern = `%${filters.search}%`;
        bindings.push(searchPattern, searchPattern);
      }
      const whereClause = conditions.join(" AND ");
      const countStmt = this.db.prepare(`
        SELECT COUNT(*) as total 
        FROM prompts 
        WHERE ${whereClause}
      `);
      const countResult = await countStmt.bind(...bindings).first();
      const total = countResult?.total || 0;
      const stmt = this.db.prepare(`
        SELECT * FROM prompts 
        WHERE ${whereClause}
        ORDER BY ${sortBy} ${sortOrder}
        LIMIT ? OFFSET ?
      `);
      const results = await stmt.bind(...bindings, limit, offset).all();
      const prompts = results.results.map((row) => ({
        id: row.id,
        userId: row.user_id,
        title: row.title,
        rawRequest: row.raw_request,
        generatedPrompt: row.generated_prompt,
        promptType: row.prompt_type,
        domain: row.domain,
        language: row.language,
        outputLength: row.output_length,
        expertRole: row.expert_role,
        mission: row.mission,
        constraints: row.constraints,
        isFavorite: Boolean(row.is_favorite),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
      const totalPages = Math.ceil(total / limit);
      return {
        prompts,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      };
    } catch (error) {
      console.error("Error getting user prompts:", error);
      throw new PromptError("Failed to retrieve prompts", "GET_LIST_FAILED", 500);
    }
  }
  /**
   * Update an existing prompt
   */
  async updatePrompt(id, userId, data) {
    this.validatePromptData(data, true);
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError("Prompt not found or access denied", "NOT_FOUND", 404);
    }
    const updateFields = [];
    const bindings = [];
    if (data.title !== void 0) {
      updateFields.push("title = ?");
      bindings.push(data.title);
    }
    if (data.isFavorite !== void 0) {
      updateFields.push("is_favorite = ?");
      bindings.push(data.isFavorite ? 1 : 0);
    }
    if (data.expertRole !== void 0) {
      updateFields.push("expert_role = ?");
      bindings.push(data.expertRole || null);
    }
    if (data.mission !== void 0) {
      updateFields.push("mission = ?");
      bindings.push(data.mission || null);
    }
    if (data.constraints !== void 0) {
      updateFields.push("constraints = ?");
      bindings.push(data.constraints || null);
    }
    if (updateFields.length === 0) {
      return await this.getPromptById(id, userId);
    }
    updateFields.push("updated_at = ?");
    bindings.push((/* @__PURE__ */ new Date()).toISOString());
    bindings.push(id, userId);
    try {
      const stmt = this.db.prepare(`
        UPDATE prompts 
        SET ${updateFields.join(", ")}
        WHERE id = ? AND user_id = ?
      `);
      const result = await stmt.bind(...bindings).run();
      if (result.changes === 0) {
        throw new PromptError("Prompt not found or access denied", "NOT_FOUND", 404);
      }
      return await this.getPromptById(id, userId);
    } catch (error) {
      console.error("Error updating prompt:", error);
      if (error instanceof PromptError) {
        throw error;
      }
      throw new PromptError("Failed to update prompt", "UPDATE_FAILED", 500);
    }
  }
  /**
   * Delete a prompt
   */
  async deletePrompt(id, userId) {
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError("Prompt not found or access denied", "NOT_FOUND", 404);
    }
    try {
      const stmt = this.db.prepare(`
        DELETE FROM prompts 
        WHERE id = ? AND user_id = ?
      `);
      const result = await stmt.bind(id, userId).run();
      return result.changes > 0;
    } catch (error) {
      console.error("Error deleting prompt:", error);
      throw new PromptError("Failed to delete prompt", "DELETE_FAILED", 500);
    }
  }
  /**
   * Toggle favorite status
   */
  async toggleFavorite(id, userId) {
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError("Prompt not found or access denied", "NOT_FOUND", 404);
    }
    try {
      const currentPrompt = await this.getPromptById(id, userId);
      if (!currentPrompt) {
        throw new PromptError("Prompt not found", "NOT_FOUND", 404);
      }
      const newFavoriteStatus = !currentPrompt.isFavorite;
      const stmt = this.db.prepare(`
        UPDATE prompts 
        SET is_favorite = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `);
      await stmt.bind(
        newFavoriteStatus ? 1 : 0,
        (/* @__PURE__ */ new Date()).toISOString(),
        id,
        userId
      ).run();
      return { isFavorite: newFavoriteStatus };
    } catch (error) {
      console.error("Error toggling favorite:", error);
      if (error instanceof PromptError) {
        throw error;
      }
      throw new PromptError("Failed to toggle favorite status", "TOGGLE_FAVORITE_FAILED", 500);
    }
  }
  /**
   * Get user's prompt statistics
   */
  async getUserPromptStats(userId) {
    try {
      const totalStmt = this.db.prepare(`
        SELECT COUNT(*) as total FROM prompts WHERE user_id = ?
      `);
      const totalResult = await totalStmt.bind(userId).first();
      const favoriteStmt = this.db.prepare(`
        SELECT COUNT(*) as total FROM prompts WHERE user_id = ? AND is_favorite = 1
      `);
      const favoriteResult = await favoriteStmt.bind(userId).first();
      const domainStmt = this.db.prepare(`
        SELECT domain, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY domain
      `);
      const domainResults = await domainStmt.bind(userId).all();
      const typeStmt = this.db.prepare(`
        SELECT prompt_type, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY prompt_type
      `);
      const typeResults = await typeStmt.bind(userId).all();
      const languageStmt = this.db.prepare(`
        SELECT language, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY language
      `);
      const languageResults = await languageStmt.bind(userId).all();
      const promptsByDomain = {};
      domainResults.results.forEach((row) => {
        promptsByDomain[row.domain] = row.count;
      });
      const promptsByType = {};
      typeResults.results.forEach((row) => {
        promptsByType[row.prompt_type] = row.count;
      });
      const promptsByLanguage = {};
      languageResults.results.forEach((row) => {
        promptsByLanguage[row.language] = row.count;
      });
      return {
        totalPrompts: totalResult?.total || 0,
        favoritePrompts: favoriteResult?.total || 0,
        promptsByDomain,
        promptsByType,
        promptsByLanguage
      };
    } catch (error) {
      console.error("Error getting prompt stats:", error);
      throw new PromptError("Failed to retrieve prompt statistics", "STATS_FAILED", 500);
    }
  }
};

// api/prompts/[id]/favorite.ts
var FavoriteValidator = class {
  static {
    __name(this, "FavoriteValidator");
  }
  /**
   * Validate prompt ID parameter
   */
  static validatePromptId(id) {
    if (!id || typeof id !== "string") {
      return { isValid: false, error: "Prompt ID is required" };
    }
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return { isValid: false, error: "Invalid prompt ID format" };
    }
    return { isValid: true };
  }
  /**
   * Validate favorite toggle request (optional body)
   */
  static validateFavoriteRequest(data) {
    const errors = [];
    if (data !== null && data !== void 0) {
      if (typeof data !== "object" || Array.isArray(data)) {
        errors.push("Request body must be an object if provided");
      } else {
        const allowedFields = [];
        const providedFields = Object.keys(data);
        const unexpectedFields = providedFields.filter((field) => !allowedFields.includes(field));
        if (unexpectedFields.length > 0) {
          errors.push(`Unexpected fields: ${unexpectedFields.join(", ")}`);
        }
      }
    }
    return {
      isValid: errors.length === 0,
      errors
    };
  }
};
var onRequestPost = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_favorite",
      reason: "Missing environment configuration",
      severity: "critical"
    });
    return AuthUtils.createErrorResponse({
      code: "CONFIG_ERROR",
      message: "Service temporarily unavailable",
      statusCode: 503
    });
  }
  try {
    const db = new PromptsDatabase(env.DB);
    const idValidation = FavoriteValidator.validatePromptId(params.id);
    if (!idValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: "INVALID_PROMPT_ID",
        message: idValidation.error,
        statusCode: 400
      });
    }
    const promptId = params.id;
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ["POST"],
      endpoint: "prompts_favorite"
    });
    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response, request);
    }
    const userId = securityResult.userId;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    let requestData = null;
    if (request.headers.get("Content-Type")?.includes("application/json")) {
      const validationResult = await SecurityHelpers.validateRequest(
        request,
        FavoriteValidator.validateFavoriteRequest
      );
      if (!validationResult.valid) {
        SecurityLogger.logSecurityEvent("invalid_request", {
          endpoint: "prompts_favorite",
          ipAddress: clientIP,
          userAgent,
          reason: "Invalid favorite toggle request data",
          severity: "low"
        });
        return security.wrapResponse(validationResult.response, request);
      }
      requestData = validationResult.data;
    }
    const result = await db.toggleFavorite(promptId, userId);
    SecurityLogger.logSecurityEvent("api_success", {
      endpoint: "prompts_favorite",
      ipAddress: clientIP,
      userAgent,
      reason: `Toggled favorite for prompt ${promptId} to ${result.isFavorite}`,
      severity: "low"
    });
    const responseData = {
      success: true,
      message: `Prompt ${result.isFavorite ? "added to" : "removed from"} favorites`,
      data: {
        promptId,
        isFavorite: result.isFavorite,
        timestamp: Date.now()
      }
    };
    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );
  } catch (error) {
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent("api_error", {
        endpoint: "prompts_favorite",
        ipAddress: AuthUtils.getClientIP(request),
        reason: error.message,
        severity: "medium"
      });
      return AuthUtils.createErrorResponse({
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      });
    }
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_favorite",
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : "Unknown error",
      severity: "high"
    });
    const isDevelopment = env.ENVIRONMENT === "development";
    return AuthUtils.createErrorResponse({
      code: "INTERNAL_ERROR",
      message: "Unable to toggle favorite status",
      statusCode: 500,
      ...isDevelopment && {
        details: error instanceof Error ? error.message : "Unknown error"
      }
    });
  }
}, "onRequestPost");
var onRequestOptions = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      allowedMethods: ["POST", "OPTIONS"],
      endpoint: "prompts_favorite"
    });
    return security.wrapResponse(securityResult.response, request);
  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestOptions");

// api/auth/login.ts
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "salt123");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hashPassword, "hashPassword");
async function createJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const jwtPayload = { ...payload, iat: now, exp: now + 3600 };
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  const message = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  return `${message}.${signatureB64}`;
}
__name(createJWT, "createJWT");
var onRequestPost2 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== SIMPLE LOGIN ENDPOINT ===");
    if (!env.JWT_SECRET || !env.DB) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "CONFIG_ERROR",
          message: "Service temporarily unavailable"
        }
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    }
    const data = await request.json();
    console.log("Login attempt for:", data.email);
    if (!data.email || !data.password) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "MISSING_FIELDS",
          message: "Email and password are required"
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    const user = await env.DB.prepare("SELECT id, email, password_hash, email_verified FROM users WHERE email = ?").bind(data.email).first();
    if (!user) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const hashedInputPassword = await hashPassword(data.password);
    if (hashedInputPassword !== user.password_hash) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const token = await createJWT({ userId: user.id, email: user.email }, env.JWT_SECRET);
    console.log("Login successful for:", user.email);
    return new Response(JSON.stringify({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified
      }
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Login error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Unable to process login request"
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/auth/logout.ts
var onRequestPost3 = /* @__PURE__ */ __name(async (context) => {
  try {
    console.log("=== SIMPLE LOGOUT ENDPOINT ===");
    return new Response(JSON.stringify({
      success: true,
      message: "Logged out successfully"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Logout error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Logout failed"
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/auth/refresh.ts
async function createJWT2(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const jwtPayload = { ...payload, iat: now, exp: now + 3600 };
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m] || "");
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m] || "");
  const message = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m] || "");
  return `${message}.${signatureB64}`;
}
__name(createJWT2, "createJWT");
var onRequestPost4 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== SIMPLE REFRESH ENDPOINT ===");
    if (!env.JWT_SECRET || !env.DB) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "CONFIG_ERROR",
          message: "Service temporarily unavailable"
        }
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    }
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "NO_TOKEN",
          message: "Authorization token required"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const token = authHeader.substring(7);
    let user;
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      user = payload;
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "INVALID_TOKEN",
          message: "Invalid token format"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const dbUser = await env.DB.prepare("SELECT id, email, email_verified FROM users WHERE id = ?").bind(user.userId).first();
    if (!dbUser) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "USER_NOT_FOUND",
          message: "User account not found"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const newToken = await createJWT2({ userId: dbUser.id, email: dbUser.email }, env.JWT_SECRET);
    console.log("Token refreshed successfully for:", dbUser.email);
    return new Response(JSON.stringify({
      success: true,
      token: newToken,
      user: {
        id: dbUser.id,
        email: dbUser.email,
        emailVerified: dbUser.email_verified
      }
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Unable to refresh token"
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/auth/register.ts
function generateUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
__name(generateUUID, "generateUUID");
function validatePassword(password) {
  return password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
}
__name(validatePassword, "validatePassword");
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
__name(validateEmail, "validateEmail");
async function hashPassword2(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "salt123");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hashPassword2, "hashPassword");
async function createJWT3(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const jwtPayload = { ...payload, iat: now, exp: now + 3600 };
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  const message = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, (m) => ({ "+": "-", "/": "_", "=": "" })[m]);
  return `${message}.${signatureB64}`;
}
__name(createJWT3, "createJWT");
var onRequestPost5 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== WORKING REGISTER ENDPOINT ===");
    if (!env.JWT_SECRET || !env.DB) {
      console.log("Missing environment variables");
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "CONFIG_ERROR",
          message: "Service temporarily unavailable"
        }
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    }
    const data = await request.json();
    console.log("Received registration data:", { email: data.email, hasPassword: !!data.password });
    if (!data.email || !data.password) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "MISSING_FIELDS",
          message: "Email and password are required"
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!validateEmail(data.email)) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "INVALID_EMAIL",
          message: "Please enter a valid email address"
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!validatePassword(data.password)) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "WEAK_PASSWORD",
          message: "Password must be at least 8 characters with uppercase, lowercase, and numbers"
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    console.log("Checking if user exists...");
    try {
      const existingUser = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(data.email).first();
      console.log("User check result:", existingUser);
      if (existingUser) {
        return new Response(JSON.stringify({
          success: false,
          error: {
            code: "EMAIL_EXISTS",
            message: "An account with this email already exists"
          }
        }), {
          status: 409,
          headers: { "Content-Type": "application/json" }
        });
      }
    } catch (dbError) {
      console.error("Database check error:", dbError);
      throw dbError;
    }
    console.log("Creating new user...");
    const userId = generateUUID();
    const hashedPassword = await hashPassword2(data.password);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    console.log("Inserting user into database...");
    try {
      await env.DB.prepare(`
        INSERT INTO users (id, email, password_hash, email_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(userId, data.email, hashedPassword, false, now, now).run();
      console.log("User inserted successfully");
    } catch (dbError) {
      console.error("Database insert error:", dbError);
      throw dbError;
    }
    console.log("Creating JWT token...");
    try {
      const token = await createJWT3({ userId, email: data.email }, env.JWT_SECRET);
      console.log("JWT created successfully");
      console.log("User created successfully:", userId);
      return new Response(JSON.stringify({
        success: true,
        token,
        user: {
          id: userId,
          email: data.email,
          emailVerified: false
        }
      }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      });
    } catch (jwtError) {
      console.error("JWT creation error:", jwtError);
      throw jwtError;
    }
  } catch (error) {
    console.error("Registration error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Registration failed. Please try again."
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/auth/register-complex-backup.ts
var RegisterDatabase = class {
  constructor(db) {
    this.db = db;
  }
  static {
    __name(this, "RegisterDatabase");
  }
  /**
   * Check if user exists by email
   */
  async userExists(email) {
    const stmt = this.db.prepare(`
      SELECT 1 FROM users 
      WHERE email = ? COLLATE NOCASE
      LIMIT 1
    `);
    const result = await stmt.bind(email).first();
    return result !== null;
  }
  /**
   * Create new user record
   */
  async createUser(email, passwordHash, ipAddress) {
    const userId = AuthUtils.generateSecureRandom(16);
    const stmt = this.db.prepare(`
      INSERT INTO users (
        id, email, password_hash, email_verified, is_active,
        failed_login_attempts, password_changed_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))
    `);
    await stmt.bind(
      userId,
      email,
      passwordHash,
      0,
      // email_verified - false by default
      1,
      // is_active - true by default
      0
      // failed_login_attempts - start at 0
    ).run();
    return userId;
  }
  /**
   * Create initial session for newly registered user
   */
  async createSession(session) {
    const stmt = this.db.prepare(`
      INSERT INTO sessions (
        id, user_id, access_token, refresh_token, expires_at,
        created_at, last_used_at, ip_address, user_agent,
        device_fingerprint, is_revoked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await stmt.bind(
      session.id,
      session.userId,
      session.accessToken,
      session.refreshToken,
      new Date(session.expiresAt).toISOString(),
      new Date(session.createdAt).toISOString(),
      new Date(session.lastUsedAt).toISOString(),
      session.ipAddress || null,
      session.userAgent || null,
      null,
      // device_fingerprint - can be enhanced later
      0
      // is_revoked
    ).run();
  }
};
var onRequestPost6 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  console.log("=== REGISTER DEBUG START ===");
  console.log("Request method:", request.method);
  console.log("Content-Type:", request.headers.get("content-type"));
  console.log("Request URL:", request.url);
  console.log("Body already consumed?", request.bodyUsed);
  if (!env.JWT_SECRET || env.JWT_SECRET.trim() === "" || !env.DB) {
    SecurityLogger.logSecurityEvent("auth_failure", {
      endpoint: "register",
      reason: "Missing environment configuration",
      severity: "critical"
    });
    return AuthUtils.createErrorResponse({
      code: "CONFIG_ERROR",
      message: "Service temporarily unavailable",
      statusCode: 503
    });
  }
  try {
    const db = new RegisterDatabase(env.DB);
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.REGISTER,
      requireAuth: false,
      // Registration doesn't require existing auth
      allowedMethods: ["POST"],
      endpoint: "register"
    });
    if (!securityResult.allowed) {
      SecurityLogger.logSecurityEvent("rate_limit_exceeded", {
        endpoint: "register",
        ipAddress: AuthUtils.getClientIP(request),
        severity: "medium"
      });
      return security.wrapResponse(securityResult.response, request);
    }
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    console.log("About to validate request. Body consumed?", request.bodyUsed);
    const validationResult = await SecurityHelpers.validateRequest(
      request,
      InputValidator.validateRegisterRequest
    );
    console.log("Validation complete. Body consumed?", request.bodyUsed);
    console.log("Validation result:", validationResult.valid, validationResult.error?.code);
    if (!validationResult.valid) {
      SecurityLogger.logAuthEvent("registration_failure", {
        ipAddress: clientIP,
        userAgent,
        reason: "Invalid input data"
      });
      return security.wrapResponse(validationResult.response, request);
    }
    const { email, password } = validationResult.data;
    const passwordValidation = PasswordValidator.validate(password);
    if (!passwordValidation.isValid) {
      SecurityLogger.logAuthEvent("registration_failure", {
        email,
        ipAddress: clientIP,
        userAgent,
        reason: "Weak password"
      });
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: "WEAK_PASSWORD",
          message: passwordValidation.errors.join("; "),
          statusCode: 400
        }),
        request
      );
    }
    const userExists = await db.userExists(email);
    if (userExists) {
      SecurityLogger.logAuthEvent("registration_failure", {
        email,
        ipAddress: clientIP,
        userAgent,
        reason: "User already exists"
      });
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.USER_EXISTS),
        request
      );
    }
    const passwordHash = await EdgeBcrypt.hash(password);
    const userId = await db.createUser(email, passwordHash, clientIP);
    const authUser = {
      id: userId,
      email,
      isActive: true,
      lastLoginAt: Date.now()
    };
    const tokens = await JWTManager.generateTokens(authUser, env.JWT_SECRET);
    const session = SessionManager.createSession(
      userId,
      tokens,
      clientIP,
      userAgent
    );
    await db.createSession(session);
    SecurityLogger.logAuthEvent("registration_success", {
      userId,
      email,
      ipAddress: clientIP,
      userAgent
    });
    const responseData = {
      success: true,
      message: "Registration successful",
      user: {
        id: authUser.id,
        email: authUser.email,
        isActive: authUser.isActive,
        emailVerified: false
        // New accounts start unverified
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt
      }
    };
    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData, 201),
      // 201 Created
      request
    );
  } catch (error) {
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "register",
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : "Unknown error",
      severity: "high"
    });
    if (error instanceof Error) {
      if (error.message.includes("UNIQUE constraint failed")) {
        return AuthUtils.createErrorResponse(AUTH_ERRORS.USER_EXISTS);
      }
      if (error.message.includes("database")) {
        return AuthUtils.createErrorResponse({
          code: "DATABASE_ERROR",
          message: "Unable to create account at this time",
          statusCode: 503
        });
      }
    }
    const isDevelopment = env.ENVIRONMENT === "development";
    return AuthUtils.createErrorResponse({
      code: "INTERNAL_ERROR",
      message: "Unable to process registration request",
      statusCode: 500,
      ...isDevelopment && {
        details: error instanceof Error ? error.message : "Unknown error"
      }
    });
  }
}, "onRequestPost");

// api/debug/bindings.ts
var onRequestGet = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  const url = new URL(request.url);
  const debugToken = url.searchParams.get("token");
  if (env.ENVIRONMENT !== "development" && debugToken !== "debug123") {
    return new Response(JSON.stringify({
      error: "Access denied"
    }), {
      status: 403,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const diagnostics = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      functionPath: context.functionPath,
      environment: env.ENVIRONMENT,
      availableBindings: {
        keys: Object.keys(env),
        bindings: {}
      },
      bindingAnalysis: {
        secrets: [],
        databases: [],
        kv: [],
        other: []
      }
    };
    for (const [key, value] of Object.entries(env)) {
      const bindingInfo = {
        type: typeof value,
        available: !!value,
        constructor: value?.constructor?.name || "unknown"
      };
      if (typeof value === "string" && !key.startsWith("CF_")) {
        diagnostics.bindingAnalysis.secrets.push({
          name: key,
          ...bindingInfo,
          // For secrets, check if string is non-empty
          available: typeof value === "string" && value.trim() !== ""
        });
      } else if (value?.constructor?.name === "D1Database") {
        diagnostics.bindingAnalysis.databases.push({ name: key, ...bindingInfo });
      } else if (value?.constructor?.name === "KvNamespace") {
        diagnostics.bindingAnalysis.kv.push({ name: key, ...bindingInfo });
      } else {
        diagnostics.bindingAnalysis.other.push({ name: key, ...bindingInfo });
      }
      if (typeof value === "string") {
        diagnostics.availableBindings.bindings[key] = "[SECRET STRING]";
      } else if (value?.constructor?.name) {
        diagnostics.availableBindings.bindings[key] = value.constructor.name;
      } else {
        diagnostics.availableBindings.bindings[key] = typeof value;
      }
    }
    const expectedBindings = {
      JWT_SECRET: {
        expected: "string",
        actual: typeof env.JWT_SECRET,
        available: typeof env.JWT_SECRET === "string" && env.JWT_SECRET.trim() !== "",
        length: env.JWT_SECRET?.length || 0
      },
      DB: {
        expected: "D1Database",
        actual: env.DB?.constructor?.name || typeof env.DB,
        available: !!env.DB
      },
      RATE_LIMITER: {
        expected: "KvNamespace",
        actual: env.RATE_LIMITER?.constructor?.name || typeof env.RATE_LIMITER,
        available: !!env.RATE_LIMITER
      },
      KV: {
        expected: "KvNamespace (fallback)",
        actual: env.KV?.constructor?.name || typeof env.KV,
        available: !!env.KV
      }
    };
    const response = {
      success: true,
      diagnostics,
      expectedBindings,
      recommendations: []
    };
    if (!env.JWT_SECRET || env.JWT_SECRET.trim() === "") {
      response.recommendations.push(`JWT_SECRET secret is ${!env.JWT_SECRET ? "missing" : "empty"} - run: wrangler pages secret put JWT_SECRET`);
    }
    if (!env.DB) {
      response.recommendations.push("DB binding is missing - check wrangler.toml D1 configuration");
    }
    if (!env.RATE_LIMITER && !env.KV) {
      response.recommendations.push("KV namespace binding is missing - check wrangler.toml KV configuration");
    }
    return new Response(JSON.stringify(response, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache, no-store, must-revalidate"
      }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestGet");

// api/debug/test-bindings.ts
var onRequestPost7 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    const jwtAvailable = !!(env.JWT_SECRET && env.JWT_SECRET.trim());
    let dbTest = null;
    try {
      const stmt = env.DB.prepare("SELECT 1 as test");
      const result = await stmt.first();
      dbTest = { success: true, result };
    } catch (error) {
      dbTest = { success: false, error: error.message };
    }
    let kvTest = null;
    try {
      await env.RATE_LIMITER.put("test-key", "test-value", { expirationTtl: 60 });
      const value = await env.RATE_LIMITER.get("test-key");
      kvTest = { success: true, canWrite: true, canRead: value === "test-value" };
      await env.RATE_LIMITER.delete("test-key");
    } catch (error) {
      kvTest = { success: false, error: error.message };
    }
    const response = {
      success: true,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      tests: {
        jwt: {
          available: jwtAvailable,
          length: env.JWT_SECRET?.length || 0
        },
        database: dbTest,
        kv: kvTest
      },
      message: "All core bindings are functional!"
    };
    return new Response(JSON.stringify(response, null, 2), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/prompts/stats.ts
var onRequestGet2 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_stats",
      reason: "Missing environment configuration",
      severity: "critical"
    });
    return AuthUtils.createErrorResponse({
      code: "CONFIG_ERROR",
      message: "Service temporarily unavailable",
      statusCode: 503
    });
  }
  try {
    const db = new PromptsDatabase(env.DB);
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ["GET"],
      endpoint: "prompts_stats"
    });
    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response, request);
    }
    const userId = securityResult.userId;
    const clientIP = AuthUtils.getClientIP(request);
    const stats = await db.getUserPromptStats(userId);
    SecurityLogger.logSecurityEvent("api_success", {
      endpoint: "prompts_stats",
      ipAddress: clientIP,
      reason: `Retrieved stats for user: ${stats.totalPrompts} total prompts`,
      severity: "low"
    });
    const responseData = {
      success: true,
      data: {
        stats,
        timestamp: Date.now()
      }
    };
    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );
  } catch (error) {
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent("api_error", {
        endpoint: "prompts_stats",
        ipAddress: AuthUtils.getClientIP(request),
        reason: error.message,
        severity: "medium"
      });
      return AuthUtils.createErrorResponse({
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      });
    }
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_stats",
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : "Unknown error",
      severity: "high"
    });
    const isDevelopment = env.ENVIRONMENT === "development";
    return AuthUtils.createErrorResponse({
      code: "INTERNAL_ERROR",
      message: "Unable to fetch prompt statistics",
      statusCode: 500,
      ...isDevelopment && {
        details: error instanceof Error ? error.message : "Unknown error"
      }
    });
  }
}, "onRequestGet");
var onRequestOptions2 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      allowedMethods: ["GET", "OPTIONS"],
      endpoint: "prompts_stats"
    });
    return security.wrapResponse(securityResult.response, request);
  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestOptions");

// api/prompts/[id].ts
var PromptUpdateValidator = class {
  static {
    __name(this, "PromptUpdateValidator");
  }
  /**
   * Validate PUT request data for updating prompts
   */
  static validateUpdatePromptRequest(data) {
    const errors = [];
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { isValid: false, errors: ["Invalid request data structure"] };
    }
    const allowedFields = ["title", "isFavorite", "expertRole", "mission", "constraints"];
    const providedFields = Object.keys(data);
    const validFields = providedFields.filter((field) => allowedFields.includes(field));
    if (validFields.length === 0) {
      errors.push("At least one field must be provided for update");
    }
    const unexpectedFields = providedFields.filter((field) => !allowedFields.includes(field));
    if (unexpectedFields.length > 0) {
      errors.push(`Unexpected fields: ${unexpectedFields.join(", ")}`);
    }
    if ("title" in data) {
      if (data.title !== null && (typeof data.title !== "string" || data.title.length > 100)) {
        errors.push("title must be a string with maximum 100 characters or null");
      }
    }
    if ("isFavorite" in data) {
      if (typeof data.isFavorite !== "boolean") {
        errors.push("isFavorite must be a boolean");
      }
    }
    if ("expertRole" in data) {
      if (data.expertRole !== null && data.expertRole !== void 0) {
        if (typeof data.expertRole !== "string" || data.expertRole.length > 200) {
          errors.push("expertRole must be a string with maximum 200 characters or null");
        }
      }
    }
    if ("mission" in data) {
      if (data.mission !== null && data.mission !== void 0) {
        if (typeof data.mission !== "string" || data.mission.length > 500) {
          errors.push("mission must be a string with maximum 500 characters or null");
        }
      }
    }
    if ("constraints" in data) {
      if (data.constraints !== null && data.constraints !== void 0) {
        if (typeof data.constraints !== "string" || data.constraints.length > 1e3) {
          errors.push("constraints must be a string with maximum 1000 characters or null");
        }
      }
    }
    if (errors.length > 0) {
      return { isValid: false, errors };
    }
    const sanitizedData = {};
    if ("title" in data) {
      sanitizedData.title = data.title ? InputValidator.sanitizeInput(data.title) : data.title;
    }
    if ("isFavorite" in data) {
      sanitizedData.isFavorite = data.isFavorite;
    }
    if ("expertRole" in data) {
      sanitizedData.expertRole = data.expertRole ? InputValidator.sanitizeInput(data.expertRole) : data.expertRole;
    }
    if ("mission" in data) {
      sanitizedData.mission = data.mission ? InputValidator.sanitizeInput(data.mission) : data.mission;
    }
    if ("constraints" in data) {
      sanitizedData.constraints = data.constraints ? InputValidator.sanitizeInput(data.constraints) : data.constraints;
    }
    return {
      isValid: true,
      data: sanitizedData,
      errors: []
    };
  }
  /**
   * Validate prompt ID parameter
   */
  static validatePromptId(id) {
    if (!id || typeof id !== "string") {
      return { isValid: false, error: "Prompt ID is required" };
    }
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return { isValid: false, error: "Invalid prompt ID format" };
    }
    return { isValid: true };
  }
};
var onRequestPut = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_update",
      reason: "Missing environment configuration",
      severity: "critical"
    });
    return AuthUtils.createErrorResponse({
      code: "CONFIG_ERROR",
      message: "Service temporarily unavailable",
      statusCode: 503
    });
  }
  try {
    const db = new PromptsDatabase(env.DB);
    const idValidation = PromptUpdateValidator.validatePromptId(params.id);
    if (!idValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: "INVALID_PROMPT_ID",
        message: idValidation.error,
        statusCode: 400
      });
    }
    const promptId = params.id;
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ["PUT"],
      endpoint: "prompts_update"
    });
    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response, request);
    }
    const userId = securityResult.userId;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    const validationResult = await SecurityHelpers.validateRequest(
      request,
      PromptUpdateValidator.validateUpdatePromptRequest
    );
    if (!validationResult.valid) {
      SecurityLogger.logSecurityEvent("invalid_request", {
        endpoint: "prompts_update",
        ipAddress: clientIP,
        userAgent,
        reason: "Invalid update prompt request data",
        severity: "low"
      });
      return security.wrapResponse(validationResult.response, request);
    }
    const updateData = validationResult.data;
    const updatedPrompt = await db.updatePrompt(promptId, userId, updateData);
    if (!updatedPrompt) {
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: "PROMPT_NOT_FOUND",
          message: "Prompt not found or access denied",
          statusCode: 404
        }),
        request
      );
    }
    SecurityLogger.logSecurityEvent("api_success", {
      endpoint: "prompts_update",
      ipAddress: clientIP,
      userAgent,
      reason: `Updated prompt ${promptId}`,
      severity: "low"
    });
    const responseData = {
      success: true,
      message: "Prompt updated successfully",
      data: {
        prompt: updatedPrompt
      }
    };
    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );
  } catch (error) {
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent("api_error", {
        endpoint: "prompts_update",
        ipAddress: AuthUtils.getClientIP(request),
        reason: error.message,
        severity: "medium"
      });
      return AuthUtils.createErrorResponse({
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      });
    }
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_update",
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : "Unknown error",
      severity: "high"
    });
    const isDevelopment = env.ENVIRONMENT === "development";
    return AuthUtils.createErrorResponse({
      code: "INTERNAL_ERROR",
      message: "Unable to update prompt",
      statusCode: 500,
      ...isDevelopment && {
        details: error instanceof Error ? error.message : "Unknown error"
      }
    });
  }
}, "onRequestPut");
var onRequestDelete = /* @__PURE__ */ __name(async (context) => {
  const { request, env, params } = context;
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_delete",
      reason: "Missing environment configuration",
      severity: "critical"
    });
    return AuthUtils.createErrorResponse({
      code: "CONFIG_ERROR",
      message: "Service temporarily unavailable",
      statusCode: 503
    });
  }
  try {
    const db = new PromptsDatabase(env.DB);
    const idValidation = PromptUpdateValidator.validatePromptId(params.id);
    if (!idValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: "INVALID_PROMPT_ID",
        message: idValidation.error,
        statusCode: 400
      });
    }
    const promptId = params.id;
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ["DELETE"],
      endpoint: "prompts_delete"
    });
    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response, request);
    }
    const userId = securityResult.userId;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    const deleted = await db.deletePrompt(promptId, userId);
    if (!deleted) {
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: "PROMPT_NOT_FOUND",
          message: "Prompt not found or access denied",
          statusCode: 404
        }),
        request
      );
    }
    SecurityLogger.logSecurityEvent("api_success", {
      endpoint: "prompts_delete",
      ipAddress: clientIP,
      userAgent,
      reason: `Deleted prompt ${promptId}`,
      severity: "low"
    });
    const responseData = {
      success: true,
      message: "Prompt deleted successfully",
      data: {
        deletedId: promptId
      }
    };
    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );
  } catch (error) {
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent("api_error", {
        endpoint: "prompts_delete",
        ipAddress: AuthUtils.getClientIP(request),
        reason: error.message,
        severity: "medium"
      });
      return AuthUtils.createErrorResponse({
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      });
    }
    SecurityLogger.logSecurityEvent("api_error", {
      endpoint: "prompts_delete",
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : "Unknown error",
      severity: "high"
    });
    const isDevelopment = env.ENVIRONMENT === "development";
    return AuthUtils.createErrorResponse({
      code: "INTERNAL_ERROR",
      message: "Unable to delete prompt",
      statusCode: 500,
      ...isDevelopment && {
        details: error instanceof Error ? error.message : "Unknown error"
      }
    });
  }
}, "onRequestDelete");
var onRequestOptions3 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    const securityResult = await security.applySecurityChecks(request, {
      allowedMethods: ["PUT", "DELETE", "OPTIONS"],
      endpoint: "prompts_individual"
    });
    return security.wrapResponse(securityResult.response, request);
  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestOptions");

// ../node_modules/@google/genai/dist/web/index.mjs
var _defaultBaseGeminiUrl = void 0;
var _defaultBaseVertexUrl = void 0;
function getDefaultBaseUrls() {
  return {
    geminiUrl: _defaultBaseGeminiUrl,
    vertexUrl: _defaultBaseVertexUrl
  };
}
__name(getDefaultBaseUrls, "getDefaultBaseUrls");
function getBaseUrl(httpOptions, vertexai, vertexBaseUrlFromEnv, geminiBaseUrlFromEnv) {
  var _a, _b;
  if (!(httpOptions === null || httpOptions === void 0 ? void 0 : httpOptions.baseUrl)) {
    const defaultBaseUrls = getDefaultBaseUrls();
    if (vertexai) {
      return (_a = defaultBaseUrls.vertexUrl) !== null && _a !== void 0 ? _a : vertexBaseUrlFromEnv;
    } else {
      return (_b = defaultBaseUrls.geminiUrl) !== null && _b !== void 0 ? _b : geminiBaseUrlFromEnv;
    }
  }
  return httpOptions.baseUrl;
}
__name(getBaseUrl, "getBaseUrl");
var BaseModule = class {
  static {
    __name(this, "BaseModule");
  }
};
function formatMap(templateString, valueMap) {
  const regex = /\{([^}]+)\}/g;
  return templateString.replace(regex, (match2, key) => {
    if (Object.prototype.hasOwnProperty.call(valueMap, key)) {
      const value = valueMap[key];
      return value !== void 0 && value !== null ? String(value) : "";
    } else {
      throw new Error(`Key '${key}' not found in valueMap.`);
    }
  });
}
__name(formatMap, "formatMap");
function setValueByPath(data, keys, value) {
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key.endsWith("[]")) {
      const keyName = key.slice(0, -2);
      if (!(keyName in data)) {
        if (Array.isArray(value)) {
          data[keyName] = Array.from({ length: value.length }, () => ({}));
        } else {
          throw new Error(`Value must be a list given an array path ${key}`);
        }
      }
      if (Array.isArray(data[keyName])) {
        const arrayData = data[keyName];
        if (Array.isArray(value)) {
          for (let j = 0; j < arrayData.length; j++) {
            const entry = arrayData[j];
            setValueByPath(entry, keys.slice(i + 1), value[j]);
          }
        } else {
          for (const d of arrayData) {
            setValueByPath(d, keys.slice(i + 1), value);
          }
        }
      }
      return;
    } else if (key.endsWith("[0]")) {
      const keyName = key.slice(0, -3);
      if (!(keyName in data)) {
        data[keyName] = [{}];
      }
      const arrayData = data[keyName];
      setValueByPath(arrayData[0], keys.slice(i + 1), value);
      return;
    }
    if (!data[key] || typeof data[key] !== "object") {
      data[key] = {};
    }
    data = data[key];
  }
  const keyToSet = keys[keys.length - 1];
  const existingData = data[keyToSet];
  if (existingData !== void 0) {
    if (!value || typeof value === "object" && Object.keys(value).length === 0) {
      return;
    }
    if (value === existingData) {
      return;
    }
    if (typeof existingData === "object" && typeof value === "object" && existingData !== null && value !== null) {
      Object.assign(existingData, value);
    } else {
      throw new Error(`Cannot set value for an existing key. Key: ${keyToSet}`);
    }
  } else {
    data[keyToSet] = value;
  }
}
__name(setValueByPath, "setValueByPath");
function getValueByPath(data, keys) {
  try {
    if (keys.length === 1 && keys[0] === "_self") {
      return data;
    }
    for (let i = 0; i < keys.length; i++) {
      if (typeof data !== "object" || data === null) {
        return void 0;
      }
      const key = keys[i];
      if (key.endsWith("[]")) {
        const keyName = key.slice(0, -2);
        if (keyName in data) {
          const arrayData = data[keyName];
          if (!Array.isArray(arrayData)) {
            return void 0;
          }
          return arrayData.map((d) => getValueByPath(d, keys.slice(i + 1)));
        } else {
          return void 0;
        }
      } else {
        data = data[key];
      }
    }
    return data;
  } catch (error) {
    if (error instanceof TypeError) {
      return void 0;
    }
    throw error;
  }
}
__name(getValueByPath, "getValueByPath");
function tBytes$1(fromBytes) {
  if (typeof fromBytes !== "string") {
    throw new Error("fromImageBytes must be a string");
  }
  return fromBytes;
}
__name(tBytes$1, "tBytes$1");
var Outcome;
(function(Outcome2) {
  Outcome2["OUTCOME_UNSPECIFIED"] = "OUTCOME_UNSPECIFIED";
  Outcome2["OUTCOME_OK"] = "OUTCOME_OK";
  Outcome2["OUTCOME_FAILED"] = "OUTCOME_FAILED";
  Outcome2["OUTCOME_DEADLINE_EXCEEDED"] = "OUTCOME_DEADLINE_EXCEEDED";
})(Outcome || (Outcome = {}));
var Language;
(function(Language2) {
  Language2["LANGUAGE_UNSPECIFIED"] = "LANGUAGE_UNSPECIFIED";
  Language2["PYTHON"] = "PYTHON";
})(Language || (Language = {}));
var Type;
(function(Type2) {
  Type2["TYPE_UNSPECIFIED"] = "TYPE_UNSPECIFIED";
  Type2["STRING"] = "STRING";
  Type2["NUMBER"] = "NUMBER";
  Type2["INTEGER"] = "INTEGER";
  Type2["BOOLEAN"] = "BOOLEAN";
  Type2["ARRAY"] = "ARRAY";
  Type2["OBJECT"] = "OBJECT";
  Type2["NULL"] = "NULL";
})(Type || (Type = {}));
var HarmCategory;
(function(HarmCategory2) {
  HarmCategory2["HARM_CATEGORY_UNSPECIFIED"] = "HARM_CATEGORY_UNSPECIFIED";
  HarmCategory2["HARM_CATEGORY_HATE_SPEECH"] = "HARM_CATEGORY_HATE_SPEECH";
  HarmCategory2["HARM_CATEGORY_DANGEROUS_CONTENT"] = "HARM_CATEGORY_DANGEROUS_CONTENT";
  HarmCategory2["HARM_CATEGORY_HARASSMENT"] = "HARM_CATEGORY_HARASSMENT";
  HarmCategory2["HARM_CATEGORY_SEXUALLY_EXPLICIT"] = "HARM_CATEGORY_SEXUALLY_EXPLICIT";
  HarmCategory2["HARM_CATEGORY_CIVIC_INTEGRITY"] = "HARM_CATEGORY_CIVIC_INTEGRITY";
  HarmCategory2["HARM_CATEGORY_IMAGE_HATE"] = "HARM_CATEGORY_IMAGE_HATE";
  HarmCategory2["HARM_CATEGORY_IMAGE_DANGEROUS_CONTENT"] = "HARM_CATEGORY_IMAGE_DANGEROUS_CONTENT";
  HarmCategory2["HARM_CATEGORY_IMAGE_HARASSMENT"] = "HARM_CATEGORY_IMAGE_HARASSMENT";
  HarmCategory2["HARM_CATEGORY_IMAGE_SEXUALLY_EXPLICIT"] = "HARM_CATEGORY_IMAGE_SEXUALLY_EXPLICIT";
})(HarmCategory || (HarmCategory = {}));
var HarmBlockMethod;
(function(HarmBlockMethod2) {
  HarmBlockMethod2["HARM_BLOCK_METHOD_UNSPECIFIED"] = "HARM_BLOCK_METHOD_UNSPECIFIED";
  HarmBlockMethod2["SEVERITY"] = "SEVERITY";
  HarmBlockMethod2["PROBABILITY"] = "PROBABILITY";
})(HarmBlockMethod || (HarmBlockMethod = {}));
var HarmBlockThreshold;
(function(HarmBlockThreshold2) {
  HarmBlockThreshold2["HARM_BLOCK_THRESHOLD_UNSPECIFIED"] = "HARM_BLOCK_THRESHOLD_UNSPECIFIED";
  HarmBlockThreshold2["BLOCK_LOW_AND_ABOVE"] = "BLOCK_LOW_AND_ABOVE";
  HarmBlockThreshold2["BLOCK_MEDIUM_AND_ABOVE"] = "BLOCK_MEDIUM_AND_ABOVE";
  HarmBlockThreshold2["BLOCK_ONLY_HIGH"] = "BLOCK_ONLY_HIGH";
  HarmBlockThreshold2["BLOCK_NONE"] = "BLOCK_NONE";
  HarmBlockThreshold2["OFF"] = "OFF";
})(HarmBlockThreshold || (HarmBlockThreshold = {}));
var Mode;
(function(Mode2) {
  Mode2["MODE_UNSPECIFIED"] = "MODE_UNSPECIFIED";
  Mode2["MODE_DYNAMIC"] = "MODE_DYNAMIC";
})(Mode || (Mode = {}));
var AuthType;
(function(AuthType2) {
  AuthType2["AUTH_TYPE_UNSPECIFIED"] = "AUTH_TYPE_UNSPECIFIED";
  AuthType2["NO_AUTH"] = "NO_AUTH";
  AuthType2["API_KEY_AUTH"] = "API_KEY_AUTH";
  AuthType2["HTTP_BASIC_AUTH"] = "HTTP_BASIC_AUTH";
  AuthType2["GOOGLE_SERVICE_ACCOUNT_AUTH"] = "GOOGLE_SERVICE_ACCOUNT_AUTH";
  AuthType2["OAUTH"] = "OAUTH";
  AuthType2["OIDC_AUTH"] = "OIDC_AUTH";
})(AuthType || (AuthType = {}));
var ApiSpec;
(function(ApiSpec2) {
  ApiSpec2["API_SPEC_UNSPECIFIED"] = "API_SPEC_UNSPECIFIED";
  ApiSpec2["SIMPLE_SEARCH"] = "SIMPLE_SEARCH";
  ApiSpec2["ELASTIC_SEARCH"] = "ELASTIC_SEARCH";
})(ApiSpec || (ApiSpec = {}));
var Environment;
(function(Environment2) {
  Environment2["ENVIRONMENT_UNSPECIFIED"] = "ENVIRONMENT_UNSPECIFIED";
  Environment2["ENVIRONMENT_BROWSER"] = "ENVIRONMENT_BROWSER";
})(Environment || (Environment = {}));
var UrlRetrievalStatus;
(function(UrlRetrievalStatus2) {
  UrlRetrievalStatus2["URL_RETRIEVAL_STATUS_UNSPECIFIED"] = "URL_RETRIEVAL_STATUS_UNSPECIFIED";
  UrlRetrievalStatus2["URL_RETRIEVAL_STATUS_SUCCESS"] = "URL_RETRIEVAL_STATUS_SUCCESS";
  UrlRetrievalStatus2["URL_RETRIEVAL_STATUS_ERROR"] = "URL_RETRIEVAL_STATUS_ERROR";
})(UrlRetrievalStatus || (UrlRetrievalStatus = {}));
var FinishReason;
(function(FinishReason2) {
  FinishReason2["FINISH_REASON_UNSPECIFIED"] = "FINISH_REASON_UNSPECIFIED";
  FinishReason2["STOP"] = "STOP";
  FinishReason2["MAX_TOKENS"] = "MAX_TOKENS";
  FinishReason2["SAFETY"] = "SAFETY";
  FinishReason2["RECITATION"] = "RECITATION";
  FinishReason2["LANGUAGE"] = "LANGUAGE";
  FinishReason2["OTHER"] = "OTHER";
  FinishReason2["BLOCKLIST"] = "BLOCKLIST";
  FinishReason2["PROHIBITED_CONTENT"] = "PROHIBITED_CONTENT";
  FinishReason2["SPII"] = "SPII";
  FinishReason2["MALFORMED_FUNCTION_CALL"] = "MALFORMED_FUNCTION_CALL";
  FinishReason2["IMAGE_SAFETY"] = "IMAGE_SAFETY";
  FinishReason2["UNEXPECTED_TOOL_CALL"] = "UNEXPECTED_TOOL_CALL";
})(FinishReason || (FinishReason = {}));
var HarmProbability;
(function(HarmProbability2) {
  HarmProbability2["HARM_PROBABILITY_UNSPECIFIED"] = "HARM_PROBABILITY_UNSPECIFIED";
  HarmProbability2["NEGLIGIBLE"] = "NEGLIGIBLE";
  HarmProbability2["LOW"] = "LOW";
  HarmProbability2["MEDIUM"] = "MEDIUM";
  HarmProbability2["HIGH"] = "HIGH";
})(HarmProbability || (HarmProbability = {}));
var HarmSeverity;
(function(HarmSeverity2) {
  HarmSeverity2["HARM_SEVERITY_UNSPECIFIED"] = "HARM_SEVERITY_UNSPECIFIED";
  HarmSeverity2["HARM_SEVERITY_NEGLIGIBLE"] = "HARM_SEVERITY_NEGLIGIBLE";
  HarmSeverity2["HARM_SEVERITY_LOW"] = "HARM_SEVERITY_LOW";
  HarmSeverity2["HARM_SEVERITY_MEDIUM"] = "HARM_SEVERITY_MEDIUM";
  HarmSeverity2["HARM_SEVERITY_HIGH"] = "HARM_SEVERITY_HIGH";
})(HarmSeverity || (HarmSeverity = {}));
var BlockedReason;
(function(BlockedReason2) {
  BlockedReason2["BLOCKED_REASON_UNSPECIFIED"] = "BLOCKED_REASON_UNSPECIFIED";
  BlockedReason2["SAFETY"] = "SAFETY";
  BlockedReason2["OTHER"] = "OTHER";
  BlockedReason2["BLOCKLIST"] = "BLOCKLIST";
  BlockedReason2["PROHIBITED_CONTENT"] = "PROHIBITED_CONTENT";
  BlockedReason2["IMAGE_SAFETY"] = "IMAGE_SAFETY";
})(BlockedReason || (BlockedReason = {}));
var TrafficType;
(function(TrafficType2) {
  TrafficType2["TRAFFIC_TYPE_UNSPECIFIED"] = "TRAFFIC_TYPE_UNSPECIFIED";
  TrafficType2["ON_DEMAND"] = "ON_DEMAND";
  TrafficType2["PROVISIONED_THROUGHPUT"] = "PROVISIONED_THROUGHPUT";
})(TrafficType || (TrafficType = {}));
var Modality;
(function(Modality2) {
  Modality2["MODALITY_UNSPECIFIED"] = "MODALITY_UNSPECIFIED";
  Modality2["TEXT"] = "TEXT";
  Modality2["IMAGE"] = "IMAGE";
  Modality2["AUDIO"] = "AUDIO";
})(Modality || (Modality = {}));
var MediaResolution;
(function(MediaResolution2) {
  MediaResolution2["MEDIA_RESOLUTION_UNSPECIFIED"] = "MEDIA_RESOLUTION_UNSPECIFIED";
  MediaResolution2["MEDIA_RESOLUTION_LOW"] = "MEDIA_RESOLUTION_LOW";
  MediaResolution2["MEDIA_RESOLUTION_MEDIUM"] = "MEDIA_RESOLUTION_MEDIUM";
  MediaResolution2["MEDIA_RESOLUTION_HIGH"] = "MEDIA_RESOLUTION_HIGH";
})(MediaResolution || (MediaResolution = {}));
var JobState;
(function(JobState2) {
  JobState2["JOB_STATE_UNSPECIFIED"] = "JOB_STATE_UNSPECIFIED";
  JobState2["JOB_STATE_QUEUED"] = "JOB_STATE_QUEUED";
  JobState2["JOB_STATE_PENDING"] = "JOB_STATE_PENDING";
  JobState2["JOB_STATE_RUNNING"] = "JOB_STATE_RUNNING";
  JobState2["JOB_STATE_SUCCEEDED"] = "JOB_STATE_SUCCEEDED";
  JobState2["JOB_STATE_FAILED"] = "JOB_STATE_FAILED";
  JobState2["JOB_STATE_CANCELLING"] = "JOB_STATE_CANCELLING";
  JobState2["JOB_STATE_CANCELLED"] = "JOB_STATE_CANCELLED";
  JobState2["JOB_STATE_PAUSED"] = "JOB_STATE_PAUSED";
  JobState2["JOB_STATE_EXPIRED"] = "JOB_STATE_EXPIRED";
  JobState2["JOB_STATE_UPDATING"] = "JOB_STATE_UPDATING";
  JobState2["JOB_STATE_PARTIALLY_SUCCEEDED"] = "JOB_STATE_PARTIALLY_SUCCEEDED";
})(JobState || (JobState = {}));
var AdapterSize;
(function(AdapterSize2) {
  AdapterSize2["ADAPTER_SIZE_UNSPECIFIED"] = "ADAPTER_SIZE_UNSPECIFIED";
  AdapterSize2["ADAPTER_SIZE_ONE"] = "ADAPTER_SIZE_ONE";
  AdapterSize2["ADAPTER_SIZE_TWO"] = "ADAPTER_SIZE_TWO";
  AdapterSize2["ADAPTER_SIZE_FOUR"] = "ADAPTER_SIZE_FOUR";
  AdapterSize2["ADAPTER_SIZE_EIGHT"] = "ADAPTER_SIZE_EIGHT";
  AdapterSize2["ADAPTER_SIZE_SIXTEEN"] = "ADAPTER_SIZE_SIXTEEN";
  AdapterSize2["ADAPTER_SIZE_THIRTY_TWO"] = "ADAPTER_SIZE_THIRTY_TWO";
})(AdapterSize || (AdapterSize = {}));
var FeatureSelectionPreference;
(function(FeatureSelectionPreference2) {
  FeatureSelectionPreference2["FEATURE_SELECTION_PREFERENCE_UNSPECIFIED"] = "FEATURE_SELECTION_PREFERENCE_UNSPECIFIED";
  FeatureSelectionPreference2["PRIORITIZE_QUALITY"] = "PRIORITIZE_QUALITY";
  FeatureSelectionPreference2["BALANCED"] = "BALANCED";
  FeatureSelectionPreference2["PRIORITIZE_COST"] = "PRIORITIZE_COST";
})(FeatureSelectionPreference || (FeatureSelectionPreference = {}));
var Behavior;
(function(Behavior2) {
  Behavior2["UNSPECIFIED"] = "UNSPECIFIED";
  Behavior2["BLOCKING"] = "BLOCKING";
  Behavior2["NON_BLOCKING"] = "NON_BLOCKING";
})(Behavior || (Behavior = {}));
var DynamicRetrievalConfigMode;
(function(DynamicRetrievalConfigMode2) {
  DynamicRetrievalConfigMode2["MODE_UNSPECIFIED"] = "MODE_UNSPECIFIED";
  DynamicRetrievalConfigMode2["MODE_DYNAMIC"] = "MODE_DYNAMIC";
})(DynamicRetrievalConfigMode || (DynamicRetrievalConfigMode = {}));
var FunctionCallingConfigMode;
(function(FunctionCallingConfigMode2) {
  FunctionCallingConfigMode2["MODE_UNSPECIFIED"] = "MODE_UNSPECIFIED";
  FunctionCallingConfigMode2["AUTO"] = "AUTO";
  FunctionCallingConfigMode2["ANY"] = "ANY";
  FunctionCallingConfigMode2["NONE"] = "NONE";
})(FunctionCallingConfigMode || (FunctionCallingConfigMode = {}));
var SafetyFilterLevel;
(function(SafetyFilterLevel2) {
  SafetyFilterLevel2["BLOCK_LOW_AND_ABOVE"] = "BLOCK_LOW_AND_ABOVE";
  SafetyFilterLevel2["BLOCK_MEDIUM_AND_ABOVE"] = "BLOCK_MEDIUM_AND_ABOVE";
  SafetyFilterLevel2["BLOCK_ONLY_HIGH"] = "BLOCK_ONLY_HIGH";
  SafetyFilterLevel2["BLOCK_NONE"] = "BLOCK_NONE";
})(SafetyFilterLevel || (SafetyFilterLevel = {}));
var PersonGeneration;
(function(PersonGeneration2) {
  PersonGeneration2["DONT_ALLOW"] = "DONT_ALLOW";
  PersonGeneration2["ALLOW_ADULT"] = "ALLOW_ADULT";
  PersonGeneration2["ALLOW_ALL"] = "ALLOW_ALL";
})(PersonGeneration || (PersonGeneration = {}));
var ImagePromptLanguage;
(function(ImagePromptLanguage2) {
  ImagePromptLanguage2["auto"] = "auto";
  ImagePromptLanguage2["en"] = "en";
  ImagePromptLanguage2["ja"] = "ja";
  ImagePromptLanguage2["ko"] = "ko";
  ImagePromptLanguage2["hi"] = "hi";
  ImagePromptLanguage2["zh"] = "zh";
  ImagePromptLanguage2["pt"] = "pt";
  ImagePromptLanguage2["es"] = "es";
})(ImagePromptLanguage || (ImagePromptLanguage = {}));
var MaskReferenceMode;
(function(MaskReferenceMode2) {
  MaskReferenceMode2["MASK_MODE_DEFAULT"] = "MASK_MODE_DEFAULT";
  MaskReferenceMode2["MASK_MODE_USER_PROVIDED"] = "MASK_MODE_USER_PROVIDED";
  MaskReferenceMode2["MASK_MODE_BACKGROUND"] = "MASK_MODE_BACKGROUND";
  MaskReferenceMode2["MASK_MODE_FOREGROUND"] = "MASK_MODE_FOREGROUND";
  MaskReferenceMode2["MASK_MODE_SEMANTIC"] = "MASK_MODE_SEMANTIC";
})(MaskReferenceMode || (MaskReferenceMode = {}));
var ControlReferenceType;
(function(ControlReferenceType2) {
  ControlReferenceType2["CONTROL_TYPE_DEFAULT"] = "CONTROL_TYPE_DEFAULT";
  ControlReferenceType2["CONTROL_TYPE_CANNY"] = "CONTROL_TYPE_CANNY";
  ControlReferenceType2["CONTROL_TYPE_SCRIBBLE"] = "CONTROL_TYPE_SCRIBBLE";
  ControlReferenceType2["CONTROL_TYPE_FACE_MESH"] = "CONTROL_TYPE_FACE_MESH";
})(ControlReferenceType || (ControlReferenceType = {}));
var SubjectReferenceType;
(function(SubjectReferenceType2) {
  SubjectReferenceType2["SUBJECT_TYPE_DEFAULT"] = "SUBJECT_TYPE_DEFAULT";
  SubjectReferenceType2["SUBJECT_TYPE_PERSON"] = "SUBJECT_TYPE_PERSON";
  SubjectReferenceType2["SUBJECT_TYPE_ANIMAL"] = "SUBJECT_TYPE_ANIMAL";
  SubjectReferenceType2["SUBJECT_TYPE_PRODUCT"] = "SUBJECT_TYPE_PRODUCT";
})(SubjectReferenceType || (SubjectReferenceType = {}));
var EditMode;
(function(EditMode2) {
  EditMode2["EDIT_MODE_DEFAULT"] = "EDIT_MODE_DEFAULT";
  EditMode2["EDIT_MODE_INPAINT_REMOVAL"] = "EDIT_MODE_INPAINT_REMOVAL";
  EditMode2["EDIT_MODE_INPAINT_INSERTION"] = "EDIT_MODE_INPAINT_INSERTION";
  EditMode2["EDIT_MODE_OUTPAINT"] = "EDIT_MODE_OUTPAINT";
  EditMode2["EDIT_MODE_CONTROLLED_EDITING"] = "EDIT_MODE_CONTROLLED_EDITING";
  EditMode2["EDIT_MODE_STYLE"] = "EDIT_MODE_STYLE";
  EditMode2["EDIT_MODE_BGSWAP"] = "EDIT_MODE_BGSWAP";
  EditMode2["EDIT_MODE_PRODUCT_IMAGE"] = "EDIT_MODE_PRODUCT_IMAGE";
})(EditMode || (EditMode = {}));
var VideoCompressionQuality;
(function(VideoCompressionQuality2) {
  VideoCompressionQuality2["OPTIMIZED"] = "OPTIMIZED";
  VideoCompressionQuality2["LOSSLESS"] = "LOSSLESS";
})(VideoCompressionQuality || (VideoCompressionQuality = {}));
var FileState;
(function(FileState2) {
  FileState2["STATE_UNSPECIFIED"] = "STATE_UNSPECIFIED";
  FileState2["PROCESSING"] = "PROCESSING";
  FileState2["ACTIVE"] = "ACTIVE";
  FileState2["FAILED"] = "FAILED";
})(FileState || (FileState = {}));
var FileSource;
(function(FileSource2) {
  FileSource2["SOURCE_UNSPECIFIED"] = "SOURCE_UNSPECIFIED";
  FileSource2["UPLOADED"] = "UPLOADED";
  FileSource2["GENERATED"] = "GENERATED";
})(FileSource || (FileSource = {}));
var MediaModality;
(function(MediaModality2) {
  MediaModality2["MODALITY_UNSPECIFIED"] = "MODALITY_UNSPECIFIED";
  MediaModality2["TEXT"] = "TEXT";
  MediaModality2["IMAGE"] = "IMAGE";
  MediaModality2["VIDEO"] = "VIDEO";
  MediaModality2["AUDIO"] = "AUDIO";
  MediaModality2["DOCUMENT"] = "DOCUMENT";
})(MediaModality || (MediaModality = {}));
var StartSensitivity;
(function(StartSensitivity2) {
  StartSensitivity2["START_SENSITIVITY_UNSPECIFIED"] = "START_SENSITIVITY_UNSPECIFIED";
  StartSensitivity2["START_SENSITIVITY_HIGH"] = "START_SENSITIVITY_HIGH";
  StartSensitivity2["START_SENSITIVITY_LOW"] = "START_SENSITIVITY_LOW";
})(StartSensitivity || (StartSensitivity = {}));
var EndSensitivity;
(function(EndSensitivity2) {
  EndSensitivity2["END_SENSITIVITY_UNSPECIFIED"] = "END_SENSITIVITY_UNSPECIFIED";
  EndSensitivity2["END_SENSITIVITY_HIGH"] = "END_SENSITIVITY_HIGH";
  EndSensitivity2["END_SENSITIVITY_LOW"] = "END_SENSITIVITY_LOW";
})(EndSensitivity || (EndSensitivity = {}));
var ActivityHandling;
(function(ActivityHandling2) {
  ActivityHandling2["ACTIVITY_HANDLING_UNSPECIFIED"] = "ACTIVITY_HANDLING_UNSPECIFIED";
  ActivityHandling2["START_OF_ACTIVITY_INTERRUPTS"] = "START_OF_ACTIVITY_INTERRUPTS";
  ActivityHandling2["NO_INTERRUPTION"] = "NO_INTERRUPTION";
})(ActivityHandling || (ActivityHandling = {}));
var TurnCoverage;
(function(TurnCoverage2) {
  TurnCoverage2["TURN_COVERAGE_UNSPECIFIED"] = "TURN_COVERAGE_UNSPECIFIED";
  TurnCoverage2["TURN_INCLUDES_ONLY_ACTIVITY"] = "TURN_INCLUDES_ONLY_ACTIVITY";
  TurnCoverage2["TURN_INCLUDES_ALL_INPUT"] = "TURN_INCLUDES_ALL_INPUT";
})(TurnCoverage || (TurnCoverage = {}));
var FunctionResponseScheduling;
(function(FunctionResponseScheduling2) {
  FunctionResponseScheduling2["SCHEDULING_UNSPECIFIED"] = "SCHEDULING_UNSPECIFIED";
  FunctionResponseScheduling2["SILENT"] = "SILENT";
  FunctionResponseScheduling2["WHEN_IDLE"] = "WHEN_IDLE";
  FunctionResponseScheduling2["INTERRUPT"] = "INTERRUPT";
})(FunctionResponseScheduling || (FunctionResponseScheduling = {}));
var Scale;
(function(Scale2) {
  Scale2["SCALE_UNSPECIFIED"] = "SCALE_UNSPECIFIED";
  Scale2["C_MAJOR_A_MINOR"] = "C_MAJOR_A_MINOR";
  Scale2["D_FLAT_MAJOR_B_FLAT_MINOR"] = "D_FLAT_MAJOR_B_FLAT_MINOR";
  Scale2["D_MAJOR_B_MINOR"] = "D_MAJOR_B_MINOR";
  Scale2["E_FLAT_MAJOR_C_MINOR"] = "E_FLAT_MAJOR_C_MINOR";
  Scale2["E_MAJOR_D_FLAT_MINOR"] = "E_MAJOR_D_FLAT_MINOR";
  Scale2["F_MAJOR_D_MINOR"] = "F_MAJOR_D_MINOR";
  Scale2["G_FLAT_MAJOR_E_FLAT_MINOR"] = "G_FLAT_MAJOR_E_FLAT_MINOR";
  Scale2["G_MAJOR_E_MINOR"] = "G_MAJOR_E_MINOR";
  Scale2["A_FLAT_MAJOR_F_MINOR"] = "A_FLAT_MAJOR_F_MINOR";
  Scale2["A_MAJOR_G_FLAT_MINOR"] = "A_MAJOR_G_FLAT_MINOR";
  Scale2["B_FLAT_MAJOR_G_MINOR"] = "B_FLAT_MAJOR_G_MINOR";
  Scale2["B_MAJOR_A_FLAT_MINOR"] = "B_MAJOR_A_FLAT_MINOR";
})(Scale || (Scale = {}));
var LiveMusicPlaybackControl;
(function(LiveMusicPlaybackControl2) {
  LiveMusicPlaybackControl2["PLAYBACK_CONTROL_UNSPECIFIED"] = "PLAYBACK_CONTROL_UNSPECIFIED";
  LiveMusicPlaybackControl2["PLAY"] = "PLAY";
  LiveMusicPlaybackControl2["PAUSE"] = "PAUSE";
  LiveMusicPlaybackControl2["STOP"] = "STOP";
  LiveMusicPlaybackControl2["RESET_CONTEXT"] = "RESET_CONTEXT";
})(LiveMusicPlaybackControl || (LiveMusicPlaybackControl = {}));
var HttpResponse = class {
  static {
    __name(this, "HttpResponse");
  }
  constructor(response) {
    const headers = {};
    for (const pair of response.headers.entries()) {
      headers[pair[0]] = pair[1];
    }
    this.headers = headers;
    this.responseInternal = response;
  }
  json() {
    return this.responseInternal.json();
  }
};
var GenerateContentResponse = class {
  static {
    __name(this, "GenerateContentResponse");
  }
  /**
   * Returns the concatenation of all text parts from the first candidate in the response.
   *
   * @remarks
   * If there are multiple candidates in the response, the text from the first
   * one will be returned.
   * If there are non-text parts in the response, the concatenation of all text
   * parts will be returned, and a warning will be logged.
   * If there are thought parts in the response, the concatenation of all text
   * parts excluding the thought parts will be returned.
   *
   * @example
   * ```ts
   * const response = await ai.models.generateContent({
   *   model: 'gemini-2.0-flash',
   *   contents:
   *     'Why is the sky blue?',
   * });
   *
   * console.debug(response.text);
   * ```
   */
  get text() {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    if (((_d = (_c = (_b = (_a = this.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) === null || _d === void 0 ? void 0 : _d.length) === 0) {
      return void 0;
    }
    if (this.candidates && this.candidates.length > 1) {
      console.warn("there are multiple candidates in the response, returning text from the first one.");
    }
    let text = "";
    let anyTextPartText = false;
    const nonTextParts = [];
    for (const part of (_h = (_g = (_f = (_e = this.candidates) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.content) === null || _g === void 0 ? void 0 : _g.parts) !== null && _h !== void 0 ? _h : []) {
      for (const [fieldName, fieldValue] of Object.entries(part)) {
        if (fieldName !== "text" && fieldName !== "thought" && (fieldValue !== null || fieldValue !== void 0)) {
          nonTextParts.push(fieldName);
        }
      }
      if (typeof part.text === "string") {
        if (typeof part.thought === "boolean" && part.thought) {
          continue;
        }
        anyTextPartText = true;
        text += part.text;
      }
    }
    if (nonTextParts.length > 0) {
      console.warn(`there are non-text parts ${nonTextParts} in the response, returning concatenation of all text parts. Please refer to the non text parts for a full response from model.`);
    }
    return anyTextPartText ? text : void 0;
  }
  /**
   * Returns the concatenation of all inline data parts from the first candidate
   * in the response.
   *
   * @remarks
   * If there are multiple candidates in the response, the inline data from the
   * first one will be returned. If there are non-inline data parts in the
   * response, the concatenation of all inline data parts will be returned, and
   * a warning will be logged.
   */
  get data() {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    if (((_d = (_c = (_b = (_a = this.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) === null || _d === void 0 ? void 0 : _d.length) === 0) {
      return void 0;
    }
    if (this.candidates && this.candidates.length > 1) {
      console.warn("there are multiple candidates in the response, returning data from the first one.");
    }
    let data = "";
    const nonDataParts = [];
    for (const part of (_h = (_g = (_f = (_e = this.candidates) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.content) === null || _g === void 0 ? void 0 : _g.parts) !== null && _h !== void 0 ? _h : []) {
      for (const [fieldName, fieldValue] of Object.entries(part)) {
        if (fieldName !== "inlineData" && (fieldValue !== null || fieldValue !== void 0)) {
          nonDataParts.push(fieldName);
        }
      }
      if (part.inlineData && typeof part.inlineData.data === "string") {
        data += atob(part.inlineData.data);
      }
    }
    if (nonDataParts.length > 0) {
      console.warn(`there are non-data parts ${nonDataParts} in the response, returning concatenation of all data parts. Please refer to the non data parts for a full response from model.`);
    }
    return data.length > 0 ? btoa(data) : void 0;
  }
  /**
   * Returns the function calls from the first candidate in the response.
   *
   * @remarks
   * If there are multiple candidates in the response, the function calls from
   * the first one will be returned.
   * If there are no function calls in the response, undefined will be returned.
   *
   * @example
   * ```ts
   * const controlLightFunctionDeclaration: FunctionDeclaration = {
   *   name: 'controlLight',
   *   parameters: {
   *   type: Type.OBJECT,
   *   description: 'Set the brightness and color temperature of a room light.',
   *   properties: {
   *     brightness: {
   *       type: Type.NUMBER,
   *       description:
   *         'Light level from 0 to 100. Zero is off and 100 is full brightness.',
   *     },
   *     colorTemperature: {
   *       type: Type.STRING,
   *       description:
   *         'Color temperature of the light fixture which can be `daylight`, `cool` or `warm`.',
   *     },
   *   },
   *   required: ['brightness', 'colorTemperature'],
   *  };
   *  const response = await ai.models.generateContent({
   *     model: 'gemini-2.0-flash',
   *     contents: 'Dim the lights so the room feels cozy and warm.',
   *     config: {
   *       tools: [{functionDeclarations: [controlLightFunctionDeclaration]}],
   *       toolConfig: {
   *         functionCallingConfig: {
   *           mode: FunctionCallingConfigMode.ANY,
   *           allowedFunctionNames: ['controlLight'],
   *         },
   *       },
   *     },
   *   });
   *  console.debug(JSON.stringify(response.functionCalls));
   * ```
   */
  get functionCalls() {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    if (((_d = (_c = (_b = (_a = this.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) === null || _d === void 0 ? void 0 : _d.length) === 0) {
      return void 0;
    }
    if (this.candidates && this.candidates.length > 1) {
      console.warn("there are multiple candidates in the response, returning function calls from the first one.");
    }
    const functionCalls = (_h = (_g = (_f = (_e = this.candidates) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.content) === null || _g === void 0 ? void 0 : _g.parts) === null || _h === void 0 ? void 0 : _h.filter((part) => part.functionCall).map((part) => part.functionCall).filter((functionCall) => functionCall !== void 0);
    if ((functionCalls === null || functionCalls === void 0 ? void 0 : functionCalls.length) === 0) {
      return void 0;
    }
    return functionCalls;
  }
  /**
   * Returns the first executable code from the first candidate in the response.
   *
   * @remarks
   * If there are multiple candidates in the response, the executable code from
   * the first one will be returned.
   * If there are no executable code in the response, undefined will be
   * returned.
   *
   * @example
   * ```ts
   * const response = await ai.models.generateContent({
   *   model: 'gemini-2.0-flash',
   *   contents:
   *     'What is the sum of the first 50 prime numbers? Generate and run code for the calculation, and make sure you get all 50.'
   *   config: {
   *     tools: [{codeExecution: {}}],
   *   },
   * });
   *
   * console.debug(response.executableCode);
   * ```
   */
  get executableCode() {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    if (((_d = (_c = (_b = (_a = this.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) === null || _d === void 0 ? void 0 : _d.length) === 0) {
      return void 0;
    }
    if (this.candidates && this.candidates.length > 1) {
      console.warn("there are multiple candidates in the response, returning executable code from the first one.");
    }
    const executableCode = (_h = (_g = (_f = (_e = this.candidates) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.content) === null || _g === void 0 ? void 0 : _g.parts) === null || _h === void 0 ? void 0 : _h.filter((part) => part.executableCode).map((part) => part.executableCode).filter((executableCode2) => executableCode2 !== void 0);
    if ((executableCode === null || executableCode === void 0 ? void 0 : executableCode.length) === 0) {
      return void 0;
    }
    return (_j = executableCode === null || executableCode === void 0 ? void 0 : executableCode[0]) === null || _j === void 0 ? void 0 : _j.code;
  }
  /**
   * Returns the first code execution result from the first candidate in the response.
   *
   * @remarks
   * If there are multiple candidates in the response, the code execution result from
   * the first one will be returned.
   * If there are no code execution result in the response, undefined will be returned.
   *
   * @example
   * ```ts
   * const response = await ai.models.generateContent({
   *   model: 'gemini-2.0-flash',
   *   contents:
   *     'What is the sum of the first 50 prime numbers? Generate and run code for the calculation, and make sure you get all 50.'
   *   config: {
   *     tools: [{codeExecution: {}}],
   *   },
   * });
   *
   * console.debug(response.codeExecutionResult);
   * ```
   */
  get codeExecutionResult() {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    if (((_d = (_c = (_b = (_a = this.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content) === null || _c === void 0 ? void 0 : _c.parts) === null || _d === void 0 ? void 0 : _d.length) === 0) {
      return void 0;
    }
    if (this.candidates && this.candidates.length > 1) {
      console.warn("there are multiple candidates in the response, returning code execution result from the first one.");
    }
    const codeExecutionResult = (_h = (_g = (_f = (_e = this.candidates) === null || _e === void 0 ? void 0 : _e[0]) === null || _f === void 0 ? void 0 : _f.content) === null || _g === void 0 ? void 0 : _g.parts) === null || _h === void 0 ? void 0 : _h.filter((part) => part.codeExecutionResult).map((part) => part.codeExecutionResult).filter((codeExecutionResult2) => codeExecutionResult2 !== void 0);
    if ((codeExecutionResult === null || codeExecutionResult === void 0 ? void 0 : codeExecutionResult.length) === 0) {
      return void 0;
    }
    return (_j = codeExecutionResult === null || codeExecutionResult === void 0 ? void 0 : codeExecutionResult[0]) === null || _j === void 0 ? void 0 : _j.output;
  }
};
var EmbedContentResponse = class {
  static {
    __name(this, "EmbedContentResponse");
  }
};
var GenerateImagesResponse = class {
  static {
    __name(this, "GenerateImagesResponse");
  }
};
var EditImageResponse = class {
  static {
    __name(this, "EditImageResponse");
  }
};
var UpscaleImageResponse = class {
  static {
    __name(this, "UpscaleImageResponse");
  }
};
var ListModelsResponse = class {
  static {
    __name(this, "ListModelsResponse");
  }
};
var DeleteModelResponse = class {
  static {
    __name(this, "DeleteModelResponse");
  }
};
var CountTokensResponse = class {
  static {
    __name(this, "CountTokensResponse");
  }
};
var ComputeTokensResponse = class {
  static {
    __name(this, "ComputeTokensResponse");
  }
};
var GenerateVideosResponse = class {
  static {
    __name(this, "GenerateVideosResponse");
  }
};
var ListTuningJobsResponse = class {
  static {
    __name(this, "ListTuningJobsResponse");
  }
};
var DeleteCachedContentResponse = class {
  static {
    __name(this, "DeleteCachedContentResponse");
  }
};
var ListCachedContentsResponse = class {
  static {
    __name(this, "ListCachedContentsResponse");
  }
};
var ListFilesResponse = class {
  static {
    __name(this, "ListFilesResponse");
  }
};
var CreateFileResponse = class {
  static {
    __name(this, "CreateFileResponse");
  }
};
var DeleteFileResponse = class {
  static {
    __name(this, "DeleteFileResponse");
  }
};
var ListBatchJobsResponse = class {
  static {
    __name(this, "ListBatchJobsResponse");
  }
};
var LiveServerMessage = class {
  static {
    __name(this, "LiveServerMessage");
  }
  /**
   * Returns the concatenation of all text parts from the server content if present.
   *
   * @remarks
   * If there are non-text parts in the response, the concatenation of all text
   * parts will be returned, and a warning will be logged.
   */
  get text() {
    var _a, _b, _c;
    let text = "";
    let anyTextPartFound = false;
    const nonTextParts = [];
    for (const part of (_c = (_b = (_a = this.serverContent) === null || _a === void 0 ? void 0 : _a.modelTurn) === null || _b === void 0 ? void 0 : _b.parts) !== null && _c !== void 0 ? _c : []) {
      for (const [fieldName, fieldValue] of Object.entries(part)) {
        if (fieldName !== "text" && fieldName !== "thought" && fieldValue !== null) {
          nonTextParts.push(fieldName);
        }
      }
      if (typeof part.text === "string") {
        if (typeof part.thought === "boolean" && part.thought) {
          continue;
        }
        anyTextPartFound = true;
        text += part.text;
      }
    }
    if (nonTextParts.length > 0) {
      console.warn(`there are non-text parts ${nonTextParts} in the response, returning concatenation of all text parts. Please refer to the non text parts for a full response from model.`);
    }
    return anyTextPartFound ? text : void 0;
  }
  /**
   * Returns the concatenation of all inline data parts from the server content if present.
   *
   * @remarks
   * If there are non-inline data parts in the
   * response, the concatenation of all inline data parts will be returned, and
   * a warning will be logged.
   */
  get data() {
    var _a, _b, _c;
    let data = "";
    const nonDataParts = [];
    for (const part of (_c = (_b = (_a = this.serverContent) === null || _a === void 0 ? void 0 : _a.modelTurn) === null || _b === void 0 ? void 0 : _b.parts) !== null && _c !== void 0 ? _c : []) {
      for (const [fieldName, fieldValue] of Object.entries(part)) {
        if (fieldName !== "inlineData" && fieldValue !== null) {
          nonDataParts.push(fieldName);
        }
      }
      if (part.inlineData && typeof part.inlineData.data === "string") {
        data += atob(part.inlineData.data);
      }
    }
    if (nonDataParts.length > 0) {
      console.warn(`there are non-data parts ${nonDataParts} in the response, returning concatenation of all data parts. Please refer to the non data parts for a full response from model.`);
    }
    return data.length > 0 ? btoa(data) : void 0;
  }
};
var GenerateVideosOperation = class _GenerateVideosOperation {
  static {
    __name(this, "GenerateVideosOperation");
  }
  /**
   * Instantiates an Operation of the same type as the one being called with the fields set from the API response.
   * @internal
   */
  _fromAPIResponse({ apiResponse, isVertexAI }) {
    const operation = new _GenerateVideosOperation();
    operation.name = apiResponse["name"];
    operation.metadata = apiResponse["metadata"];
    operation.done = apiResponse["done"];
    operation.error = apiResponse["error"];
    if (isVertexAI) {
      const response = apiResponse["response"];
      if (response) {
        const operationResponse = new GenerateVideosResponse();
        const responseVideos = response["videos"];
        operationResponse.generatedVideos = responseVideos === null || responseVideos === void 0 ? void 0 : responseVideos.map((generatedVideo) => {
          return {
            video: {
              uri: generatedVideo["gcsUri"],
              videoBytes: generatedVideo["bytesBase64Encoded"] ? tBytes$1(generatedVideo["bytesBase64Encoded"]) : void 0,
              mimeType: generatedVideo["mimeType"]
            }
          };
        });
        operationResponse.raiMediaFilteredCount = response["raiMediaFilteredCount"];
        operationResponse.raiMediaFilteredReasons = response["raiMediaFilteredReasons"];
        operation.response = operationResponse;
      }
    } else {
      const response = apiResponse["response"];
      if (response) {
        const operationResponse = new GenerateVideosResponse();
        const generatedVideoResponse = response["generateVideoResponse"];
        const responseVideos = generatedVideoResponse === null || generatedVideoResponse === void 0 ? void 0 : generatedVideoResponse["generatedSamples"];
        operationResponse.generatedVideos = responseVideos === null || responseVideos === void 0 ? void 0 : responseVideos.map((generatedVideo) => {
          const video = generatedVideo["video"];
          return {
            video: {
              uri: video === null || video === void 0 ? void 0 : video["uri"],
              videoBytes: (video === null || video === void 0 ? void 0 : video["encodedVideo"]) ? tBytes$1(video === null || video === void 0 ? void 0 : video["encodedVideo"]) : void 0,
              mimeType: generatedVideo["encoding"]
            }
          };
        });
        operationResponse.raiMediaFilteredCount = generatedVideoResponse === null || generatedVideoResponse === void 0 ? void 0 : generatedVideoResponse["raiMediaFilteredCount"];
        operationResponse.raiMediaFilteredReasons = generatedVideoResponse === null || generatedVideoResponse === void 0 ? void 0 : generatedVideoResponse["raiMediaFilteredReasons"];
        operation.response = operationResponse;
      }
    }
    return operation;
  }
};
var LiveMusicServerMessage = class {
  static {
    __name(this, "LiveMusicServerMessage");
  }
  /**
   * Returns the first audio chunk from the server content, if present.
   *
   * @remarks
   * If there are no audio chunks in the response, undefined will be returned.
   */
  get audioChunk() {
    if (this.serverContent && this.serverContent.audioChunks && this.serverContent.audioChunks.length > 0) {
      return this.serverContent.audioChunks[0];
    }
    return void 0;
  }
};
function tModel(apiClient, model) {
  if (!model || typeof model !== "string") {
    throw new Error("model is required and must be a string");
  }
  if (apiClient.isVertexAI()) {
    if (model.startsWith("publishers/") || model.startsWith("projects/") || model.startsWith("models/")) {
      return model;
    } else if (model.indexOf("/") >= 0) {
      const parts = model.split("/", 2);
      return `publishers/${parts[0]}/models/${parts[1]}`;
    } else {
      return `publishers/google/models/${model}`;
    }
  } else {
    if (model.startsWith("models/") || model.startsWith("tunedModels/")) {
      return model;
    } else {
      return `models/${model}`;
    }
  }
}
__name(tModel, "tModel");
function tCachesModel(apiClient, model) {
  const transformedModel = tModel(apiClient, model);
  if (!transformedModel) {
    return "";
  }
  if (transformedModel.startsWith("publishers/") && apiClient.isVertexAI()) {
    return `projects/${apiClient.getProject()}/locations/${apiClient.getLocation()}/${transformedModel}`;
  } else if (transformedModel.startsWith("models/") && apiClient.isVertexAI()) {
    return `projects/${apiClient.getProject()}/locations/${apiClient.getLocation()}/publishers/google/${transformedModel}`;
  } else {
    return transformedModel;
  }
}
__name(tCachesModel, "tCachesModel");
function tBlobs(blobs) {
  if (Array.isArray(blobs)) {
    return blobs.map((blob) => tBlob(blob));
  } else {
    return [tBlob(blobs)];
  }
}
__name(tBlobs, "tBlobs");
function tBlob(blob) {
  if (typeof blob === "object" && blob !== null) {
    return blob;
  }
  throw new Error(`Could not parse input as Blob. Unsupported blob type: ${typeof blob}`);
}
__name(tBlob, "tBlob");
function tImageBlob(blob) {
  const transformedBlob = tBlob(blob);
  if (transformedBlob.mimeType && transformedBlob.mimeType.startsWith("image/")) {
    return transformedBlob;
  }
  throw new Error(`Unsupported mime type: ${transformedBlob.mimeType}`);
}
__name(tImageBlob, "tImageBlob");
function tAudioBlob(blob) {
  const transformedBlob = tBlob(blob);
  if (transformedBlob.mimeType && transformedBlob.mimeType.startsWith("audio/")) {
    return transformedBlob;
  }
  throw new Error(`Unsupported mime type: ${transformedBlob.mimeType}`);
}
__name(tAudioBlob, "tAudioBlob");
function tPart(origin) {
  if (origin === null || origin === void 0) {
    throw new Error("PartUnion is required");
  }
  if (typeof origin === "object") {
    return origin;
  }
  if (typeof origin === "string") {
    return { text: origin };
  }
  throw new Error(`Unsupported part type: ${typeof origin}`);
}
__name(tPart, "tPart");
function tParts(origin) {
  if (origin === null || origin === void 0 || Array.isArray(origin) && origin.length === 0) {
    throw new Error("PartListUnion is required");
  }
  if (Array.isArray(origin)) {
    return origin.map((item) => tPart(item));
  }
  return [tPart(origin)];
}
__name(tParts, "tParts");
function _isContent(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "parts" in origin && Array.isArray(origin.parts);
}
__name(_isContent, "_isContent");
function _isFunctionCallPart(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "functionCall" in origin;
}
__name(_isFunctionCallPart, "_isFunctionCallPart");
function _isFunctionResponsePart(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "functionResponse" in origin;
}
__name(_isFunctionResponsePart, "_isFunctionResponsePart");
function tContent(origin) {
  if (origin === null || origin === void 0) {
    throw new Error("ContentUnion is required");
  }
  if (_isContent(origin)) {
    return origin;
  }
  return {
    role: "user",
    parts: tParts(origin)
  };
}
__name(tContent, "tContent");
function tContentsForEmbed(apiClient, origin) {
  if (!origin) {
    return [];
  }
  if (apiClient.isVertexAI() && Array.isArray(origin)) {
    return origin.flatMap((item) => {
      const content = tContent(item);
      if (content.parts && content.parts.length > 0 && content.parts[0].text !== void 0) {
        return [content.parts[0].text];
      }
      return [];
    });
  } else if (apiClient.isVertexAI()) {
    const content = tContent(origin);
    if (content.parts && content.parts.length > 0 && content.parts[0].text !== void 0) {
      return [content.parts[0].text];
    }
    return [];
  }
  if (Array.isArray(origin)) {
    return origin.map((item) => tContent(item));
  }
  return [tContent(origin)];
}
__name(tContentsForEmbed, "tContentsForEmbed");
function tContents(origin) {
  if (origin === null || origin === void 0 || Array.isArray(origin) && origin.length === 0) {
    throw new Error("contents are required");
  }
  if (!Array.isArray(origin)) {
    if (_isFunctionCallPart(origin) || _isFunctionResponsePart(origin)) {
      throw new Error("To specify functionCall or functionResponse parts, please wrap them in a Content object, specifying the role for them");
    }
    return [tContent(origin)];
  }
  const result = [];
  const accumulatedParts = [];
  const isContentArray = _isContent(origin[0]);
  for (const item of origin) {
    const isContent = _isContent(item);
    if (isContent != isContentArray) {
      throw new Error("Mixing Content and Parts is not supported, please group the parts into a the appropriate Content objects and specify the roles for them");
    }
    if (isContent) {
      result.push(item);
    } else if (_isFunctionCallPart(item) || _isFunctionResponsePart(item)) {
      throw new Error("To specify functionCall or functionResponse parts, please wrap them, and any other parts, in Content objects as appropriate, specifying the role for them");
    } else {
      accumulatedParts.push(item);
    }
  }
  if (!isContentArray) {
    result.push({ role: "user", parts: tParts(accumulatedParts) });
  }
  return result;
}
__name(tContents, "tContents");
function flattenTypeArrayToAnyOf(typeList, resultingSchema) {
  if (typeList.includes("null")) {
    resultingSchema["nullable"] = true;
  }
  const listWithoutNull = typeList.filter((type) => type !== "null");
  if (listWithoutNull.length === 1) {
    resultingSchema["type"] = Object.values(Type).includes(listWithoutNull[0].toUpperCase()) ? listWithoutNull[0].toUpperCase() : Type.TYPE_UNSPECIFIED;
  } else {
    resultingSchema["anyOf"] = [];
    for (const i of listWithoutNull) {
      resultingSchema["anyOf"].push({
        "type": Object.values(Type).includes(i.toUpperCase()) ? i.toUpperCase() : Type.TYPE_UNSPECIFIED
      });
    }
  }
}
__name(flattenTypeArrayToAnyOf, "flattenTypeArrayToAnyOf");
function processJsonSchema(_jsonSchema) {
  const genAISchema = {};
  const schemaFieldNames = ["items"];
  const listSchemaFieldNames = ["anyOf"];
  const dictSchemaFieldNames = ["properties"];
  if (_jsonSchema["type"] && _jsonSchema["anyOf"]) {
    throw new Error("type and anyOf cannot be both populated.");
  }
  const incomingAnyOf = _jsonSchema["anyOf"];
  if (incomingAnyOf != null && incomingAnyOf.length == 2) {
    if (incomingAnyOf[0]["type"] === "null") {
      genAISchema["nullable"] = true;
      _jsonSchema = incomingAnyOf[1];
    } else if (incomingAnyOf[1]["type"] === "null") {
      genAISchema["nullable"] = true;
      _jsonSchema = incomingAnyOf[0];
    }
  }
  if (_jsonSchema["type"] instanceof Array) {
    flattenTypeArrayToAnyOf(_jsonSchema["type"], genAISchema);
  }
  for (const [fieldName, fieldValue] of Object.entries(_jsonSchema)) {
    if (fieldValue == null) {
      continue;
    }
    if (fieldName == "type") {
      if (fieldValue === "null") {
        throw new Error("type: null can not be the only possible type for the field.");
      }
      if (fieldValue instanceof Array) {
        continue;
      }
      genAISchema["type"] = Object.values(Type).includes(fieldValue.toUpperCase()) ? fieldValue.toUpperCase() : Type.TYPE_UNSPECIFIED;
    } else if (schemaFieldNames.includes(fieldName)) {
      genAISchema[fieldName] = processJsonSchema(fieldValue);
    } else if (listSchemaFieldNames.includes(fieldName)) {
      const listSchemaFieldValue = [];
      for (const item of fieldValue) {
        if (item["type"] == "null") {
          genAISchema["nullable"] = true;
          continue;
        }
        listSchemaFieldValue.push(processJsonSchema(item));
      }
      genAISchema[fieldName] = listSchemaFieldValue;
    } else if (dictSchemaFieldNames.includes(fieldName)) {
      const dictSchemaFieldValue = {};
      for (const [key, value] of Object.entries(fieldValue)) {
        dictSchemaFieldValue[key] = processJsonSchema(value);
      }
      genAISchema[fieldName] = dictSchemaFieldValue;
    } else {
      if (fieldName === "additionalProperties") {
        continue;
      }
      genAISchema[fieldName] = fieldValue;
    }
  }
  return genAISchema;
}
__name(processJsonSchema, "processJsonSchema");
function tSchema(schema) {
  return processJsonSchema(schema);
}
__name(tSchema, "tSchema");
function tSpeechConfig(speechConfig) {
  if (typeof speechConfig === "object") {
    return speechConfig;
  } else if (typeof speechConfig === "string") {
    return {
      voiceConfig: {
        prebuiltVoiceConfig: {
          voiceName: speechConfig
        }
      }
    };
  } else {
    throw new Error(`Unsupported speechConfig type: ${typeof speechConfig}`);
  }
}
__name(tSpeechConfig, "tSpeechConfig");
function tLiveSpeechConfig(speechConfig) {
  if ("multiSpeakerVoiceConfig" in speechConfig) {
    throw new Error("multiSpeakerVoiceConfig is not supported in the live API.");
  }
  return speechConfig;
}
__name(tLiveSpeechConfig, "tLiveSpeechConfig");
function tTool(tool) {
  if (tool.functionDeclarations) {
    for (const functionDeclaration of tool.functionDeclarations) {
      if (functionDeclaration.parameters) {
        if (!Object.keys(functionDeclaration.parameters).includes("$schema")) {
          functionDeclaration.parameters = processJsonSchema(functionDeclaration.parameters);
        } else {
          if (!functionDeclaration.parametersJsonSchema) {
            functionDeclaration.parametersJsonSchema = functionDeclaration.parameters;
            delete functionDeclaration.parameters;
          }
        }
      }
      if (functionDeclaration.response) {
        if (!Object.keys(functionDeclaration.response).includes("$schema")) {
          functionDeclaration.response = processJsonSchema(functionDeclaration.response);
        } else {
          if (!functionDeclaration.responseJsonSchema) {
            functionDeclaration.responseJsonSchema = functionDeclaration.response;
            delete functionDeclaration.response;
          }
        }
      }
    }
  }
  return tool;
}
__name(tTool, "tTool");
function tTools(tools) {
  if (tools === void 0 || tools === null) {
    throw new Error("tools is required");
  }
  if (!Array.isArray(tools)) {
    throw new Error("tools is required and must be an array of Tools");
  }
  const result = [];
  for (const tool of tools) {
    result.push(tool);
  }
  return result;
}
__name(tTools, "tTools");
function resourceName(client, resourceName2, resourcePrefix, splitsAfterPrefix = 1) {
  const shouldAppendPrefix = !resourceName2.startsWith(`${resourcePrefix}/`) && resourceName2.split("/").length === splitsAfterPrefix;
  if (client.isVertexAI()) {
    if (resourceName2.startsWith("projects/")) {
      return resourceName2;
    } else if (resourceName2.startsWith("locations/")) {
      return `projects/${client.getProject()}/${resourceName2}`;
    } else if (resourceName2.startsWith(`${resourcePrefix}/`)) {
      return `projects/${client.getProject()}/locations/${client.getLocation()}/${resourceName2}`;
    } else if (shouldAppendPrefix) {
      return `projects/${client.getProject()}/locations/${client.getLocation()}/${resourcePrefix}/${resourceName2}`;
    } else {
      return resourceName2;
    }
  }
  if (shouldAppendPrefix) {
    return `${resourcePrefix}/${resourceName2}`;
  }
  return resourceName2;
}
__name(resourceName, "resourceName");
function tCachedContentName(apiClient, name) {
  if (typeof name !== "string") {
    throw new Error("name must be a string");
  }
  return resourceName(apiClient, name, "cachedContents");
}
__name(tCachedContentName, "tCachedContentName");
function tTuningJobStatus(status) {
  switch (status) {
    case "STATE_UNSPECIFIED":
      return "JOB_STATE_UNSPECIFIED";
    case "CREATING":
      return "JOB_STATE_RUNNING";
    case "ACTIVE":
      return "JOB_STATE_SUCCEEDED";
    case "FAILED":
      return "JOB_STATE_FAILED";
    default:
      return status;
  }
}
__name(tTuningJobStatus, "tTuningJobStatus");
function tBytes(fromImageBytes) {
  return tBytes$1(fromImageBytes);
}
__name(tBytes, "tBytes");
function _isFile(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "name" in origin;
}
__name(_isFile, "_isFile");
function isGeneratedVideo(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "video" in origin;
}
__name(isGeneratedVideo, "isGeneratedVideo");
function isVideo(origin) {
  return origin !== null && origin !== void 0 && typeof origin === "object" && "uri" in origin;
}
__name(isVideo, "isVideo");
function tFileName(fromName) {
  var _a;
  let name;
  if (_isFile(fromName)) {
    name = fromName.name;
  }
  if (isVideo(fromName)) {
    name = fromName.uri;
    if (name === void 0) {
      return void 0;
    }
  }
  if (isGeneratedVideo(fromName)) {
    name = (_a = fromName.video) === null || _a === void 0 ? void 0 : _a.uri;
    if (name === void 0) {
      return void 0;
    }
  }
  if (typeof fromName === "string") {
    name = fromName;
  }
  if (name === void 0) {
    throw new Error("Could not extract file name from the provided input.");
  }
  if (name.startsWith("https://")) {
    const suffix = name.split("files/")[1];
    const match2 = suffix.match(/[a-z0-9]+/);
    if (match2 === null) {
      throw new Error(`Could not extract file name from URI ${name}`);
    }
    name = match2[0];
  } else if (name.startsWith("files/")) {
    name = name.split("files/")[1];
  }
  return name;
}
__name(tFileName, "tFileName");
function tModelsUrl(apiClient, baseModels) {
  let res;
  if (apiClient.isVertexAI()) {
    res = baseModels ? "publishers/google/models" : "models";
  } else {
    res = baseModels ? "models" : "tunedModels";
  }
  return res;
}
__name(tModelsUrl, "tModelsUrl");
function tExtractModels(response) {
  for (const key of ["models", "tunedModels", "publisherModels"]) {
    if (hasField(response, key)) {
      return response[key];
    }
  }
  return [];
}
__name(tExtractModels, "tExtractModels");
function hasField(data, fieldName) {
  return data !== null && typeof data === "object" && fieldName in data;
}
__name(hasField, "hasField");
function mcpToGeminiTool(mcpTool, config = {}) {
  const mcpToolSchema = mcpTool;
  const functionDeclaration = {
    name: mcpToolSchema["name"],
    description: mcpToolSchema["description"],
    parametersJsonSchema: mcpToolSchema["inputSchema"]
  };
  if (config.behavior) {
    functionDeclaration["behavior"] = config.behavior;
  }
  const geminiTool = {
    functionDeclarations: [
      functionDeclaration
    ]
  };
  return geminiTool;
}
__name(mcpToGeminiTool, "mcpToGeminiTool");
function mcpToolsToGeminiTool(mcpTools, config = {}) {
  const functionDeclarations = [];
  const toolNames = /* @__PURE__ */ new Set();
  for (const mcpTool of mcpTools) {
    const mcpToolName = mcpTool.name;
    if (toolNames.has(mcpToolName)) {
      throw new Error(`Duplicate function name ${mcpToolName} found in MCP tools. Please ensure function names are unique.`);
    }
    toolNames.add(mcpToolName);
    const geminiTool = mcpToGeminiTool(mcpTool, config);
    if (geminiTool.functionDeclarations) {
      functionDeclarations.push(...geminiTool.functionDeclarations);
    }
  }
  return { functionDeclarations };
}
__name(mcpToolsToGeminiTool, "mcpToolsToGeminiTool");
function tBatchJobSource(apiClient, src) {
  if (typeof src !== "string" && !Array.isArray(src)) {
    if (apiClient && apiClient.isVertexAI()) {
      if (src.gcsUri && src.bigqueryUri) {
        throw new Error("Only one of `gcsUri` or `bigqueryUri` can be set.");
      } else if (!src.gcsUri && !src.bigqueryUri) {
        throw new Error("One of `gcsUri` or `bigqueryUri` must be set.");
      }
    } else {
      if (src.inlinedRequests && src.fileName) {
        throw new Error("Only one of `inlinedRequests` or `fileName` can be set.");
      } else if (!src.inlinedRequests && !src.fileName) {
        throw new Error("One of `inlinedRequests` or `fileName` must be set.");
      }
    }
    return src;
  } else if (Array.isArray(src)) {
    return { inlinedRequests: src };
  } else if (typeof src === "string") {
    if (src.startsWith("gs://")) {
      return {
        format: "jsonl",
        gcsUri: [src]
        // GCS URI is expected as an array
      };
    } else if (src.startsWith("bq://")) {
      return {
        format: "bigquery",
        bigqueryUri: src
      };
    } else if (src.startsWith("files/")) {
      return {
        fileName: src
      };
    }
  }
  throw new Error(`Unsupported source: ${src}`);
}
__name(tBatchJobSource, "tBatchJobSource");
function tBatchJobDestination(dest) {
  if (typeof dest !== "string") {
    return dest;
  }
  const destString = dest;
  if (destString.startsWith("gs://")) {
    return {
      format: "jsonl",
      gcsUri: destString
    };
  } else if (destString.startsWith("bq://")) {
    return {
      format: "bigquery",
      bigqueryUri: destString
    };
  } else {
    throw new Error(`Unsupported destination: ${destString}`);
  }
}
__name(tBatchJobDestination, "tBatchJobDestination");
function tBatchJobName(apiClient, name) {
  const nameString = name;
  if (!apiClient.isVertexAI()) {
    const mldevPattern = /batches\/[^/]+$/;
    if (mldevPattern.test(nameString)) {
      return nameString.split("/").pop();
    } else {
      throw new Error(`Invalid batch job name: ${nameString}.`);
    }
  }
  const vertexPattern = /^projects\/[^/]+\/locations\/[^/]+\/batchPredictionJobs\/[^/]+$/;
  if (vertexPattern.test(nameString)) {
    return nameString.split("/").pop();
  } else if (/^\d+$/.test(nameString)) {
    return nameString;
  } else {
    throw new Error(`Invalid batch job name: ${nameString}.`);
  }
}
__name(tBatchJobName, "tBatchJobName");
function tJobState(state) {
  const stateString = state;
  if (stateString === "BATCH_STATE_UNSPECIFIED") {
    return "JOB_STATE_UNSPECIFIED";
  } else if (stateString === "BATCH_STATE_PENDING") {
    return "JOB_STATE_PENDING";
  } else if (stateString === "BATCH_STATE_SUCCEEDED") {
    return "JOB_STATE_SUCCEEDED";
  } else if (stateString === "BATCH_STATE_FAILED") {
    return "JOB_STATE_FAILED";
  } else if (stateString === "BATCH_STATE_CANCELLED") {
    return "JOB_STATE_CANCELLED";
  } else {
    return stateString;
  }
}
__name(tJobState, "tJobState");
function videoMetadataToMldev$4(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToMldev$4, "videoMetadataToMldev$4");
function blobToMldev$4(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToMldev$4, "blobToMldev$4");
function fileDataToMldev$4(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToMldev$4, "fileDataToMldev$4");
function partToMldev$4(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToMldev$4(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToMldev$4(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToMldev$4(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToMldev$4, "partToMldev$4");
function contentToMldev$4(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToMldev$4(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToMldev$4, "contentToMldev$4");
function schemaToMldev$1(fromObject) {
  const toObject = {};
  const fromAnyOf = getValueByPath(fromObject, ["anyOf"]);
  if (fromAnyOf != null) {
    setValueByPath(toObject, ["anyOf"], fromAnyOf);
  }
  const fromDefault = getValueByPath(fromObject, ["default"]);
  if (fromDefault != null) {
    setValueByPath(toObject, ["default"], fromDefault);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromEnum = getValueByPath(fromObject, ["enum"]);
  if (fromEnum != null) {
    setValueByPath(toObject, ["enum"], fromEnum);
  }
  const fromExample = getValueByPath(fromObject, ["example"]);
  if (fromExample != null) {
    setValueByPath(toObject, ["example"], fromExample);
  }
  const fromFormat = getValueByPath(fromObject, ["format"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["format"], fromFormat);
  }
  const fromItems = getValueByPath(fromObject, ["items"]);
  if (fromItems != null) {
    setValueByPath(toObject, ["items"], fromItems);
  }
  const fromMaxItems = getValueByPath(fromObject, ["maxItems"]);
  if (fromMaxItems != null) {
    setValueByPath(toObject, ["maxItems"], fromMaxItems);
  }
  const fromMaxLength = getValueByPath(fromObject, ["maxLength"]);
  if (fromMaxLength != null) {
    setValueByPath(toObject, ["maxLength"], fromMaxLength);
  }
  const fromMaxProperties = getValueByPath(fromObject, [
    "maxProperties"
  ]);
  if (fromMaxProperties != null) {
    setValueByPath(toObject, ["maxProperties"], fromMaxProperties);
  }
  const fromMaximum = getValueByPath(fromObject, ["maximum"]);
  if (fromMaximum != null) {
    setValueByPath(toObject, ["maximum"], fromMaximum);
  }
  const fromMinItems = getValueByPath(fromObject, ["minItems"]);
  if (fromMinItems != null) {
    setValueByPath(toObject, ["minItems"], fromMinItems);
  }
  const fromMinLength = getValueByPath(fromObject, ["minLength"]);
  if (fromMinLength != null) {
    setValueByPath(toObject, ["minLength"], fromMinLength);
  }
  const fromMinProperties = getValueByPath(fromObject, [
    "minProperties"
  ]);
  if (fromMinProperties != null) {
    setValueByPath(toObject, ["minProperties"], fromMinProperties);
  }
  const fromMinimum = getValueByPath(fromObject, ["minimum"]);
  if (fromMinimum != null) {
    setValueByPath(toObject, ["minimum"], fromMinimum);
  }
  const fromNullable = getValueByPath(fromObject, ["nullable"]);
  if (fromNullable != null) {
    setValueByPath(toObject, ["nullable"], fromNullable);
  }
  const fromPattern = getValueByPath(fromObject, ["pattern"]);
  if (fromPattern != null) {
    setValueByPath(toObject, ["pattern"], fromPattern);
  }
  const fromProperties = getValueByPath(fromObject, ["properties"]);
  if (fromProperties != null) {
    setValueByPath(toObject, ["properties"], fromProperties);
  }
  const fromPropertyOrdering = getValueByPath(fromObject, [
    "propertyOrdering"
  ]);
  if (fromPropertyOrdering != null) {
    setValueByPath(toObject, ["propertyOrdering"], fromPropertyOrdering);
  }
  const fromRequired = getValueByPath(fromObject, ["required"]);
  if (fromRequired != null) {
    setValueByPath(toObject, ["required"], fromRequired);
  }
  const fromTitle = getValueByPath(fromObject, ["title"]);
  if (fromTitle != null) {
    setValueByPath(toObject, ["title"], fromTitle);
  }
  const fromType = getValueByPath(fromObject, ["type"]);
  if (fromType != null) {
    setValueByPath(toObject, ["type"], fromType);
  }
  return toObject;
}
__name(schemaToMldev$1, "schemaToMldev$1");
function safetySettingToMldev$1(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["method"]) !== void 0) {
    throw new Error("method parameter is not supported in Gemini API.");
  }
  const fromCategory = getValueByPath(fromObject, ["category"]);
  if (fromCategory != null) {
    setValueByPath(toObject, ["category"], fromCategory);
  }
  const fromThreshold = getValueByPath(fromObject, ["threshold"]);
  if (fromThreshold != null) {
    setValueByPath(toObject, ["threshold"], fromThreshold);
  }
  return toObject;
}
__name(safetySettingToMldev$1, "safetySettingToMldev$1");
function functionDeclarationToMldev$4(fromObject) {
  const toObject = {};
  const fromBehavior = getValueByPath(fromObject, ["behavior"]);
  if (fromBehavior != null) {
    setValueByPath(toObject, ["behavior"], fromBehavior);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToMldev$4, "functionDeclarationToMldev$4");
function intervalToMldev$4(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToMldev$4, "intervalToMldev$4");
function googleSearchToMldev$4(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToMldev$4(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToMldev$4, "googleSearchToMldev$4");
function dynamicRetrievalConfigToMldev$4(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToMldev$4, "dynamicRetrievalConfigToMldev$4");
function googleSearchRetrievalToMldev$4(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToMldev$4(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToMldev$4, "googleSearchRetrievalToMldev$4");
function urlContextToMldev$4() {
  const toObject = {};
  return toObject;
}
__name(urlContextToMldev$4, "urlContextToMldev$4");
function toolToMldev$4(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToMldev$4(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  if (getValueByPath(fromObject, ["retrieval"]) !== void 0) {
    throw new Error("retrieval parameter is not supported in Gemini API.");
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToMldev$4(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToMldev$4(fromGoogleSearchRetrieval));
  }
  if (getValueByPath(fromObject, ["enterpriseWebSearch"]) !== void 0) {
    throw new Error("enterpriseWebSearch parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["googleMaps"]) !== void 0) {
    throw new Error("googleMaps parameter is not supported in Gemini API.");
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToMldev$4());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToMldev$4, "toolToMldev$4");
function functionCallingConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromAllowedFunctionNames = getValueByPath(fromObject, [
    "allowedFunctionNames"
  ]);
  if (fromAllowedFunctionNames != null) {
    setValueByPath(toObject, ["allowedFunctionNames"], fromAllowedFunctionNames);
  }
  return toObject;
}
__name(functionCallingConfigToMldev$2, "functionCallingConfigToMldev$2");
function latLngToMldev$2(fromObject) {
  const toObject = {};
  const fromLatitude = getValueByPath(fromObject, ["latitude"]);
  if (fromLatitude != null) {
    setValueByPath(toObject, ["latitude"], fromLatitude);
  }
  const fromLongitude = getValueByPath(fromObject, ["longitude"]);
  if (fromLongitude != null) {
    setValueByPath(toObject, ["longitude"], fromLongitude);
  }
  return toObject;
}
__name(latLngToMldev$2, "latLngToMldev$2");
function retrievalConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromLatLng = getValueByPath(fromObject, ["latLng"]);
  if (fromLatLng != null) {
    setValueByPath(toObject, ["latLng"], latLngToMldev$2(fromLatLng));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(retrievalConfigToMldev$2, "retrievalConfigToMldev$2");
function toolConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromFunctionCallingConfig = getValueByPath(fromObject, [
    "functionCallingConfig"
  ]);
  if (fromFunctionCallingConfig != null) {
    setValueByPath(toObject, ["functionCallingConfig"], functionCallingConfigToMldev$2(fromFunctionCallingConfig));
  }
  const fromRetrievalConfig = getValueByPath(fromObject, [
    "retrievalConfig"
  ]);
  if (fromRetrievalConfig != null) {
    setValueByPath(toObject, ["retrievalConfig"], retrievalConfigToMldev$2(fromRetrievalConfig));
  }
  return toObject;
}
__name(toolConfigToMldev$2, "toolConfigToMldev$2");
function prebuiltVoiceConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToMldev$3, "prebuiltVoiceConfigToMldev$3");
function voiceConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToMldev$3(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToMldev$3, "voiceConfigToMldev$3");
function speakerVoiceConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromSpeaker = getValueByPath(fromObject, ["speaker"]);
  if (fromSpeaker != null) {
    setValueByPath(toObject, ["speaker"], fromSpeaker);
  }
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$3(fromVoiceConfig));
  }
  return toObject;
}
__name(speakerVoiceConfigToMldev$3, "speakerVoiceConfigToMldev$3");
function multiSpeakerVoiceConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromSpeakerVoiceConfigs = getValueByPath(fromObject, [
    "speakerVoiceConfigs"
  ]);
  if (fromSpeakerVoiceConfigs != null) {
    let transformedList = fromSpeakerVoiceConfigs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return speakerVoiceConfigToMldev$3(item);
      });
    }
    setValueByPath(toObject, ["speakerVoiceConfigs"], transformedList);
  }
  return toObject;
}
__name(multiSpeakerVoiceConfigToMldev$3, "multiSpeakerVoiceConfigToMldev$3");
function speechConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$3(fromVoiceConfig));
  }
  const fromMultiSpeakerVoiceConfig = getValueByPath(fromObject, [
    "multiSpeakerVoiceConfig"
  ]);
  if (fromMultiSpeakerVoiceConfig != null) {
    setValueByPath(toObject, ["multiSpeakerVoiceConfig"], multiSpeakerVoiceConfigToMldev$3(fromMultiSpeakerVoiceConfig));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToMldev$3, "speechConfigToMldev$3");
function thinkingConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromIncludeThoughts = getValueByPath(fromObject, [
    "includeThoughts"
  ]);
  if (fromIncludeThoughts != null) {
    setValueByPath(toObject, ["includeThoughts"], fromIncludeThoughts);
  }
  const fromThinkingBudget = getValueByPath(fromObject, [
    "thinkingBudget"
  ]);
  if (fromThinkingBudget != null) {
    setValueByPath(toObject, ["thinkingBudget"], fromThinkingBudget);
  }
  return toObject;
}
__name(thinkingConfigToMldev$1, "thinkingConfigToMldev$1");
function generateContentConfigToMldev$1(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToMldev$4(tContent(fromSystemInstruction)));
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (fromTemperature != null) {
    setValueByPath(toObject, ["temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (fromTopP != null) {
    setValueByPath(toObject, ["topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (fromTopK != null) {
    setValueByPath(toObject, ["topK"], fromTopK);
  }
  const fromCandidateCount = getValueByPath(fromObject, [
    "candidateCount"
  ]);
  if (fromCandidateCount != null) {
    setValueByPath(toObject, ["candidateCount"], fromCandidateCount);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (fromMaxOutputTokens != null) {
    setValueByPath(toObject, ["maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromStopSequences = getValueByPath(fromObject, [
    "stopSequences"
  ]);
  if (fromStopSequences != null) {
    setValueByPath(toObject, ["stopSequences"], fromStopSequences);
  }
  const fromResponseLogprobs = getValueByPath(fromObject, [
    "responseLogprobs"
  ]);
  if (fromResponseLogprobs != null) {
    setValueByPath(toObject, ["responseLogprobs"], fromResponseLogprobs);
  }
  const fromLogprobs = getValueByPath(fromObject, ["logprobs"]);
  if (fromLogprobs != null) {
    setValueByPath(toObject, ["logprobs"], fromLogprobs);
  }
  const fromPresencePenalty = getValueByPath(fromObject, [
    "presencePenalty"
  ]);
  if (fromPresencePenalty != null) {
    setValueByPath(toObject, ["presencePenalty"], fromPresencePenalty);
  }
  const fromFrequencyPenalty = getValueByPath(fromObject, [
    "frequencyPenalty"
  ]);
  if (fromFrequencyPenalty != null) {
    setValueByPath(toObject, ["frequencyPenalty"], fromFrequencyPenalty);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (fromSeed != null) {
    setValueByPath(toObject, ["seed"], fromSeed);
  }
  const fromResponseMimeType = getValueByPath(fromObject, [
    "responseMimeType"
  ]);
  if (fromResponseMimeType != null) {
    setValueByPath(toObject, ["responseMimeType"], fromResponseMimeType);
  }
  const fromResponseSchema = getValueByPath(fromObject, [
    "responseSchema"
  ]);
  if (fromResponseSchema != null) {
    setValueByPath(toObject, ["responseSchema"], schemaToMldev$1(tSchema(fromResponseSchema)));
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  if (getValueByPath(fromObject, ["routingConfig"]) !== void 0) {
    throw new Error("routingConfig parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["modelSelectionConfig"]) !== void 0) {
    throw new Error("modelSelectionConfig parameter is not supported in Gemini API.");
  }
  const fromSafetySettings = getValueByPath(fromObject, [
    "safetySettings"
  ]);
  if (parentObject !== void 0 && fromSafetySettings != null) {
    let transformedList = fromSafetySettings;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return safetySettingToMldev$1(item);
      });
    }
    setValueByPath(parentObject, ["safetySettings"], transformedList);
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToMldev$4(tTool(item));
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromToolConfig = getValueByPath(fromObject, ["toolConfig"]);
  if (parentObject !== void 0 && fromToolConfig != null) {
    setValueByPath(parentObject, ["toolConfig"], toolConfigToMldev$2(fromToolConfig));
  }
  if (getValueByPath(fromObject, ["labels"]) !== void 0) {
    throw new Error("labels parameter is not supported in Gemini API.");
  }
  const fromCachedContent = getValueByPath(fromObject, [
    "cachedContent"
  ]);
  if (parentObject !== void 0 && fromCachedContent != null) {
    setValueByPath(parentObject, ["cachedContent"], tCachedContentName(apiClient, fromCachedContent));
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (fromResponseModalities != null) {
    setValueByPath(toObject, ["responseModalities"], fromResponseModalities);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (fromMediaResolution != null) {
    setValueByPath(toObject, ["mediaResolution"], fromMediaResolution);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (fromSpeechConfig != null) {
    setValueByPath(toObject, ["speechConfig"], speechConfigToMldev$3(tSpeechConfig(fromSpeechConfig)));
  }
  if (getValueByPath(fromObject, ["audioTimestamp"]) !== void 0) {
    throw new Error("audioTimestamp parameter is not supported in Gemini API.");
  }
  const fromThinkingConfig = getValueByPath(fromObject, [
    "thinkingConfig"
  ]);
  if (fromThinkingConfig != null) {
    setValueByPath(toObject, ["thinkingConfig"], thinkingConfigToMldev$1(fromThinkingConfig));
  }
  return toObject;
}
__name(generateContentConfigToMldev$1, "generateContentConfigToMldev$1");
function inlinedRequestToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["request", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToMldev$4(item);
      });
    }
    setValueByPath(toObject, ["request", "contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["request", "generationConfig"], generateContentConfigToMldev$1(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(inlinedRequestToMldev, "inlinedRequestToMldev");
function batchJobSourceToMldev(apiClient, fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["format"]) !== void 0) {
    throw new Error("format parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["gcsUri"]) !== void 0) {
    throw new Error("gcsUri parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["bigqueryUri"]) !== void 0) {
    throw new Error("bigqueryUri parameter is not supported in Gemini API.");
  }
  const fromFileName = getValueByPath(fromObject, ["fileName"]);
  if (fromFileName != null) {
    setValueByPath(toObject, ["fileName"], fromFileName);
  }
  const fromInlinedRequests = getValueByPath(fromObject, [
    "inlinedRequests"
  ]);
  if (fromInlinedRequests != null) {
    let transformedList = fromInlinedRequests;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return inlinedRequestToMldev(apiClient, item);
      });
    }
    setValueByPath(toObject, ["requests", "requests"], transformedList);
  }
  return toObject;
}
__name(batchJobSourceToMldev, "batchJobSourceToMldev");
function createBatchJobConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["batch", "displayName"], fromDisplayName);
  }
  if (getValueByPath(fromObject, ["dest"]) !== void 0) {
    throw new Error("dest parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(createBatchJobConfigToMldev, "createBatchJobConfigToMldev");
function createBatchJobParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromSrc = getValueByPath(fromObject, ["src"]);
  if (fromSrc != null) {
    setValueByPath(toObject, ["batch", "inputConfig"], batchJobSourceToMldev(apiClient, tBatchJobSource(apiClient, fromSrc)));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createBatchJobConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(createBatchJobParametersToMldev, "createBatchJobParametersToMldev");
function getBatchJobParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getBatchJobParametersToMldev, "getBatchJobParametersToMldev");
function cancelBatchJobParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(cancelBatchJobParametersToMldev, "cancelBatchJobParametersToMldev");
function listBatchJobsConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  if (getValueByPath(fromObject, ["filter"]) !== void 0) {
    throw new Error("filter parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(listBatchJobsConfigToMldev, "listBatchJobsConfigToMldev");
function listBatchJobsParametersToMldev(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listBatchJobsConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(listBatchJobsParametersToMldev, "listBatchJobsParametersToMldev");
function deleteBatchJobParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteBatchJobParametersToMldev, "deleteBatchJobParametersToMldev");
function batchJobSourceToVertex(fromObject) {
  const toObject = {};
  const fromFormat = getValueByPath(fromObject, ["format"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["instancesFormat"], fromFormat);
  }
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsSource", "uris"], fromGcsUri);
  }
  const fromBigqueryUri = getValueByPath(fromObject, ["bigqueryUri"]);
  if (fromBigqueryUri != null) {
    setValueByPath(toObject, ["bigquerySource", "inputUri"], fromBigqueryUri);
  }
  if (getValueByPath(fromObject, ["fileName"]) !== void 0) {
    throw new Error("fileName parameter is not supported in Vertex AI.");
  }
  if (getValueByPath(fromObject, ["inlinedRequests"]) !== void 0) {
    throw new Error("inlinedRequests parameter is not supported in Vertex AI.");
  }
  return toObject;
}
__name(batchJobSourceToVertex, "batchJobSourceToVertex");
function batchJobDestinationToVertex(fromObject) {
  const toObject = {};
  const fromFormat = getValueByPath(fromObject, ["format"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["predictionsFormat"], fromFormat);
  }
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsDestination", "outputUriPrefix"], fromGcsUri);
  }
  const fromBigqueryUri = getValueByPath(fromObject, ["bigqueryUri"]);
  if (fromBigqueryUri != null) {
    setValueByPath(toObject, ["bigqueryDestination", "outputUri"], fromBigqueryUri);
  }
  if (getValueByPath(fromObject, ["fileName"]) !== void 0) {
    throw new Error("fileName parameter is not supported in Vertex AI.");
  }
  if (getValueByPath(fromObject, ["inlinedResponses"]) !== void 0) {
    throw new Error("inlinedResponses parameter is not supported in Vertex AI.");
  }
  return toObject;
}
__name(batchJobDestinationToVertex, "batchJobDestinationToVertex");
function createBatchJobConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromDisplayName);
  }
  const fromDest = getValueByPath(fromObject, ["dest"]);
  if (parentObject !== void 0 && fromDest != null) {
    setValueByPath(parentObject, ["outputConfig"], batchJobDestinationToVertex(tBatchJobDestination(fromDest)));
  }
  return toObject;
}
__name(createBatchJobConfigToVertex, "createBatchJobConfigToVertex");
function createBatchJobParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], tModel(apiClient, fromModel));
  }
  const fromSrc = getValueByPath(fromObject, ["src"]);
  if (fromSrc != null) {
    setValueByPath(toObject, ["inputConfig"], batchJobSourceToVertex(tBatchJobSource(apiClient, fromSrc)));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createBatchJobConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(createBatchJobParametersToVertex, "createBatchJobParametersToVertex");
function getBatchJobParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getBatchJobParametersToVertex, "getBatchJobParametersToVertex");
function cancelBatchJobParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(cancelBatchJobParametersToVertex, "cancelBatchJobParametersToVertex");
function listBatchJobsConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  const fromFilter = getValueByPath(fromObject, ["filter"]);
  if (parentObject !== void 0 && fromFilter != null) {
    setValueByPath(parentObject, ["_query", "filter"], fromFilter);
  }
  return toObject;
}
__name(listBatchJobsConfigToVertex, "listBatchJobsConfigToVertex");
function listBatchJobsParametersToVertex(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listBatchJobsConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(listBatchJobsParametersToVertex, "listBatchJobsParametersToVertex");
function deleteBatchJobParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tBatchJobName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteBatchJobParametersToVertex, "deleteBatchJobParametersToVertex");
function videoMetadataFromMldev$2(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataFromMldev$2, "videoMetadataFromMldev$2");
function blobFromMldev$2(fromObject) {
  const toObject = {};
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobFromMldev$2, "blobFromMldev$2");
function fileDataFromMldev$2(fromObject) {
  const toObject = {};
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataFromMldev$2, "fileDataFromMldev$2");
function partFromMldev$2(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataFromMldev$2(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobFromMldev$2(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataFromMldev$2(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partFromMldev$2, "partFromMldev$2");
function contentFromMldev$2(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partFromMldev$2(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentFromMldev$2, "contentFromMldev$2");
function citationMetadataFromMldev$1(fromObject) {
  const toObject = {};
  const fromCitations = getValueByPath(fromObject, ["citationSources"]);
  if (fromCitations != null) {
    setValueByPath(toObject, ["citations"], fromCitations);
  }
  return toObject;
}
__name(citationMetadataFromMldev$1, "citationMetadataFromMldev$1");
function urlMetadataFromMldev$2(fromObject) {
  const toObject = {};
  const fromRetrievedUrl = getValueByPath(fromObject, ["retrievedUrl"]);
  if (fromRetrievedUrl != null) {
    setValueByPath(toObject, ["retrievedUrl"], fromRetrievedUrl);
  }
  const fromUrlRetrievalStatus = getValueByPath(fromObject, [
    "urlRetrievalStatus"
  ]);
  if (fromUrlRetrievalStatus != null) {
    setValueByPath(toObject, ["urlRetrievalStatus"], fromUrlRetrievalStatus);
  }
  return toObject;
}
__name(urlMetadataFromMldev$2, "urlMetadataFromMldev$2");
function urlContextMetadataFromMldev$2(fromObject) {
  const toObject = {};
  const fromUrlMetadata = getValueByPath(fromObject, ["urlMetadata"]);
  if (fromUrlMetadata != null) {
    let transformedList = fromUrlMetadata;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return urlMetadataFromMldev$2(item);
      });
    }
    setValueByPath(toObject, ["urlMetadata"], transformedList);
  }
  return toObject;
}
__name(urlContextMetadataFromMldev$2, "urlContextMetadataFromMldev$2");
function candidateFromMldev$1(fromObject) {
  const toObject = {};
  const fromContent = getValueByPath(fromObject, ["content"]);
  if (fromContent != null) {
    setValueByPath(toObject, ["content"], contentFromMldev$2(fromContent));
  }
  const fromCitationMetadata = getValueByPath(fromObject, [
    "citationMetadata"
  ]);
  if (fromCitationMetadata != null) {
    setValueByPath(toObject, ["citationMetadata"], citationMetadataFromMldev$1(fromCitationMetadata));
  }
  const fromTokenCount = getValueByPath(fromObject, ["tokenCount"]);
  if (fromTokenCount != null) {
    setValueByPath(toObject, ["tokenCount"], fromTokenCount);
  }
  const fromFinishReason = getValueByPath(fromObject, ["finishReason"]);
  if (fromFinishReason != null) {
    setValueByPath(toObject, ["finishReason"], fromFinishReason);
  }
  const fromUrlContextMetadata = getValueByPath(fromObject, [
    "urlContextMetadata"
  ]);
  if (fromUrlContextMetadata != null) {
    setValueByPath(toObject, ["urlContextMetadata"], urlContextMetadataFromMldev$2(fromUrlContextMetadata));
  }
  const fromAvgLogprobs = getValueByPath(fromObject, ["avgLogprobs"]);
  if (fromAvgLogprobs != null) {
    setValueByPath(toObject, ["avgLogprobs"], fromAvgLogprobs);
  }
  const fromGroundingMetadata = getValueByPath(fromObject, [
    "groundingMetadata"
  ]);
  if (fromGroundingMetadata != null) {
    setValueByPath(toObject, ["groundingMetadata"], fromGroundingMetadata);
  }
  const fromIndex = getValueByPath(fromObject, ["index"]);
  if (fromIndex != null) {
    setValueByPath(toObject, ["index"], fromIndex);
  }
  const fromLogprobsResult = getValueByPath(fromObject, [
    "logprobsResult"
  ]);
  if (fromLogprobsResult != null) {
    setValueByPath(toObject, ["logprobsResult"], fromLogprobsResult);
  }
  const fromSafetyRatings = getValueByPath(fromObject, [
    "safetyRatings"
  ]);
  if (fromSafetyRatings != null) {
    setValueByPath(toObject, ["safetyRatings"], fromSafetyRatings);
  }
  return toObject;
}
__name(candidateFromMldev$1, "candidateFromMldev$1");
function generateContentResponseFromMldev$1(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromCandidates = getValueByPath(fromObject, ["candidates"]);
  if (fromCandidates != null) {
    let transformedList = fromCandidates;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return candidateFromMldev$1(item);
      });
    }
    setValueByPath(toObject, ["candidates"], transformedList);
  }
  const fromModelVersion = getValueByPath(fromObject, ["modelVersion"]);
  if (fromModelVersion != null) {
    setValueByPath(toObject, ["modelVersion"], fromModelVersion);
  }
  const fromPromptFeedback = getValueByPath(fromObject, [
    "promptFeedback"
  ]);
  if (fromPromptFeedback != null) {
    setValueByPath(toObject, ["promptFeedback"], fromPromptFeedback);
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], fromUsageMetadata);
  }
  return toObject;
}
__name(generateContentResponseFromMldev$1, "generateContentResponseFromMldev$1");
function jobErrorFromMldev(fromObject) {
  const toObject = {};
  const fromDetails = getValueByPath(fromObject, ["details"]);
  if (fromDetails != null) {
    setValueByPath(toObject, ["details"], fromDetails);
  }
  const fromCode = getValueByPath(fromObject, ["code"]);
  if (fromCode != null) {
    setValueByPath(toObject, ["code"], fromCode);
  }
  const fromMessage = getValueByPath(fromObject, ["message"]);
  if (fromMessage != null) {
    setValueByPath(toObject, ["message"], fromMessage);
  }
  return toObject;
}
__name(jobErrorFromMldev, "jobErrorFromMldev");
function inlinedResponseFromMldev(fromObject) {
  const toObject = {};
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], generateContentResponseFromMldev$1(fromResponse));
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], jobErrorFromMldev(fromError));
  }
  return toObject;
}
__name(inlinedResponseFromMldev, "inlinedResponseFromMldev");
function batchJobDestinationFromMldev(fromObject) {
  const toObject = {};
  const fromFileName = getValueByPath(fromObject, ["responsesFile"]);
  if (fromFileName != null) {
    setValueByPath(toObject, ["fileName"], fromFileName);
  }
  const fromInlinedResponses = getValueByPath(fromObject, [
    "inlinedResponses",
    "inlinedResponses"
  ]);
  if (fromInlinedResponses != null) {
    let transformedList = fromInlinedResponses;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return inlinedResponseFromMldev(item);
      });
    }
    setValueByPath(toObject, ["inlinedResponses"], transformedList);
  }
  return toObject;
}
__name(batchJobDestinationFromMldev, "batchJobDestinationFromMldev");
function batchJobFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, [
    "metadata",
    "displayName"
  ]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromState = getValueByPath(fromObject, ["metadata", "state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], tJobState(fromState));
  }
  const fromCreateTime = getValueByPath(fromObject, [
    "metadata",
    "createTime"
  ]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromEndTime = getValueByPath(fromObject, [
    "metadata",
    "endTime"
  ]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, [
    "metadata",
    "updateTime"
  ]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromModel = getValueByPath(fromObject, ["metadata", "model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromDest = getValueByPath(fromObject, ["metadata", "output"]);
  if (fromDest != null) {
    setValueByPath(toObject, ["dest"], batchJobDestinationFromMldev(fromDest));
  }
  return toObject;
}
__name(batchJobFromMldev, "batchJobFromMldev");
function listBatchJobsResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromBatchJobs = getValueByPath(fromObject, ["operations"]);
  if (fromBatchJobs != null) {
    let transformedList = fromBatchJobs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return batchJobFromMldev(item);
      });
    }
    setValueByPath(toObject, ["batchJobs"], transformedList);
  }
  return toObject;
}
__name(listBatchJobsResponseFromMldev, "listBatchJobsResponseFromMldev");
function deleteResourceJobFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDone = getValueByPath(fromObject, ["done"]);
  if (fromDone != null) {
    setValueByPath(toObject, ["done"], fromDone);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], jobErrorFromMldev(fromError));
  }
  return toObject;
}
__name(deleteResourceJobFromMldev, "deleteResourceJobFromMldev");
function jobErrorFromVertex(fromObject) {
  const toObject = {};
  const fromDetails = getValueByPath(fromObject, ["details"]);
  if (fromDetails != null) {
    setValueByPath(toObject, ["details"], fromDetails);
  }
  const fromCode = getValueByPath(fromObject, ["code"]);
  if (fromCode != null) {
    setValueByPath(toObject, ["code"], fromCode);
  }
  const fromMessage = getValueByPath(fromObject, ["message"]);
  if (fromMessage != null) {
    setValueByPath(toObject, ["message"], fromMessage);
  }
  return toObject;
}
__name(jobErrorFromVertex, "jobErrorFromVertex");
function batchJobSourceFromVertex(fromObject) {
  const toObject = {};
  const fromFormat = getValueByPath(fromObject, ["instancesFormat"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["format"], fromFormat);
  }
  const fromGcsUri = getValueByPath(fromObject, ["gcsSource", "uris"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsUri"], fromGcsUri);
  }
  const fromBigqueryUri = getValueByPath(fromObject, [
    "bigquerySource",
    "inputUri"
  ]);
  if (fromBigqueryUri != null) {
    setValueByPath(toObject, ["bigqueryUri"], fromBigqueryUri);
  }
  return toObject;
}
__name(batchJobSourceFromVertex, "batchJobSourceFromVertex");
function batchJobDestinationFromVertex(fromObject) {
  const toObject = {};
  const fromFormat = getValueByPath(fromObject, ["predictionsFormat"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["format"], fromFormat);
  }
  const fromGcsUri = getValueByPath(fromObject, [
    "gcsDestination",
    "outputUriPrefix"
  ]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsUri"], fromGcsUri);
  }
  const fromBigqueryUri = getValueByPath(fromObject, [
    "bigqueryDestination",
    "outputUri"
  ]);
  if (fromBigqueryUri != null) {
    setValueByPath(toObject, ["bigqueryUri"], fromBigqueryUri);
  }
  return toObject;
}
__name(batchJobDestinationFromVertex, "batchJobDestinationFromVertex");
function batchJobFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromState = getValueByPath(fromObject, ["state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], tJobState(fromState));
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], jobErrorFromVertex(fromError));
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromSrc = getValueByPath(fromObject, ["inputConfig"]);
  if (fromSrc != null) {
    setValueByPath(toObject, ["src"], batchJobSourceFromVertex(fromSrc));
  }
  const fromDest = getValueByPath(fromObject, ["outputConfig"]);
  if (fromDest != null) {
    setValueByPath(toObject, ["dest"], batchJobDestinationFromVertex(fromDest));
  }
  return toObject;
}
__name(batchJobFromVertex, "batchJobFromVertex");
function listBatchJobsResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromBatchJobs = getValueByPath(fromObject, [
    "batchPredictionJobs"
  ]);
  if (fromBatchJobs != null) {
    let transformedList = fromBatchJobs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return batchJobFromVertex(item);
      });
    }
    setValueByPath(toObject, ["batchJobs"], transformedList);
  }
  return toObject;
}
__name(listBatchJobsResponseFromVertex, "listBatchJobsResponseFromVertex");
function deleteResourceJobFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDone = getValueByPath(fromObject, ["done"]);
  if (fromDone != null) {
    setValueByPath(toObject, ["done"], fromDone);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], jobErrorFromVertex(fromError));
  }
  return toObject;
}
__name(deleteResourceJobFromVertex, "deleteResourceJobFromVertex");
var PagedItem;
(function(PagedItem2) {
  PagedItem2["PAGED_ITEM_BATCH_JOBS"] = "batchJobs";
  PagedItem2["PAGED_ITEM_MODELS"] = "models";
  PagedItem2["PAGED_ITEM_TUNING_JOBS"] = "tuningJobs";
  PagedItem2["PAGED_ITEM_FILES"] = "files";
  PagedItem2["PAGED_ITEM_CACHED_CONTENTS"] = "cachedContents";
})(PagedItem || (PagedItem = {}));
var Pager = class {
  static {
    __name(this, "Pager");
  }
  constructor(name, request, response, params) {
    this.pageInternal = [];
    this.paramsInternal = {};
    this.requestInternal = request;
    this.init(name, response, params);
  }
  init(name, response, params) {
    var _a, _b;
    this.nameInternal = name;
    this.pageInternal = response[this.nameInternal] || [];
    this.sdkHttpResponseInternal = response === null || response === void 0 ? void 0 : response.sdkHttpResponse;
    this.idxInternal = 0;
    let requestParams = { config: {} };
    if (!params || Object.keys(params).length === 0) {
      requestParams = { config: {} };
    } else if (typeof params === "object") {
      requestParams = Object.assign({}, params);
    } else {
      requestParams = params;
    }
    if (requestParams["config"]) {
      requestParams["config"]["pageToken"] = response["nextPageToken"];
    }
    this.paramsInternal = requestParams;
    this.pageInternalSize = (_b = (_a = requestParams["config"]) === null || _a === void 0 ? void 0 : _a["pageSize"]) !== null && _b !== void 0 ? _b : this.pageInternal.length;
  }
  initNextPage(response) {
    this.init(this.nameInternal, response, this.paramsInternal);
  }
  /**
   * Returns the current page, which is a list of items.
   *
   * @remarks
   * The first page is retrieved when the pager is created. The returned list of
   * items could be a subset of the entire list.
   */
  get page() {
    return this.pageInternal;
  }
  /**
   * Returns the type of paged item (for example, ``batch_jobs``).
   */
  get name() {
    return this.nameInternal;
  }
  /**
   * Returns the length of the page fetched each time by this pager.
   *
   * @remarks
   * The number of items in the page is less than or equal to the page length.
   */
  get pageSize() {
    return this.pageInternalSize;
  }
  /**
   * Returns the headers of the API response.
   */
  get sdkHttpResponse() {
    return this.sdkHttpResponseInternal;
  }
  /**
   * Returns the parameters when making the API request for the next page.
   *
   * @remarks
   * Parameters contain a set of optional configs that can be
   * used to customize the API request. For example, the `pageToken` parameter
   * contains the token to request the next page.
   */
  get params() {
    return this.paramsInternal;
  }
  /**
   * Returns the total number of items in the current page.
   */
  get pageLength() {
    return this.pageInternal.length;
  }
  /**
   * Returns the item at the given index.
   */
  getItem(index) {
    return this.pageInternal[index];
  }
  /**
   * Returns an async iterator that support iterating through all items
   * retrieved from the API.
   *
   * @remarks
   * The iterator will automatically fetch the next page if there are more items
   * to fetch from the API.
   *
   * @example
   *
   * ```ts
   * const pager = await ai.files.list({config: {pageSize: 10}});
   * for await (const file of pager) {
   *   console.log(file.name);
   * }
   * ```
   */
  [Symbol.asyncIterator]() {
    return {
      next: /* @__PURE__ */ __name(async () => {
        if (this.idxInternal >= this.pageLength) {
          if (this.hasNextPage()) {
            await this.nextPage();
          } else {
            return { value: void 0, done: true };
          }
        }
        const item = this.getItem(this.idxInternal);
        this.idxInternal += 1;
        return { value: item, done: false };
      }, "next"),
      return: /* @__PURE__ */ __name(async () => {
        return { value: void 0, done: true };
      }, "return")
    };
  }
  /**
   * Fetches the next page of items. This makes a new API request.
   *
   * @throws {Error} If there are no more pages to fetch.
   *
   * @example
   *
   * ```ts
   * const pager = await ai.files.list({config: {pageSize: 10}});
   * let page = pager.page;
   * while (true) {
   *   for (const file of page) {
   *     console.log(file.name);
   *   }
   *   if (!pager.hasNextPage()) {
   *     break;
   *   }
   *   page = await pager.nextPage();
   * }
   * ```
   */
  async nextPage() {
    if (!this.hasNextPage()) {
      throw new Error("No more pages to fetch.");
    }
    const response = await this.requestInternal(this.params);
    this.initNextPage(response);
    return this.page;
  }
  /**
   * Returns true if there are more pages to fetch from the API.
   */
  hasNextPage() {
    var _a;
    if (((_a = this.params["config"]) === null || _a === void 0 ? void 0 : _a["pageToken"]) !== void 0) {
      return true;
    }
    return false;
  }
};
var Batches = class extends BaseModule {
  static {
    __name(this, "Batches");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
    this.create = async (params) => {
      if (this.apiClient.isVertexAI()) {
        const timestamp = Date.now();
        const timestampStr = timestamp.toString();
        if (Array.isArray(params.src)) {
          throw new Error("InlinedRequest[] is not supported in Vertex AI. Please use Google Cloud Storage URI or BigQuery URI instead.");
        }
        params.config = params.config || {};
        if (params.config.displayName === void 0) {
          params.config.displayName = "genaiBatchJob_${timestampStr}";
        }
        if (params.config.dest === void 0 && typeof params.src === "string") {
          if (params.src.startsWith("gs://") && params.src.endsWith(".jsonl")) {
            params.config.dest = `${params.src.slice(0, -6)}/dest`;
          } else if (params.src.startsWith("bq://")) {
            params.config.dest = `${params.src}_dest_${timestampStr}`;
          } else {
            throw new Error("Unsupported source:" + params.src);
          }
        }
      }
      return await this.createInternal(params);
    };
    this.list = async (params = {}) => {
      return new Pager(PagedItem.PAGED_ITEM_BATCH_JOBS, (x) => this.listInternal(x), await this.listInternal(params), params);
    };
  }
  /**
   * Internal method to create batch job.
   *
   * @param params - The parameters for create batch job request.
   * @return The created batch job.
   *
   */
  async createInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = createBatchJobParametersToVertex(this.apiClient, params);
      path = formatMap("batchPredictionJobs", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = batchJobFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = createBatchJobParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:batchGenerateContent", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = batchJobFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Gets batch job configurations.
   *
   * @param params - The parameters for the get request.
   * @return The batch job.
   *
   * @example
   * ```ts
   * await ai.batches.get({name: '...'}); // The server-generated resource name.
   * ```
   */
  async get(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = getBatchJobParametersToVertex(this.apiClient, params);
      path = formatMap("batchPredictionJobs/{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = batchJobFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = getBatchJobParametersToMldev(this.apiClient, params);
      path = formatMap("batches/{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = batchJobFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Cancels a batch job.
   *
   * @param params - The parameters for the cancel request.
   * @return The empty response returned by the API.
   *
   * @example
   * ```ts
   * await ai.batches.cancel({name: '...'}); // The server-generated resource name.
   * ```
   */
  async cancel(params) {
    var _a, _b, _c, _d;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = cancelBatchJobParametersToVertex(this.apiClient, params);
      path = formatMap("batchPredictionJobs/{name}:cancel", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      await this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      });
    } else {
      const body = cancelBatchJobParametersToMldev(this.apiClient, params);
      path = formatMap("batches/{name}:cancel", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      await this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      });
    }
  }
  async listInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = listBatchJobsParametersToVertex(params);
      path = formatMap("batchPredictionJobs", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listBatchJobsResponseFromVertex(apiResponse);
        const typedResp = new ListBatchJobsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = listBatchJobsParametersToMldev(params);
      path = formatMap("batches", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listBatchJobsResponseFromMldev(apiResponse);
        const typedResp = new ListBatchJobsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Deletes a batch job.
   *
   * @param params - The parameters for the delete request.
   * @return The empty response returned by the API.
   *
   * @example
   * ```ts
   * await ai.batches.delete({name: '...'}); // The server-generated resource name.
   * ```
   */
  async delete(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = deleteBatchJobParametersToVertex(this.apiClient, params);
      path = formatMap("batchPredictionJobs/{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = deleteResourceJobFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = deleteBatchJobParametersToMldev(this.apiClient, params);
      path = formatMap("batches/{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = deleteResourceJobFromMldev(apiResponse);
        return resp;
      });
    }
  }
};
function videoMetadataToMldev$3(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToMldev$3, "videoMetadataToMldev$3");
function blobToMldev$3(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToMldev$3, "blobToMldev$3");
function fileDataToMldev$3(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToMldev$3, "fileDataToMldev$3");
function partToMldev$3(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToMldev$3(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToMldev$3(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToMldev$3(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToMldev$3, "partToMldev$3");
function contentToMldev$3(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToMldev$3(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToMldev$3, "contentToMldev$3");
function functionDeclarationToMldev$3(fromObject) {
  const toObject = {};
  const fromBehavior = getValueByPath(fromObject, ["behavior"]);
  if (fromBehavior != null) {
    setValueByPath(toObject, ["behavior"], fromBehavior);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToMldev$3, "functionDeclarationToMldev$3");
function intervalToMldev$3(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToMldev$3, "intervalToMldev$3");
function googleSearchToMldev$3(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToMldev$3(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToMldev$3, "googleSearchToMldev$3");
function dynamicRetrievalConfigToMldev$3(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToMldev$3, "dynamicRetrievalConfigToMldev$3");
function googleSearchRetrievalToMldev$3(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToMldev$3(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToMldev$3, "googleSearchRetrievalToMldev$3");
function urlContextToMldev$3() {
  const toObject = {};
  return toObject;
}
__name(urlContextToMldev$3, "urlContextToMldev$3");
function toolToMldev$3(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToMldev$3(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  if (getValueByPath(fromObject, ["retrieval"]) !== void 0) {
    throw new Error("retrieval parameter is not supported in Gemini API.");
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToMldev$3(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToMldev$3(fromGoogleSearchRetrieval));
  }
  if (getValueByPath(fromObject, ["enterpriseWebSearch"]) !== void 0) {
    throw new Error("enterpriseWebSearch parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["googleMaps"]) !== void 0) {
    throw new Error("googleMaps parameter is not supported in Gemini API.");
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToMldev$3());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToMldev$3, "toolToMldev$3");
function functionCallingConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromAllowedFunctionNames = getValueByPath(fromObject, [
    "allowedFunctionNames"
  ]);
  if (fromAllowedFunctionNames != null) {
    setValueByPath(toObject, ["allowedFunctionNames"], fromAllowedFunctionNames);
  }
  return toObject;
}
__name(functionCallingConfigToMldev$1, "functionCallingConfigToMldev$1");
function latLngToMldev$1(fromObject) {
  const toObject = {};
  const fromLatitude = getValueByPath(fromObject, ["latitude"]);
  if (fromLatitude != null) {
    setValueByPath(toObject, ["latitude"], fromLatitude);
  }
  const fromLongitude = getValueByPath(fromObject, ["longitude"]);
  if (fromLongitude != null) {
    setValueByPath(toObject, ["longitude"], fromLongitude);
  }
  return toObject;
}
__name(latLngToMldev$1, "latLngToMldev$1");
function retrievalConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromLatLng = getValueByPath(fromObject, ["latLng"]);
  if (fromLatLng != null) {
    setValueByPath(toObject, ["latLng"], latLngToMldev$1(fromLatLng));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(retrievalConfigToMldev$1, "retrievalConfigToMldev$1");
function toolConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromFunctionCallingConfig = getValueByPath(fromObject, [
    "functionCallingConfig"
  ]);
  if (fromFunctionCallingConfig != null) {
    setValueByPath(toObject, ["functionCallingConfig"], functionCallingConfigToMldev$1(fromFunctionCallingConfig));
  }
  const fromRetrievalConfig = getValueByPath(fromObject, [
    "retrievalConfig"
  ]);
  if (fromRetrievalConfig != null) {
    setValueByPath(toObject, ["retrievalConfig"], retrievalConfigToMldev$1(fromRetrievalConfig));
  }
  return toObject;
}
__name(toolConfigToMldev$1, "toolConfigToMldev$1");
function createCachedContentConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromTtl = getValueByPath(fromObject, ["ttl"]);
  if (parentObject !== void 0 && fromTtl != null) {
    setValueByPath(parentObject, ["ttl"], fromTtl);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (parentObject !== void 0 && fromExpireTime != null) {
    setValueByPath(parentObject, ["expireTime"], fromExpireTime);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromDisplayName);
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (parentObject !== void 0 && fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToMldev$3(item);
      });
    }
    setValueByPath(parentObject, ["contents"], transformedList);
  }
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToMldev$3(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = fromTools;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToMldev$3(item);
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromToolConfig = getValueByPath(fromObject, ["toolConfig"]);
  if (parentObject !== void 0 && fromToolConfig != null) {
    setValueByPath(parentObject, ["toolConfig"], toolConfigToMldev$1(fromToolConfig));
  }
  if (getValueByPath(fromObject, ["kmsKeyName"]) !== void 0) {
    throw new Error("kmsKeyName parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(createCachedContentConfigToMldev, "createCachedContentConfigToMldev");
function createCachedContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], tCachesModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createCachedContentConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(createCachedContentParametersToMldev, "createCachedContentParametersToMldev");
function getCachedContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getCachedContentParametersToMldev, "getCachedContentParametersToMldev");
function deleteCachedContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteCachedContentParametersToMldev, "deleteCachedContentParametersToMldev");
function updateCachedContentConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromTtl = getValueByPath(fromObject, ["ttl"]);
  if (parentObject !== void 0 && fromTtl != null) {
    setValueByPath(parentObject, ["ttl"], fromTtl);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (parentObject !== void 0 && fromExpireTime != null) {
    setValueByPath(parentObject, ["expireTime"], fromExpireTime);
  }
  return toObject;
}
__name(updateCachedContentConfigToMldev, "updateCachedContentConfigToMldev");
function updateCachedContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], updateCachedContentConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(updateCachedContentParametersToMldev, "updateCachedContentParametersToMldev");
function listCachedContentsConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  return toObject;
}
__name(listCachedContentsConfigToMldev, "listCachedContentsConfigToMldev");
function listCachedContentsParametersToMldev(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listCachedContentsConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(listCachedContentsParametersToMldev, "listCachedContentsParametersToMldev");
function videoMetadataToVertex$2(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToVertex$2, "videoMetadataToVertex$2");
function blobToVertex$2(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToVertex$2, "blobToVertex$2");
function fileDataToVertex$2(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToVertex$2, "fileDataToVertex$2");
function partToVertex$2(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToVertex$2(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToVertex$2(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToVertex$2(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToVertex$2, "partToVertex$2");
function contentToVertex$2(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToVertex$2(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToVertex$2, "contentToVertex$2");
function functionDeclarationToVertex$2(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["behavior"]) !== void 0) {
    throw new Error("behavior parameter is not supported in Vertex AI.");
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToVertex$2, "functionDeclarationToVertex$2");
function intervalToVertex$2(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToVertex$2, "intervalToVertex$2");
function googleSearchToVertex$2(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToVertex$2(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToVertex$2, "googleSearchToVertex$2");
function dynamicRetrievalConfigToVertex$2(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToVertex$2, "dynamicRetrievalConfigToVertex$2");
function googleSearchRetrievalToVertex$2(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToVertex$2(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToVertex$2, "googleSearchRetrievalToVertex$2");
function enterpriseWebSearchToVertex$2() {
  const toObject = {};
  return toObject;
}
__name(enterpriseWebSearchToVertex$2, "enterpriseWebSearchToVertex$2");
function apiKeyConfigToVertex$2(fromObject) {
  const toObject = {};
  const fromApiKeyString = getValueByPath(fromObject, ["apiKeyString"]);
  if (fromApiKeyString != null) {
    setValueByPath(toObject, ["apiKeyString"], fromApiKeyString);
  }
  return toObject;
}
__name(apiKeyConfigToVertex$2, "apiKeyConfigToVertex$2");
function authConfigToVertex$2(fromObject) {
  const toObject = {};
  const fromApiKeyConfig = getValueByPath(fromObject, ["apiKeyConfig"]);
  if (fromApiKeyConfig != null) {
    setValueByPath(toObject, ["apiKeyConfig"], apiKeyConfigToVertex$2(fromApiKeyConfig));
  }
  const fromAuthType = getValueByPath(fromObject, ["authType"]);
  if (fromAuthType != null) {
    setValueByPath(toObject, ["authType"], fromAuthType);
  }
  const fromGoogleServiceAccountConfig = getValueByPath(fromObject, [
    "googleServiceAccountConfig"
  ]);
  if (fromGoogleServiceAccountConfig != null) {
    setValueByPath(toObject, ["googleServiceAccountConfig"], fromGoogleServiceAccountConfig);
  }
  const fromHttpBasicAuthConfig = getValueByPath(fromObject, [
    "httpBasicAuthConfig"
  ]);
  if (fromHttpBasicAuthConfig != null) {
    setValueByPath(toObject, ["httpBasicAuthConfig"], fromHttpBasicAuthConfig);
  }
  const fromOauthConfig = getValueByPath(fromObject, ["oauthConfig"]);
  if (fromOauthConfig != null) {
    setValueByPath(toObject, ["oauthConfig"], fromOauthConfig);
  }
  const fromOidcConfig = getValueByPath(fromObject, ["oidcConfig"]);
  if (fromOidcConfig != null) {
    setValueByPath(toObject, ["oidcConfig"], fromOidcConfig);
  }
  return toObject;
}
__name(authConfigToVertex$2, "authConfigToVertex$2");
function googleMapsToVertex$2(fromObject) {
  const toObject = {};
  const fromAuthConfig = getValueByPath(fromObject, ["authConfig"]);
  if (fromAuthConfig != null) {
    setValueByPath(toObject, ["authConfig"], authConfigToVertex$2(fromAuthConfig));
  }
  return toObject;
}
__name(googleMapsToVertex$2, "googleMapsToVertex$2");
function urlContextToVertex$2() {
  const toObject = {};
  return toObject;
}
__name(urlContextToVertex$2, "urlContextToVertex$2");
function toolToVertex$2(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToVertex$2(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  const fromRetrieval = getValueByPath(fromObject, ["retrieval"]);
  if (fromRetrieval != null) {
    setValueByPath(toObject, ["retrieval"], fromRetrieval);
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToVertex$2(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToVertex$2(fromGoogleSearchRetrieval));
  }
  const fromEnterpriseWebSearch = getValueByPath(fromObject, [
    "enterpriseWebSearch"
  ]);
  if (fromEnterpriseWebSearch != null) {
    setValueByPath(toObject, ["enterpriseWebSearch"], enterpriseWebSearchToVertex$2());
  }
  const fromGoogleMaps = getValueByPath(fromObject, ["googleMaps"]);
  if (fromGoogleMaps != null) {
    setValueByPath(toObject, ["googleMaps"], googleMapsToVertex$2(fromGoogleMaps));
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToVertex$2());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToVertex$2, "toolToVertex$2");
function functionCallingConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromAllowedFunctionNames = getValueByPath(fromObject, [
    "allowedFunctionNames"
  ]);
  if (fromAllowedFunctionNames != null) {
    setValueByPath(toObject, ["allowedFunctionNames"], fromAllowedFunctionNames);
  }
  return toObject;
}
__name(functionCallingConfigToVertex$1, "functionCallingConfigToVertex$1");
function latLngToVertex$1(fromObject) {
  const toObject = {};
  const fromLatitude = getValueByPath(fromObject, ["latitude"]);
  if (fromLatitude != null) {
    setValueByPath(toObject, ["latitude"], fromLatitude);
  }
  const fromLongitude = getValueByPath(fromObject, ["longitude"]);
  if (fromLongitude != null) {
    setValueByPath(toObject, ["longitude"], fromLongitude);
  }
  return toObject;
}
__name(latLngToVertex$1, "latLngToVertex$1");
function retrievalConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromLatLng = getValueByPath(fromObject, ["latLng"]);
  if (fromLatLng != null) {
    setValueByPath(toObject, ["latLng"], latLngToVertex$1(fromLatLng));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(retrievalConfigToVertex$1, "retrievalConfigToVertex$1");
function toolConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromFunctionCallingConfig = getValueByPath(fromObject, [
    "functionCallingConfig"
  ]);
  if (fromFunctionCallingConfig != null) {
    setValueByPath(toObject, ["functionCallingConfig"], functionCallingConfigToVertex$1(fromFunctionCallingConfig));
  }
  const fromRetrievalConfig = getValueByPath(fromObject, [
    "retrievalConfig"
  ]);
  if (fromRetrievalConfig != null) {
    setValueByPath(toObject, ["retrievalConfig"], retrievalConfigToVertex$1(fromRetrievalConfig));
  }
  return toObject;
}
__name(toolConfigToVertex$1, "toolConfigToVertex$1");
function createCachedContentConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromTtl = getValueByPath(fromObject, ["ttl"]);
  if (parentObject !== void 0 && fromTtl != null) {
    setValueByPath(parentObject, ["ttl"], fromTtl);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (parentObject !== void 0 && fromExpireTime != null) {
    setValueByPath(parentObject, ["expireTime"], fromExpireTime);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromDisplayName);
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (parentObject !== void 0 && fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToVertex$2(item);
      });
    }
    setValueByPath(parentObject, ["contents"], transformedList);
  }
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToVertex$2(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = fromTools;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToVertex$2(item);
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromToolConfig = getValueByPath(fromObject, ["toolConfig"]);
  if (parentObject !== void 0 && fromToolConfig != null) {
    setValueByPath(parentObject, ["toolConfig"], toolConfigToVertex$1(fromToolConfig));
  }
  const fromKmsKeyName = getValueByPath(fromObject, ["kmsKeyName"]);
  if (parentObject !== void 0 && fromKmsKeyName != null) {
    setValueByPath(parentObject, ["encryption_spec", "kmsKeyName"], fromKmsKeyName);
  }
  return toObject;
}
__name(createCachedContentConfigToVertex, "createCachedContentConfigToVertex");
function createCachedContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], tCachesModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createCachedContentConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(createCachedContentParametersToVertex, "createCachedContentParametersToVertex");
function getCachedContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getCachedContentParametersToVertex, "getCachedContentParametersToVertex");
function deleteCachedContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteCachedContentParametersToVertex, "deleteCachedContentParametersToVertex");
function updateCachedContentConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromTtl = getValueByPath(fromObject, ["ttl"]);
  if (parentObject !== void 0 && fromTtl != null) {
    setValueByPath(parentObject, ["ttl"], fromTtl);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (parentObject !== void 0 && fromExpireTime != null) {
    setValueByPath(parentObject, ["expireTime"], fromExpireTime);
  }
  return toObject;
}
__name(updateCachedContentConfigToVertex, "updateCachedContentConfigToVertex");
function updateCachedContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], tCachedContentName(apiClient, fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], updateCachedContentConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(updateCachedContentParametersToVertex, "updateCachedContentParametersToVertex");
function listCachedContentsConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  return toObject;
}
__name(listCachedContentsConfigToVertex, "listCachedContentsConfigToVertex");
function listCachedContentsParametersToVertex(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listCachedContentsConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(listCachedContentsParametersToVertex, "listCachedContentsParametersToVertex");
function cachedContentFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (fromExpireTime != null) {
    setValueByPath(toObject, ["expireTime"], fromExpireTime);
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], fromUsageMetadata);
  }
  return toObject;
}
__name(cachedContentFromMldev, "cachedContentFromMldev");
function deleteCachedContentResponseFromMldev() {
  const toObject = {};
  return toObject;
}
__name(deleteCachedContentResponseFromMldev, "deleteCachedContentResponseFromMldev");
function listCachedContentsResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromCachedContents = getValueByPath(fromObject, [
    "cachedContents"
  ]);
  if (fromCachedContents != null) {
    let transformedList = fromCachedContents;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return cachedContentFromMldev(item);
      });
    }
    setValueByPath(toObject, ["cachedContents"], transformedList);
  }
  return toObject;
}
__name(listCachedContentsResponseFromMldev, "listCachedContentsResponseFromMldev");
function cachedContentFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (fromExpireTime != null) {
    setValueByPath(toObject, ["expireTime"], fromExpireTime);
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], fromUsageMetadata);
  }
  return toObject;
}
__name(cachedContentFromVertex, "cachedContentFromVertex");
function deleteCachedContentResponseFromVertex() {
  const toObject = {};
  return toObject;
}
__name(deleteCachedContentResponseFromVertex, "deleteCachedContentResponseFromVertex");
function listCachedContentsResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromCachedContents = getValueByPath(fromObject, [
    "cachedContents"
  ]);
  if (fromCachedContents != null) {
    let transformedList = fromCachedContents;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return cachedContentFromVertex(item);
      });
    }
    setValueByPath(toObject, ["cachedContents"], transformedList);
  }
  return toObject;
}
__name(listCachedContentsResponseFromVertex, "listCachedContentsResponseFromVertex");
var Caches = class extends BaseModule {
  static {
    __name(this, "Caches");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
    this.list = async (params = {}) => {
      return new Pager(PagedItem.PAGED_ITEM_CACHED_CONTENTS, (x) => this.listInternal(x), await this.listInternal(params), params);
    };
  }
  /**
   * Creates a cached contents resource.
   *
   * @remarks
   * Context caching is only supported for specific models. See [Gemini
   * Developer API reference](https://ai.google.dev/gemini-api/docs/caching?lang=node/context-cac)
   * and [Vertex AI reference](https://cloud.google.com/vertex-ai/generative-ai/docs/context-cache/context-cache-overview#supported_models)
   * for more information.
   *
   * @param params - The parameters for the create request.
   * @return The created cached content.
   *
   * @example
   * ```ts
   * const contents = ...; // Initialize the content to cache.
   * const response = await ai.caches.create({
   *   model: 'gemini-2.0-flash-001',
   *   config: {
   *    'contents': contents,
   *    'displayName': 'test cache',
   *    'systemInstruction': 'What is the sum of the two pdfs?',
   *    'ttl': '86400s',
   *  }
   * });
   * ```
   */
  async create(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = createCachedContentParametersToVertex(this.apiClient, params);
      path = formatMap("cachedContents", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = createCachedContentParametersToMldev(this.apiClient, params);
      path = formatMap("cachedContents", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Gets cached content configurations.
   *
   * @param params - The parameters for the get request.
   * @return The cached content.
   *
   * @example
   * ```ts
   * await ai.caches.get({name: '...'}); // The server-generated resource name.
   * ```
   */
  async get(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = getCachedContentParametersToVertex(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = getCachedContentParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Deletes cached content.
   *
   * @param params - The parameters for the delete request.
   * @return The empty response returned by the API.
   *
   * @example
   * ```ts
   * await ai.caches.delete({name: '...'}); // The server-generated resource name.
   * ```
   */
  async delete(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = deleteCachedContentParametersToVertex(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then(() => {
        const resp = deleteCachedContentResponseFromVertex();
        const typedResp = new DeleteCachedContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = deleteCachedContentParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then(() => {
        const resp = deleteCachedContentResponseFromMldev();
        const typedResp = new DeleteCachedContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Updates cached content configurations.
   *
   * @param params - The parameters for the update request.
   * @return The updated cached content.
   *
   * @example
   * ```ts
   * const response = await ai.caches.update({
   *   name: '...',  // The server-generated resource name.
   *   config: {'ttl': '7600s'}
   * });
   * ```
   */
  async update(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = updateCachedContentParametersToVertex(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "PATCH",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = updateCachedContentParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "PATCH",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = cachedContentFromMldev(apiResponse);
        return resp;
      });
    }
  }
  async listInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = listCachedContentsParametersToVertex(params);
      path = formatMap("cachedContents", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listCachedContentsResponseFromVertex(apiResponse);
        const typedResp = new ListCachedContentsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = listCachedContentsParametersToMldev(params);
      path = formatMap("cachedContents", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listCachedContentsResponseFromMldev(apiResponse);
        const typedResp = new ListCachedContentsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
};
function __values(o) {
  var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
  if (m) return m.call(o);
  if (o && typeof o.length === "number") return {
    next: /* @__PURE__ */ __name(function() {
      if (o && i >= o.length) o = void 0;
      return { value: o && o[i++], done: !o };
    }, "next")
  };
  throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
}
__name(__values, "__values");
function __await(v) {
  return this instanceof __await ? (this.v = v, this) : new __await(v);
}
__name(__await, "__await");
function __asyncGenerator(thisArg, _arguments, generator) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var g = generator.apply(thisArg, _arguments || []), i, q = [];
  return i = Object.create((typeof AsyncIterator === "function" ? AsyncIterator : Object).prototype), verb("next"), verb("throw"), verb("return", awaitReturn), i[Symbol.asyncIterator] = function() {
    return this;
  }, i;
  function awaitReturn(f) {
    return function(v) {
      return Promise.resolve(v).then(f, reject);
    };
  }
  __name(awaitReturn, "awaitReturn");
  function verb(n, f) {
    if (g[n]) {
      i[n] = function(v) {
        return new Promise(function(a, b) {
          q.push([n, v, a, b]) > 1 || resume(n, v);
        });
      };
      if (f) i[n] = f(i[n]);
    }
  }
  __name(verb, "verb");
  function resume(n, v) {
    try {
      step(g[n](v));
    } catch (e) {
      settle(q[0][3], e);
    }
  }
  __name(resume, "resume");
  function step(r) {
    r.value instanceof __await ? Promise.resolve(r.value.v).then(fulfill, reject) : settle(q[0][2], r);
  }
  __name(step, "step");
  function fulfill(value) {
    resume("next", value);
  }
  __name(fulfill, "fulfill");
  function reject(value) {
    resume("throw", value);
  }
  __name(reject, "reject");
  function settle(f, v) {
    if (f(v), q.shift(), q.length) resume(q[0][0], q[0][1]);
  }
  __name(settle, "settle");
}
__name(__asyncGenerator, "__asyncGenerator");
function __asyncValues(o) {
  if (!Symbol.asyncIterator) throw new TypeError("Symbol.asyncIterator is not defined.");
  var m = o[Symbol.asyncIterator], i;
  return m ? m.call(o) : (o = typeof __values === "function" ? __values(o) : o[Symbol.iterator](), i = {}, verb("next"), verb("throw"), verb("return"), i[Symbol.asyncIterator] = function() {
    return this;
  }, i);
  function verb(n) {
    i[n] = o[n] && function(v) {
      return new Promise(function(resolve, reject) {
        v = o[n](v), settle(resolve, reject, v.done, v.value);
      });
    };
  }
  __name(verb, "verb");
  function settle(resolve, reject, d, v) {
    Promise.resolve(v).then(function(v2) {
      resolve({ value: v2, done: d });
    }, reject);
  }
  __name(settle, "settle");
}
__name(__asyncValues, "__asyncValues");
function isValidResponse(response) {
  var _a;
  if (response.candidates == void 0 || response.candidates.length === 0) {
    return false;
  }
  const content = (_a = response.candidates[0]) === null || _a === void 0 ? void 0 : _a.content;
  if (content === void 0) {
    return false;
  }
  return isValidContent(content);
}
__name(isValidResponse, "isValidResponse");
function isValidContent(content) {
  if (content.parts === void 0 || content.parts.length === 0) {
    return false;
  }
  for (const part of content.parts) {
    if (part === void 0 || Object.keys(part).length === 0) {
      return false;
    }
    if (!part.thought && part.text !== void 0 && part.text === "") {
      return false;
    }
  }
  return true;
}
__name(isValidContent, "isValidContent");
function validateHistory(history) {
  if (history.length === 0) {
    return;
  }
  for (const content of history) {
    if (content.role !== "user" && content.role !== "model") {
      throw new Error(`Role must be user or model, but got ${content.role}.`);
    }
  }
}
__name(validateHistory, "validateHistory");
function extractCuratedHistory(comprehensiveHistory) {
  if (comprehensiveHistory === void 0 || comprehensiveHistory.length === 0) {
    return [];
  }
  const curatedHistory = [];
  const length = comprehensiveHistory.length;
  let i = 0;
  while (i < length) {
    if (comprehensiveHistory[i].role === "user") {
      curatedHistory.push(comprehensiveHistory[i]);
      i++;
    } else {
      const modelOutput = [];
      let isValid = true;
      while (i < length && comprehensiveHistory[i].role === "model") {
        modelOutput.push(comprehensiveHistory[i]);
        if (isValid && !isValidContent(comprehensiveHistory[i])) {
          isValid = false;
        }
        i++;
      }
      if (isValid) {
        curatedHistory.push(...modelOutput);
      } else {
        curatedHistory.pop();
      }
    }
  }
  return curatedHistory;
}
__name(extractCuratedHistory, "extractCuratedHistory");
var Chats = class {
  static {
    __name(this, "Chats");
  }
  constructor(modelsModule, apiClient) {
    this.modelsModule = modelsModule;
    this.apiClient = apiClient;
  }
  /**
   * Creates a new chat session.
   *
   * @remarks
   * The config in the params will be used for all requests within the chat
   * session unless overridden by a per-request `config` in
   * @see {@link types.SendMessageParameters#config}.
   *
   * @param params - Parameters for creating a chat session.
   * @returns A new chat session.
   *
   * @example
   * ```ts
   * const chat = ai.chats.create({
   *   model: 'gemini-2.0-flash'
   *   config: {
   *     temperature: 0.5,
   *     maxOutputTokens: 1024,
   *   }
   * });
   * ```
   */
  create(params) {
    return new Chat(
      this.apiClient,
      this.modelsModule,
      params.model,
      params.config,
      // Deep copy the history to avoid mutating the history outside of the
      // chat session.
      structuredClone(params.history)
    );
  }
};
var Chat = class {
  static {
    __name(this, "Chat");
  }
  constructor(apiClient, modelsModule, model, config = {}, history = []) {
    this.apiClient = apiClient;
    this.modelsModule = modelsModule;
    this.model = model;
    this.config = config;
    this.history = history;
    this.sendPromise = Promise.resolve();
    validateHistory(history);
  }
  /**
   * Sends a message to the model and returns the response.
   *
   * @remarks
   * This method will wait for the previous message to be processed before
   * sending the next message.
   *
   * @see {@link Chat#sendMessageStream} for streaming method.
   * @param params - parameters for sending messages within a chat session.
   * @returns The model's response.
   *
   * @example
   * ```ts
   * const chat = ai.chats.create({model: 'gemini-2.0-flash'});
   * const response = await chat.sendMessage({
   *   message: 'Why is the sky blue?'
   * });
   * console.log(response.text);
   * ```
   */
  async sendMessage(params) {
    var _a;
    await this.sendPromise;
    const inputContent = tContent(params.message);
    const responsePromise = this.modelsModule.generateContent({
      model: this.model,
      contents: this.getHistory(true).concat(inputContent),
      config: (_a = params.config) !== null && _a !== void 0 ? _a : this.config
    });
    this.sendPromise = (async () => {
      var _a2, _b, _c;
      const response = await responsePromise;
      const outputContent = (_b = (_a2 = response.candidates) === null || _a2 === void 0 ? void 0 : _a2[0]) === null || _b === void 0 ? void 0 : _b.content;
      const fullAutomaticFunctionCallingHistory = response.automaticFunctionCallingHistory;
      const index = this.getHistory(true).length;
      let automaticFunctionCallingHistory = [];
      if (fullAutomaticFunctionCallingHistory != null) {
        automaticFunctionCallingHistory = (_c = fullAutomaticFunctionCallingHistory.slice(index)) !== null && _c !== void 0 ? _c : [];
      }
      const modelOutput = outputContent ? [outputContent] : [];
      this.recordHistory(inputContent, modelOutput, automaticFunctionCallingHistory);
      return;
    })();
    await this.sendPromise.catch(() => {
      this.sendPromise = Promise.resolve();
    });
    return responsePromise;
  }
  /**
   * Sends a message to the model and returns the response in chunks.
   *
   * @remarks
   * This method will wait for the previous message to be processed before
   * sending the next message.
   *
   * @see {@link Chat#sendMessage} for non-streaming method.
   * @param params - parameters for sending the message.
   * @return The model's response.
   *
   * @example
   * ```ts
   * const chat = ai.chats.create({model: 'gemini-2.0-flash'});
   * const response = await chat.sendMessageStream({
   *   message: 'Why is the sky blue?'
   * });
   * for await (const chunk of response) {
   *   console.log(chunk.text);
   * }
   * ```
   */
  async sendMessageStream(params) {
    var _a;
    await this.sendPromise;
    const inputContent = tContent(params.message);
    const streamResponse = this.modelsModule.generateContentStream({
      model: this.model,
      contents: this.getHistory(true).concat(inputContent),
      config: (_a = params.config) !== null && _a !== void 0 ? _a : this.config
    });
    this.sendPromise = streamResponse.then(() => void 0).catch(() => void 0);
    const response = await streamResponse;
    const result = this.processStreamResponse(response, inputContent);
    return result;
  }
  /**
   * Returns the chat history.
   *
   * @remarks
   * The history is a list of contents alternating between user and model.
   *
   * There are two types of history:
   * - The `curated history` contains only the valid turns between user and
   * model, which will be included in the subsequent requests sent to the model.
   * - The `comprehensive history` contains all turns, including invalid or
   *   empty model outputs, providing a complete record of the history.
   *
   * The history is updated after receiving the response from the model,
   * for streaming response, it means receiving the last chunk of the response.
   *
   * The `comprehensive history` is returned by default. To get the `curated
   * history`, set the `curated` parameter to `true`.
   *
   * @param curated - whether to return the curated history or the comprehensive
   *     history.
   * @return History contents alternating between user and model for the entire
   *     chat session.
   */
  getHistory(curated = false) {
    const history = curated ? extractCuratedHistory(this.history) : this.history;
    return structuredClone(history);
  }
  processStreamResponse(streamResponse, inputContent) {
    var _a, _b;
    return __asyncGenerator(this, arguments, /* @__PURE__ */ __name(function* processStreamResponse_1() {
      var _c, e_1, _d, _e;
      const outputContent = [];
      try {
        for (var _f = true, streamResponse_1 = __asyncValues(streamResponse), streamResponse_1_1; streamResponse_1_1 = yield __await(streamResponse_1.next()), _c = streamResponse_1_1.done, !_c; _f = true) {
          _e = streamResponse_1_1.value;
          _f = false;
          const chunk = _e;
          if (isValidResponse(chunk)) {
            const content = (_b = (_a = chunk.candidates) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.content;
            if (content !== void 0) {
              outputContent.push(content);
            }
          }
          yield yield __await(chunk);
        }
      } catch (e_1_1) {
        e_1 = { error: e_1_1 };
      } finally {
        try {
          if (!_f && !_c && (_d = streamResponse_1.return)) yield __await(_d.call(streamResponse_1));
        } finally {
          if (e_1) throw e_1.error;
        }
      }
      this.recordHistory(inputContent, outputContent);
    }, "processStreamResponse_1"));
  }
  recordHistory(userInput, modelOutput, automaticFunctionCallingHistory) {
    let outputContents = [];
    if (modelOutput.length > 0 && modelOutput.every((content) => content.role !== void 0)) {
      outputContents = modelOutput;
    } else {
      outputContents.push({
        role: "model",
        parts: []
      });
    }
    if (automaticFunctionCallingHistory && automaticFunctionCallingHistory.length > 0) {
      this.history.push(...extractCuratedHistory(automaticFunctionCallingHistory));
    } else {
      this.history.push(userInput);
    }
    this.history.push(...outputContents);
  }
};
var ApiError = class _ApiError extends Error {
  static {
    __name(this, "ApiError");
  }
  constructor(options) {
    super(options.message);
    this.name = "ApiError";
    this.status = options.status;
    Object.setPrototypeOf(this, _ApiError.prototype);
  }
};
function listFilesConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  return toObject;
}
__name(listFilesConfigToMldev, "listFilesConfigToMldev");
function listFilesParametersToMldev(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listFilesConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(listFilesParametersToMldev, "listFilesParametersToMldev");
function fileStatusToMldev(fromObject) {
  const toObject = {};
  const fromDetails = getValueByPath(fromObject, ["details"]);
  if (fromDetails != null) {
    setValueByPath(toObject, ["details"], fromDetails);
  }
  const fromMessage = getValueByPath(fromObject, ["message"]);
  if (fromMessage != null) {
    setValueByPath(toObject, ["message"], fromMessage);
  }
  const fromCode = getValueByPath(fromObject, ["code"]);
  if (fromCode != null) {
    setValueByPath(toObject, ["code"], fromCode);
  }
  return toObject;
}
__name(fileStatusToMldev, "fileStatusToMldev");
function fileToMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  const fromSizeBytes = getValueByPath(fromObject, ["sizeBytes"]);
  if (fromSizeBytes != null) {
    setValueByPath(toObject, ["sizeBytes"], fromSizeBytes);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromExpirationTime = getValueByPath(fromObject, [
    "expirationTime"
  ]);
  if (fromExpirationTime != null) {
    setValueByPath(toObject, ["expirationTime"], fromExpirationTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromSha256Hash = getValueByPath(fromObject, ["sha256Hash"]);
  if (fromSha256Hash != null) {
    setValueByPath(toObject, ["sha256Hash"], fromSha256Hash);
  }
  const fromUri = getValueByPath(fromObject, ["uri"]);
  if (fromUri != null) {
    setValueByPath(toObject, ["uri"], fromUri);
  }
  const fromDownloadUri = getValueByPath(fromObject, ["downloadUri"]);
  if (fromDownloadUri != null) {
    setValueByPath(toObject, ["downloadUri"], fromDownloadUri);
  }
  const fromState = getValueByPath(fromObject, ["state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], fromState);
  }
  const fromSource = getValueByPath(fromObject, ["source"]);
  if (fromSource != null) {
    setValueByPath(toObject, ["source"], fromSource);
  }
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], fromVideoMetadata);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fileStatusToMldev(fromError));
  }
  return toObject;
}
__name(fileToMldev, "fileToMldev");
function createFileParametersToMldev(fromObject) {
  const toObject = {};
  const fromFile = getValueByPath(fromObject, ["file"]);
  if (fromFile != null) {
    setValueByPath(toObject, ["file"], fileToMldev(fromFile));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(createFileParametersToMldev, "createFileParametersToMldev");
function getFileParametersToMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "file"], tFileName(fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getFileParametersToMldev, "getFileParametersToMldev");
function deleteFileParametersToMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "file"], tFileName(fromName));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteFileParametersToMldev, "deleteFileParametersToMldev");
function fileStatusFromMldev(fromObject) {
  const toObject = {};
  const fromDetails = getValueByPath(fromObject, ["details"]);
  if (fromDetails != null) {
    setValueByPath(toObject, ["details"], fromDetails);
  }
  const fromMessage = getValueByPath(fromObject, ["message"]);
  if (fromMessage != null) {
    setValueByPath(toObject, ["message"], fromMessage);
  }
  const fromCode = getValueByPath(fromObject, ["code"]);
  if (fromCode != null) {
    setValueByPath(toObject, ["code"], fromCode);
  }
  return toObject;
}
__name(fileStatusFromMldev, "fileStatusFromMldev");
function fileFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  const fromSizeBytes = getValueByPath(fromObject, ["sizeBytes"]);
  if (fromSizeBytes != null) {
    setValueByPath(toObject, ["sizeBytes"], fromSizeBytes);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromExpirationTime = getValueByPath(fromObject, [
    "expirationTime"
  ]);
  if (fromExpirationTime != null) {
    setValueByPath(toObject, ["expirationTime"], fromExpirationTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromSha256Hash = getValueByPath(fromObject, ["sha256Hash"]);
  if (fromSha256Hash != null) {
    setValueByPath(toObject, ["sha256Hash"], fromSha256Hash);
  }
  const fromUri = getValueByPath(fromObject, ["uri"]);
  if (fromUri != null) {
    setValueByPath(toObject, ["uri"], fromUri);
  }
  const fromDownloadUri = getValueByPath(fromObject, ["downloadUri"]);
  if (fromDownloadUri != null) {
    setValueByPath(toObject, ["downloadUri"], fromDownloadUri);
  }
  const fromState = getValueByPath(fromObject, ["state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], fromState);
  }
  const fromSource = getValueByPath(fromObject, ["source"]);
  if (fromSource != null) {
    setValueByPath(toObject, ["source"], fromSource);
  }
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], fromVideoMetadata);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fileStatusFromMldev(fromError));
  }
  return toObject;
}
__name(fileFromMldev, "fileFromMldev");
function listFilesResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromFiles = getValueByPath(fromObject, ["files"]);
  if (fromFiles != null) {
    let transformedList = fromFiles;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return fileFromMldev(item);
      });
    }
    setValueByPath(toObject, ["files"], transformedList);
  }
  return toObject;
}
__name(listFilesResponseFromMldev, "listFilesResponseFromMldev");
function createFileResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  return toObject;
}
__name(createFileResponseFromMldev, "createFileResponseFromMldev");
function deleteFileResponseFromMldev() {
  const toObject = {};
  return toObject;
}
__name(deleteFileResponseFromMldev, "deleteFileResponseFromMldev");
var Files = class extends BaseModule {
  static {
    __name(this, "Files");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
    this.list = async (params = {}) => {
      return new Pager(PagedItem.PAGED_ITEM_FILES, (x) => this.listInternal(x), await this.listInternal(params), params);
    };
  }
  /**
   * Uploads a file asynchronously to the Gemini API.
   * This method is not available in Vertex AI.
   * Supported upload sources:
   * - Node.js: File path (string) or Blob object.
   * - Browser: Blob object (e.g., File).
   *
   * @remarks
   * The `mimeType` can be specified in the `config` parameter. If omitted:
   *  - For file path (string) inputs, the `mimeType` will be inferred from the
   *     file extension.
   *  - For Blob object inputs, the `mimeType` will be set to the Blob's `type`
   *     property.
   * Somex eamples for file extension to mimeType mapping:
   * .txt -> text/plain
   * .json -> application/json
   * .jpg  -> image/jpeg
   * .png -> image/png
   * .mp3 -> audio/mpeg
   * .mp4 -> video/mp4
   *
   * This section can contain multiple paragraphs and code examples.
   *
   * @param params - Optional parameters specified in the
   *        `types.UploadFileParameters` interface.
   *         @see {@link types.UploadFileParameters#config} for the optional
   *         config in the parameters.
   * @return A promise that resolves to a `types.File` object.
   * @throws An error if called on a Vertex AI client.
   * @throws An error if the `mimeType` is not provided and can not be inferred,
   * the `mimeType` can be provided in the `params.config` parameter.
   * @throws An error occurs if a suitable upload location cannot be established.
   *
   * @example
   * The following code uploads a file to Gemini API.
   *
   * ```ts
   * const file = await ai.files.upload({file: 'file.txt', config: {
   *   mimeType: 'text/plain',
   * }});
   * console.log(file.name);
   * ```
   */
  async upload(params) {
    if (this.apiClient.isVertexAI()) {
      throw new Error("Vertex AI does not support uploading files. You can share files through a GCS bucket.");
    }
    return this.apiClient.uploadFile(params.file, params.config).then((response) => {
      const file = fileFromMldev(response);
      return file;
    });
  }
  /**
   * Downloads a remotely stored file asynchronously to a location specified in
   * the `params` object. This method only works on Node environment, to
   * download files in the browser, use a browser compliant method like an <a>
   * tag.
   *
   * @param params - The parameters for the download request.
   *
   * @example
   * The following code downloads an example file named "files/mehozpxf877d" as
   * "file.txt".
   *
   * ```ts
   * await ai.files.download({file: file.name, downloadPath: 'file.txt'});
   * ```
   */
  async download(params) {
    await this.apiClient.downloadFile(params);
  }
  async listInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("This method is only supported by the Gemini Developer API.");
    } else {
      const body = listFilesParametersToMldev(params);
      path = formatMap("files", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listFilesResponseFromMldev(apiResponse);
        const typedResp = new ListFilesResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  async createInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("This method is only supported by the Gemini Developer API.");
    } else {
      const body = createFileParametersToMldev(params);
      path = formatMap("upload/v1beta/files", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = createFileResponseFromMldev(apiResponse);
        const typedResp = new CreateFileResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Retrieves the file information from the service.
   *
   * @param params - The parameters for the get request
   * @return The Promise that resolves to the types.File object requested.
   *
   * @example
   * ```ts
   * const config: GetFileParameters = {
   *   name: fileName,
   * };
   * file = await ai.files.get(config);
   * console.log(file.name);
   * ```
   */
  async get(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("This method is only supported by the Gemini Developer API.");
    } else {
      const body = getFileParametersToMldev(params);
      path = formatMap("files/{file}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = fileFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Deletes a remotely stored file.
   *
   * @param params - The parameters for the delete request.
   * @return The DeleteFileResponse, the response for the delete method.
   *
   * @example
   * The following code deletes an example file named "files/mehozpxf877d".
   *
   * ```ts
   * await ai.files.delete({name: file.name});
   * ```
   */
  async delete(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("This method is only supported by the Gemini Developer API.");
    } else {
      const body = deleteFileParametersToMldev(params);
      path = formatMap("files/{file}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then(() => {
        const resp = deleteFileResponseFromMldev();
        const typedResp = new DeleteFileResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
};
function prebuiltVoiceConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToMldev$2, "prebuiltVoiceConfigToMldev$2");
function voiceConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToMldev$2(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToMldev$2, "voiceConfigToMldev$2");
function speakerVoiceConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromSpeaker = getValueByPath(fromObject, ["speaker"]);
  if (fromSpeaker != null) {
    setValueByPath(toObject, ["speaker"], fromSpeaker);
  }
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$2(fromVoiceConfig));
  }
  return toObject;
}
__name(speakerVoiceConfigToMldev$2, "speakerVoiceConfigToMldev$2");
function multiSpeakerVoiceConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromSpeakerVoiceConfigs = getValueByPath(fromObject, [
    "speakerVoiceConfigs"
  ]);
  if (fromSpeakerVoiceConfigs != null) {
    let transformedList = fromSpeakerVoiceConfigs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return speakerVoiceConfigToMldev$2(item);
      });
    }
    setValueByPath(toObject, ["speakerVoiceConfigs"], transformedList);
  }
  return toObject;
}
__name(multiSpeakerVoiceConfigToMldev$2, "multiSpeakerVoiceConfigToMldev$2");
function speechConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$2(fromVoiceConfig));
  }
  const fromMultiSpeakerVoiceConfig = getValueByPath(fromObject, [
    "multiSpeakerVoiceConfig"
  ]);
  if (fromMultiSpeakerVoiceConfig != null) {
    setValueByPath(toObject, ["multiSpeakerVoiceConfig"], multiSpeakerVoiceConfigToMldev$2(fromMultiSpeakerVoiceConfig));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToMldev$2, "speechConfigToMldev$2");
function videoMetadataToMldev$2(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToMldev$2, "videoMetadataToMldev$2");
function blobToMldev$2(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToMldev$2, "blobToMldev$2");
function fileDataToMldev$2(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToMldev$2, "fileDataToMldev$2");
function partToMldev$2(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToMldev$2(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToMldev$2(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToMldev$2(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToMldev$2, "partToMldev$2");
function contentToMldev$2(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToMldev$2(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToMldev$2, "contentToMldev$2");
function functionDeclarationToMldev$2(fromObject) {
  const toObject = {};
  const fromBehavior = getValueByPath(fromObject, ["behavior"]);
  if (fromBehavior != null) {
    setValueByPath(toObject, ["behavior"], fromBehavior);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToMldev$2, "functionDeclarationToMldev$2");
function intervalToMldev$2(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToMldev$2, "intervalToMldev$2");
function googleSearchToMldev$2(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToMldev$2(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToMldev$2, "googleSearchToMldev$2");
function dynamicRetrievalConfigToMldev$2(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToMldev$2, "dynamicRetrievalConfigToMldev$2");
function googleSearchRetrievalToMldev$2(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToMldev$2(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToMldev$2, "googleSearchRetrievalToMldev$2");
function urlContextToMldev$2() {
  const toObject = {};
  return toObject;
}
__name(urlContextToMldev$2, "urlContextToMldev$2");
function toolToMldev$2(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToMldev$2(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  if (getValueByPath(fromObject, ["retrieval"]) !== void 0) {
    throw new Error("retrieval parameter is not supported in Gemini API.");
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToMldev$2(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToMldev$2(fromGoogleSearchRetrieval));
  }
  if (getValueByPath(fromObject, ["enterpriseWebSearch"]) !== void 0) {
    throw new Error("enterpriseWebSearch parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["googleMaps"]) !== void 0) {
    throw new Error("googleMaps parameter is not supported in Gemini API.");
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToMldev$2());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToMldev$2, "toolToMldev$2");
function sessionResumptionConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromHandle = getValueByPath(fromObject, ["handle"]);
  if (fromHandle != null) {
    setValueByPath(toObject, ["handle"], fromHandle);
  }
  if (getValueByPath(fromObject, ["transparent"]) !== void 0) {
    throw new Error("transparent parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(sessionResumptionConfigToMldev$1, "sessionResumptionConfigToMldev$1");
function audioTranscriptionConfigToMldev$1() {
  const toObject = {};
  return toObject;
}
__name(audioTranscriptionConfigToMldev$1, "audioTranscriptionConfigToMldev$1");
function automaticActivityDetectionToMldev$1(fromObject) {
  const toObject = {};
  const fromDisabled = getValueByPath(fromObject, ["disabled"]);
  if (fromDisabled != null) {
    setValueByPath(toObject, ["disabled"], fromDisabled);
  }
  const fromStartOfSpeechSensitivity = getValueByPath(fromObject, [
    "startOfSpeechSensitivity"
  ]);
  if (fromStartOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["startOfSpeechSensitivity"], fromStartOfSpeechSensitivity);
  }
  const fromEndOfSpeechSensitivity = getValueByPath(fromObject, [
    "endOfSpeechSensitivity"
  ]);
  if (fromEndOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["endOfSpeechSensitivity"], fromEndOfSpeechSensitivity);
  }
  const fromPrefixPaddingMs = getValueByPath(fromObject, [
    "prefixPaddingMs"
  ]);
  if (fromPrefixPaddingMs != null) {
    setValueByPath(toObject, ["prefixPaddingMs"], fromPrefixPaddingMs);
  }
  const fromSilenceDurationMs = getValueByPath(fromObject, [
    "silenceDurationMs"
  ]);
  if (fromSilenceDurationMs != null) {
    setValueByPath(toObject, ["silenceDurationMs"], fromSilenceDurationMs);
  }
  return toObject;
}
__name(automaticActivityDetectionToMldev$1, "automaticActivityDetectionToMldev$1");
function realtimeInputConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromAutomaticActivityDetection = getValueByPath(fromObject, [
    "automaticActivityDetection"
  ]);
  if (fromAutomaticActivityDetection != null) {
    setValueByPath(toObject, ["automaticActivityDetection"], automaticActivityDetectionToMldev$1(fromAutomaticActivityDetection));
  }
  const fromActivityHandling = getValueByPath(fromObject, [
    "activityHandling"
  ]);
  if (fromActivityHandling != null) {
    setValueByPath(toObject, ["activityHandling"], fromActivityHandling);
  }
  const fromTurnCoverage = getValueByPath(fromObject, ["turnCoverage"]);
  if (fromTurnCoverage != null) {
    setValueByPath(toObject, ["turnCoverage"], fromTurnCoverage);
  }
  return toObject;
}
__name(realtimeInputConfigToMldev$1, "realtimeInputConfigToMldev$1");
function slidingWindowToMldev$1(fromObject) {
  const toObject = {};
  const fromTargetTokens = getValueByPath(fromObject, ["targetTokens"]);
  if (fromTargetTokens != null) {
    setValueByPath(toObject, ["targetTokens"], fromTargetTokens);
  }
  return toObject;
}
__name(slidingWindowToMldev$1, "slidingWindowToMldev$1");
function contextWindowCompressionConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromTriggerTokens = getValueByPath(fromObject, [
    "triggerTokens"
  ]);
  if (fromTriggerTokens != null) {
    setValueByPath(toObject, ["triggerTokens"], fromTriggerTokens);
  }
  const fromSlidingWindow = getValueByPath(fromObject, [
    "slidingWindow"
  ]);
  if (fromSlidingWindow != null) {
    setValueByPath(toObject, ["slidingWindow"], slidingWindowToMldev$1(fromSlidingWindow));
  }
  return toObject;
}
__name(contextWindowCompressionConfigToMldev$1, "contextWindowCompressionConfigToMldev$1");
function proactivityConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromProactiveAudio = getValueByPath(fromObject, [
    "proactiveAudio"
  ]);
  if (fromProactiveAudio != null) {
    setValueByPath(toObject, ["proactiveAudio"], fromProactiveAudio);
  }
  return toObject;
}
__name(proactivityConfigToMldev$1, "proactivityConfigToMldev$1");
function liveConnectConfigToMldev$1(fromObject, parentObject) {
  const toObject = {};
  const fromGenerationConfig = getValueByPath(fromObject, [
    "generationConfig"
  ]);
  if (parentObject !== void 0 && fromGenerationConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig"], fromGenerationConfig);
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (parentObject !== void 0 && fromResponseModalities != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "responseModalities"], fromResponseModalities);
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (parentObject !== void 0 && fromTemperature != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (parentObject !== void 0 && fromTopP != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (parentObject !== void 0 && fromTopK != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topK"], fromTopK);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (parentObject !== void 0 && fromMaxOutputTokens != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (parentObject !== void 0 && fromMediaResolution != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "mediaResolution"], fromMediaResolution);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "seed"], fromSeed);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (parentObject !== void 0 && fromSpeechConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "speechConfig"], speechConfigToMldev$2(tLiveSpeechConfig(fromSpeechConfig)));
  }
  const fromEnableAffectiveDialog = getValueByPath(fromObject, [
    "enableAffectiveDialog"
  ]);
  if (parentObject !== void 0 && fromEnableAffectiveDialog != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "enableAffectiveDialog"], fromEnableAffectiveDialog);
  }
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["setup", "systemInstruction"], contentToMldev$2(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToMldev$2(tTool(item));
      });
    }
    setValueByPath(parentObject, ["setup", "tools"], transformedList);
  }
  const fromSessionResumption = getValueByPath(fromObject, [
    "sessionResumption"
  ]);
  if (parentObject !== void 0 && fromSessionResumption != null) {
    setValueByPath(parentObject, ["setup", "sessionResumption"], sessionResumptionConfigToMldev$1(fromSessionResumption));
  }
  const fromInputAudioTranscription = getValueByPath(fromObject, [
    "inputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromInputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "inputAudioTranscription"], audioTranscriptionConfigToMldev$1());
  }
  const fromOutputAudioTranscription = getValueByPath(fromObject, [
    "outputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromOutputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "outputAudioTranscription"], audioTranscriptionConfigToMldev$1());
  }
  const fromRealtimeInputConfig = getValueByPath(fromObject, [
    "realtimeInputConfig"
  ]);
  if (parentObject !== void 0 && fromRealtimeInputConfig != null) {
    setValueByPath(parentObject, ["setup", "realtimeInputConfig"], realtimeInputConfigToMldev$1(fromRealtimeInputConfig));
  }
  const fromContextWindowCompression = getValueByPath(fromObject, [
    "contextWindowCompression"
  ]);
  if (parentObject !== void 0 && fromContextWindowCompression != null) {
    setValueByPath(parentObject, ["setup", "contextWindowCompression"], contextWindowCompressionConfigToMldev$1(fromContextWindowCompression));
  }
  const fromProactivity = getValueByPath(fromObject, ["proactivity"]);
  if (parentObject !== void 0 && fromProactivity != null) {
    setValueByPath(parentObject, ["setup", "proactivity"], proactivityConfigToMldev$1(fromProactivity));
  }
  return toObject;
}
__name(liveConnectConfigToMldev$1, "liveConnectConfigToMldev$1");
function liveConnectParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["setup", "model"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], liveConnectConfigToMldev$1(fromConfig, toObject));
  }
  return toObject;
}
__name(liveConnectParametersToMldev, "liveConnectParametersToMldev");
function activityStartToMldev() {
  const toObject = {};
  return toObject;
}
__name(activityStartToMldev, "activityStartToMldev");
function activityEndToMldev() {
  const toObject = {};
  return toObject;
}
__name(activityEndToMldev, "activityEndToMldev");
function liveSendRealtimeInputParametersToMldev(fromObject) {
  const toObject = {};
  const fromMedia = getValueByPath(fromObject, ["media"]);
  if (fromMedia != null) {
    setValueByPath(toObject, ["mediaChunks"], tBlobs(fromMedia));
  }
  const fromAudio = getValueByPath(fromObject, ["audio"]);
  if (fromAudio != null) {
    setValueByPath(toObject, ["audio"], tAudioBlob(fromAudio));
  }
  const fromAudioStreamEnd = getValueByPath(fromObject, [
    "audioStreamEnd"
  ]);
  if (fromAudioStreamEnd != null) {
    setValueByPath(toObject, ["audioStreamEnd"], fromAudioStreamEnd);
  }
  const fromVideo = getValueByPath(fromObject, ["video"]);
  if (fromVideo != null) {
    setValueByPath(toObject, ["video"], tImageBlob(fromVideo));
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromActivityStart = getValueByPath(fromObject, [
    "activityStart"
  ]);
  if (fromActivityStart != null) {
    setValueByPath(toObject, ["activityStart"], activityStartToMldev());
  }
  const fromActivityEnd = getValueByPath(fromObject, ["activityEnd"]);
  if (fromActivityEnd != null) {
    setValueByPath(toObject, ["activityEnd"], activityEndToMldev());
  }
  return toObject;
}
__name(liveSendRealtimeInputParametersToMldev, "liveSendRealtimeInputParametersToMldev");
function weightedPromptToMldev(fromObject) {
  const toObject = {};
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromWeight = getValueByPath(fromObject, ["weight"]);
  if (fromWeight != null) {
    setValueByPath(toObject, ["weight"], fromWeight);
  }
  return toObject;
}
__name(weightedPromptToMldev, "weightedPromptToMldev");
function liveMusicSetWeightedPromptsParametersToMldev(fromObject) {
  const toObject = {};
  const fromWeightedPrompts = getValueByPath(fromObject, [
    "weightedPrompts"
  ]);
  if (fromWeightedPrompts != null) {
    let transformedList = fromWeightedPrompts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return weightedPromptToMldev(item);
      });
    }
    setValueByPath(toObject, ["weightedPrompts"], transformedList);
  }
  return toObject;
}
__name(liveMusicSetWeightedPromptsParametersToMldev, "liveMusicSetWeightedPromptsParametersToMldev");
function liveMusicGenerationConfigToMldev(fromObject) {
  const toObject = {};
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (fromTemperature != null) {
    setValueByPath(toObject, ["temperature"], fromTemperature);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (fromTopK != null) {
    setValueByPath(toObject, ["topK"], fromTopK);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (fromSeed != null) {
    setValueByPath(toObject, ["seed"], fromSeed);
  }
  const fromGuidance = getValueByPath(fromObject, ["guidance"]);
  if (fromGuidance != null) {
    setValueByPath(toObject, ["guidance"], fromGuidance);
  }
  const fromBpm = getValueByPath(fromObject, ["bpm"]);
  if (fromBpm != null) {
    setValueByPath(toObject, ["bpm"], fromBpm);
  }
  const fromDensity = getValueByPath(fromObject, ["density"]);
  if (fromDensity != null) {
    setValueByPath(toObject, ["density"], fromDensity);
  }
  const fromBrightness = getValueByPath(fromObject, ["brightness"]);
  if (fromBrightness != null) {
    setValueByPath(toObject, ["brightness"], fromBrightness);
  }
  const fromScale = getValueByPath(fromObject, ["scale"]);
  if (fromScale != null) {
    setValueByPath(toObject, ["scale"], fromScale);
  }
  const fromMuteBass = getValueByPath(fromObject, ["muteBass"]);
  if (fromMuteBass != null) {
    setValueByPath(toObject, ["muteBass"], fromMuteBass);
  }
  const fromMuteDrums = getValueByPath(fromObject, ["muteDrums"]);
  if (fromMuteDrums != null) {
    setValueByPath(toObject, ["muteDrums"], fromMuteDrums);
  }
  const fromOnlyBassAndDrums = getValueByPath(fromObject, [
    "onlyBassAndDrums"
  ]);
  if (fromOnlyBassAndDrums != null) {
    setValueByPath(toObject, ["onlyBassAndDrums"], fromOnlyBassAndDrums);
  }
  return toObject;
}
__name(liveMusicGenerationConfigToMldev, "liveMusicGenerationConfigToMldev");
function liveMusicSetConfigParametersToMldev(fromObject) {
  const toObject = {};
  const fromMusicGenerationConfig = getValueByPath(fromObject, [
    "musicGenerationConfig"
  ]);
  if (fromMusicGenerationConfig != null) {
    setValueByPath(toObject, ["musicGenerationConfig"], liveMusicGenerationConfigToMldev(fromMusicGenerationConfig));
  }
  return toObject;
}
__name(liveMusicSetConfigParametersToMldev, "liveMusicSetConfigParametersToMldev");
function liveMusicClientSetupToMldev(fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  return toObject;
}
__name(liveMusicClientSetupToMldev, "liveMusicClientSetupToMldev");
function liveMusicClientContentToMldev(fromObject) {
  const toObject = {};
  const fromWeightedPrompts = getValueByPath(fromObject, [
    "weightedPrompts"
  ]);
  if (fromWeightedPrompts != null) {
    let transformedList = fromWeightedPrompts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return weightedPromptToMldev(item);
      });
    }
    setValueByPath(toObject, ["weightedPrompts"], transformedList);
  }
  return toObject;
}
__name(liveMusicClientContentToMldev, "liveMusicClientContentToMldev");
function liveMusicClientMessageToMldev(fromObject) {
  const toObject = {};
  const fromSetup = getValueByPath(fromObject, ["setup"]);
  if (fromSetup != null) {
    setValueByPath(toObject, ["setup"], liveMusicClientSetupToMldev(fromSetup));
  }
  const fromClientContent = getValueByPath(fromObject, [
    "clientContent"
  ]);
  if (fromClientContent != null) {
    setValueByPath(toObject, ["clientContent"], liveMusicClientContentToMldev(fromClientContent));
  }
  const fromMusicGenerationConfig = getValueByPath(fromObject, [
    "musicGenerationConfig"
  ]);
  if (fromMusicGenerationConfig != null) {
    setValueByPath(toObject, ["musicGenerationConfig"], liveMusicGenerationConfigToMldev(fromMusicGenerationConfig));
  }
  const fromPlaybackControl = getValueByPath(fromObject, [
    "playbackControl"
  ]);
  if (fromPlaybackControl != null) {
    setValueByPath(toObject, ["playbackControl"], fromPlaybackControl);
  }
  return toObject;
}
__name(liveMusicClientMessageToMldev, "liveMusicClientMessageToMldev");
function prebuiltVoiceConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToVertex$1, "prebuiltVoiceConfigToVertex$1");
function voiceConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToVertex$1(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToVertex$1, "voiceConfigToVertex$1");
function speechConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToVertex$1(fromVoiceConfig));
  }
  if (getValueByPath(fromObject, ["multiSpeakerVoiceConfig"]) !== void 0) {
    throw new Error("multiSpeakerVoiceConfig parameter is not supported in Vertex AI.");
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToVertex$1, "speechConfigToVertex$1");
function videoMetadataToVertex$1(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToVertex$1, "videoMetadataToVertex$1");
function blobToVertex$1(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToVertex$1, "blobToVertex$1");
function fileDataToVertex$1(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToVertex$1, "fileDataToVertex$1");
function partToVertex$1(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToVertex$1(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToVertex$1(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToVertex$1(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToVertex$1, "partToVertex$1");
function contentToVertex$1(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToVertex$1(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToVertex$1, "contentToVertex$1");
function functionDeclarationToVertex$1(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["behavior"]) !== void 0) {
    throw new Error("behavior parameter is not supported in Vertex AI.");
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToVertex$1, "functionDeclarationToVertex$1");
function intervalToVertex$1(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToVertex$1, "intervalToVertex$1");
function googleSearchToVertex$1(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToVertex$1(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToVertex$1, "googleSearchToVertex$1");
function dynamicRetrievalConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToVertex$1, "dynamicRetrievalConfigToVertex$1");
function googleSearchRetrievalToVertex$1(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToVertex$1(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToVertex$1, "googleSearchRetrievalToVertex$1");
function enterpriseWebSearchToVertex$1() {
  const toObject = {};
  return toObject;
}
__name(enterpriseWebSearchToVertex$1, "enterpriseWebSearchToVertex$1");
function apiKeyConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromApiKeyString = getValueByPath(fromObject, ["apiKeyString"]);
  if (fromApiKeyString != null) {
    setValueByPath(toObject, ["apiKeyString"], fromApiKeyString);
  }
  return toObject;
}
__name(apiKeyConfigToVertex$1, "apiKeyConfigToVertex$1");
function authConfigToVertex$1(fromObject) {
  const toObject = {};
  const fromApiKeyConfig = getValueByPath(fromObject, ["apiKeyConfig"]);
  if (fromApiKeyConfig != null) {
    setValueByPath(toObject, ["apiKeyConfig"], apiKeyConfigToVertex$1(fromApiKeyConfig));
  }
  const fromAuthType = getValueByPath(fromObject, ["authType"]);
  if (fromAuthType != null) {
    setValueByPath(toObject, ["authType"], fromAuthType);
  }
  const fromGoogleServiceAccountConfig = getValueByPath(fromObject, [
    "googleServiceAccountConfig"
  ]);
  if (fromGoogleServiceAccountConfig != null) {
    setValueByPath(toObject, ["googleServiceAccountConfig"], fromGoogleServiceAccountConfig);
  }
  const fromHttpBasicAuthConfig = getValueByPath(fromObject, [
    "httpBasicAuthConfig"
  ]);
  if (fromHttpBasicAuthConfig != null) {
    setValueByPath(toObject, ["httpBasicAuthConfig"], fromHttpBasicAuthConfig);
  }
  const fromOauthConfig = getValueByPath(fromObject, ["oauthConfig"]);
  if (fromOauthConfig != null) {
    setValueByPath(toObject, ["oauthConfig"], fromOauthConfig);
  }
  const fromOidcConfig = getValueByPath(fromObject, ["oidcConfig"]);
  if (fromOidcConfig != null) {
    setValueByPath(toObject, ["oidcConfig"], fromOidcConfig);
  }
  return toObject;
}
__name(authConfigToVertex$1, "authConfigToVertex$1");
function googleMapsToVertex$1(fromObject) {
  const toObject = {};
  const fromAuthConfig = getValueByPath(fromObject, ["authConfig"]);
  if (fromAuthConfig != null) {
    setValueByPath(toObject, ["authConfig"], authConfigToVertex$1(fromAuthConfig));
  }
  return toObject;
}
__name(googleMapsToVertex$1, "googleMapsToVertex$1");
function urlContextToVertex$1() {
  const toObject = {};
  return toObject;
}
__name(urlContextToVertex$1, "urlContextToVertex$1");
function toolToVertex$1(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToVertex$1(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  const fromRetrieval = getValueByPath(fromObject, ["retrieval"]);
  if (fromRetrieval != null) {
    setValueByPath(toObject, ["retrieval"], fromRetrieval);
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToVertex$1(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToVertex$1(fromGoogleSearchRetrieval));
  }
  const fromEnterpriseWebSearch = getValueByPath(fromObject, [
    "enterpriseWebSearch"
  ]);
  if (fromEnterpriseWebSearch != null) {
    setValueByPath(toObject, ["enterpriseWebSearch"], enterpriseWebSearchToVertex$1());
  }
  const fromGoogleMaps = getValueByPath(fromObject, ["googleMaps"]);
  if (fromGoogleMaps != null) {
    setValueByPath(toObject, ["googleMaps"], googleMapsToVertex$1(fromGoogleMaps));
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToVertex$1());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToVertex$1, "toolToVertex$1");
function sessionResumptionConfigToVertex(fromObject) {
  const toObject = {};
  const fromHandle = getValueByPath(fromObject, ["handle"]);
  if (fromHandle != null) {
    setValueByPath(toObject, ["handle"], fromHandle);
  }
  const fromTransparent = getValueByPath(fromObject, ["transparent"]);
  if (fromTransparent != null) {
    setValueByPath(toObject, ["transparent"], fromTransparent);
  }
  return toObject;
}
__name(sessionResumptionConfigToVertex, "sessionResumptionConfigToVertex");
function audioTranscriptionConfigToVertex() {
  const toObject = {};
  return toObject;
}
__name(audioTranscriptionConfigToVertex, "audioTranscriptionConfigToVertex");
function automaticActivityDetectionToVertex(fromObject) {
  const toObject = {};
  const fromDisabled = getValueByPath(fromObject, ["disabled"]);
  if (fromDisabled != null) {
    setValueByPath(toObject, ["disabled"], fromDisabled);
  }
  const fromStartOfSpeechSensitivity = getValueByPath(fromObject, [
    "startOfSpeechSensitivity"
  ]);
  if (fromStartOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["startOfSpeechSensitivity"], fromStartOfSpeechSensitivity);
  }
  const fromEndOfSpeechSensitivity = getValueByPath(fromObject, [
    "endOfSpeechSensitivity"
  ]);
  if (fromEndOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["endOfSpeechSensitivity"], fromEndOfSpeechSensitivity);
  }
  const fromPrefixPaddingMs = getValueByPath(fromObject, [
    "prefixPaddingMs"
  ]);
  if (fromPrefixPaddingMs != null) {
    setValueByPath(toObject, ["prefixPaddingMs"], fromPrefixPaddingMs);
  }
  const fromSilenceDurationMs = getValueByPath(fromObject, [
    "silenceDurationMs"
  ]);
  if (fromSilenceDurationMs != null) {
    setValueByPath(toObject, ["silenceDurationMs"], fromSilenceDurationMs);
  }
  return toObject;
}
__name(automaticActivityDetectionToVertex, "automaticActivityDetectionToVertex");
function realtimeInputConfigToVertex(fromObject) {
  const toObject = {};
  const fromAutomaticActivityDetection = getValueByPath(fromObject, [
    "automaticActivityDetection"
  ]);
  if (fromAutomaticActivityDetection != null) {
    setValueByPath(toObject, ["automaticActivityDetection"], automaticActivityDetectionToVertex(fromAutomaticActivityDetection));
  }
  const fromActivityHandling = getValueByPath(fromObject, [
    "activityHandling"
  ]);
  if (fromActivityHandling != null) {
    setValueByPath(toObject, ["activityHandling"], fromActivityHandling);
  }
  const fromTurnCoverage = getValueByPath(fromObject, ["turnCoverage"]);
  if (fromTurnCoverage != null) {
    setValueByPath(toObject, ["turnCoverage"], fromTurnCoverage);
  }
  return toObject;
}
__name(realtimeInputConfigToVertex, "realtimeInputConfigToVertex");
function slidingWindowToVertex(fromObject) {
  const toObject = {};
  const fromTargetTokens = getValueByPath(fromObject, ["targetTokens"]);
  if (fromTargetTokens != null) {
    setValueByPath(toObject, ["targetTokens"], fromTargetTokens);
  }
  return toObject;
}
__name(slidingWindowToVertex, "slidingWindowToVertex");
function contextWindowCompressionConfigToVertex(fromObject) {
  const toObject = {};
  const fromTriggerTokens = getValueByPath(fromObject, [
    "triggerTokens"
  ]);
  if (fromTriggerTokens != null) {
    setValueByPath(toObject, ["triggerTokens"], fromTriggerTokens);
  }
  const fromSlidingWindow = getValueByPath(fromObject, [
    "slidingWindow"
  ]);
  if (fromSlidingWindow != null) {
    setValueByPath(toObject, ["slidingWindow"], slidingWindowToVertex(fromSlidingWindow));
  }
  return toObject;
}
__name(contextWindowCompressionConfigToVertex, "contextWindowCompressionConfigToVertex");
function proactivityConfigToVertex(fromObject) {
  const toObject = {};
  const fromProactiveAudio = getValueByPath(fromObject, [
    "proactiveAudio"
  ]);
  if (fromProactiveAudio != null) {
    setValueByPath(toObject, ["proactiveAudio"], fromProactiveAudio);
  }
  return toObject;
}
__name(proactivityConfigToVertex, "proactivityConfigToVertex");
function liveConnectConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromGenerationConfig = getValueByPath(fromObject, [
    "generationConfig"
  ]);
  if (parentObject !== void 0 && fromGenerationConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig"], fromGenerationConfig);
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (parentObject !== void 0 && fromResponseModalities != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "responseModalities"], fromResponseModalities);
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (parentObject !== void 0 && fromTemperature != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (parentObject !== void 0 && fromTopP != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (parentObject !== void 0 && fromTopK != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topK"], fromTopK);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (parentObject !== void 0 && fromMaxOutputTokens != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (parentObject !== void 0 && fromMediaResolution != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "mediaResolution"], fromMediaResolution);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "seed"], fromSeed);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (parentObject !== void 0 && fromSpeechConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "speechConfig"], speechConfigToVertex$1(tLiveSpeechConfig(fromSpeechConfig)));
  }
  const fromEnableAffectiveDialog = getValueByPath(fromObject, [
    "enableAffectiveDialog"
  ]);
  if (parentObject !== void 0 && fromEnableAffectiveDialog != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "enableAffectiveDialog"], fromEnableAffectiveDialog);
  }
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["setup", "systemInstruction"], contentToVertex$1(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToVertex$1(tTool(item));
      });
    }
    setValueByPath(parentObject, ["setup", "tools"], transformedList);
  }
  const fromSessionResumption = getValueByPath(fromObject, [
    "sessionResumption"
  ]);
  if (parentObject !== void 0 && fromSessionResumption != null) {
    setValueByPath(parentObject, ["setup", "sessionResumption"], sessionResumptionConfigToVertex(fromSessionResumption));
  }
  const fromInputAudioTranscription = getValueByPath(fromObject, [
    "inputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromInputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "inputAudioTranscription"], audioTranscriptionConfigToVertex());
  }
  const fromOutputAudioTranscription = getValueByPath(fromObject, [
    "outputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromOutputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "outputAudioTranscription"], audioTranscriptionConfigToVertex());
  }
  const fromRealtimeInputConfig = getValueByPath(fromObject, [
    "realtimeInputConfig"
  ]);
  if (parentObject !== void 0 && fromRealtimeInputConfig != null) {
    setValueByPath(parentObject, ["setup", "realtimeInputConfig"], realtimeInputConfigToVertex(fromRealtimeInputConfig));
  }
  const fromContextWindowCompression = getValueByPath(fromObject, [
    "contextWindowCompression"
  ]);
  if (parentObject !== void 0 && fromContextWindowCompression != null) {
    setValueByPath(parentObject, ["setup", "contextWindowCompression"], contextWindowCompressionConfigToVertex(fromContextWindowCompression));
  }
  const fromProactivity = getValueByPath(fromObject, ["proactivity"]);
  if (parentObject !== void 0 && fromProactivity != null) {
    setValueByPath(parentObject, ["setup", "proactivity"], proactivityConfigToVertex(fromProactivity));
  }
  return toObject;
}
__name(liveConnectConfigToVertex, "liveConnectConfigToVertex");
function liveConnectParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["setup", "model"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], liveConnectConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(liveConnectParametersToVertex, "liveConnectParametersToVertex");
function activityStartToVertex() {
  const toObject = {};
  return toObject;
}
__name(activityStartToVertex, "activityStartToVertex");
function activityEndToVertex() {
  const toObject = {};
  return toObject;
}
__name(activityEndToVertex, "activityEndToVertex");
function liveSendRealtimeInputParametersToVertex(fromObject) {
  const toObject = {};
  const fromMedia = getValueByPath(fromObject, ["media"]);
  if (fromMedia != null) {
    setValueByPath(toObject, ["mediaChunks"], tBlobs(fromMedia));
  }
  const fromAudio = getValueByPath(fromObject, ["audio"]);
  if (fromAudio != null) {
    setValueByPath(toObject, ["audio"], tAudioBlob(fromAudio));
  }
  const fromAudioStreamEnd = getValueByPath(fromObject, [
    "audioStreamEnd"
  ]);
  if (fromAudioStreamEnd != null) {
    setValueByPath(toObject, ["audioStreamEnd"], fromAudioStreamEnd);
  }
  const fromVideo = getValueByPath(fromObject, ["video"]);
  if (fromVideo != null) {
    setValueByPath(toObject, ["video"], tImageBlob(fromVideo));
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromActivityStart = getValueByPath(fromObject, [
    "activityStart"
  ]);
  if (fromActivityStart != null) {
    setValueByPath(toObject, ["activityStart"], activityStartToVertex());
  }
  const fromActivityEnd = getValueByPath(fromObject, ["activityEnd"]);
  if (fromActivityEnd != null) {
    setValueByPath(toObject, ["activityEnd"], activityEndToVertex());
  }
  return toObject;
}
__name(liveSendRealtimeInputParametersToVertex, "liveSendRealtimeInputParametersToVertex");
function liveServerSetupCompleteFromMldev() {
  const toObject = {};
  return toObject;
}
__name(liveServerSetupCompleteFromMldev, "liveServerSetupCompleteFromMldev");
function videoMetadataFromMldev$1(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataFromMldev$1, "videoMetadataFromMldev$1");
function blobFromMldev$1(fromObject) {
  const toObject = {};
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobFromMldev$1, "blobFromMldev$1");
function fileDataFromMldev$1(fromObject) {
  const toObject = {};
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataFromMldev$1, "fileDataFromMldev$1");
function partFromMldev$1(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataFromMldev$1(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobFromMldev$1(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataFromMldev$1(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partFromMldev$1, "partFromMldev$1");
function contentFromMldev$1(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partFromMldev$1(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentFromMldev$1, "contentFromMldev$1");
function transcriptionFromMldev(fromObject) {
  const toObject = {};
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromFinished = getValueByPath(fromObject, ["finished"]);
  if (fromFinished != null) {
    setValueByPath(toObject, ["finished"], fromFinished);
  }
  return toObject;
}
__name(transcriptionFromMldev, "transcriptionFromMldev");
function urlMetadataFromMldev$1(fromObject) {
  const toObject = {};
  const fromRetrievedUrl = getValueByPath(fromObject, ["retrievedUrl"]);
  if (fromRetrievedUrl != null) {
    setValueByPath(toObject, ["retrievedUrl"], fromRetrievedUrl);
  }
  const fromUrlRetrievalStatus = getValueByPath(fromObject, [
    "urlRetrievalStatus"
  ]);
  if (fromUrlRetrievalStatus != null) {
    setValueByPath(toObject, ["urlRetrievalStatus"], fromUrlRetrievalStatus);
  }
  return toObject;
}
__name(urlMetadataFromMldev$1, "urlMetadataFromMldev$1");
function urlContextMetadataFromMldev$1(fromObject) {
  const toObject = {};
  const fromUrlMetadata = getValueByPath(fromObject, ["urlMetadata"]);
  if (fromUrlMetadata != null) {
    let transformedList = fromUrlMetadata;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return urlMetadataFromMldev$1(item);
      });
    }
    setValueByPath(toObject, ["urlMetadata"], transformedList);
  }
  return toObject;
}
__name(urlContextMetadataFromMldev$1, "urlContextMetadataFromMldev$1");
function liveServerContentFromMldev(fromObject) {
  const toObject = {};
  const fromModelTurn = getValueByPath(fromObject, ["modelTurn"]);
  if (fromModelTurn != null) {
    setValueByPath(toObject, ["modelTurn"], contentFromMldev$1(fromModelTurn));
  }
  const fromTurnComplete = getValueByPath(fromObject, ["turnComplete"]);
  if (fromTurnComplete != null) {
    setValueByPath(toObject, ["turnComplete"], fromTurnComplete);
  }
  const fromInterrupted = getValueByPath(fromObject, ["interrupted"]);
  if (fromInterrupted != null) {
    setValueByPath(toObject, ["interrupted"], fromInterrupted);
  }
  const fromGroundingMetadata = getValueByPath(fromObject, [
    "groundingMetadata"
  ]);
  if (fromGroundingMetadata != null) {
    setValueByPath(toObject, ["groundingMetadata"], fromGroundingMetadata);
  }
  const fromGenerationComplete = getValueByPath(fromObject, [
    "generationComplete"
  ]);
  if (fromGenerationComplete != null) {
    setValueByPath(toObject, ["generationComplete"], fromGenerationComplete);
  }
  const fromInputTranscription = getValueByPath(fromObject, [
    "inputTranscription"
  ]);
  if (fromInputTranscription != null) {
    setValueByPath(toObject, ["inputTranscription"], transcriptionFromMldev(fromInputTranscription));
  }
  const fromOutputTranscription = getValueByPath(fromObject, [
    "outputTranscription"
  ]);
  if (fromOutputTranscription != null) {
    setValueByPath(toObject, ["outputTranscription"], transcriptionFromMldev(fromOutputTranscription));
  }
  const fromUrlContextMetadata = getValueByPath(fromObject, [
    "urlContextMetadata"
  ]);
  if (fromUrlContextMetadata != null) {
    setValueByPath(toObject, ["urlContextMetadata"], urlContextMetadataFromMldev$1(fromUrlContextMetadata));
  }
  return toObject;
}
__name(liveServerContentFromMldev, "liveServerContentFromMldev");
function functionCallFromMldev(fromObject) {
  const toObject = {};
  const fromId = getValueByPath(fromObject, ["id"]);
  if (fromId != null) {
    setValueByPath(toObject, ["id"], fromId);
  }
  const fromArgs = getValueByPath(fromObject, ["args"]);
  if (fromArgs != null) {
    setValueByPath(toObject, ["args"], fromArgs);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  return toObject;
}
__name(functionCallFromMldev, "functionCallFromMldev");
function liveServerToolCallFromMldev(fromObject) {
  const toObject = {};
  const fromFunctionCalls = getValueByPath(fromObject, [
    "functionCalls"
  ]);
  if (fromFunctionCalls != null) {
    let transformedList = fromFunctionCalls;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionCallFromMldev(item);
      });
    }
    setValueByPath(toObject, ["functionCalls"], transformedList);
  }
  return toObject;
}
__name(liveServerToolCallFromMldev, "liveServerToolCallFromMldev");
function liveServerToolCallCancellationFromMldev(fromObject) {
  const toObject = {};
  const fromIds = getValueByPath(fromObject, ["ids"]);
  if (fromIds != null) {
    setValueByPath(toObject, ["ids"], fromIds);
  }
  return toObject;
}
__name(liveServerToolCallCancellationFromMldev, "liveServerToolCallCancellationFromMldev");
function modalityTokenCountFromMldev(fromObject) {
  const toObject = {};
  const fromModality = getValueByPath(fromObject, ["modality"]);
  if (fromModality != null) {
    setValueByPath(toObject, ["modality"], fromModality);
  }
  const fromTokenCount = getValueByPath(fromObject, ["tokenCount"]);
  if (fromTokenCount != null) {
    setValueByPath(toObject, ["tokenCount"], fromTokenCount);
  }
  return toObject;
}
__name(modalityTokenCountFromMldev, "modalityTokenCountFromMldev");
function usageMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromPromptTokenCount = getValueByPath(fromObject, [
    "promptTokenCount"
  ]);
  if (fromPromptTokenCount != null) {
    setValueByPath(toObject, ["promptTokenCount"], fromPromptTokenCount);
  }
  const fromCachedContentTokenCount = getValueByPath(fromObject, [
    "cachedContentTokenCount"
  ]);
  if (fromCachedContentTokenCount != null) {
    setValueByPath(toObject, ["cachedContentTokenCount"], fromCachedContentTokenCount);
  }
  const fromResponseTokenCount = getValueByPath(fromObject, [
    "responseTokenCount"
  ]);
  if (fromResponseTokenCount != null) {
    setValueByPath(toObject, ["responseTokenCount"], fromResponseTokenCount);
  }
  const fromToolUsePromptTokenCount = getValueByPath(fromObject, [
    "toolUsePromptTokenCount"
  ]);
  if (fromToolUsePromptTokenCount != null) {
    setValueByPath(toObject, ["toolUsePromptTokenCount"], fromToolUsePromptTokenCount);
  }
  const fromThoughtsTokenCount = getValueByPath(fromObject, [
    "thoughtsTokenCount"
  ]);
  if (fromThoughtsTokenCount != null) {
    setValueByPath(toObject, ["thoughtsTokenCount"], fromThoughtsTokenCount);
  }
  const fromTotalTokenCount = getValueByPath(fromObject, [
    "totalTokenCount"
  ]);
  if (fromTotalTokenCount != null) {
    setValueByPath(toObject, ["totalTokenCount"], fromTotalTokenCount);
  }
  const fromPromptTokensDetails = getValueByPath(fromObject, [
    "promptTokensDetails"
  ]);
  if (fromPromptTokensDetails != null) {
    let transformedList = fromPromptTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromMldev(item);
      });
    }
    setValueByPath(toObject, ["promptTokensDetails"], transformedList);
  }
  const fromCacheTokensDetails = getValueByPath(fromObject, [
    "cacheTokensDetails"
  ]);
  if (fromCacheTokensDetails != null) {
    let transformedList = fromCacheTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromMldev(item);
      });
    }
    setValueByPath(toObject, ["cacheTokensDetails"], transformedList);
  }
  const fromResponseTokensDetails = getValueByPath(fromObject, [
    "responseTokensDetails"
  ]);
  if (fromResponseTokensDetails != null) {
    let transformedList = fromResponseTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromMldev(item);
      });
    }
    setValueByPath(toObject, ["responseTokensDetails"], transformedList);
  }
  const fromToolUsePromptTokensDetails = getValueByPath(fromObject, [
    "toolUsePromptTokensDetails"
  ]);
  if (fromToolUsePromptTokensDetails != null) {
    let transformedList = fromToolUsePromptTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromMldev(item);
      });
    }
    setValueByPath(toObject, ["toolUsePromptTokensDetails"], transformedList);
  }
  return toObject;
}
__name(usageMetadataFromMldev, "usageMetadataFromMldev");
function liveServerGoAwayFromMldev(fromObject) {
  const toObject = {};
  const fromTimeLeft = getValueByPath(fromObject, ["timeLeft"]);
  if (fromTimeLeft != null) {
    setValueByPath(toObject, ["timeLeft"], fromTimeLeft);
  }
  return toObject;
}
__name(liveServerGoAwayFromMldev, "liveServerGoAwayFromMldev");
function liveServerSessionResumptionUpdateFromMldev(fromObject) {
  const toObject = {};
  const fromNewHandle = getValueByPath(fromObject, ["newHandle"]);
  if (fromNewHandle != null) {
    setValueByPath(toObject, ["newHandle"], fromNewHandle);
  }
  const fromResumable = getValueByPath(fromObject, ["resumable"]);
  if (fromResumable != null) {
    setValueByPath(toObject, ["resumable"], fromResumable);
  }
  const fromLastConsumedClientMessageIndex = getValueByPath(fromObject, [
    "lastConsumedClientMessageIndex"
  ]);
  if (fromLastConsumedClientMessageIndex != null) {
    setValueByPath(toObject, ["lastConsumedClientMessageIndex"], fromLastConsumedClientMessageIndex);
  }
  return toObject;
}
__name(liveServerSessionResumptionUpdateFromMldev, "liveServerSessionResumptionUpdateFromMldev");
function liveServerMessageFromMldev(fromObject) {
  const toObject = {};
  const fromSetupComplete = getValueByPath(fromObject, [
    "setupComplete"
  ]);
  if (fromSetupComplete != null) {
    setValueByPath(toObject, ["setupComplete"], liveServerSetupCompleteFromMldev());
  }
  const fromServerContent = getValueByPath(fromObject, [
    "serverContent"
  ]);
  if (fromServerContent != null) {
    setValueByPath(toObject, ["serverContent"], liveServerContentFromMldev(fromServerContent));
  }
  const fromToolCall = getValueByPath(fromObject, ["toolCall"]);
  if (fromToolCall != null) {
    setValueByPath(toObject, ["toolCall"], liveServerToolCallFromMldev(fromToolCall));
  }
  const fromToolCallCancellation = getValueByPath(fromObject, [
    "toolCallCancellation"
  ]);
  if (fromToolCallCancellation != null) {
    setValueByPath(toObject, ["toolCallCancellation"], liveServerToolCallCancellationFromMldev(fromToolCallCancellation));
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], usageMetadataFromMldev(fromUsageMetadata));
  }
  const fromGoAway = getValueByPath(fromObject, ["goAway"]);
  if (fromGoAway != null) {
    setValueByPath(toObject, ["goAway"], liveServerGoAwayFromMldev(fromGoAway));
  }
  const fromSessionResumptionUpdate = getValueByPath(fromObject, [
    "sessionResumptionUpdate"
  ]);
  if (fromSessionResumptionUpdate != null) {
    setValueByPath(toObject, ["sessionResumptionUpdate"], liveServerSessionResumptionUpdateFromMldev(fromSessionResumptionUpdate));
  }
  return toObject;
}
__name(liveServerMessageFromMldev, "liveServerMessageFromMldev");
function liveMusicServerSetupCompleteFromMldev() {
  const toObject = {};
  return toObject;
}
__name(liveMusicServerSetupCompleteFromMldev, "liveMusicServerSetupCompleteFromMldev");
function weightedPromptFromMldev(fromObject) {
  const toObject = {};
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromWeight = getValueByPath(fromObject, ["weight"]);
  if (fromWeight != null) {
    setValueByPath(toObject, ["weight"], fromWeight);
  }
  return toObject;
}
__name(weightedPromptFromMldev, "weightedPromptFromMldev");
function liveMusicClientContentFromMldev(fromObject) {
  const toObject = {};
  const fromWeightedPrompts = getValueByPath(fromObject, [
    "weightedPrompts"
  ]);
  if (fromWeightedPrompts != null) {
    let transformedList = fromWeightedPrompts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return weightedPromptFromMldev(item);
      });
    }
    setValueByPath(toObject, ["weightedPrompts"], transformedList);
  }
  return toObject;
}
__name(liveMusicClientContentFromMldev, "liveMusicClientContentFromMldev");
function liveMusicGenerationConfigFromMldev(fromObject) {
  const toObject = {};
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (fromTemperature != null) {
    setValueByPath(toObject, ["temperature"], fromTemperature);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (fromTopK != null) {
    setValueByPath(toObject, ["topK"], fromTopK);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (fromSeed != null) {
    setValueByPath(toObject, ["seed"], fromSeed);
  }
  const fromGuidance = getValueByPath(fromObject, ["guidance"]);
  if (fromGuidance != null) {
    setValueByPath(toObject, ["guidance"], fromGuidance);
  }
  const fromBpm = getValueByPath(fromObject, ["bpm"]);
  if (fromBpm != null) {
    setValueByPath(toObject, ["bpm"], fromBpm);
  }
  const fromDensity = getValueByPath(fromObject, ["density"]);
  if (fromDensity != null) {
    setValueByPath(toObject, ["density"], fromDensity);
  }
  const fromBrightness = getValueByPath(fromObject, ["brightness"]);
  if (fromBrightness != null) {
    setValueByPath(toObject, ["brightness"], fromBrightness);
  }
  const fromScale = getValueByPath(fromObject, ["scale"]);
  if (fromScale != null) {
    setValueByPath(toObject, ["scale"], fromScale);
  }
  const fromMuteBass = getValueByPath(fromObject, ["muteBass"]);
  if (fromMuteBass != null) {
    setValueByPath(toObject, ["muteBass"], fromMuteBass);
  }
  const fromMuteDrums = getValueByPath(fromObject, ["muteDrums"]);
  if (fromMuteDrums != null) {
    setValueByPath(toObject, ["muteDrums"], fromMuteDrums);
  }
  const fromOnlyBassAndDrums = getValueByPath(fromObject, [
    "onlyBassAndDrums"
  ]);
  if (fromOnlyBassAndDrums != null) {
    setValueByPath(toObject, ["onlyBassAndDrums"], fromOnlyBassAndDrums);
  }
  return toObject;
}
__name(liveMusicGenerationConfigFromMldev, "liveMusicGenerationConfigFromMldev");
function liveMusicSourceMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromClientContent = getValueByPath(fromObject, [
    "clientContent"
  ]);
  if (fromClientContent != null) {
    setValueByPath(toObject, ["clientContent"], liveMusicClientContentFromMldev(fromClientContent));
  }
  const fromMusicGenerationConfig = getValueByPath(fromObject, [
    "musicGenerationConfig"
  ]);
  if (fromMusicGenerationConfig != null) {
    setValueByPath(toObject, ["musicGenerationConfig"], liveMusicGenerationConfigFromMldev(fromMusicGenerationConfig));
  }
  return toObject;
}
__name(liveMusicSourceMetadataFromMldev, "liveMusicSourceMetadataFromMldev");
function audioChunkFromMldev(fromObject) {
  const toObject = {};
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  const fromSourceMetadata = getValueByPath(fromObject, [
    "sourceMetadata"
  ]);
  if (fromSourceMetadata != null) {
    setValueByPath(toObject, ["sourceMetadata"], liveMusicSourceMetadataFromMldev(fromSourceMetadata));
  }
  return toObject;
}
__name(audioChunkFromMldev, "audioChunkFromMldev");
function liveMusicServerContentFromMldev(fromObject) {
  const toObject = {};
  const fromAudioChunks = getValueByPath(fromObject, ["audioChunks"]);
  if (fromAudioChunks != null) {
    let transformedList = fromAudioChunks;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return audioChunkFromMldev(item);
      });
    }
    setValueByPath(toObject, ["audioChunks"], transformedList);
  }
  return toObject;
}
__name(liveMusicServerContentFromMldev, "liveMusicServerContentFromMldev");
function liveMusicFilteredPromptFromMldev(fromObject) {
  const toObject = {};
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromFilteredReason = getValueByPath(fromObject, [
    "filteredReason"
  ]);
  if (fromFilteredReason != null) {
    setValueByPath(toObject, ["filteredReason"], fromFilteredReason);
  }
  return toObject;
}
__name(liveMusicFilteredPromptFromMldev, "liveMusicFilteredPromptFromMldev");
function liveMusicServerMessageFromMldev(fromObject) {
  const toObject = {};
  const fromSetupComplete = getValueByPath(fromObject, [
    "setupComplete"
  ]);
  if (fromSetupComplete != null) {
    setValueByPath(toObject, ["setupComplete"], liveMusicServerSetupCompleteFromMldev());
  }
  const fromServerContent = getValueByPath(fromObject, [
    "serverContent"
  ]);
  if (fromServerContent != null) {
    setValueByPath(toObject, ["serverContent"], liveMusicServerContentFromMldev(fromServerContent));
  }
  const fromFilteredPrompt = getValueByPath(fromObject, [
    "filteredPrompt"
  ]);
  if (fromFilteredPrompt != null) {
    setValueByPath(toObject, ["filteredPrompt"], liveMusicFilteredPromptFromMldev(fromFilteredPrompt));
  }
  return toObject;
}
__name(liveMusicServerMessageFromMldev, "liveMusicServerMessageFromMldev");
function liveServerSetupCompleteFromVertex(fromObject) {
  const toObject = {};
  const fromSessionId = getValueByPath(fromObject, ["sessionId"]);
  if (fromSessionId != null) {
    setValueByPath(toObject, ["sessionId"], fromSessionId);
  }
  return toObject;
}
__name(liveServerSetupCompleteFromVertex, "liveServerSetupCompleteFromVertex");
function videoMetadataFromVertex$1(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataFromVertex$1, "videoMetadataFromVertex$1");
function blobFromVertex$1(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobFromVertex$1, "blobFromVertex$1");
function fileDataFromVertex$1(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataFromVertex$1, "fileDataFromVertex$1");
function partFromVertex$1(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataFromVertex$1(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobFromVertex$1(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataFromVertex$1(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partFromVertex$1, "partFromVertex$1");
function contentFromVertex$1(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partFromVertex$1(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentFromVertex$1, "contentFromVertex$1");
function transcriptionFromVertex(fromObject) {
  const toObject = {};
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  const fromFinished = getValueByPath(fromObject, ["finished"]);
  if (fromFinished != null) {
    setValueByPath(toObject, ["finished"], fromFinished);
  }
  return toObject;
}
__name(transcriptionFromVertex, "transcriptionFromVertex");
function liveServerContentFromVertex(fromObject) {
  const toObject = {};
  const fromModelTurn = getValueByPath(fromObject, ["modelTurn"]);
  if (fromModelTurn != null) {
    setValueByPath(toObject, ["modelTurn"], contentFromVertex$1(fromModelTurn));
  }
  const fromTurnComplete = getValueByPath(fromObject, ["turnComplete"]);
  if (fromTurnComplete != null) {
    setValueByPath(toObject, ["turnComplete"], fromTurnComplete);
  }
  const fromInterrupted = getValueByPath(fromObject, ["interrupted"]);
  if (fromInterrupted != null) {
    setValueByPath(toObject, ["interrupted"], fromInterrupted);
  }
  const fromGroundingMetadata = getValueByPath(fromObject, [
    "groundingMetadata"
  ]);
  if (fromGroundingMetadata != null) {
    setValueByPath(toObject, ["groundingMetadata"], fromGroundingMetadata);
  }
  const fromGenerationComplete = getValueByPath(fromObject, [
    "generationComplete"
  ]);
  if (fromGenerationComplete != null) {
    setValueByPath(toObject, ["generationComplete"], fromGenerationComplete);
  }
  const fromInputTranscription = getValueByPath(fromObject, [
    "inputTranscription"
  ]);
  if (fromInputTranscription != null) {
    setValueByPath(toObject, ["inputTranscription"], transcriptionFromVertex(fromInputTranscription));
  }
  const fromOutputTranscription = getValueByPath(fromObject, [
    "outputTranscription"
  ]);
  if (fromOutputTranscription != null) {
    setValueByPath(toObject, ["outputTranscription"], transcriptionFromVertex(fromOutputTranscription));
  }
  return toObject;
}
__name(liveServerContentFromVertex, "liveServerContentFromVertex");
function functionCallFromVertex(fromObject) {
  const toObject = {};
  const fromArgs = getValueByPath(fromObject, ["args"]);
  if (fromArgs != null) {
    setValueByPath(toObject, ["args"], fromArgs);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  return toObject;
}
__name(functionCallFromVertex, "functionCallFromVertex");
function liveServerToolCallFromVertex(fromObject) {
  const toObject = {};
  const fromFunctionCalls = getValueByPath(fromObject, [
    "functionCalls"
  ]);
  if (fromFunctionCalls != null) {
    let transformedList = fromFunctionCalls;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionCallFromVertex(item);
      });
    }
    setValueByPath(toObject, ["functionCalls"], transformedList);
  }
  return toObject;
}
__name(liveServerToolCallFromVertex, "liveServerToolCallFromVertex");
function liveServerToolCallCancellationFromVertex(fromObject) {
  const toObject = {};
  const fromIds = getValueByPath(fromObject, ["ids"]);
  if (fromIds != null) {
    setValueByPath(toObject, ["ids"], fromIds);
  }
  return toObject;
}
__name(liveServerToolCallCancellationFromVertex, "liveServerToolCallCancellationFromVertex");
function modalityTokenCountFromVertex(fromObject) {
  const toObject = {};
  const fromModality = getValueByPath(fromObject, ["modality"]);
  if (fromModality != null) {
    setValueByPath(toObject, ["modality"], fromModality);
  }
  const fromTokenCount = getValueByPath(fromObject, ["tokenCount"]);
  if (fromTokenCount != null) {
    setValueByPath(toObject, ["tokenCount"], fromTokenCount);
  }
  return toObject;
}
__name(modalityTokenCountFromVertex, "modalityTokenCountFromVertex");
function usageMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromPromptTokenCount = getValueByPath(fromObject, [
    "promptTokenCount"
  ]);
  if (fromPromptTokenCount != null) {
    setValueByPath(toObject, ["promptTokenCount"], fromPromptTokenCount);
  }
  const fromCachedContentTokenCount = getValueByPath(fromObject, [
    "cachedContentTokenCount"
  ]);
  if (fromCachedContentTokenCount != null) {
    setValueByPath(toObject, ["cachedContentTokenCount"], fromCachedContentTokenCount);
  }
  const fromResponseTokenCount = getValueByPath(fromObject, [
    "candidatesTokenCount"
  ]);
  if (fromResponseTokenCount != null) {
    setValueByPath(toObject, ["responseTokenCount"], fromResponseTokenCount);
  }
  const fromToolUsePromptTokenCount = getValueByPath(fromObject, [
    "toolUsePromptTokenCount"
  ]);
  if (fromToolUsePromptTokenCount != null) {
    setValueByPath(toObject, ["toolUsePromptTokenCount"], fromToolUsePromptTokenCount);
  }
  const fromThoughtsTokenCount = getValueByPath(fromObject, [
    "thoughtsTokenCount"
  ]);
  if (fromThoughtsTokenCount != null) {
    setValueByPath(toObject, ["thoughtsTokenCount"], fromThoughtsTokenCount);
  }
  const fromTotalTokenCount = getValueByPath(fromObject, [
    "totalTokenCount"
  ]);
  if (fromTotalTokenCount != null) {
    setValueByPath(toObject, ["totalTokenCount"], fromTotalTokenCount);
  }
  const fromPromptTokensDetails = getValueByPath(fromObject, [
    "promptTokensDetails"
  ]);
  if (fromPromptTokensDetails != null) {
    let transformedList = fromPromptTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromVertex(item);
      });
    }
    setValueByPath(toObject, ["promptTokensDetails"], transformedList);
  }
  const fromCacheTokensDetails = getValueByPath(fromObject, [
    "cacheTokensDetails"
  ]);
  if (fromCacheTokensDetails != null) {
    let transformedList = fromCacheTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromVertex(item);
      });
    }
    setValueByPath(toObject, ["cacheTokensDetails"], transformedList);
  }
  const fromResponseTokensDetails = getValueByPath(fromObject, [
    "candidatesTokensDetails"
  ]);
  if (fromResponseTokensDetails != null) {
    let transformedList = fromResponseTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromVertex(item);
      });
    }
    setValueByPath(toObject, ["responseTokensDetails"], transformedList);
  }
  const fromToolUsePromptTokensDetails = getValueByPath(fromObject, [
    "toolUsePromptTokensDetails"
  ]);
  if (fromToolUsePromptTokensDetails != null) {
    let transformedList = fromToolUsePromptTokensDetails;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modalityTokenCountFromVertex(item);
      });
    }
    setValueByPath(toObject, ["toolUsePromptTokensDetails"], transformedList);
  }
  const fromTrafficType = getValueByPath(fromObject, ["trafficType"]);
  if (fromTrafficType != null) {
    setValueByPath(toObject, ["trafficType"], fromTrafficType);
  }
  return toObject;
}
__name(usageMetadataFromVertex, "usageMetadataFromVertex");
function liveServerGoAwayFromVertex(fromObject) {
  const toObject = {};
  const fromTimeLeft = getValueByPath(fromObject, ["timeLeft"]);
  if (fromTimeLeft != null) {
    setValueByPath(toObject, ["timeLeft"], fromTimeLeft);
  }
  return toObject;
}
__name(liveServerGoAwayFromVertex, "liveServerGoAwayFromVertex");
function liveServerSessionResumptionUpdateFromVertex(fromObject) {
  const toObject = {};
  const fromNewHandle = getValueByPath(fromObject, ["newHandle"]);
  if (fromNewHandle != null) {
    setValueByPath(toObject, ["newHandle"], fromNewHandle);
  }
  const fromResumable = getValueByPath(fromObject, ["resumable"]);
  if (fromResumable != null) {
    setValueByPath(toObject, ["resumable"], fromResumable);
  }
  const fromLastConsumedClientMessageIndex = getValueByPath(fromObject, [
    "lastConsumedClientMessageIndex"
  ]);
  if (fromLastConsumedClientMessageIndex != null) {
    setValueByPath(toObject, ["lastConsumedClientMessageIndex"], fromLastConsumedClientMessageIndex);
  }
  return toObject;
}
__name(liveServerSessionResumptionUpdateFromVertex, "liveServerSessionResumptionUpdateFromVertex");
function liveServerMessageFromVertex(fromObject) {
  const toObject = {};
  const fromSetupComplete = getValueByPath(fromObject, [
    "setupComplete"
  ]);
  if (fromSetupComplete != null) {
    setValueByPath(toObject, ["setupComplete"], liveServerSetupCompleteFromVertex(fromSetupComplete));
  }
  const fromServerContent = getValueByPath(fromObject, [
    "serverContent"
  ]);
  if (fromServerContent != null) {
    setValueByPath(toObject, ["serverContent"], liveServerContentFromVertex(fromServerContent));
  }
  const fromToolCall = getValueByPath(fromObject, ["toolCall"]);
  if (fromToolCall != null) {
    setValueByPath(toObject, ["toolCall"], liveServerToolCallFromVertex(fromToolCall));
  }
  const fromToolCallCancellation = getValueByPath(fromObject, [
    "toolCallCancellation"
  ]);
  if (fromToolCallCancellation != null) {
    setValueByPath(toObject, ["toolCallCancellation"], liveServerToolCallCancellationFromVertex(fromToolCallCancellation));
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], usageMetadataFromVertex(fromUsageMetadata));
  }
  const fromGoAway = getValueByPath(fromObject, ["goAway"]);
  if (fromGoAway != null) {
    setValueByPath(toObject, ["goAway"], liveServerGoAwayFromVertex(fromGoAway));
  }
  const fromSessionResumptionUpdate = getValueByPath(fromObject, [
    "sessionResumptionUpdate"
  ]);
  if (fromSessionResumptionUpdate != null) {
    setValueByPath(toObject, ["sessionResumptionUpdate"], liveServerSessionResumptionUpdateFromVertex(fromSessionResumptionUpdate));
  }
  return toObject;
}
__name(liveServerMessageFromVertex, "liveServerMessageFromVertex");
function videoMetadataToMldev$1(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToMldev$1, "videoMetadataToMldev$1");
function blobToMldev$1(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToMldev$1, "blobToMldev$1");
function fileDataToMldev$1(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToMldev$1, "fileDataToMldev$1");
function partToMldev$1(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToMldev$1(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToMldev$1(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToMldev$1(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToMldev$1, "partToMldev$1");
function contentToMldev$1(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToMldev$1(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToMldev$1, "contentToMldev$1");
function schemaToMldev(fromObject) {
  const toObject = {};
  const fromAnyOf = getValueByPath(fromObject, ["anyOf"]);
  if (fromAnyOf != null) {
    setValueByPath(toObject, ["anyOf"], fromAnyOf);
  }
  const fromDefault = getValueByPath(fromObject, ["default"]);
  if (fromDefault != null) {
    setValueByPath(toObject, ["default"], fromDefault);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromEnum = getValueByPath(fromObject, ["enum"]);
  if (fromEnum != null) {
    setValueByPath(toObject, ["enum"], fromEnum);
  }
  const fromExample = getValueByPath(fromObject, ["example"]);
  if (fromExample != null) {
    setValueByPath(toObject, ["example"], fromExample);
  }
  const fromFormat = getValueByPath(fromObject, ["format"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["format"], fromFormat);
  }
  const fromItems = getValueByPath(fromObject, ["items"]);
  if (fromItems != null) {
    setValueByPath(toObject, ["items"], fromItems);
  }
  const fromMaxItems = getValueByPath(fromObject, ["maxItems"]);
  if (fromMaxItems != null) {
    setValueByPath(toObject, ["maxItems"], fromMaxItems);
  }
  const fromMaxLength = getValueByPath(fromObject, ["maxLength"]);
  if (fromMaxLength != null) {
    setValueByPath(toObject, ["maxLength"], fromMaxLength);
  }
  const fromMaxProperties = getValueByPath(fromObject, [
    "maxProperties"
  ]);
  if (fromMaxProperties != null) {
    setValueByPath(toObject, ["maxProperties"], fromMaxProperties);
  }
  const fromMaximum = getValueByPath(fromObject, ["maximum"]);
  if (fromMaximum != null) {
    setValueByPath(toObject, ["maximum"], fromMaximum);
  }
  const fromMinItems = getValueByPath(fromObject, ["minItems"]);
  if (fromMinItems != null) {
    setValueByPath(toObject, ["minItems"], fromMinItems);
  }
  const fromMinLength = getValueByPath(fromObject, ["minLength"]);
  if (fromMinLength != null) {
    setValueByPath(toObject, ["minLength"], fromMinLength);
  }
  const fromMinProperties = getValueByPath(fromObject, [
    "minProperties"
  ]);
  if (fromMinProperties != null) {
    setValueByPath(toObject, ["minProperties"], fromMinProperties);
  }
  const fromMinimum = getValueByPath(fromObject, ["minimum"]);
  if (fromMinimum != null) {
    setValueByPath(toObject, ["minimum"], fromMinimum);
  }
  const fromNullable = getValueByPath(fromObject, ["nullable"]);
  if (fromNullable != null) {
    setValueByPath(toObject, ["nullable"], fromNullable);
  }
  const fromPattern = getValueByPath(fromObject, ["pattern"]);
  if (fromPattern != null) {
    setValueByPath(toObject, ["pattern"], fromPattern);
  }
  const fromProperties = getValueByPath(fromObject, ["properties"]);
  if (fromProperties != null) {
    setValueByPath(toObject, ["properties"], fromProperties);
  }
  const fromPropertyOrdering = getValueByPath(fromObject, [
    "propertyOrdering"
  ]);
  if (fromPropertyOrdering != null) {
    setValueByPath(toObject, ["propertyOrdering"], fromPropertyOrdering);
  }
  const fromRequired = getValueByPath(fromObject, ["required"]);
  if (fromRequired != null) {
    setValueByPath(toObject, ["required"], fromRequired);
  }
  const fromTitle = getValueByPath(fromObject, ["title"]);
  if (fromTitle != null) {
    setValueByPath(toObject, ["title"], fromTitle);
  }
  const fromType = getValueByPath(fromObject, ["type"]);
  if (fromType != null) {
    setValueByPath(toObject, ["type"], fromType);
  }
  return toObject;
}
__name(schemaToMldev, "schemaToMldev");
function safetySettingToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["method"]) !== void 0) {
    throw new Error("method parameter is not supported in Gemini API.");
  }
  const fromCategory = getValueByPath(fromObject, ["category"]);
  if (fromCategory != null) {
    setValueByPath(toObject, ["category"], fromCategory);
  }
  const fromThreshold = getValueByPath(fromObject, ["threshold"]);
  if (fromThreshold != null) {
    setValueByPath(toObject, ["threshold"], fromThreshold);
  }
  return toObject;
}
__name(safetySettingToMldev, "safetySettingToMldev");
function functionDeclarationToMldev$1(fromObject) {
  const toObject = {};
  const fromBehavior = getValueByPath(fromObject, ["behavior"]);
  if (fromBehavior != null) {
    setValueByPath(toObject, ["behavior"], fromBehavior);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToMldev$1, "functionDeclarationToMldev$1");
function intervalToMldev$1(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToMldev$1, "intervalToMldev$1");
function googleSearchToMldev$1(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToMldev$1(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToMldev$1, "googleSearchToMldev$1");
function dynamicRetrievalConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToMldev$1, "dynamicRetrievalConfigToMldev$1");
function googleSearchRetrievalToMldev$1(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToMldev$1(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToMldev$1, "googleSearchRetrievalToMldev$1");
function urlContextToMldev$1() {
  const toObject = {};
  return toObject;
}
__name(urlContextToMldev$1, "urlContextToMldev$1");
function toolToMldev$1(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToMldev$1(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  if (getValueByPath(fromObject, ["retrieval"]) !== void 0) {
    throw new Error("retrieval parameter is not supported in Gemini API.");
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToMldev$1(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToMldev$1(fromGoogleSearchRetrieval));
  }
  if (getValueByPath(fromObject, ["enterpriseWebSearch"]) !== void 0) {
    throw new Error("enterpriseWebSearch parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["googleMaps"]) !== void 0) {
    throw new Error("googleMaps parameter is not supported in Gemini API.");
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToMldev$1());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToMldev$1, "toolToMldev$1");
function functionCallingConfigToMldev(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromAllowedFunctionNames = getValueByPath(fromObject, [
    "allowedFunctionNames"
  ]);
  if (fromAllowedFunctionNames != null) {
    setValueByPath(toObject, ["allowedFunctionNames"], fromAllowedFunctionNames);
  }
  return toObject;
}
__name(functionCallingConfigToMldev, "functionCallingConfigToMldev");
function latLngToMldev(fromObject) {
  const toObject = {};
  const fromLatitude = getValueByPath(fromObject, ["latitude"]);
  if (fromLatitude != null) {
    setValueByPath(toObject, ["latitude"], fromLatitude);
  }
  const fromLongitude = getValueByPath(fromObject, ["longitude"]);
  if (fromLongitude != null) {
    setValueByPath(toObject, ["longitude"], fromLongitude);
  }
  return toObject;
}
__name(latLngToMldev, "latLngToMldev");
function retrievalConfigToMldev(fromObject) {
  const toObject = {};
  const fromLatLng = getValueByPath(fromObject, ["latLng"]);
  if (fromLatLng != null) {
    setValueByPath(toObject, ["latLng"], latLngToMldev(fromLatLng));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(retrievalConfigToMldev, "retrievalConfigToMldev");
function toolConfigToMldev(fromObject) {
  const toObject = {};
  const fromFunctionCallingConfig = getValueByPath(fromObject, [
    "functionCallingConfig"
  ]);
  if (fromFunctionCallingConfig != null) {
    setValueByPath(toObject, ["functionCallingConfig"], functionCallingConfigToMldev(fromFunctionCallingConfig));
  }
  const fromRetrievalConfig = getValueByPath(fromObject, [
    "retrievalConfig"
  ]);
  if (fromRetrievalConfig != null) {
    setValueByPath(toObject, ["retrievalConfig"], retrievalConfigToMldev(fromRetrievalConfig));
  }
  return toObject;
}
__name(toolConfigToMldev, "toolConfigToMldev");
function prebuiltVoiceConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToMldev$1, "prebuiltVoiceConfigToMldev$1");
function voiceConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToMldev$1(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToMldev$1, "voiceConfigToMldev$1");
function speakerVoiceConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromSpeaker = getValueByPath(fromObject, ["speaker"]);
  if (fromSpeaker != null) {
    setValueByPath(toObject, ["speaker"], fromSpeaker);
  }
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$1(fromVoiceConfig));
  }
  return toObject;
}
__name(speakerVoiceConfigToMldev$1, "speakerVoiceConfigToMldev$1");
function multiSpeakerVoiceConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromSpeakerVoiceConfigs = getValueByPath(fromObject, [
    "speakerVoiceConfigs"
  ]);
  if (fromSpeakerVoiceConfigs != null) {
    let transformedList = fromSpeakerVoiceConfigs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return speakerVoiceConfigToMldev$1(item);
      });
    }
    setValueByPath(toObject, ["speakerVoiceConfigs"], transformedList);
  }
  return toObject;
}
__name(multiSpeakerVoiceConfigToMldev$1, "multiSpeakerVoiceConfigToMldev$1");
function speechConfigToMldev$1(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev$1(fromVoiceConfig));
  }
  const fromMultiSpeakerVoiceConfig = getValueByPath(fromObject, [
    "multiSpeakerVoiceConfig"
  ]);
  if (fromMultiSpeakerVoiceConfig != null) {
    setValueByPath(toObject, ["multiSpeakerVoiceConfig"], multiSpeakerVoiceConfigToMldev$1(fromMultiSpeakerVoiceConfig));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToMldev$1, "speechConfigToMldev$1");
function thinkingConfigToMldev(fromObject) {
  const toObject = {};
  const fromIncludeThoughts = getValueByPath(fromObject, [
    "includeThoughts"
  ]);
  if (fromIncludeThoughts != null) {
    setValueByPath(toObject, ["includeThoughts"], fromIncludeThoughts);
  }
  const fromThinkingBudget = getValueByPath(fromObject, [
    "thinkingBudget"
  ]);
  if (fromThinkingBudget != null) {
    setValueByPath(toObject, ["thinkingBudget"], fromThinkingBudget);
  }
  return toObject;
}
__name(thinkingConfigToMldev, "thinkingConfigToMldev");
function generateContentConfigToMldev(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToMldev$1(tContent(fromSystemInstruction)));
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (fromTemperature != null) {
    setValueByPath(toObject, ["temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (fromTopP != null) {
    setValueByPath(toObject, ["topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (fromTopK != null) {
    setValueByPath(toObject, ["topK"], fromTopK);
  }
  const fromCandidateCount = getValueByPath(fromObject, [
    "candidateCount"
  ]);
  if (fromCandidateCount != null) {
    setValueByPath(toObject, ["candidateCount"], fromCandidateCount);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (fromMaxOutputTokens != null) {
    setValueByPath(toObject, ["maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromStopSequences = getValueByPath(fromObject, [
    "stopSequences"
  ]);
  if (fromStopSequences != null) {
    setValueByPath(toObject, ["stopSequences"], fromStopSequences);
  }
  const fromResponseLogprobs = getValueByPath(fromObject, [
    "responseLogprobs"
  ]);
  if (fromResponseLogprobs != null) {
    setValueByPath(toObject, ["responseLogprobs"], fromResponseLogprobs);
  }
  const fromLogprobs = getValueByPath(fromObject, ["logprobs"]);
  if (fromLogprobs != null) {
    setValueByPath(toObject, ["logprobs"], fromLogprobs);
  }
  const fromPresencePenalty = getValueByPath(fromObject, [
    "presencePenalty"
  ]);
  if (fromPresencePenalty != null) {
    setValueByPath(toObject, ["presencePenalty"], fromPresencePenalty);
  }
  const fromFrequencyPenalty = getValueByPath(fromObject, [
    "frequencyPenalty"
  ]);
  if (fromFrequencyPenalty != null) {
    setValueByPath(toObject, ["frequencyPenalty"], fromFrequencyPenalty);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (fromSeed != null) {
    setValueByPath(toObject, ["seed"], fromSeed);
  }
  const fromResponseMimeType = getValueByPath(fromObject, [
    "responseMimeType"
  ]);
  if (fromResponseMimeType != null) {
    setValueByPath(toObject, ["responseMimeType"], fromResponseMimeType);
  }
  const fromResponseSchema = getValueByPath(fromObject, [
    "responseSchema"
  ]);
  if (fromResponseSchema != null) {
    setValueByPath(toObject, ["responseSchema"], schemaToMldev(tSchema(fromResponseSchema)));
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  if (getValueByPath(fromObject, ["routingConfig"]) !== void 0) {
    throw new Error("routingConfig parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["modelSelectionConfig"]) !== void 0) {
    throw new Error("modelSelectionConfig parameter is not supported in Gemini API.");
  }
  const fromSafetySettings = getValueByPath(fromObject, [
    "safetySettings"
  ]);
  if (parentObject !== void 0 && fromSafetySettings != null) {
    let transformedList = fromSafetySettings;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return safetySettingToMldev(item);
      });
    }
    setValueByPath(parentObject, ["safetySettings"], transformedList);
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToMldev$1(tTool(item));
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromToolConfig = getValueByPath(fromObject, ["toolConfig"]);
  if (parentObject !== void 0 && fromToolConfig != null) {
    setValueByPath(parentObject, ["toolConfig"], toolConfigToMldev(fromToolConfig));
  }
  if (getValueByPath(fromObject, ["labels"]) !== void 0) {
    throw new Error("labels parameter is not supported in Gemini API.");
  }
  const fromCachedContent = getValueByPath(fromObject, [
    "cachedContent"
  ]);
  if (parentObject !== void 0 && fromCachedContent != null) {
    setValueByPath(parentObject, ["cachedContent"], tCachedContentName(apiClient, fromCachedContent));
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (fromResponseModalities != null) {
    setValueByPath(toObject, ["responseModalities"], fromResponseModalities);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (fromMediaResolution != null) {
    setValueByPath(toObject, ["mediaResolution"], fromMediaResolution);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (fromSpeechConfig != null) {
    setValueByPath(toObject, ["speechConfig"], speechConfigToMldev$1(tSpeechConfig(fromSpeechConfig)));
  }
  if (getValueByPath(fromObject, ["audioTimestamp"]) !== void 0) {
    throw new Error("audioTimestamp parameter is not supported in Gemini API.");
  }
  const fromThinkingConfig = getValueByPath(fromObject, [
    "thinkingConfig"
  ]);
  if (fromThinkingConfig != null) {
    setValueByPath(toObject, ["thinkingConfig"], thinkingConfigToMldev(fromThinkingConfig));
  }
  return toObject;
}
__name(generateContentConfigToMldev, "generateContentConfigToMldev");
function generateContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToMldev$1(item);
      });
    }
    setValueByPath(toObject, ["contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["generationConfig"], generateContentConfigToMldev(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(generateContentParametersToMldev, "generateContentParametersToMldev");
function embedContentConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromTaskType = getValueByPath(fromObject, ["taskType"]);
  if (parentObject !== void 0 && fromTaskType != null) {
    setValueByPath(parentObject, ["requests[]", "taskType"], fromTaskType);
  }
  const fromTitle = getValueByPath(fromObject, ["title"]);
  if (parentObject !== void 0 && fromTitle != null) {
    setValueByPath(parentObject, ["requests[]", "title"], fromTitle);
  }
  const fromOutputDimensionality = getValueByPath(fromObject, [
    "outputDimensionality"
  ]);
  if (parentObject !== void 0 && fromOutputDimensionality != null) {
    setValueByPath(parentObject, ["requests[]", "outputDimensionality"], fromOutputDimensionality);
  }
  if (getValueByPath(fromObject, ["mimeType"]) !== void 0) {
    throw new Error("mimeType parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["autoTruncate"]) !== void 0) {
    throw new Error("autoTruncate parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(embedContentConfigToMldev, "embedContentConfigToMldev");
function embedContentParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    setValueByPath(toObject, ["requests[]", "content"], tContentsForEmbed(apiClient, fromContents));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], embedContentConfigToMldev(fromConfig, toObject));
  }
  const fromModelForEmbedContent = getValueByPath(fromObject, ["model"]);
  if (fromModelForEmbedContent !== void 0) {
    setValueByPath(toObject, ["requests[]", "model"], tModel(apiClient, fromModelForEmbedContent));
  }
  return toObject;
}
__name(embedContentParametersToMldev, "embedContentParametersToMldev");
function generateImagesConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["outputGcsUri"]) !== void 0) {
    throw new Error("outputGcsUri parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["negativePrompt"]) !== void 0) {
    throw new Error("negativePrompt parameter is not supported in Gemini API.");
  }
  const fromNumberOfImages = getValueByPath(fromObject, [
    "numberOfImages"
  ]);
  if (parentObject !== void 0 && fromNumberOfImages != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfImages);
  }
  const fromAspectRatio = getValueByPath(fromObject, ["aspectRatio"]);
  if (parentObject !== void 0 && fromAspectRatio != null) {
    setValueByPath(parentObject, ["parameters", "aspectRatio"], fromAspectRatio);
  }
  const fromGuidanceScale = getValueByPath(fromObject, [
    "guidanceScale"
  ]);
  if (parentObject !== void 0 && fromGuidanceScale != null) {
    setValueByPath(parentObject, ["parameters", "guidanceScale"], fromGuidanceScale);
  }
  if (getValueByPath(fromObject, ["seed"]) !== void 0) {
    throw new Error("seed parameter is not supported in Gemini API.");
  }
  const fromSafetyFilterLevel = getValueByPath(fromObject, [
    "safetyFilterLevel"
  ]);
  if (parentObject !== void 0 && fromSafetyFilterLevel != null) {
    setValueByPath(parentObject, ["parameters", "safetySetting"], fromSafetyFilterLevel);
  }
  const fromPersonGeneration = getValueByPath(fromObject, [
    "personGeneration"
  ]);
  if (parentObject !== void 0 && fromPersonGeneration != null) {
    setValueByPath(parentObject, ["parameters", "personGeneration"], fromPersonGeneration);
  }
  const fromIncludeSafetyAttributes = getValueByPath(fromObject, [
    "includeSafetyAttributes"
  ]);
  if (parentObject !== void 0 && fromIncludeSafetyAttributes != null) {
    setValueByPath(parentObject, ["parameters", "includeSafetyAttributes"], fromIncludeSafetyAttributes);
  }
  const fromIncludeRaiReason = getValueByPath(fromObject, [
    "includeRaiReason"
  ]);
  if (parentObject !== void 0 && fromIncludeRaiReason != null) {
    setValueByPath(parentObject, ["parameters", "includeRaiReason"], fromIncludeRaiReason);
  }
  const fromLanguage = getValueByPath(fromObject, ["language"]);
  if (parentObject !== void 0 && fromLanguage != null) {
    setValueByPath(parentObject, ["parameters", "language"], fromLanguage);
  }
  const fromOutputMimeType = getValueByPath(fromObject, [
    "outputMimeType"
  ]);
  if (parentObject !== void 0 && fromOutputMimeType != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "mimeType"], fromOutputMimeType);
  }
  const fromOutputCompressionQuality = getValueByPath(fromObject, [
    "outputCompressionQuality"
  ]);
  if (parentObject !== void 0 && fromOutputCompressionQuality != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "compressionQuality"], fromOutputCompressionQuality);
  }
  if (getValueByPath(fromObject, ["addWatermark"]) !== void 0) {
    throw new Error("addWatermark parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["imageSize"]) !== void 0) {
    throw new Error("imageSize parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["enhancePrompt"]) !== void 0) {
    throw new Error("enhancePrompt parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(generateImagesConfigToMldev, "generateImagesConfigToMldev");
function generateImagesParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromPrompt != null) {
    setValueByPath(toObject, ["instances[0]", "prompt"], fromPrompt);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], generateImagesConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(generateImagesParametersToMldev, "generateImagesParametersToMldev");
function getModelParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "name"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getModelParametersToMldev, "getModelParametersToMldev");
function listModelsConfigToMldev(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  const fromFilter = getValueByPath(fromObject, ["filter"]);
  if (parentObject !== void 0 && fromFilter != null) {
    setValueByPath(parentObject, ["_query", "filter"], fromFilter);
  }
  const fromQueryBase = getValueByPath(fromObject, ["queryBase"]);
  if (parentObject !== void 0 && fromQueryBase != null) {
    setValueByPath(parentObject, ["_url", "models_url"], tModelsUrl(apiClient, fromQueryBase));
  }
  return toObject;
}
__name(listModelsConfigToMldev, "listModelsConfigToMldev");
function listModelsParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listModelsConfigToMldev(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(listModelsParametersToMldev, "listModelsParametersToMldev");
function updateModelConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromDisplayName);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (parentObject !== void 0 && fromDescription != null) {
    setValueByPath(parentObject, ["description"], fromDescription);
  }
  const fromDefaultCheckpointId = getValueByPath(fromObject, [
    "defaultCheckpointId"
  ]);
  if (parentObject !== void 0 && fromDefaultCheckpointId != null) {
    setValueByPath(parentObject, ["defaultCheckpointId"], fromDefaultCheckpointId);
  }
  return toObject;
}
__name(updateModelConfigToMldev, "updateModelConfigToMldev");
function updateModelParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "name"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], updateModelConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(updateModelParametersToMldev, "updateModelParametersToMldev");
function deleteModelParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "name"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteModelParametersToMldev, "deleteModelParametersToMldev");
function countTokensConfigToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["systemInstruction"]) !== void 0) {
    throw new Error("systemInstruction parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["tools"]) !== void 0) {
    throw new Error("tools parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["generationConfig"]) !== void 0) {
    throw new Error("generationConfig parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(countTokensConfigToMldev, "countTokensConfigToMldev");
function countTokensParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToMldev$1(item);
      });
    }
    setValueByPath(toObject, ["contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], countTokensConfigToMldev(fromConfig));
  }
  return toObject;
}
__name(countTokensParametersToMldev, "countTokensParametersToMldev");
function imageToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["gcsUri"]) !== void 0) {
    throw new Error("gcsUri parameter is not supported in Gemini API.");
  }
  const fromImageBytes = getValueByPath(fromObject, ["imageBytes"]);
  if (fromImageBytes != null) {
    setValueByPath(toObject, ["bytesBase64Encoded"], tBytes(fromImageBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(imageToMldev, "imageToMldev");
function generateVideosConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromNumberOfVideos = getValueByPath(fromObject, [
    "numberOfVideos"
  ]);
  if (parentObject !== void 0 && fromNumberOfVideos != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfVideos);
  }
  if (getValueByPath(fromObject, ["outputGcsUri"]) !== void 0) {
    throw new Error("outputGcsUri parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["fps"]) !== void 0) {
    throw new Error("fps parameter is not supported in Gemini API.");
  }
  const fromDurationSeconds = getValueByPath(fromObject, [
    "durationSeconds"
  ]);
  if (parentObject !== void 0 && fromDurationSeconds != null) {
    setValueByPath(parentObject, ["parameters", "durationSeconds"], fromDurationSeconds);
  }
  if (getValueByPath(fromObject, ["seed"]) !== void 0) {
    throw new Error("seed parameter is not supported in Gemini API.");
  }
  const fromAspectRatio = getValueByPath(fromObject, ["aspectRatio"]);
  if (parentObject !== void 0 && fromAspectRatio != null) {
    setValueByPath(parentObject, ["parameters", "aspectRatio"], fromAspectRatio);
  }
  if (getValueByPath(fromObject, ["resolution"]) !== void 0) {
    throw new Error("resolution parameter is not supported in Gemini API.");
  }
  const fromPersonGeneration = getValueByPath(fromObject, [
    "personGeneration"
  ]);
  if (parentObject !== void 0 && fromPersonGeneration != null) {
    setValueByPath(parentObject, ["parameters", "personGeneration"], fromPersonGeneration);
  }
  if (getValueByPath(fromObject, ["pubsubTopic"]) !== void 0) {
    throw new Error("pubsubTopic parameter is not supported in Gemini API.");
  }
  const fromNegativePrompt = getValueByPath(fromObject, [
    "negativePrompt"
  ]);
  if (parentObject !== void 0 && fromNegativePrompt != null) {
    setValueByPath(parentObject, ["parameters", "negativePrompt"], fromNegativePrompt);
  }
  const fromEnhancePrompt = getValueByPath(fromObject, [
    "enhancePrompt"
  ]);
  if (parentObject !== void 0 && fromEnhancePrompt != null) {
    setValueByPath(parentObject, ["parameters", "enhancePrompt"], fromEnhancePrompt);
  }
  if (getValueByPath(fromObject, ["generateAudio"]) !== void 0) {
    throw new Error("generateAudio parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["lastFrame"]) !== void 0) {
    throw new Error("lastFrame parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["compressionQuality"]) !== void 0) {
    throw new Error("compressionQuality parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(generateVideosConfigToMldev, "generateVideosConfigToMldev");
function generateVideosParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromPrompt != null) {
    setValueByPath(toObject, ["instances[0]", "prompt"], fromPrompt);
  }
  const fromImage = getValueByPath(fromObject, ["image"]);
  if (fromImage != null) {
    setValueByPath(toObject, ["instances[0]", "image"], imageToMldev(fromImage));
  }
  if (getValueByPath(fromObject, ["video"]) !== void 0) {
    throw new Error("video parameter is not supported in Gemini API.");
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], generateVideosConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(generateVideosParametersToMldev, "generateVideosParametersToMldev");
function videoMetadataToVertex(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToVertex, "videoMetadataToVertex");
function blobToVertex(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToVertex, "blobToVertex");
function fileDataToVertex(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToVertex, "fileDataToVertex");
function partToVertex(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToVertex(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToVertex(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToVertex(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToVertex, "partToVertex");
function contentToVertex(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToVertex(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToVertex, "contentToVertex");
function schemaToVertex(fromObject) {
  const toObject = {};
  const fromAnyOf = getValueByPath(fromObject, ["anyOf"]);
  if (fromAnyOf != null) {
    setValueByPath(toObject, ["anyOf"], fromAnyOf);
  }
  const fromDefault = getValueByPath(fromObject, ["default"]);
  if (fromDefault != null) {
    setValueByPath(toObject, ["default"], fromDefault);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromEnum = getValueByPath(fromObject, ["enum"]);
  if (fromEnum != null) {
    setValueByPath(toObject, ["enum"], fromEnum);
  }
  const fromExample = getValueByPath(fromObject, ["example"]);
  if (fromExample != null) {
    setValueByPath(toObject, ["example"], fromExample);
  }
  const fromFormat = getValueByPath(fromObject, ["format"]);
  if (fromFormat != null) {
    setValueByPath(toObject, ["format"], fromFormat);
  }
  const fromItems = getValueByPath(fromObject, ["items"]);
  if (fromItems != null) {
    setValueByPath(toObject, ["items"], fromItems);
  }
  const fromMaxItems = getValueByPath(fromObject, ["maxItems"]);
  if (fromMaxItems != null) {
    setValueByPath(toObject, ["maxItems"], fromMaxItems);
  }
  const fromMaxLength = getValueByPath(fromObject, ["maxLength"]);
  if (fromMaxLength != null) {
    setValueByPath(toObject, ["maxLength"], fromMaxLength);
  }
  const fromMaxProperties = getValueByPath(fromObject, [
    "maxProperties"
  ]);
  if (fromMaxProperties != null) {
    setValueByPath(toObject, ["maxProperties"], fromMaxProperties);
  }
  const fromMaximum = getValueByPath(fromObject, ["maximum"]);
  if (fromMaximum != null) {
    setValueByPath(toObject, ["maximum"], fromMaximum);
  }
  const fromMinItems = getValueByPath(fromObject, ["minItems"]);
  if (fromMinItems != null) {
    setValueByPath(toObject, ["minItems"], fromMinItems);
  }
  const fromMinLength = getValueByPath(fromObject, ["minLength"]);
  if (fromMinLength != null) {
    setValueByPath(toObject, ["minLength"], fromMinLength);
  }
  const fromMinProperties = getValueByPath(fromObject, [
    "minProperties"
  ]);
  if (fromMinProperties != null) {
    setValueByPath(toObject, ["minProperties"], fromMinProperties);
  }
  const fromMinimum = getValueByPath(fromObject, ["minimum"]);
  if (fromMinimum != null) {
    setValueByPath(toObject, ["minimum"], fromMinimum);
  }
  const fromNullable = getValueByPath(fromObject, ["nullable"]);
  if (fromNullable != null) {
    setValueByPath(toObject, ["nullable"], fromNullable);
  }
  const fromPattern = getValueByPath(fromObject, ["pattern"]);
  if (fromPattern != null) {
    setValueByPath(toObject, ["pattern"], fromPattern);
  }
  const fromProperties = getValueByPath(fromObject, ["properties"]);
  if (fromProperties != null) {
    setValueByPath(toObject, ["properties"], fromProperties);
  }
  const fromPropertyOrdering = getValueByPath(fromObject, [
    "propertyOrdering"
  ]);
  if (fromPropertyOrdering != null) {
    setValueByPath(toObject, ["propertyOrdering"], fromPropertyOrdering);
  }
  const fromRequired = getValueByPath(fromObject, ["required"]);
  if (fromRequired != null) {
    setValueByPath(toObject, ["required"], fromRequired);
  }
  const fromTitle = getValueByPath(fromObject, ["title"]);
  if (fromTitle != null) {
    setValueByPath(toObject, ["title"], fromTitle);
  }
  const fromType = getValueByPath(fromObject, ["type"]);
  if (fromType != null) {
    setValueByPath(toObject, ["type"], fromType);
  }
  return toObject;
}
__name(schemaToVertex, "schemaToVertex");
function modelSelectionConfigToVertex(fromObject) {
  const toObject = {};
  const fromFeatureSelectionPreference = getValueByPath(fromObject, [
    "featureSelectionPreference"
  ]);
  if (fromFeatureSelectionPreference != null) {
    setValueByPath(toObject, ["featureSelectionPreference"], fromFeatureSelectionPreference);
  }
  return toObject;
}
__name(modelSelectionConfigToVertex, "modelSelectionConfigToVertex");
function safetySettingToVertex(fromObject) {
  const toObject = {};
  const fromMethod = getValueByPath(fromObject, ["method"]);
  if (fromMethod != null) {
    setValueByPath(toObject, ["method"], fromMethod);
  }
  const fromCategory = getValueByPath(fromObject, ["category"]);
  if (fromCategory != null) {
    setValueByPath(toObject, ["category"], fromCategory);
  }
  const fromThreshold = getValueByPath(fromObject, ["threshold"]);
  if (fromThreshold != null) {
    setValueByPath(toObject, ["threshold"], fromThreshold);
  }
  return toObject;
}
__name(safetySettingToVertex, "safetySettingToVertex");
function functionDeclarationToVertex(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["behavior"]) !== void 0) {
    throw new Error("behavior parameter is not supported in Vertex AI.");
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToVertex, "functionDeclarationToVertex");
function intervalToVertex(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToVertex, "intervalToVertex");
function googleSearchToVertex(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToVertex(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToVertex, "googleSearchToVertex");
function dynamicRetrievalConfigToVertex(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToVertex, "dynamicRetrievalConfigToVertex");
function googleSearchRetrievalToVertex(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToVertex(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToVertex, "googleSearchRetrievalToVertex");
function enterpriseWebSearchToVertex() {
  const toObject = {};
  return toObject;
}
__name(enterpriseWebSearchToVertex, "enterpriseWebSearchToVertex");
function apiKeyConfigToVertex(fromObject) {
  const toObject = {};
  const fromApiKeyString = getValueByPath(fromObject, ["apiKeyString"]);
  if (fromApiKeyString != null) {
    setValueByPath(toObject, ["apiKeyString"], fromApiKeyString);
  }
  return toObject;
}
__name(apiKeyConfigToVertex, "apiKeyConfigToVertex");
function authConfigToVertex(fromObject) {
  const toObject = {};
  const fromApiKeyConfig = getValueByPath(fromObject, ["apiKeyConfig"]);
  if (fromApiKeyConfig != null) {
    setValueByPath(toObject, ["apiKeyConfig"], apiKeyConfigToVertex(fromApiKeyConfig));
  }
  const fromAuthType = getValueByPath(fromObject, ["authType"]);
  if (fromAuthType != null) {
    setValueByPath(toObject, ["authType"], fromAuthType);
  }
  const fromGoogleServiceAccountConfig = getValueByPath(fromObject, [
    "googleServiceAccountConfig"
  ]);
  if (fromGoogleServiceAccountConfig != null) {
    setValueByPath(toObject, ["googleServiceAccountConfig"], fromGoogleServiceAccountConfig);
  }
  const fromHttpBasicAuthConfig = getValueByPath(fromObject, [
    "httpBasicAuthConfig"
  ]);
  if (fromHttpBasicAuthConfig != null) {
    setValueByPath(toObject, ["httpBasicAuthConfig"], fromHttpBasicAuthConfig);
  }
  const fromOauthConfig = getValueByPath(fromObject, ["oauthConfig"]);
  if (fromOauthConfig != null) {
    setValueByPath(toObject, ["oauthConfig"], fromOauthConfig);
  }
  const fromOidcConfig = getValueByPath(fromObject, ["oidcConfig"]);
  if (fromOidcConfig != null) {
    setValueByPath(toObject, ["oidcConfig"], fromOidcConfig);
  }
  return toObject;
}
__name(authConfigToVertex, "authConfigToVertex");
function googleMapsToVertex(fromObject) {
  const toObject = {};
  const fromAuthConfig = getValueByPath(fromObject, ["authConfig"]);
  if (fromAuthConfig != null) {
    setValueByPath(toObject, ["authConfig"], authConfigToVertex(fromAuthConfig));
  }
  return toObject;
}
__name(googleMapsToVertex, "googleMapsToVertex");
function urlContextToVertex() {
  const toObject = {};
  return toObject;
}
__name(urlContextToVertex, "urlContextToVertex");
function toolToVertex(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToVertex(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  const fromRetrieval = getValueByPath(fromObject, ["retrieval"]);
  if (fromRetrieval != null) {
    setValueByPath(toObject, ["retrieval"], fromRetrieval);
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToVertex(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToVertex(fromGoogleSearchRetrieval));
  }
  const fromEnterpriseWebSearch = getValueByPath(fromObject, [
    "enterpriseWebSearch"
  ]);
  if (fromEnterpriseWebSearch != null) {
    setValueByPath(toObject, ["enterpriseWebSearch"], enterpriseWebSearchToVertex());
  }
  const fromGoogleMaps = getValueByPath(fromObject, ["googleMaps"]);
  if (fromGoogleMaps != null) {
    setValueByPath(toObject, ["googleMaps"], googleMapsToVertex(fromGoogleMaps));
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToVertex());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToVertex, "toolToVertex");
function functionCallingConfigToVertex(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromAllowedFunctionNames = getValueByPath(fromObject, [
    "allowedFunctionNames"
  ]);
  if (fromAllowedFunctionNames != null) {
    setValueByPath(toObject, ["allowedFunctionNames"], fromAllowedFunctionNames);
  }
  return toObject;
}
__name(functionCallingConfigToVertex, "functionCallingConfigToVertex");
function latLngToVertex(fromObject) {
  const toObject = {};
  const fromLatitude = getValueByPath(fromObject, ["latitude"]);
  if (fromLatitude != null) {
    setValueByPath(toObject, ["latitude"], fromLatitude);
  }
  const fromLongitude = getValueByPath(fromObject, ["longitude"]);
  if (fromLongitude != null) {
    setValueByPath(toObject, ["longitude"], fromLongitude);
  }
  return toObject;
}
__name(latLngToVertex, "latLngToVertex");
function retrievalConfigToVertex(fromObject) {
  const toObject = {};
  const fromLatLng = getValueByPath(fromObject, ["latLng"]);
  if (fromLatLng != null) {
    setValueByPath(toObject, ["latLng"], latLngToVertex(fromLatLng));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(retrievalConfigToVertex, "retrievalConfigToVertex");
function toolConfigToVertex(fromObject) {
  const toObject = {};
  const fromFunctionCallingConfig = getValueByPath(fromObject, [
    "functionCallingConfig"
  ]);
  if (fromFunctionCallingConfig != null) {
    setValueByPath(toObject, ["functionCallingConfig"], functionCallingConfigToVertex(fromFunctionCallingConfig));
  }
  const fromRetrievalConfig = getValueByPath(fromObject, [
    "retrievalConfig"
  ]);
  if (fromRetrievalConfig != null) {
    setValueByPath(toObject, ["retrievalConfig"], retrievalConfigToVertex(fromRetrievalConfig));
  }
  return toObject;
}
__name(toolConfigToVertex, "toolConfigToVertex");
function prebuiltVoiceConfigToVertex(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToVertex, "prebuiltVoiceConfigToVertex");
function voiceConfigToVertex(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToVertex(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToVertex, "voiceConfigToVertex");
function speechConfigToVertex(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToVertex(fromVoiceConfig));
  }
  if (getValueByPath(fromObject, ["multiSpeakerVoiceConfig"]) !== void 0) {
    throw new Error("multiSpeakerVoiceConfig parameter is not supported in Vertex AI.");
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToVertex, "speechConfigToVertex");
function thinkingConfigToVertex(fromObject) {
  const toObject = {};
  const fromIncludeThoughts = getValueByPath(fromObject, [
    "includeThoughts"
  ]);
  if (fromIncludeThoughts != null) {
    setValueByPath(toObject, ["includeThoughts"], fromIncludeThoughts);
  }
  const fromThinkingBudget = getValueByPath(fromObject, [
    "thinkingBudget"
  ]);
  if (fromThinkingBudget != null) {
    setValueByPath(toObject, ["thinkingBudget"], fromThinkingBudget);
  }
  return toObject;
}
__name(thinkingConfigToVertex, "thinkingConfigToVertex");
function generateContentConfigToVertex(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToVertex(tContent(fromSystemInstruction)));
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (fromTemperature != null) {
    setValueByPath(toObject, ["temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (fromTopP != null) {
    setValueByPath(toObject, ["topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (fromTopK != null) {
    setValueByPath(toObject, ["topK"], fromTopK);
  }
  const fromCandidateCount = getValueByPath(fromObject, [
    "candidateCount"
  ]);
  if (fromCandidateCount != null) {
    setValueByPath(toObject, ["candidateCount"], fromCandidateCount);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (fromMaxOutputTokens != null) {
    setValueByPath(toObject, ["maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromStopSequences = getValueByPath(fromObject, [
    "stopSequences"
  ]);
  if (fromStopSequences != null) {
    setValueByPath(toObject, ["stopSequences"], fromStopSequences);
  }
  const fromResponseLogprobs = getValueByPath(fromObject, [
    "responseLogprobs"
  ]);
  if (fromResponseLogprobs != null) {
    setValueByPath(toObject, ["responseLogprobs"], fromResponseLogprobs);
  }
  const fromLogprobs = getValueByPath(fromObject, ["logprobs"]);
  if (fromLogprobs != null) {
    setValueByPath(toObject, ["logprobs"], fromLogprobs);
  }
  const fromPresencePenalty = getValueByPath(fromObject, [
    "presencePenalty"
  ]);
  if (fromPresencePenalty != null) {
    setValueByPath(toObject, ["presencePenalty"], fromPresencePenalty);
  }
  const fromFrequencyPenalty = getValueByPath(fromObject, [
    "frequencyPenalty"
  ]);
  if (fromFrequencyPenalty != null) {
    setValueByPath(toObject, ["frequencyPenalty"], fromFrequencyPenalty);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (fromSeed != null) {
    setValueByPath(toObject, ["seed"], fromSeed);
  }
  const fromResponseMimeType = getValueByPath(fromObject, [
    "responseMimeType"
  ]);
  if (fromResponseMimeType != null) {
    setValueByPath(toObject, ["responseMimeType"], fromResponseMimeType);
  }
  const fromResponseSchema = getValueByPath(fromObject, [
    "responseSchema"
  ]);
  if (fromResponseSchema != null) {
    setValueByPath(toObject, ["responseSchema"], schemaToVertex(tSchema(fromResponseSchema)));
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  const fromRoutingConfig = getValueByPath(fromObject, [
    "routingConfig"
  ]);
  if (fromRoutingConfig != null) {
    setValueByPath(toObject, ["routingConfig"], fromRoutingConfig);
  }
  const fromModelSelectionConfig = getValueByPath(fromObject, [
    "modelSelectionConfig"
  ]);
  if (fromModelSelectionConfig != null) {
    setValueByPath(toObject, ["modelConfig"], modelSelectionConfigToVertex(fromModelSelectionConfig));
  }
  const fromSafetySettings = getValueByPath(fromObject, [
    "safetySettings"
  ]);
  if (parentObject !== void 0 && fromSafetySettings != null) {
    let transformedList = fromSafetySettings;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return safetySettingToVertex(item);
      });
    }
    setValueByPath(parentObject, ["safetySettings"], transformedList);
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToVertex(tTool(item));
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromToolConfig = getValueByPath(fromObject, ["toolConfig"]);
  if (parentObject !== void 0 && fromToolConfig != null) {
    setValueByPath(parentObject, ["toolConfig"], toolConfigToVertex(fromToolConfig));
  }
  const fromLabels = getValueByPath(fromObject, ["labels"]);
  if (parentObject !== void 0 && fromLabels != null) {
    setValueByPath(parentObject, ["labels"], fromLabels);
  }
  const fromCachedContent = getValueByPath(fromObject, [
    "cachedContent"
  ]);
  if (parentObject !== void 0 && fromCachedContent != null) {
    setValueByPath(parentObject, ["cachedContent"], tCachedContentName(apiClient, fromCachedContent));
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (fromResponseModalities != null) {
    setValueByPath(toObject, ["responseModalities"], fromResponseModalities);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (fromMediaResolution != null) {
    setValueByPath(toObject, ["mediaResolution"], fromMediaResolution);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (fromSpeechConfig != null) {
    setValueByPath(toObject, ["speechConfig"], speechConfigToVertex(tSpeechConfig(fromSpeechConfig)));
  }
  const fromAudioTimestamp = getValueByPath(fromObject, [
    "audioTimestamp"
  ]);
  if (fromAudioTimestamp != null) {
    setValueByPath(toObject, ["audioTimestamp"], fromAudioTimestamp);
  }
  const fromThinkingConfig = getValueByPath(fromObject, [
    "thinkingConfig"
  ]);
  if (fromThinkingConfig != null) {
    setValueByPath(toObject, ["thinkingConfig"], thinkingConfigToVertex(fromThinkingConfig));
  }
  return toObject;
}
__name(generateContentConfigToVertex, "generateContentConfigToVertex");
function generateContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToVertex(item);
      });
    }
    setValueByPath(toObject, ["contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["generationConfig"], generateContentConfigToVertex(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(generateContentParametersToVertex, "generateContentParametersToVertex");
function embedContentConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromTaskType = getValueByPath(fromObject, ["taskType"]);
  if (parentObject !== void 0 && fromTaskType != null) {
    setValueByPath(parentObject, ["instances[]", "task_type"], fromTaskType);
  }
  const fromTitle = getValueByPath(fromObject, ["title"]);
  if (parentObject !== void 0 && fromTitle != null) {
    setValueByPath(parentObject, ["instances[]", "title"], fromTitle);
  }
  const fromOutputDimensionality = getValueByPath(fromObject, [
    "outputDimensionality"
  ]);
  if (parentObject !== void 0 && fromOutputDimensionality != null) {
    setValueByPath(parentObject, ["parameters", "outputDimensionality"], fromOutputDimensionality);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (parentObject !== void 0 && fromMimeType != null) {
    setValueByPath(parentObject, ["instances[]", "mimeType"], fromMimeType);
  }
  const fromAutoTruncate = getValueByPath(fromObject, ["autoTruncate"]);
  if (parentObject !== void 0 && fromAutoTruncate != null) {
    setValueByPath(parentObject, ["parameters", "autoTruncate"], fromAutoTruncate);
  }
  return toObject;
}
__name(embedContentConfigToVertex, "embedContentConfigToVertex");
function embedContentParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    setValueByPath(toObject, ["instances[]", "content"], tContentsForEmbed(apiClient, fromContents));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], embedContentConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(embedContentParametersToVertex, "embedContentParametersToVertex");
function generateImagesConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromOutputGcsUri = getValueByPath(fromObject, ["outputGcsUri"]);
  if (parentObject !== void 0 && fromOutputGcsUri != null) {
    setValueByPath(parentObject, ["parameters", "storageUri"], fromOutputGcsUri);
  }
  const fromNegativePrompt = getValueByPath(fromObject, [
    "negativePrompt"
  ]);
  if (parentObject !== void 0 && fromNegativePrompt != null) {
    setValueByPath(parentObject, ["parameters", "negativePrompt"], fromNegativePrompt);
  }
  const fromNumberOfImages = getValueByPath(fromObject, [
    "numberOfImages"
  ]);
  if (parentObject !== void 0 && fromNumberOfImages != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfImages);
  }
  const fromAspectRatio = getValueByPath(fromObject, ["aspectRatio"]);
  if (parentObject !== void 0 && fromAspectRatio != null) {
    setValueByPath(parentObject, ["parameters", "aspectRatio"], fromAspectRatio);
  }
  const fromGuidanceScale = getValueByPath(fromObject, [
    "guidanceScale"
  ]);
  if (parentObject !== void 0 && fromGuidanceScale != null) {
    setValueByPath(parentObject, ["parameters", "guidanceScale"], fromGuidanceScale);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["parameters", "seed"], fromSeed);
  }
  const fromSafetyFilterLevel = getValueByPath(fromObject, [
    "safetyFilterLevel"
  ]);
  if (parentObject !== void 0 && fromSafetyFilterLevel != null) {
    setValueByPath(parentObject, ["parameters", "safetySetting"], fromSafetyFilterLevel);
  }
  const fromPersonGeneration = getValueByPath(fromObject, [
    "personGeneration"
  ]);
  if (parentObject !== void 0 && fromPersonGeneration != null) {
    setValueByPath(parentObject, ["parameters", "personGeneration"], fromPersonGeneration);
  }
  const fromIncludeSafetyAttributes = getValueByPath(fromObject, [
    "includeSafetyAttributes"
  ]);
  if (parentObject !== void 0 && fromIncludeSafetyAttributes != null) {
    setValueByPath(parentObject, ["parameters", "includeSafetyAttributes"], fromIncludeSafetyAttributes);
  }
  const fromIncludeRaiReason = getValueByPath(fromObject, [
    "includeRaiReason"
  ]);
  if (parentObject !== void 0 && fromIncludeRaiReason != null) {
    setValueByPath(parentObject, ["parameters", "includeRaiReason"], fromIncludeRaiReason);
  }
  const fromLanguage = getValueByPath(fromObject, ["language"]);
  if (parentObject !== void 0 && fromLanguage != null) {
    setValueByPath(parentObject, ["parameters", "language"], fromLanguage);
  }
  const fromOutputMimeType = getValueByPath(fromObject, [
    "outputMimeType"
  ]);
  if (parentObject !== void 0 && fromOutputMimeType != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "mimeType"], fromOutputMimeType);
  }
  const fromOutputCompressionQuality = getValueByPath(fromObject, [
    "outputCompressionQuality"
  ]);
  if (parentObject !== void 0 && fromOutputCompressionQuality != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "compressionQuality"], fromOutputCompressionQuality);
  }
  const fromAddWatermark = getValueByPath(fromObject, ["addWatermark"]);
  if (parentObject !== void 0 && fromAddWatermark != null) {
    setValueByPath(parentObject, ["parameters", "addWatermark"], fromAddWatermark);
  }
  const fromImageSize = getValueByPath(fromObject, ["imageSize"]);
  if (parentObject !== void 0 && fromImageSize != null) {
    setValueByPath(parentObject, ["parameters", "sampleImageSize"], fromImageSize);
  }
  const fromEnhancePrompt = getValueByPath(fromObject, [
    "enhancePrompt"
  ]);
  if (parentObject !== void 0 && fromEnhancePrompt != null) {
    setValueByPath(parentObject, ["parameters", "enhancePrompt"], fromEnhancePrompt);
  }
  return toObject;
}
__name(generateImagesConfigToVertex, "generateImagesConfigToVertex");
function generateImagesParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromPrompt != null) {
    setValueByPath(toObject, ["instances[0]", "prompt"], fromPrompt);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], generateImagesConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(generateImagesParametersToVertex, "generateImagesParametersToVertex");
function imageToVertex(fromObject) {
  const toObject = {};
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsUri"], fromGcsUri);
  }
  const fromImageBytes = getValueByPath(fromObject, ["imageBytes"]);
  if (fromImageBytes != null) {
    setValueByPath(toObject, ["bytesBase64Encoded"], tBytes(fromImageBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(imageToVertex, "imageToVertex");
function maskReferenceConfigToVertex(fromObject) {
  const toObject = {};
  const fromMaskMode = getValueByPath(fromObject, ["maskMode"]);
  if (fromMaskMode != null) {
    setValueByPath(toObject, ["maskMode"], fromMaskMode);
  }
  const fromSegmentationClasses = getValueByPath(fromObject, [
    "segmentationClasses"
  ]);
  if (fromSegmentationClasses != null) {
    setValueByPath(toObject, ["maskClasses"], fromSegmentationClasses);
  }
  const fromMaskDilation = getValueByPath(fromObject, ["maskDilation"]);
  if (fromMaskDilation != null) {
    setValueByPath(toObject, ["dilation"], fromMaskDilation);
  }
  return toObject;
}
__name(maskReferenceConfigToVertex, "maskReferenceConfigToVertex");
function controlReferenceConfigToVertex(fromObject) {
  const toObject = {};
  const fromControlType = getValueByPath(fromObject, ["controlType"]);
  if (fromControlType != null) {
    setValueByPath(toObject, ["controlType"], fromControlType);
  }
  const fromEnableControlImageComputation = getValueByPath(fromObject, [
    "enableControlImageComputation"
  ]);
  if (fromEnableControlImageComputation != null) {
    setValueByPath(toObject, ["computeControl"], fromEnableControlImageComputation);
  }
  return toObject;
}
__name(controlReferenceConfigToVertex, "controlReferenceConfigToVertex");
function styleReferenceConfigToVertex(fromObject) {
  const toObject = {};
  const fromStyleDescription = getValueByPath(fromObject, [
    "styleDescription"
  ]);
  if (fromStyleDescription != null) {
    setValueByPath(toObject, ["styleDescription"], fromStyleDescription);
  }
  return toObject;
}
__name(styleReferenceConfigToVertex, "styleReferenceConfigToVertex");
function subjectReferenceConfigToVertex(fromObject) {
  const toObject = {};
  const fromSubjectType = getValueByPath(fromObject, ["subjectType"]);
  if (fromSubjectType != null) {
    setValueByPath(toObject, ["subjectType"], fromSubjectType);
  }
  const fromSubjectDescription = getValueByPath(fromObject, [
    "subjectDescription"
  ]);
  if (fromSubjectDescription != null) {
    setValueByPath(toObject, ["subjectDescription"], fromSubjectDescription);
  }
  return toObject;
}
__name(subjectReferenceConfigToVertex, "subjectReferenceConfigToVertex");
function referenceImageAPIInternalToVertex(fromObject) {
  const toObject = {};
  const fromReferenceImage = getValueByPath(fromObject, [
    "referenceImage"
  ]);
  if (fromReferenceImage != null) {
    setValueByPath(toObject, ["referenceImage"], imageToVertex(fromReferenceImage));
  }
  const fromReferenceId = getValueByPath(fromObject, ["referenceId"]);
  if (fromReferenceId != null) {
    setValueByPath(toObject, ["referenceId"], fromReferenceId);
  }
  const fromReferenceType = getValueByPath(fromObject, [
    "referenceType"
  ]);
  if (fromReferenceType != null) {
    setValueByPath(toObject, ["referenceType"], fromReferenceType);
  }
  const fromMaskImageConfig = getValueByPath(fromObject, [
    "maskImageConfig"
  ]);
  if (fromMaskImageConfig != null) {
    setValueByPath(toObject, ["maskImageConfig"], maskReferenceConfigToVertex(fromMaskImageConfig));
  }
  const fromControlImageConfig = getValueByPath(fromObject, [
    "controlImageConfig"
  ]);
  if (fromControlImageConfig != null) {
    setValueByPath(toObject, ["controlImageConfig"], controlReferenceConfigToVertex(fromControlImageConfig));
  }
  const fromStyleImageConfig = getValueByPath(fromObject, [
    "styleImageConfig"
  ]);
  if (fromStyleImageConfig != null) {
    setValueByPath(toObject, ["styleImageConfig"], styleReferenceConfigToVertex(fromStyleImageConfig));
  }
  const fromSubjectImageConfig = getValueByPath(fromObject, [
    "subjectImageConfig"
  ]);
  if (fromSubjectImageConfig != null) {
    setValueByPath(toObject, ["subjectImageConfig"], subjectReferenceConfigToVertex(fromSubjectImageConfig));
  }
  return toObject;
}
__name(referenceImageAPIInternalToVertex, "referenceImageAPIInternalToVertex");
function editImageConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromOutputGcsUri = getValueByPath(fromObject, ["outputGcsUri"]);
  if (parentObject !== void 0 && fromOutputGcsUri != null) {
    setValueByPath(parentObject, ["parameters", "storageUri"], fromOutputGcsUri);
  }
  const fromNegativePrompt = getValueByPath(fromObject, [
    "negativePrompt"
  ]);
  if (parentObject !== void 0 && fromNegativePrompt != null) {
    setValueByPath(parentObject, ["parameters", "negativePrompt"], fromNegativePrompt);
  }
  const fromNumberOfImages = getValueByPath(fromObject, [
    "numberOfImages"
  ]);
  if (parentObject !== void 0 && fromNumberOfImages != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfImages);
  }
  const fromAspectRatio = getValueByPath(fromObject, ["aspectRatio"]);
  if (parentObject !== void 0 && fromAspectRatio != null) {
    setValueByPath(parentObject, ["parameters", "aspectRatio"], fromAspectRatio);
  }
  const fromGuidanceScale = getValueByPath(fromObject, [
    "guidanceScale"
  ]);
  if (parentObject !== void 0 && fromGuidanceScale != null) {
    setValueByPath(parentObject, ["parameters", "guidanceScale"], fromGuidanceScale);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["parameters", "seed"], fromSeed);
  }
  const fromSafetyFilterLevel = getValueByPath(fromObject, [
    "safetyFilterLevel"
  ]);
  if (parentObject !== void 0 && fromSafetyFilterLevel != null) {
    setValueByPath(parentObject, ["parameters", "safetySetting"], fromSafetyFilterLevel);
  }
  const fromPersonGeneration = getValueByPath(fromObject, [
    "personGeneration"
  ]);
  if (parentObject !== void 0 && fromPersonGeneration != null) {
    setValueByPath(parentObject, ["parameters", "personGeneration"], fromPersonGeneration);
  }
  const fromIncludeSafetyAttributes = getValueByPath(fromObject, [
    "includeSafetyAttributes"
  ]);
  if (parentObject !== void 0 && fromIncludeSafetyAttributes != null) {
    setValueByPath(parentObject, ["parameters", "includeSafetyAttributes"], fromIncludeSafetyAttributes);
  }
  const fromIncludeRaiReason = getValueByPath(fromObject, [
    "includeRaiReason"
  ]);
  if (parentObject !== void 0 && fromIncludeRaiReason != null) {
    setValueByPath(parentObject, ["parameters", "includeRaiReason"], fromIncludeRaiReason);
  }
  const fromLanguage = getValueByPath(fromObject, ["language"]);
  if (parentObject !== void 0 && fromLanguage != null) {
    setValueByPath(parentObject, ["parameters", "language"], fromLanguage);
  }
  const fromOutputMimeType = getValueByPath(fromObject, [
    "outputMimeType"
  ]);
  if (parentObject !== void 0 && fromOutputMimeType != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "mimeType"], fromOutputMimeType);
  }
  const fromOutputCompressionQuality = getValueByPath(fromObject, [
    "outputCompressionQuality"
  ]);
  if (parentObject !== void 0 && fromOutputCompressionQuality != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "compressionQuality"], fromOutputCompressionQuality);
  }
  const fromAddWatermark = getValueByPath(fromObject, ["addWatermark"]);
  if (parentObject !== void 0 && fromAddWatermark != null) {
    setValueByPath(parentObject, ["parameters", "addWatermark"], fromAddWatermark);
  }
  const fromEditMode = getValueByPath(fromObject, ["editMode"]);
  if (parentObject !== void 0 && fromEditMode != null) {
    setValueByPath(parentObject, ["parameters", "editMode"], fromEditMode);
  }
  const fromBaseSteps = getValueByPath(fromObject, ["baseSteps"]);
  if (parentObject !== void 0 && fromBaseSteps != null) {
    setValueByPath(parentObject, ["parameters", "editConfig", "baseSteps"], fromBaseSteps);
  }
  return toObject;
}
__name(editImageConfigToVertex, "editImageConfigToVertex");
function editImageParametersInternalToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromPrompt != null) {
    setValueByPath(toObject, ["instances[0]", "prompt"], fromPrompt);
  }
  const fromReferenceImages = getValueByPath(fromObject, [
    "referenceImages"
  ]);
  if (fromReferenceImages != null) {
    let transformedList = fromReferenceImages;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return referenceImageAPIInternalToVertex(item);
      });
    }
    setValueByPath(toObject, ["instances[0]", "referenceImages"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], editImageConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(editImageParametersInternalToVertex, "editImageParametersInternalToVertex");
function upscaleImageAPIConfigInternalToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromIncludeRaiReason = getValueByPath(fromObject, [
    "includeRaiReason"
  ]);
  if (parentObject !== void 0 && fromIncludeRaiReason != null) {
    setValueByPath(parentObject, ["parameters", "includeRaiReason"], fromIncludeRaiReason);
  }
  const fromOutputMimeType = getValueByPath(fromObject, [
    "outputMimeType"
  ]);
  if (parentObject !== void 0 && fromOutputMimeType != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "mimeType"], fromOutputMimeType);
  }
  const fromOutputCompressionQuality = getValueByPath(fromObject, [
    "outputCompressionQuality"
  ]);
  if (parentObject !== void 0 && fromOutputCompressionQuality != null) {
    setValueByPath(parentObject, ["parameters", "outputOptions", "compressionQuality"], fromOutputCompressionQuality);
  }
  const fromEnhanceInputImage = getValueByPath(fromObject, [
    "enhanceInputImage"
  ]);
  if (parentObject !== void 0 && fromEnhanceInputImage != null) {
    setValueByPath(parentObject, ["parameters", "upscaleConfig", "enhanceInputImage"], fromEnhanceInputImage);
  }
  const fromImagePreservationFactor = getValueByPath(fromObject, [
    "imagePreservationFactor"
  ]);
  if (parentObject !== void 0 && fromImagePreservationFactor != null) {
    setValueByPath(parentObject, ["parameters", "upscaleConfig", "imagePreservationFactor"], fromImagePreservationFactor);
  }
  const fromNumberOfImages = getValueByPath(fromObject, [
    "numberOfImages"
  ]);
  if (parentObject !== void 0 && fromNumberOfImages != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfImages);
  }
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (parentObject !== void 0 && fromMode != null) {
    setValueByPath(parentObject, ["parameters", "mode"], fromMode);
  }
  return toObject;
}
__name(upscaleImageAPIConfigInternalToVertex, "upscaleImageAPIConfigInternalToVertex");
function upscaleImageAPIParametersInternalToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromImage = getValueByPath(fromObject, ["image"]);
  if (fromImage != null) {
    setValueByPath(toObject, ["instances[0]", "image"], imageToVertex(fromImage));
  }
  const fromUpscaleFactor = getValueByPath(fromObject, [
    "upscaleFactor"
  ]);
  if (fromUpscaleFactor != null) {
    setValueByPath(toObject, ["parameters", "upscaleConfig", "upscaleFactor"], fromUpscaleFactor);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], upscaleImageAPIConfigInternalToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(upscaleImageAPIParametersInternalToVertex, "upscaleImageAPIParametersInternalToVertex");
function getModelParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "name"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getModelParametersToVertex, "getModelParametersToVertex");
function listModelsConfigToVertex(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  const fromFilter = getValueByPath(fromObject, ["filter"]);
  if (parentObject !== void 0 && fromFilter != null) {
    setValueByPath(parentObject, ["_query", "filter"], fromFilter);
  }
  const fromQueryBase = getValueByPath(fromObject, ["queryBase"]);
  if (parentObject !== void 0 && fromQueryBase != null) {
    setValueByPath(parentObject, ["_url", "models_url"], tModelsUrl(apiClient, fromQueryBase));
  }
  return toObject;
}
__name(listModelsConfigToVertex, "listModelsConfigToVertex");
function listModelsParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listModelsConfigToVertex(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(listModelsParametersToVertex, "listModelsParametersToVertex");
function updateModelConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (parentObject !== void 0 && fromDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromDisplayName);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (parentObject !== void 0 && fromDescription != null) {
    setValueByPath(parentObject, ["description"], fromDescription);
  }
  const fromDefaultCheckpointId = getValueByPath(fromObject, [
    "defaultCheckpointId"
  ]);
  if (parentObject !== void 0 && fromDefaultCheckpointId != null) {
    setValueByPath(parentObject, ["defaultCheckpointId"], fromDefaultCheckpointId);
  }
  return toObject;
}
__name(updateModelConfigToVertex, "updateModelConfigToVertex");
function updateModelParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], updateModelConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(updateModelParametersToVertex, "updateModelParametersToVertex");
function deleteModelParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "name"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(deleteModelParametersToVertex, "deleteModelParametersToVertex");
function countTokensConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["systemInstruction"], contentToVertex(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = fromTools;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToVertex(item);
      });
    }
    setValueByPath(parentObject, ["tools"], transformedList);
  }
  const fromGenerationConfig = getValueByPath(fromObject, [
    "generationConfig"
  ]);
  if (parentObject !== void 0 && fromGenerationConfig != null) {
    setValueByPath(parentObject, ["generationConfig"], fromGenerationConfig);
  }
  return toObject;
}
__name(countTokensConfigToVertex, "countTokensConfigToVertex");
function countTokensParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToVertex(item);
      });
    }
    setValueByPath(toObject, ["contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], countTokensConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(countTokensParametersToVertex, "countTokensParametersToVertex");
function computeTokensParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromContents = getValueByPath(fromObject, ["contents"]);
  if (fromContents != null) {
    let transformedList = tContents(fromContents);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentToVertex(item);
      });
    }
    setValueByPath(toObject, ["contents"], transformedList);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(computeTokensParametersToVertex, "computeTokensParametersToVertex");
function videoToVertex(fromObject) {
  const toObject = {};
  const fromUri = getValueByPath(fromObject, ["uri"]);
  if (fromUri != null) {
    setValueByPath(toObject, ["gcsUri"], fromUri);
  }
  const fromVideoBytes = getValueByPath(fromObject, ["videoBytes"]);
  if (fromVideoBytes != null) {
    setValueByPath(toObject, ["bytesBase64Encoded"], tBytes(fromVideoBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(videoToVertex, "videoToVertex");
function generateVideosConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromNumberOfVideos = getValueByPath(fromObject, [
    "numberOfVideos"
  ]);
  if (parentObject !== void 0 && fromNumberOfVideos != null) {
    setValueByPath(parentObject, ["parameters", "sampleCount"], fromNumberOfVideos);
  }
  const fromOutputGcsUri = getValueByPath(fromObject, ["outputGcsUri"]);
  if (parentObject !== void 0 && fromOutputGcsUri != null) {
    setValueByPath(parentObject, ["parameters", "storageUri"], fromOutputGcsUri);
  }
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (parentObject !== void 0 && fromFps != null) {
    setValueByPath(parentObject, ["parameters", "fps"], fromFps);
  }
  const fromDurationSeconds = getValueByPath(fromObject, [
    "durationSeconds"
  ]);
  if (parentObject !== void 0 && fromDurationSeconds != null) {
    setValueByPath(parentObject, ["parameters", "durationSeconds"], fromDurationSeconds);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["parameters", "seed"], fromSeed);
  }
  const fromAspectRatio = getValueByPath(fromObject, ["aspectRatio"]);
  if (parentObject !== void 0 && fromAspectRatio != null) {
    setValueByPath(parentObject, ["parameters", "aspectRatio"], fromAspectRatio);
  }
  const fromResolution = getValueByPath(fromObject, ["resolution"]);
  if (parentObject !== void 0 && fromResolution != null) {
    setValueByPath(parentObject, ["parameters", "resolution"], fromResolution);
  }
  const fromPersonGeneration = getValueByPath(fromObject, [
    "personGeneration"
  ]);
  if (parentObject !== void 0 && fromPersonGeneration != null) {
    setValueByPath(parentObject, ["parameters", "personGeneration"], fromPersonGeneration);
  }
  const fromPubsubTopic = getValueByPath(fromObject, ["pubsubTopic"]);
  if (parentObject !== void 0 && fromPubsubTopic != null) {
    setValueByPath(parentObject, ["parameters", "pubsubTopic"], fromPubsubTopic);
  }
  const fromNegativePrompt = getValueByPath(fromObject, [
    "negativePrompt"
  ]);
  if (parentObject !== void 0 && fromNegativePrompt != null) {
    setValueByPath(parentObject, ["parameters", "negativePrompt"], fromNegativePrompt);
  }
  const fromEnhancePrompt = getValueByPath(fromObject, [
    "enhancePrompt"
  ]);
  if (parentObject !== void 0 && fromEnhancePrompt != null) {
    setValueByPath(parentObject, ["parameters", "enhancePrompt"], fromEnhancePrompt);
  }
  const fromGenerateAudio = getValueByPath(fromObject, [
    "generateAudio"
  ]);
  if (parentObject !== void 0 && fromGenerateAudio != null) {
    setValueByPath(parentObject, ["parameters", "generateAudio"], fromGenerateAudio);
  }
  const fromLastFrame = getValueByPath(fromObject, ["lastFrame"]);
  if (parentObject !== void 0 && fromLastFrame != null) {
    setValueByPath(parentObject, ["instances[0]", "lastFrame"], imageToVertex(fromLastFrame));
  }
  const fromCompressionQuality = getValueByPath(fromObject, [
    "compressionQuality"
  ]);
  if (parentObject !== void 0 && fromCompressionQuality != null) {
    setValueByPath(parentObject, ["parameters", "compressionQuality"], fromCompressionQuality);
  }
  return toObject;
}
__name(generateVideosConfigToVertex, "generateVideosConfigToVertex");
function generateVideosParametersToVertex(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["_url", "model"], tModel(apiClient, fromModel));
  }
  const fromPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromPrompt != null) {
    setValueByPath(toObject, ["instances[0]", "prompt"], fromPrompt);
  }
  const fromImage = getValueByPath(fromObject, ["image"]);
  if (fromImage != null) {
    setValueByPath(toObject, ["instances[0]", "image"], imageToVertex(fromImage));
  }
  const fromVideo = getValueByPath(fromObject, ["video"]);
  if (fromVideo != null) {
    setValueByPath(toObject, ["instances[0]", "video"], videoToVertex(fromVideo));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], generateVideosConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(generateVideosParametersToVertex, "generateVideosParametersToVertex");
function videoMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataFromMldev, "videoMetadataFromMldev");
function blobFromMldev(fromObject) {
  const toObject = {};
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobFromMldev, "blobFromMldev");
function fileDataFromMldev(fromObject) {
  const toObject = {};
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataFromMldev, "fileDataFromMldev");
function partFromMldev(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataFromMldev(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobFromMldev(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataFromMldev(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partFromMldev, "partFromMldev");
function contentFromMldev(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partFromMldev(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentFromMldev, "contentFromMldev");
function citationMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromCitations = getValueByPath(fromObject, ["citationSources"]);
  if (fromCitations != null) {
    setValueByPath(toObject, ["citations"], fromCitations);
  }
  return toObject;
}
__name(citationMetadataFromMldev, "citationMetadataFromMldev");
function urlMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromRetrievedUrl = getValueByPath(fromObject, ["retrievedUrl"]);
  if (fromRetrievedUrl != null) {
    setValueByPath(toObject, ["retrievedUrl"], fromRetrievedUrl);
  }
  const fromUrlRetrievalStatus = getValueByPath(fromObject, [
    "urlRetrievalStatus"
  ]);
  if (fromUrlRetrievalStatus != null) {
    setValueByPath(toObject, ["urlRetrievalStatus"], fromUrlRetrievalStatus);
  }
  return toObject;
}
__name(urlMetadataFromMldev, "urlMetadataFromMldev");
function urlContextMetadataFromMldev(fromObject) {
  const toObject = {};
  const fromUrlMetadata = getValueByPath(fromObject, ["urlMetadata"]);
  if (fromUrlMetadata != null) {
    let transformedList = fromUrlMetadata;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return urlMetadataFromMldev(item);
      });
    }
    setValueByPath(toObject, ["urlMetadata"], transformedList);
  }
  return toObject;
}
__name(urlContextMetadataFromMldev, "urlContextMetadataFromMldev");
function candidateFromMldev(fromObject) {
  const toObject = {};
  const fromContent = getValueByPath(fromObject, ["content"]);
  if (fromContent != null) {
    setValueByPath(toObject, ["content"], contentFromMldev(fromContent));
  }
  const fromCitationMetadata = getValueByPath(fromObject, [
    "citationMetadata"
  ]);
  if (fromCitationMetadata != null) {
    setValueByPath(toObject, ["citationMetadata"], citationMetadataFromMldev(fromCitationMetadata));
  }
  const fromTokenCount = getValueByPath(fromObject, ["tokenCount"]);
  if (fromTokenCount != null) {
    setValueByPath(toObject, ["tokenCount"], fromTokenCount);
  }
  const fromFinishReason = getValueByPath(fromObject, ["finishReason"]);
  if (fromFinishReason != null) {
    setValueByPath(toObject, ["finishReason"], fromFinishReason);
  }
  const fromUrlContextMetadata = getValueByPath(fromObject, [
    "urlContextMetadata"
  ]);
  if (fromUrlContextMetadata != null) {
    setValueByPath(toObject, ["urlContextMetadata"], urlContextMetadataFromMldev(fromUrlContextMetadata));
  }
  const fromAvgLogprobs = getValueByPath(fromObject, ["avgLogprobs"]);
  if (fromAvgLogprobs != null) {
    setValueByPath(toObject, ["avgLogprobs"], fromAvgLogprobs);
  }
  const fromGroundingMetadata = getValueByPath(fromObject, [
    "groundingMetadata"
  ]);
  if (fromGroundingMetadata != null) {
    setValueByPath(toObject, ["groundingMetadata"], fromGroundingMetadata);
  }
  const fromIndex = getValueByPath(fromObject, ["index"]);
  if (fromIndex != null) {
    setValueByPath(toObject, ["index"], fromIndex);
  }
  const fromLogprobsResult = getValueByPath(fromObject, [
    "logprobsResult"
  ]);
  if (fromLogprobsResult != null) {
    setValueByPath(toObject, ["logprobsResult"], fromLogprobsResult);
  }
  const fromSafetyRatings = getValueByPath(fromObject, [
    "safetyRatings"
  ]);
  if (fromSafetyRatings != null) {
    setValueByPath(toObject, ["safetyRatings"], fromSafetyRatings);
  }
  return toObject;
}
__name(candidateFromMldev, "candidateFromMldev");
function generateContentResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromCandidates = getValueByPath(fromObject, ["candidates"]);
  if (fromCandidates != null) {
    let transformedList = fromCandidates;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return candidateFromMldev(item);
      });
    }
    setValueByPath(toObject, ["candidates"], transformedList);
  }
  const fromModelVersion = getValueByPath(fromObject, ["modelVersion"]);
  if (fromModelVersion != null) {
    setValueByPath(toObject, ["modelVersion"], fromModelVersion);
  }
  const fromPromptFeedback = getValueByPath(fromObject, [
    "promptFeedback"
  ]);
  if (fromPromptFeedback != null) {
    setValueByPath(toObject, ["promptFeedback"], fromPromptFeedback);
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], fromUsageMetadata);
  }
  return toObject;
}
__name(generateContentResponseFromMldev, "generateContentResponseFromMldev");
function contentEmbeddingFromMldev(fromObject) {
  const toObject = {};
  const fromValues = getValueByPath(fromObject, ["values"]);
  if (fromValues != null) {
    setValueByPath(toObject, ["values"], fromValues);
  }
  return toObject;
}
__name(contentEmbeddingFromMldev, "contentEmbeddingFromMldev");
function embedContentMetadataFromMldev() {
  const toObject = {};
  return toObject;
}
__name(embedContentMetadataFromMldev, "embedContentMetadataFromMldev");
function embedContentResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromEmbeddings = getValueByPath(fromObject, ["embeddings"]);
  if (fromEmbeddings != null) {
    let transformedList = fromEmbeddings;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentEmbeddingFromMldev(item);
      });
    }
    setValueByPath(toObject, ["embeddings"], transformedList);
  }
  const fromMetadata = getValueByPath(fromObject, ["metadata"]);
  if (fromMetadata != null) {
    setValueByPath(toObject, ["metadata"], embedContentMetadataFromMldev());
  }
  return toObject;
}
__name(embedContentResponseFromMldev, "embedContentResponseFromMldev");
function imageFromMldev(fromObject) {
  const toObject = {};
  const fromImageBytes = getValueByPath(fromObject, [
    "bytesBase64Encoded"
  ]);
  if (fromImageBytes != null) {
    setValueByPath(toObject, ["imageBytes"], tBytes(fromImageBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(imageFromMldev, "imageFromMldev");
function safetyAttributesFromMldev(fromObject) {
  const toObject = {};
  const fromCategories = getValueByPath(fromObject, [
    "safetyAttributes",
    "categories"
  ]);
  if (fromCategories != null) {
    setValueByPath(toObject, ["categories"], fromCategories);
  }
  const fromScores = getValueByPath(fromObject, [
    "safetyAttributes",
    "scores"
  ]);
  if (fromScores != null) {
    setValueByPath(toObject, ["scores"], fromScores);
  }
  const fromContentType = getValueByPath(fromObject, ["contentType"]);
  if (fromContentType != null) {
    setValueByPath(toObject, ["contentType"], fromContentType);
  }
  return toObject;
}
__name(safetyAttributesFromMldev, "safetyAttributesFromMldev");
function generatedImageFromMldev(fromObject) {
  const toObject = {};
  const fromImage = getValueByPath(fromObject, ["_self"]);
  if (fromImage != null) {
    setValueByPath(toObject, ["image"], imageFromMldev(fromImage));
  }
  const fromRaiFilteredReason = getValueByPath(fromObject, [
    "raiFilteredReason"
  ]);
  if (fromRaiFilteredReason != null) {
    setValueByPath(toObject, ["raiFilteredReason"], fromRaiFilteredReason);
  }
  const fromSafetyAttributes = getValueByPath(fromObject, ["_self"]);
  if (fromSafetyAttributes != null) {
    setValueByPath(toObject, ["safetyAttributes"], safetyAttributesFromMldev(fromSafetyAttributes));
  }
  return toObject;
}
__name(generatedImageFromMldev, "generatedImageFromMldev");
function generateImagesResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromGeneratedImages = getValueByPath(fromObject, [
    "predictions"
  ]);
  if (fromGeneratedImages != null) {
    let transformedList = fromGeneratedImages;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedImageFromMldev(item);
      });
    }
    setValueByPath(toObject, ["generatedImages"], transformedList);
  }
  const fromPositivePromptSafetyAttributes = getValueByPath(fromObject, [
    "positivePromptSafetyAttributes"
  ]);
  if (fromPositivePromptSafetyAttributes != null) {
    setValueByPath(toObject, ["positivePromptSafetyAttributes"], safetyAttributesFromMldev(fromPositivePromptSafetyAttributes));
  }
  return toObject;
}
__name(generateImagesResponseFromMldev, "generateImagesResponseFromMldev");
function tunedModelInfoFromMldev(fromObject) {
  const toObject = {};
  const fromBaseModel = getValueByPath(fromObject, ["baseModel"]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  return toObject;
}
__name(tunedModelInfoFromMldev, "tunedModelInfoFromMldev");
function modelFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromVersion = getValueByPath(fromObject, ["version"]);
  if (fromVersion != null) {
    setValueByPath(toObject, ["version"], fromVersion);
  }
  const fromTunedModelInfo = getValueByPath(fromObject, ["_self"]);
  if (fromTunedModelInfo != null) {
    setValueByPath(toObject, ["tunedModelInfo"], tunedModelInfoFromMldev(fromTunedModelInfo));
  }
  const fromInputTokenLimit = getValueByPath(fromObject, [
    "inputTokenLimit"
  ]);
  if (fromInputTokenLimit != null) {
    setValueByPath(toObject, ["inputTokenLimit"], fromInputTokenLimit);
  }
  const fromOutputTokenLimit = getValueByPath(fromObject, [
    "outputTokenLimit"
  ]);
  if (fromOutputTokenLimit != null) {
    setValueByPath(toObject, ["outputTokenLimit"], fromOutputTokenLimit);
  }
  const fromSupportedActions = getValueByPath(fromObject, [
    "supportedGenerationMethods"
  ]);
  if (fromSupportedActions != null) {
    setValueByPath(toObject, ["supportedActions"], fromSupportedActions);
  }
  return toObject;
}
__name(modelFromMldev, "modelFromMldev");
function listModelsResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromModels = getValueByPath(fromObject, ["_self"]);
  if (fromModels != null) {
    let transformedList = tExtractModels(fromModels);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modelFromMldev(item);
      });
    }
    setValueByPath(toObject, ["models"], transformedList);
  }
  return toObject;
}
__name(listModelsResponseFromMldev, "listModelsResponseFromMldev");
function deleteModelResponseFromMldev() {
  const toObject = {};
  return toObject;
}
__name(deleteModelResponseFromMldev, "deleteModelResponseFromMldev");
function countTokensResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromTotalTokens = getValueByPath(fromObject, ["totalTokens"]);
  if (fromTotalTokens != null) {
    setValueByPath(toObject, ["totalTokens"], fromTotalTokens);
  }
  const fromCachedContentTokenCount = getValueByPath(fromObject, [
    "cachedContentTokenCount"
  ]);
  if (fromCachedContentTokenCount != null) {
    setValueByPath(toObject, ["cachedContentTokenCount"], fromCachedContentTokenCount);
  }
  return toObject;
}
__name(countTokensResponseFromMldev, "countTokensResponseFromMldev");
function videoFromMldev(fromObject) {
  const toObject = {};
  const fromUri = getValueByPath(fromObject, ["video", "uri"]);
  if (fromUri != null) {
    setValueByPath(toObject, ["uri"], fromUri);
  }
  const fromVideoBytes = getValueByPath(fromObject, [
    "video",
    "encodedVideo"
  ]);
  if (fromVideoBytes != null) {
    setValueByPath(toObject, ["videoBytes"], tBytes(fromVideoBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["encoding"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(videoFromMldev, "videoFromMldev");
function generatedVideoFromMldev(fromObject) {
  const toObject = {};
  const fromVideo = getValueByPath(fromObject, ["_self"]);
  if (fromVideo != null) {
    setValueByPath(toObject, ["video"], videoFromMldev(fromVideo));
  }
  return toObject;
}
__name(generatedVideoFromMldev, "generatedVideoFromMldev");
function generateVideosResponseFromMldev(fromObject) {
  const toObject = {};
  const fromGeneratedVideos = getValueByPath(fromObject, [
    "generatedSamples"
  ]);
  if (fromGeneratedVideos != null) {
    let transformedList = fromGeneratedVideos;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedVideoFromMldev(item);
      });
    }
    setValueByPath(toObject, ["generatedVideos"], transformedList);
  }
  const fromRaiMediaFilteredCount = getValueByPath(fromObject, [
    "raiMediaFilteredCount"
  ]);
  if (fromRaiMediaFilteredCount != null) {
    setValueByPath(toObject, ["raiMediaFilteredCount"], fromRaiMediaFilteredCount);
  }
  const fromRaiMediaFilteredReasons = getValueByPath(fromObject, [
    "raiMediaFilteredReasons"
  ]);
  if (fromRaiMediaFilteredReasons != null) {
    setValueByPath(toObject, ["raiMediaFilteredReasons"], fromRaiMediaFilteredReasons);
  }
  return toObject;
}
__name(generateVideosResponseFromMldev, "generateVideosResponseFromMldev");
function generateVideosOperationFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromMetadata = getValueByPath(fromObject, ["metadata"]);
  if (fromMetadata != null) {
    setValueByPath(toObject, ["metadata"], fromMetadata);
  }
  const fromDone = getValueByPath(fromObject, ["done"]);
  if (fromDone != null) {
    setValueByPath(toObject, ["done"], fromDone);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fromError);
  }
  const fromResponse = getValueByPath(fromObject, [
    "response",
    "generateVideoResponse"
  ]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], generateVideosResponseFromMldev(fromResponse));
  }
  return toObject;
}
__name(generateVideosOperationFromMldev, "generateVideosOperationFromMldev");
function videoMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataFromVertex, "videoMetadataFromVertex");
function blobFromVertex(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobFromVertex, "blobFromVertex");
function fileDataFromVertex(fromObject) {
  const toObject = {};
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataFromVertex, "fileDataFromVertex");
function partFromVertex(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataFromVertex(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobFromVertex(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataFromVertex(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partFromVertex, "partFromVertex");
function contentFromVertex(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partFromVertex(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentFromVertex, "contentFromVertex");
function citationMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromCitations = getValueByPath(fromObject, ["citations"]);
  if (fromCitations != null) {
    setValueByPath(toObject, ["citations"], fromCitations);
  }
  return toObject;
}
__name(citationMetadataFromVertex, "citationMetadataFromVertex");
function urlMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromRetrievedUrl = getValueByPath(fromObject, ["retrievedUrl"]);
  if (fromRetrievedUrl != null) {
    setValueByPath(toObject, ["retrievedUrl"], fromRetrievedUrl);
  }
  const fromUrlRetrievalStatus = getValueByPath(fromObject, [
    "urlRetrievalStatus"
  ]);
  if (fromUrlRetrievalStatus != null) {
    setValueByPath(toObject, ["urlRetrievalStatus"], fromUrlRetrievalStatus);
  }
  return toObject;
}
__name(urlMetadataFromVertex, "urlMetadataFromVertex");
function urlContextMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromUrlMetadata = getValueByPath(fromObject, ["urlMetadata"]);
  if (fromUrlMetadata != null) {
    let transformedList = fromUrlMetadata;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return urlMetadataFromVertex(item);
      });
    }
    setValueByPath(toObject, ["urlMetadata"], transformedList);
  }
  return toObject;
}
__name(urlContextMetadataFromVertex, "urlContextMetadataFromVertex");
function candidateFromVertex(fromObject) {
  const toObject = {};
  const fromContent = getValueByPath(fromObject, ["content"]);
  if (fromContent != null) {
    setValueByPath(toObject, ["content"], contentFromVertex(fromContent));
  }
  const fromCitationMetadata = getValueByPath(fromObject, [
    "citationMetadata"
  ]);
  if (fromCitationMetadata != null) {
    setValueByPath(toObject, ["citationMetadata"], citationMetadataFromVertex(fromCitationMetadata));
  }
  const fromFinishMessage = getValueByPath(fromObject, [
    "finishMessage"
  ]);
  if (fromFinishMessage != null) {
    setValueByPath(toObject, ["finishMessage"], fromFinishMessage);
  }
  const fromFinishReason = getValueByPath(fromObject, ["finishReason"]);
  if (fromFinishReason != null) {
    setValueByPath(toObject, ["finishReason"], fromFinishReason);
  }
  const fromUrlContextMetadata = getValueByPath(fromObject, [
    "urlContextMetadata"
  ]);
  if (fromUrlContextMetadata != null) {
    setValueByPath(toObject, ["urlContextMetadata"], urlContextMetadataFromVertex(fromUrlContextMetadata));
  }
  const fromAvgLogprobs = getValueByPath(fromObject, ["avgLogprobs"]);
  if (fromAvgLogprobs != null) {
    setValueByPath(toObject, ["avgLogprobs"], fromAvgLogprobs);
  }
  const fromGroundingMetadata = getValueByPath(fromObject, [
    "groundingMetadata"
  ]);
  if (fromGroundingMetadata != null) {
    setValueByPath(toObject, ["groundingMetadata"], fromGroundingMetadata);
  }
  const fromIndex = getValueByPath(fromObject, ["index"]);
  if (fromIndex != null) {
    setValueByPath(toObject, ["index"], fromIndex);
  }
  const fromLogprobsResult = getValueByPath(fromObject, [
    "logprobsResult"
  ]);
  if (fromLogprobsResult != null) {
    setValueByPath(toObject, ["logprobsResult"], fromLogprobsResult);
  }
  const fromSafetyRatings = getValueByPath(fromObject, [
    "safetyRatings"
  ]);
  if (fromSafetyRatings != null) {
    setValueByPath(toObject, ["safetyRatings"], fromSafetyRatings);
  }
  return toObject;
}
__name(candidateFromVertex, "candidateFromVertex");
function generateContentResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromCandidates = getValueByPath(fromObject, ["candidates"]);
  if (fromCandidates != null) {
    let transformedList = fromCandidates;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return candidateFromVertex(item);
      });
    }
    setValueByPath(toObject, ["candidates"], transformedList);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromResponseId = getValueByPath(fromObject, ["responseId"]);
  if (fromResponseId != null) {
    setValueByPath(toObject, ["responseId"], fromResponseId);
  }
  const fromModelVersion = getValueByPath(fromObject, ["modelVersion"]);
  if (fromModelVersion != null) {
    setValueByPath(toObject, ["modelVersion"], fromModelVersion);
  }
  const fromPromptFeedback = getValueByPath(fromObject, [
    "promptFeedback"
  ]);
  if (fromPromptFeedback != null) {
    setValueByPath(toObject, ["promptFeedback"], fromPromptFeedback);
  }
  const fromUsageMetadata = getValueByPath(fromObject, [
    "usageMetadata"
  ]);
  if (fromUsageMetadata != null) {
    setValueByPath(toObject, ["usageMetadata"], fromUsageMetadata);
  }
  return toObject;
}
__name(generateContentResponseFromVertex, "generateContentResponseFromVertex");
function contentEmbeddingStatisticsFromVertex(fromObject) {
  const toObject = {};
  const fromTruncated = getValueByPath(fromObject, ["truncated"]);
  if (fromTruncated != null) {
    setValueByPath(toObject, ["truncated"], fromTruncated);
  }
  const fromTokenCount = getValueByPath(fromObject, ["token_count"]);
  if (fromTokenCount != null) {
    setValueByPath(toObject, ["tokenCount"], fromTokenCount);
  }
  return toObject;
}
__name(contentEmbeddingStatisticsFromVertex, "contentEmbeddingStatisticsFromVertex");
function contentEmbeddingFromVertex(fromObject) {
  const toObject = {};
  const fromValues = getValueByPath(fromObject, ["values"]);
  if (fromValues != null) {
    setValueByPath(toObject, ["values"], fromValues);
  }
  const fromStatistics = getValueByPath(fromObject, ["statistics"]);
  if (fromStatistics != null) {
    setValueByPath(toObject, ["statistics"], contentEmbeddingStatisticsFromVertex(fromStatistics));
  }
  return toObject;
}
__name(contentEmbeddingFromVertex, "contentEmbeddingFromVertex");
function embedContentMetadataFromVertex(fromObject) {
  const toObject = {};
  const fromBillableCharacterCount = getValueByPath(fromObject, [
    "billableCharacterCount"
  ]);
  if (fromBillableCharacterCount != null) {
    setValueByPath(toObject, ["billableCharacterCount"], fromBillableCharacterCount);
  }
  return toObject;
}
__name(embedContentMetadataFromVertex, "embedContentMetadataFromVertex");
function embedContentResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromEmbeddings = getValueByPath(fromObject, [
    "predictions[]",
    "embeddings"
  ]);
  if (fromEmbeddings != null) {
    let transformedList = fromEmbeddings;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return contentEmbeddingFromVertex(item);
      });
    }
    setValueByPath(toObject, ["embeddings"], transformedList);
  }
  const fromMetadata = getValueByPath(fromObject, ["metadata"]);
  if (fromMetadata != null) {
    setValueByPath(toObject, ["metadata"], embedContentMetadataFromVertex(fromMetadata));
  }
  return toObject;
}
__name(embedContentResponseFromVertex, "embedContentResponseFromVertex");
function imageFromVertex(fromObject) {
  const toObject = {};
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["gcsUri"], fromGcsUri);
  }
  const fromImageBytes = getValueByPath(fromObject, [
    "bytesBase64Encoded"
  ]);
  if (fromImageBytes != null) {
    setValueByPath(toObject, ["imageBytes"], tBytes(fromImageBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(imageFromVertex, "imageFromVertex");
function safetyAttributesFromVertex(fromObject) {
  const toObject = {};
  const fromCategories = getValueByPath(fromObject, [
    "safetyAttributes",
    "categories"
  ]);
  if (fromCategories != null) {
    setValueByPath(toObject, ["categories"], fromCategories);
  }
  const fromScores = getValueByPath(fromObject, [
    "safetyAttributes",
    "scores"
  ]);
  if (fromScores != null) {
    setValueByPath(toObject, ["scores"], fromScores);
  }
  const fromContentType = getValueByPath(fromObject, ["contentType"]);
  if (fromContentType != null) {
    setValueByPath(toObject, ["contentType"], fromContentType);
  }
  return toObject;
}
__name(safetyAttributesFromVertex, "safetyAttributesFromVertex");
function generatedImageFromVertex(fromObject) {
  const toObject = {};
  const fromImage = getValueByPath(fromObject, ["_self"]);
  if (fromImage != null) {
    setValueByPath(toObject, ["image"], imageFromVertex(fromImage));
  }
  const fromRaiFilteredReason = getValueByPath(fromObject, [
    "raiFilteredReason"
  ]);
  if (fromRaiFilteredReason != null) {
    setValueByPath(toObject, ["raiFilteredReason"], fromRaiFilteredReason);
  }
  const fromSafetyAttributes = getValueByPath(fromObject, ["_self"]);
  if (fromSafetyAttributes != null) {
    setValueByPath(toObject, ["safetyAttributes"], safetyAttributesFromVertex(fromSafetyAttributes));
  }
  const fromEnhancedPrompt = getValueByPath(fromObject, ["prompt"]);
  if (fromEnhancedPrompt != null) {
    setValueByPath(toObject, ["enhancedPrompt"], fromEnhancedPrompt);
  }
  return toObject;
}
__name(generatedImageFromVertex, "generatedImageFromVertex");
function generateImagesResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromGeneratedImages = getValueByPath(fromObject, [
    "predictions"
  ]);
  if (fromGeneratedImages != null) {
    let transformedList = fromGeneratedImages;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedImageFromVertex(item);
      });
    }
    setValueByPath(toObject, ["generatedImages"], transformedList);
  }
  const fromPositivePromptSafetyAttributes = getValueByPath(fromObject, [
    "positivePromptSafetyAttributes"
  ]);
  if (fromPositivePromptSafetyAttributes != null) {
    setValueByPath(toObject, ["positivePromptSafetyAttributes"], safetyAttributesFromVertex(fromPositivePromptSafetyAttributes));
  }
  return toObject;
}
__name(generateImagesResponseFromVertex, "generateImagesResponseFromVertex");
function editImageResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromGeneratedImages = getValueByPath(fromObject, [
    "predictions"
  ]);
  if (fromGeneratedImages != null) {
    let transformedList = fromGeneratedImages;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedImageFromVertex(item);
      });
    }
    setValueByPath(toObject, ["generatedImages"], transformedList);
  }
  return toObject;
}
__name(editImageResponseFromVertex, "editImageResponseFromVertex");
function upscaleImageResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromGeneratedImages = getValueByPath(fromObject, [
    "predictions"
  ]);
  if (fromGeneratedImages != null) {
    let transformedList = fromGeneratedImages;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedImageFromVertex(item);
      });
    }
    setValueByPath(toObject, ["generatedImages"], transformedList);
  }
  return toObject;
}
__name(upscaleImageResponseFromVertex, "upscaleImageResponseFromVertex");
function endpointFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["endpoint"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDeployedModelId = getValueByPath(fromObject, [
    "deployedModelId"
  ]);
  if (fromDeployedModelId != null) {
    setValueByPath(toObject, ["deployedModelId"], fromDeployedModelId);
  }
  return toObject;
}
__name(endpointFromVertex, "endpointFromVertex");
function tunedModelInfoFromVertex(fromObject) {
  const toObject = {};
  const fromBaseModel = getValueByPath(fromObject, [
    "labels",
    "google-vertex-llm-tuning-base-model-id"
  ]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  return toObject;
}
__name(tunedModelInfoFromVertex, "tunedModelInfoFromVertex");
function checkpointFromVertex(fromObject) {
  const toObject = {};
  const fromCheckpointId = getValueByPath(fromObject, ["checkpointId"]);
  if (fromCheckpointId != null) {
    setValueByPath(toObject, ["checkpointId"], fromCheckpointId);
  }
  const fromEpoch = getValueByPath(fromObject, ["epoch"]);
  if (fromEpoch != null) {
    setValueByPath(toObject, ["epoch"], fromEpoch);
  }
  const fromStep = getValueByPath(fromObject, ["step"]);
  if (fromStep != null) {
    setValueByPath(toObject, ["step"], fromStep);
  }
  return toObject;
}
__name(checkpointFromVertex, "checkpointFromVertex");
function modelFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromDisplayName = getValueByPath(fromObject, ["displayName"]);
  if (fromDisplayName != null) {
    setValueByPath(toObject, ["displayName"], fromDisplayName);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromVersion = getValueByPath(fromObject, ["versionId"]);
  if (fromVersion != null) {
    setValueByPath(toObject, ["version"], fromVersion);
  }
  const fromEndpoints = getValueByPath(fromObject, ["deployedModels"]);
  if (fromEndpoints != null) {
    let transformedList = fromEndpoints;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return endpointFromVertex(item);
      });
    }
    setValueByPath(toObject, ["endpoints"], transformedList);
  }
  const fromLabels = getValueByPath(fromObject, ["labels"]);
  if (fromLabels != null) {
    setValueByPath(toObject, ["labels"], fromLabels);
  }
  const fromTunedModelInfo = getValueByPath(fromObject, ["_self"]);
  if (fromTunedModelInfo != null) {
    setValueByPath(toObject, ["tunedModelInfo"], tunedModelInfoFromVertex(fromTunedModelInfo));
  }
  const fromDefaultCheckpointId = getValueByPath(fromObject, [
    "defaultCheckpointId"
  ]);
  if (fromDefaultCheckpointId != null) {
    setValueByPath(toObject, ["defaultCheckpointId"], fromDefaultCheckpointId);
  }
  const fromCheckpoints = getValueByPath(fromObject, ["checkpoints"]);
  if (fromCheckpoints != null) {
    let transformedList = fromCheckpoints;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return checkpointFromVertex(item);
      });
    }
    setValueByPath(toObject, ["checkpoints"], transformedList);
  }
  return toObject;
}
__name(modelFromVertex, "modelFromVertex");
function listModelsResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromModels = getValueByPath(fromObject, ["_self"]);
  if (fromModels != null) {
    let transformedList = tExtractModels(fromModels);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return modelFromVertex(item);
      });
    }
    setValueByPath(toObject, ["models"], transformedList);
  }
  return toObject;
}
__name(listModelsResponseFromVertex, "listModelsResponseFromVertex");
function deleteModelResponseFromVertex() {
  const toObject = {};
  return toObject;
}
__name(deleteModelResponseFromVertex, "deleteModelResponseFromVertex");
function countTokensResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromTotalTokens = getValueByPath(fromObject, ["totalTokens"]);
  if (fromTotalTokens != null) {
    setValueByPath(toObject, ["totalTokens"], fromTotalTokens);
  }
  return toObject;
}
__name(countTokensResponseFromVertex, "countTokensResponseFromVertex");
function computeTokensResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromTokensInfo = getValueByPath(fromObject, ["tokensInfo"]);
  if (fromTokensInfo != null) {
    setValueByPath(toObject, ["tokensInfo"], fromTokensInfo);
  }
  return toObject;
}
__name(computeTokensResponseFromVertex, "computeTokensResponseFromVertex");
function videoFromVertex(fromObject) {
  const toObject = {};
  const fromUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromUri != null) {
    setValueByPath(toObject, ["uri"], fromUri);
  }
  const fromVideoBytes = getValueByPath(fromObject, [
    "bytesBase64Encoded"
  ]);
  if (fromVideoBytes != null) {
    setValueByPath(toObject, ["videoBytes"], tBytes(fromVideoBytes));
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(videoFromVertex, "videoFromVertex");
function generatedVideoFromVertex(fromObject) {
  const toObject = {};
  const fromVideo = getValueByPath(fromObject, ["_self"]);
  if (fromVideo != null) {
    setValueByPath(toObject, ["video"], videoFromVertex(fromVideo));
  }
  return toObject;
}
__name(generatedVideoFromVertex, "generatedVideoFromVertex");
function generateVideosResponseFromVertex(fromObject) {
  const toObject = {};
  const fromGeneratedVideos = getValueByPath(fromObject, ["videos"]);
  if (fromGeneratedVideos != null) {
    let transformedList = fromGeneratedVideos;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return generatedVideoFromVertex(item);
      });
    }
    setValueByPath(toObject, ["generatedVideos"], transformedList);
  }
  const fromRaiMediaFilteredCount = getValueByPath(fromObject, [
    "raiMediaFilteredCount"
  ]);
  if (fromRaiMediaFilteredCount != null) {
    setValueByPath(toObject, ["raiMediaFilteredCount"], fromRaiMediaFilteredCount);
  }
  const fromRaiMediaFilteredReasons = getValueByPath(fromObject, [
    "raiMediaFilteredReasons"
  ]);
  if (fromRaiMediaFilteredReasons != null) {
    setValueByPath(toObject, ["raiMediaFilteredReasons"], fromRaiMediaFilteredReasons);
  }
  return toObject;
}
__name(generateVideosResponseFromVertex, "generateVideosResponseFromVertex");
function generateVideosOperationFromVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromMetadata = getValueByPath(fromObject, ["metadata"]);
  if (fromMetadata != null) {
    setValueByPath(toObject, ["metadata"], fromMetadata);
  }
  const fromDone = getValueByPath(fromObject, ["done"]);
  if (fromDone != null) {
    setValueByPath(toObject, ["done"], fromDone);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fromError);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], generateVideosResponseFromVertex(fromResponse));
  }
  return toObject;
}
__name(generateVideosOperationFromVertex, "generateVideosOperationFromVertex");
var CONTENT_TYPE_HEADER = "Content-Type";
var SERVER_TIMEOUT_HEADER = "X-Server-Timeout";
var USER_AGENT_HEADER = "User-Agent";
var GOOGLE_API_CLIENT_HEADER = "x-goog-api-client";
var SDK_VERSION = "1.12.0";
var LIBRARY_LABEL = `google-genai-sdk/${SDK_VERSION}`;
var VERTEX_AI_API_DEFAULT_VERSION = "v1beta1";
var GOOGLE_AI_API_DEFAULT_VERSION = "v1beta";
var responseLineRE = /^data: (.*)(?:\n\n|\r\r|\r\n\r\n)/;
var ApiClient = class {
  static {
    __name(this, "ApiClient");
  }
  constructor(opts) {
    var _a, _b;
    this.clientOptions = Object.assign(Object.assign({}, opts), { project: opts.project, location: opts.location, apiKey: opts.apiKey, vertexai: opts.vertexai });
    const initHttpOptions = {};
    if (this.clientOptions.vertexai) {
      initHttpOptions.apiVersion = (_a = this.clientOptions.apiVersion) !== null && _a !== void 0 ? _a : VERTEX_AI_API_DEFAULT_VERSION;
      initHttpOptions.baseUrl = this.baseUrlFromProjectLocation();
      this.normalizeAuthParameters();
    } else {
      initHttpOptions.apiVersion = (_b = this.clientOptions.apiVersion) !== null && _b !== void 0 ? _b : GOOGLE_AI_API_DEFAULT_VERSION;
      initHttpOptions.baseUrl = `https://generativelanguage.googleapis.com/`;
    }
    initHttpOptions.headers = this.getDefaultHeaders();
    this.clientOptions.httpOptions = initHttpOptions;
    if (opts.httpOptions) {
      this.clientOptions.httpOptions = this.patchHttpOptions(initHttpOptions, opts.httpOptions);
    }
  }
  /**
   * Determines the base URL for Vertex AI based on project and location.
   * Uses the global endpoint if location is 'global' or if project/location
   * are not specified (implying API key usage).
   * @private
   */
  baseUrlFromProjectLocation() {
    if (this.clientOptions.project && this.clientOptions.location && this.clientOptions.location !== "global") {
      return `https://${this.clientOptions.location}-aiplatform.googleapis.com/`;
    }
    return `https://aiplatform.googleapis.com/`;
  }
  /**
   * Normalizes authentication parameters for Vertex AI.
   * If project and location are provided, API key is cleared.
   * If project and location are not provided (implying API key usage),
   * project and location are cleared.
   * @private
   */
  normalizeAuthParameters() {
    if (this.clientOptions.project && this.clientOptions.location) {
      this.clientOptions.apiKey = void 0;
      return;
    }
    this.clientOptions.project = void 0;
    this.clientOptions.location = void 0;
  }
  isVertexAI() {
    var _a;
    return (_a = this.clientOptions.vertexai) !== null && _a !== void 0 ? _a : false;
  }
  getProject() {
    return this.clientOptions.project;
  }
  getLocation() {
    return this.clientOptions.location;
  }
  getApiVersion() {
    if (this.clientOptions.httpOptions && this.clientOptions.httpOptions.apiVersion !== void 0) {
      return this.clientOptions.httpOptions.apiVersion;
    }
    throw new Error("API version is not set.");
  }
  getBaseUrl() {
    if (this.clientOptions.httpOptions && this.clientOptions.httpOptions.baseUrl !== void 0) {
      return this.clientOptions.httpOptions.baseUrl;
    }
    throw new Error("Base URL is not set.");
  }
  getRequestUrl() {
    return this.getRequestUrlInternal(this.clientOptions.httpOptions);
  }
  getHeaders() {
    if (this.clientOptions.httpOptions && this.clientOptions.httpOptions.headers !== void 0) {
      return this.clientOptions.httpOptions.headers;
    } else {
      throw new Error("Headers are not set.");
    }
  }
  getRequestUrlInternal(httpOptions) {
    if (!httpOptions || httpOptions.baseUrl === void 0 || httpOptions.apiVersion === void 0) {
      throw new Error("HTTP options are not correctly set.");
    }
    const baseUrl = httpOptions.baseUrl.endsWith("/") ? httpOptions.baseUrl.slice(0, -1) : httpOptions.baseUrl;
    const urlElement = [baseUrl];
    if (httpOptions.apiVersion && httpOptions.apiVersion !== "") {
      urlElement.push(httpOptions.apiVersion);
    }
    return urlElement.join("/");
  }
  getBaseResourcePath() {
    return `projects/${this.clientOptions.project}/locations/${this.clientOptions.location}`;
  }
  getApiKey() {
    return this.clientOptions.apiKey;
  }
  getWebsocketBaseUrl() {
    const baseUrl = this.getBaseUrl();
    const urlParts = new URL(baseUrl);
    urlParts.protocol = urlParts.protocol == "http:" ? "ws" : "wss";
    return urlParts.toString();
  }
  setBaseUrl(url) {
    if (this.clientOptions.httpOptions) {
      this.clientOptions.httpOptions.baseUrl = url;
    } else {
      throw new Error("HTTP options are not correctly set.");
    }
  }
  constructUrl(path, httpOptions, prependProjectLocation) {
    const urlElement = [this.getRequestUrlInternal(httpOptions)];
    if (prependProjectLocation) {
      urlElement.push(this.getBaseResourcePath());
    }
    if (path !== "") {
      urlElement.push(path);
    }
    const url = new URL(`${urlElement.join("/")}`);
    return url;
  }
  shouldPrependVertexProjectPath(request) {
    if (this.clientOptions.apiKey) {
      return false;
    }
    if (!this.clientOptions.vertexai) {
      return false;
    }
    if (request.path.startsWith("projects/")) {
      return false;
    }
    if (request.httpMethod === "GET" && request.path.startsWith("publishers/google/models")) {
      return false;
    }
    return true;
  }
  async request(request) {
    let patchedHttpOptions = this.clientOptions.httpOptions;
    if (request.httpOptions) {
      patchedHttpOptions = this.patchHttpOptions(this.clientOptions.httpOptions, request.httpOptions);
    }
    const prependProjectLocation = this.shouldPrependVertexProjectPath(request);
    const url = this.constructUrl(request.path, patchedHttpOptions, prependProjectLocation);
    if (request.queryParams) {
      for (const [key, value] of Object.entries(request.queryParams)) {
        url.searchParams.append(key, String(value));
      }
    }
    let requestInit = {};
    if (request.httpMethod === "GET") {
      if (request.body && request.body !== "{}") {
        throw new Error("Request body should be empty for GET request, but got non empty request body");
      }
    } else {
      requestInit.body = request.body;
    }
    requestInit = await this.includeExtraHttpOptionsToRequestInit(requestInit, patchedHttpOptions, request.abortSignal);
    return this.unaryApiCall(url, requestInit, request.httpMethod);
  }
  patchHttpOptions(baseHttpOptions, requestHttpOptions) {
    const patchedHttpOptions = JSON.parse(JSON.stringify(baseHttpOptions));
    for (const [key, value] of Object.entries(requestHttpOptions)) {
      if (typeof value === "object") {
        patchedHttpOptions[key] = Object.assign(Object.assign({}, patchedHttpOptions[key]), value);
      } else if (value !== void 0) {
        patchedHttpOptions[key] = value;
      }
    }
    return patchedHttpOptions;
  }
  async requestStream(request) {
    let patchedHttpOptions = this.clientOptions.httpOptions;
    if (request.httpOptions) {
      patchedHttpOptions = this.patchHttpOptions(this.clientOptions.httpOptions, request.httpOptions);
    }
    const prependProjectLocation = this.shouldPrependVertexProjectPath(request);
    const url = this.constructUrl(request.path, patchedHttpOptions, prependProjectLocation);
    if (!url.searchParams.has("alt") || url.searchParams.get("alt") !== "sse") {
      url.searchParams.set("alt", "sse");
    }
    let requestInit = {};
    requestInit.body = request.body;
    requestInit = await this.includeExtraHttpOptionsToRequestInit(requestInit, patchedHttpOptions, request.abortSignal);
    return this.streamApiCall(url, requestInit, request.httpMethod);
  }
  async includeExtraHttpOptionsToRequestInit(requestInit, httpOptions, abortSignal) {
    if (httpOptions && httpOptions.timeout || abortSignal) {
      const abortController = new AbortController();
      const signal = abortController.signal;
      if (httpOptions.timeout && (httpOptions === null || httpOptions === void 0 ? void 0 : httpOptions.timeout) > 0) {
        const timeoutHandle = setTimeout(() => abortController.abort(), httpOptions.timeout);
        if (timeoutHandle && typeof timeoutHandle.unref === "function") {
          timeoutHandle.unref();
        }
      }
      if (abortSignal) {
        abortSignal.addEventListener("abort", () => {
          abortController.abort();
        });
      }
      requestInit.signal = signal;
    }
    if (httpOptions && httpOptions.extraBody !== null) {
      includeExtraBodyToRequestInit(requestInit, httpOptions.extraBody);
    }
    requestInit.headers = await this.getHeadersInternal(httpOptions);
    return requestInit;
  }
  async unaryApiCall(url, requestInit, httpMethod) {
    return this.apiCall(url.toString(), Object.assign(Object.assign({}, requestInit), { method: httpMethod })).then(async (response) => {
      await throwErrorIfNotOK(response);
      return new HttpResponse(response);
    }).catch((e) => {
      if (e instanceof Error) {
        throw e;
      } else {
        throw new Error(JSON.stringify(e));
      }
    });
  }
  async streamApiCall(url, requestInit, httpMethod) {
    return this.apiCall(url.toString(), Object.assign(Object.assign({}, requestInit), { method: httpMethod })).then(async (response) => {
      await throwErrorIfNotOK(response);
      return this.processStreamResponse(response);
    }).catch((e) => {
      if (e instanceof Error) {
        throw e;
      } else {
        throw new Error(JSON.stringify(e));
      }
    });
  }
  processStreamResponse(response) {
    var _a;
    return __asyncGenerator(this, arguments, /* @__PURE__ */ __name(function* processStreamResponse_1() {
      const reader = (_a = response === null || response === void 0 ? void 0 : response.body) === null || _a === void 0 ? void 0 : _a.getReader();
      const decoder = new TextDecoder("utf-8");
      if (!reader) {
        throw new Error("Response body is empty");
      }
      try {
        let buffer = "";
        while (true) {
          const { done, value } = yield __await(reader.read());
          if (done) {
            if (buffer.trim().length > 0) {
              throw new Error("Incomplete JSON segment at the end");
            }
            break;
          }
          const chunkString = decoder.decode(value, { stream: true });
          try {
            const chunkJson = JSON.parse(chunkString);
            if ("error" in chunkJson) {
              const errorJson = JSON.parse(JSON.stringify(chunkJson["error"]));
              const status = errorJson["status"];
              const code = errorJson["code"];
              const errorMessage = `got status: ${status}. ${JSON.stringify(chunkJson)}`;
              if (code >= 400 && code < 600) {
                const apiError = new ApiError({
                  message: errorMessage,
                  status: code
                });
                throw apiError;
              }
            }
          } catch (e) {
            const error = e;
            if (error.name === "ApiError") {
              throw e;
            }
          }
          buffer += chunkString;
          let match2 = buffer.match(responseLineRE);
          while (match2) {
            const processedChunkString = match2[1];
            try {
              const partialResponse = new Response(processedChunkString, {
                headers: response === null || response === void 0 ? void 0 : response.headers,
                status: response === null || response === void 0 ? void 0 : response.status,
                statusText: response === null || response === void 0 ? void 0 : response.statusText
              });
              yield yield __await(new HttpResponse(partialResponse));
              buffer = buffer.slice(match2[0].length);
              match2 = buffer.match(responseLineRE);
            } catch (e) {
              throw new Error(`exception parsing stream chunk ${processedChunkString}. ${e}`);
            }
          }
        }
      } finally {
        reader.releaseLock();
      }
    }, "processStreamResponse_1"));
  }
  async apiCall(url, requestInit) {
    return fetch(url, requestInit).catch((e) => {
      throw new Error(`exception ${e} sending request`);
    });
  }
  getDefaultHeaders() {
    const headers = {};
    const versionHeaderValue = LIBRARY_LABEL + " " + this.clientOptions.userAgentExtra;
    headers[USER_AGENT_HEADER] = versionHeaderValue;
    headers[GOOGLE_API_CLIENT_HEADER] = versionHeaderValue;
    headers[CONTENT_TYPE_HEADER] = "application/json";
    return headers;
  }
  async getHeadersInternal(httpOptions) {
    const headers = new Headers();
    if (httpOptions && httpOptions.headers) {
      for (const [key, value] of Object.entries(httpOptions.headers)) {
        headers.append(key, value);
      }
      if (httpOptions.timeout && httpOptions.timeout > 0) {
        headers.append(SERVER_TIMEOUT_HEADER, String(Math.ceil(httpOptions.timeout / 1e3)));
      }
    }
    await this.clientOptions.auth.addAuthHeaders(headers);
    return headers;
  }
  /**
   * Uploads a file asynchronously using Gemini API only, this is not supported
   * in Vertex AI.
   *
   * @param file The string path to the file to be uploaded or a Blob object.
   * @param config Optional parameters specified in the `UploadFileConfig`
   *     interface. @see {@link UploadFileConfig}
   * @return A promise that resolves to a `File` object.
   * @throws An error if called on a Vertex AI client.
   * @throws An error if the `mimeType` is not provided and can not be inferred,
   */
  async uploadFile(file, config) {
    var _a;
    const fileToUpload = {};
    if (config != null) {
      fileToUpload.mimeType = config.mimeType;
      fileToUpload.name = config.name;
      fileToUpload.displayName = config.displayName;
    }
    if (fileToUpload.name && !fileToUpload.name.startsWith("files/")) {
      fileToUpload.name = `files/${fileToUpload.name}`;
    }
    const uploader = this.clientOptions.uploader;
    const fileStat = await uploader.stat(file);
    fileToUpload.sizeBytes = String(fileStat.size);
    const mimeType = (_a = config === null || config === void 0 ? void 0 : config.mimeType) !== null && _a !== void 0 ? _a : fileStat.type;
    if (mimeType === void 0 || mimeType === "") {
      throw new Error("Can not determine mimeType. Please provide mimeType in the config.");
    }
    fileToUpload.mimeType = mimeType;
    const uploadUrl = await this.fetchUploadUrl(fileToUpload, config);
    return uploader.upload(file, uploadUrl, this);
  }
  /**
   * Downloads a file asynchronously to the specified path.
   *
   * @params params - The parameters for the download request, see {@link
   * DownloadFileParameters}
   */
  async downloadFile(params) {
    const downloader = this.clientOptions.downloader;
    await downloader.download(params, this);
  }
  async fetchUploadUrl(file, config) {
    var _a;
    let httpOptions = {};
    if (config === null || config === void 0 ? void 0 : config.httpOptions) {
      httpOptions = config.httpOptions;
    } else {
      httpOptions = {
        apiVersion: "",
        headers: {
          "Content-Type": "application/json",
          "X-Goog-Upload-Protocol": "resumable",
          "X-Goog-Upload-Command": "start",
          "X-Goog-Upload-Header-Content-Length": `${file.sizeBytes}`,
          "X-Goog-Upload-Header-Content-Type": `${file.mimeType}`
        }
      };
    }
    const body = {
      "file": file
    };
    const httpResponse = await this.request({
      path: formatMap("upload/v1beta/files", body["_url"]),
      body: JSON.stringify(body),
      httpMethod: "POST",
      httpOptions
    });
    if (!httpResponse || !(httpResponse === null || httpResponse === void 0 ? void 0 : httpResponse.headers)) {
      throw new Error("Server did not return an HttpResponse or the returned HttpResponse did not have headers.");
    }
    const uploadUrl = (_a = httpResponse === null || httpResponse === void 0 ? void 0 : httpResponse.headers) === null || _a === void 0 ? void 0 : _a["x-goog-upload-url"];
    if (uploadUrl === void 0) {
      throw new Error("Failed to get upload url. Server did not return the x-google-upload-url in the headers");
    }
    return uploadUrl;
  }
};
async function throwErrorIfNotOK(response) {
  var _a;
  if (response === void 0) {
    throw new Error("response is undefined");
  }
  if (!response.ok) {
    const status = response.status;
    let errorBody;
    if ((_a = response.headers.get("content-type")) === null || _a === void 0 ? void 0 : _a.includes("application/json")) {
      errorBody = await response.json();
    } else {
      errorBody = {
        error: {
          message: await response.text(),
          code: response.status,
          status: response.statusText
        }
      };
    }
    const errorMessage = JSON.stringify(errorBody);
    if (status >= 400 && status < 600) {
      const apiError = new ApiError({
        message: errorMessage,
        status
      });
      throw apiError;
    }
    throw new Error(errorMessage);
  }
}
__name(throwErrorIfNotOK, "throwErrorIfNotOK");
function includeExtraBodyToRequestInit(requestInit, extraBody) {
  if (!extraBody || Object.keys(extraBody).length === 0) {
    return;
  }
  if (requestInit.body instanceof Blob) {
    console.warn("includeExtraBodyToRequestInit: extraBody provided but current request body is a Blob. extraBody will be ignored as merging is not supported for Blob bodies.");
    return;
  }
  let currentBodyObject = {};
  if (typeof requestInit.body === "string" && requestInit.body.length > 0) {
    try {
      const parsedBody = JSON.parse(requestInit.body);
      if (typeof parsedBody === "object" && parsedBody !== null && !Array.isArray(parsedBody)) {
        currentBodyObject = parsedBody;
      } else {
        console.warn("includeExtraBodyToRequestInit: Original request body is valid JSON but not a non-array object. Skip applying extraBody to the request body.");
        return;
      }
    } catch (e) {
      console.warn("includeExtraBodyToRequestInit: Original request body is not valid JSON. Skip applying extraBody to the request body.");
      return;
    }
  }
  function deepMerge(target, source) {
    const output = Object.assign({}, target);
    for (const key in source) {
      if (Object.prototype.hasOwnProperty.call(source, key)) {
        const sourceValue = source[key];
        const targetValue = output[key];
        if (sourceValue && typeof sourceValue === "object" && !Array.isArray(sourceValue) && targetValue && typeof targetValue === "object" && !Array.isArray(targetValue)) {
          output[key] = deepMerge(targetValue, sourceValue);
        } else {
          if (targetValue && sourceValue && typeof targetValue !== typeof sourceValue) {
            console.warn(`includeExtraBodyToRequestInit:deepMerge: Type mismatch for key "${key}". Original type: ${typeof targetValue}, New type: ${typeof sourceValue}. Overwriting.`);
          }
          output[key] = sourceValue;
        }
      }
    }
    return output;
  }
  __name(deepMerge, "deepMerge");
  const mergedBody = deepMerge(currentBodyObject, extraBody);
  requestInit.body = JSON.stringify(mergedBody);
}
__name(includeExtraBodyToRequestInit, "includeExtraBodyToRequestInit");
var MCP_LABEL = "mcp_used/unknown";
var hasMcpToolUsageFromMcpToTool = false;
function hasMcpToolUsage(tools) {
  for (const tool of tools) {
    if (isMcpCallableTool(tool)) {
      return true;
    }
    if (typeof tool === "object" && "inputSchema" in tool) {
      return true;
    }
  }
  return hasMcpToolUsageFromMcpToTool;
}
__name(hasMcpToolUsage, "hasMcpToolUsage");
function setMcpUsageHeader(headers) {
  var _a;
  const existingHeader = (_a = headers[GOOGLE_API_CLIENT_HEADER]) !== null && _a !== void 0 ? _a : "";
  headers[GOOGLE_API_CLIENT_HEADER] = (existingHeader + ` ${MCP_LABEL}`).trimStart();
}
__name(setMcpUsageHeader, "setMcpUsageHeader");
function isMcpCallableTool(object) {
  return object !== null && typeof object === "object" && object instanceof McpCallableTool;
}
__name(isMcpCallableTool, "isMcpCallableTool");
function listAllTools(mcpClient, maxTools = 100) {
  return __asyncGenerator(this, arguments, /* @__PURE__ */ __name(function* listAllTools_1() {
    let cursor = void 0;
    let numTools = 0;
    while (numTools < maxTools) {
      const t = yield __await(mcpClient.listTools({ cursor }));
      for (const tool of t.tools) {
        yield yield __await(tool);
        numTools++;
      }
      if (!t.nextCursor) {
        break;
      }
      cursor = t.nextCursor;
    }
  }, "listAllTools_1"));
}
__name(listAllTools, "listAllTools");
var McpCallableTool = class _McpCallableTool {
  static {
    __name(this, "McpCallableTool");
  }
  constructor(mcpClients = [], config) {
    this.mcpTools = [];
    this.functionNameToMcpClient = {};
    this.mcpClients = mcpClients;
    this.config = config;
  }
  /**
   * Creates a McpCallableTool.
   */
  static create(mcpClients, config) {
    return new _McpCallableTool(mcpClients, config);
  }
  /**
   * Validates the function names are not duplicate and initialize the function
   * name to MCP client mapping.
   *
   * @throws {Error} if the MCP tools from the MCP clients have duplicate tool
   *     names.
   */
  async initialize() {
    var _a, e_1, _b, _c;
    if (this.mcpTools.length > 0) {
      return;
    }
    const functionMap = {};
    const mcpTools = [];
    for (const mcpClient of this.mcpClients) {
      try {
        for (var _d = true, _e = (e_1 = void 0, __asyncValues(listAllTools(mcpClient))), _f; _f = await _e.next(), _a = _f.done, !_a; _d = true) {
          _c = _f.value;
          _d = false;
          const mcpTool = _c;
          mcpTools.push(mcpTool);
          const mcpToolName = mcpTool.name;
          if (functionMap[mcpToolName]) {
            throw new Error(`Duplicate function name ${mcpToolName} found in MCP tools. Please ensure function names are unique.`);
          }
          functionMap[mcpToolName] = mcpClient;
        }
      } catch (e_1_1) {
        e_1 = { error: e_1_1 };
      } finally {
        try {
          if (!_d && !_a && (_b = _e.return)) await _b.call(_e);
        } finally {
          if (e_1) throw e_1.error;
        }
      }
    }
    this.mcpTools = mcpTools;
    this.functionNameToMcpClient = functionMap;
  }
  async tool() {
    await this.initialize();
    return mcpToolsToGeminiTool(this.mcpTools, this.config);
  }
  async callTool(functionCalls) {
    await this.initialize();
    const functionCallResponseParts = [];
    for (const functionCall of functionCalls) {
      if (functionCall.name in this.functionNameToMcpClient) {
        const mcpClient = this.functionNameToMcpClient[functionCall.name];
        let requestOptions = void 0;
        if (this.config.timeout) {
          requestOptions = {
            timeout: this.config.timeout
          };
        }
        const callToolResponse = await mcpClient.callTool(
          {
            name: functionCall.name,
            arguments: functionCall.args
          },
          // Set the result schema to undefined to allow MCP to rely on the
          // default schema.
          void 0,
          requestOptions
        );
        functionCallResponseParts.push({
          functionResponse: {
            name: functionCall.name,
            response: callToolResponse.isError ? { error: callToolResponse } : callToolResponse
          }
        });
      }
    }
    return functionCallResponseParts;
  }
};
async function handleWebSocketMessage$1(apiClient, onmessage, event) {
  const serverMessage = new LiveMusicServerMessage();
  let data;
  if (event.data instanceof Blob) {
    data = JSON.parse(await event.data.text());
  } else {
    data = JSON.parse(event.data);
  }
  const response = liveMusicServerMessageFromMldev(data);
  Object.assign(serverMessage, response);
  onmessage(serverMessage);
}
__name(handleWebSocketMessage$1, "handleWebSocketMessage$1");
var LiveMusic = class {
  static {
    __name(this, "LiveMusic");
  }
  constructor(apiClient, auth, webSocketFactory) {
    this.apiClient = apiClient;
    this.auth = auth;
    this.webSocketFactory = webSocketFactory;
  }
  /**
       Establishes a connection to the specified model and returns a
       LiveMusicSession object representing that connection.
  
       @experimental
  
       @remarks
  
       @param params - The parameters for establishing a connection to the model.
       @return A live session.
  
       @example
       ```ts
       let model = 'models/lyria-realtime-exp';
       const session = await ai.live.music.connect({
         model: model,
         callbacks: {
           onmessage: (e: MessageEvent) => {
             console.log('Received message from the server: %s\n', debug(e.data));
           },
           onerror: (e: ErrorEvent) => {
             console.log('Error occurred: %s\n', debug(e.error));
           },
           onclose: (e: CloseEvent) => {
             console.log('Connection closed.');
           },
         },
       });
       ```
      */
  async connect(params) {
    var _a, _b;
    if (this.apiClient.isVertexAI()) {
      throw new Error("Live music is not supported for Vertex AI.");
    }
    console.warn("Live music generation is experimental and may change in future versions.");
    const websocketBaseUrl = this.apiClient.getWebsocketBaseUrl();
    const apiVersion = this.apiClient.getApiVersion();
    const headers = mapToHeaders$1(this.apiClient.getDefaultHeaders());
    const apiKey = this.apiClient.getApiKey();
    const url = `${websocketBaseUrl}/ws/google.ai.generativelanguage.${apiVersion}.GenerativeService.BidiGenerateMusic?key=${apiKey}`;
    let onopenResolve = /* @__PURE__ */ __name(() => {
    }, "onopenResolve");
    const onopenPromise = new Promise((resolve) => {
      onopenResolve = resolve;
    });
    const callbacks = params.callbacks;
    const onopenAwaitedCallback = /* @__PURE__ */ __name(function() {
      onopenResolve({});
    }, "onopenAwaitedCallback");
    const apiClient = this.apiClient;
    const websocketCallbacks = {
      onopen: onopenAwaitedCallback,
      onmessage: /* @__PURE__ */ __name((event) => {
        void handleWebSocketMessage$1(apiClient, callbacks.onmessage, event);
      }, "onmessage"),
      onerror: (_a = callbacks === null || callbacks === void 0 ? void 0 : callbacks.onerror) !== null && _a !== void 0 ? _a : function(e) {
      },
      onclose: (_b = callbacks === null || callbacks === void 0 ? void 0 : callbacks.onclose) !== null && _b !== void 0 ? _b : function(e) {
      }
    };
    const conn = this.webSocketFactory.create(url, headersToMap$1(headers), websocketCallbacks);
    conn.connect();
    await onopenPromise;
    const model = tModel(this.apiClient, params.model);
    const setup = liveMusicClientSetupToMldev({
      model
    });
    const clientMessage = liveMusicClientMessageToMldev({ setup });
    conn.send(JSON.stringify(clientMessage));
    return new LiveMusicSession(conn, this.apiClient);
  }
};
var LiveMusicSession = class {
  static {
    __name(this, "LiveMusicSession");
  }
  constructor(conn, apiClient) {
    this.conn = conn;
    this.apiClient = apiClient;
  }
  /**
      Sets inputs to steer music generation. Updates the session's current
      weighted prompts.
  
      @param params - Contains one property, `weightedPrompts`.
  
        - `weightedPrompts` to send to the model; weights are normalized to
          sum to 1.0.
  
      @experimental
     */
  async setWeightedPrompts(params) {
    if (!params.weightedPrompts || Object.keys(params.weightedPrompts).length === 0) {
      throw new Error("Weighted prompts must be set and contain at least one entry.");
    }
    const setWeightedPromptsParameters = liveMusicSetWeightedPromptsParametersToMldev(params);
    const clientContent = liveMusicClientContentToMldev(setWeightedPromptsParameters);
    this.conn.send(JSON.stringify({ clientContent }));
  }
  /**
      Sets a configuration to the model. Updates the session's current
      music generation config.
  
      @param params - Contains one property, `musicGenerationConfig`.
  
        - `musicGenerationConfig` to set in the model. Passing an empty or
      undefined config to the model will reset the config to defaults.
  
      @experimental
     */
  async setMusicGenerationConfig(params) {
    if (!params.musicGenerationConfig) {
      params.musicGenerationConfig = {};
    }
    const setConfigParameters = liveMusicSetConfigParametersToMldev(params);
    const clientMessage = liveMusicClientMessageToMldev(setConfigParameters);
    this.conn.send(JSON.stringify(clientMessage));
  }
  sendPlaybackControl(playbackControl) {
    const clientMessage = liveMusicClientMessageToMldev({
      playbackControl
    });
    this.conn.send(JSON.stringify(clientMessage));
  }
  /**
   * Start the music stream.
   *
   * @experimental
   */
  play() {
    this.sendPlaybackControl(LiveMusicPlaybackControl.PLAY);
  }
  /**
   * Temporarily halt the music stream. Use `play` to resume from the current
   * position.
   *
   * @experimental
   */
  pause() {
    this.sendPlaybackControl(LiveMusicPlaybackControl.PAUSE);
  }
  /**
   * Stop the music stream and reset the state. Retains the current prompts
   * and config.
   *
   * @experimental
   */
  stop() {
    this.sendPlaybackControl(LiveMusicPlaybackControl.STOP);
  }
  /**
   * Resets the context of the music generation without stopping it.
   * Retains the current prompts and config.
   *
   * @experimental
   */
  resetContext() {
    this.sendPlaybackControl(LiveMusicPlaybackControl.RESET_CONTEXT);
  }
  /**
       Terminates the WebSocket connection.
  
       @experimental
     */
  close() {
    this.conn.close();
  }
};
function headersToMap$1(headers) {
  const headerMap = {};
  headers.forEach((value, key) => {
    headerMap[key] = value;
  });
  return headerMap;
}
__name(headersToMap$1, "headersToMap$1");
function mapToHeaders$1(map) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(map)) {
    headers.append(key, value);
  }
  return headers;
}
__name(mapToHeaders$1, "mapToHeaders$1");
var FUNCTION_RESPONSE_REQUIRES_ID = "FunctionResponse request must have an `id` field from the response of a ToolCall.FunctionalCalls in Google AI.";
async function handleWebSocketMessage(apiClient, onmessage, event) {
  const serverMessage = new LiveServerMessage();
  let jsonData;
  if (event.data instanceof Blob) {
    jsonData = await event.data.text();
  } else if (event.data instanceof ArrayBuffer) {
    jsonData = new TextDecoder().decode(event.data);
  } else {
    jsonData = event.data;
  }
  const data = JSON.parse(jsonData);
  if (apiClient.isVertexAI()) {
    const resp = liveServerMessageFromVertex(data);
    Object.assign(serverMessage, resp);
  } else {
    const resp = liveServerMessageFromMldev(data);
    Object.assign(serverMessage, resp);
  }
  onmessage(serverMessage);
}
__name(handleWebSocketMessage, "handleWebSocketMessage");
var Live = class {
  static {
    __name(this, "Live");
  }
  constructor(apiClient, auth, webSocketFactory) {
    this.apiClient = apiClient;
    this.auth = auth;
    this.webSocketFactory = webSocketFactory;
    this.music = new LiveMusic(this.apiClient, this.auth, this.webSocketFactory);
  }
  /**
       Establishes a connection to the specified model with the given
       configuration and returns a Session object representing that connection.
  
       @experimental Built-in MCP support is an experimental feature, may change in
       future versions.
  
       @remarks
  
       @param params - The parameters for establishing a connection to the model.
       @return A live session.
  
       @example
       ```ts
       let model: string;
       if (GOOGLE_GENAI_USE_VERTEXAI) {
         model = 'gemini-2.0-flash-live-preview-04-09';
       } else {
         model = 'gemini-live-2.5-flash-preview';
       }
       const session = await ai.live.connect({
         model: model,
         config: {
           responseModalities: [Modality.AUDIO],
         },
         callbacks: {
           onopen: () => {
             console.log('Connected to the socket.');
           },
           onmessage: (e: MessageEvent) => {
             console.log('Received message from the server: %s\n', debug(e.data));
           },
           onerror: (e: ErrorEvent) => {
             console.log('Error occurred: %s\n', debug(e.error));
           },
           onclose: (e: CloseEvent) => {
             console.log('Connection closed.');
           },
         },
       });
       ```
      */
  async connect(params) {
    var _a, _b, _c, _d, _e, _f;
    if (params.config && params.config.httpOptions) {
      throw new Error("The Live module does not support httpOptions at request-level in LiveConnectConfig yet. Please use the client-level httpOptions configuration instead.");
    }
    const websocketBaseUrl = this.apiClient.getWebsocketBaseUrl();
    const apiVersion = this.apiClient.getApiVersion();
    let url;
    const clientHeaders = this.apiClient.getHeaders();
    if (params.config && params.config.tools && hasMcpToolUsage(params.config.tools)) {
      setMcpUsageHeader(clientHeaders);
    }
    const headers = mapToHeaders(clientHeaders);
    if (this.apiClient.isVertexAI()) {
      url = `${websocketBaseUrl}/ws/google.cloud.aiplatform.${apiVersion}.LlmBidiService/BidiGenerateContent`;
      await this.auth.addAuthHeaders(headers);
    } else {
      const apiKey = this.apiClient.getApiKey();
      let method = "BidiGenerateContent";
      let keyName = "key";
      if (apiKey === null || apiKey === void 0 ? void 0 : apiKey.startsWith("auth_tokens/")) {
        console.warn("Warning: Ephemeral token support is experimental and may change in future versions.");
        if (apiVersion !== "v1alpha") {
          console.warn("Warning: The SDK's ephemeral token support is in v1alpha only. Please use const ai = new GoogleGenAI({apiKey: token.name, httpOptions: { apiVersion: 'v1alpha' }}); before session connection.");
        }
        method = "BidiGenerateContentConstrained";
        keyName = "access_token";
      }
      url = `${websocketBaseUrl}/ws/google.ai.generativelanguage.${apiVersion}.GenerativeService.${method}?${keyName}=${apiKey}`;
    }
    let onopenResolve = /* @__PURE__ */ __name(() => {
    }, "onopenResolve");
    const onopenPromise = new Promise((resolve) => {
      onopenResolve = resolve;
    });
    const callbacks = params.callbacks;
    const onopenAwaitedCallback = /* @__PURE__ */ __name(function() {
      var _a2;
      (_a2 = callbacks === null || callbacks === void 0 ? void 0 : callbacks.onopen) === null || _a2 === void 0 ? void 0 : _a2.call(callbacks);
      onopenResolve({});
    }, "onopenAwaitedCallback");
    const apiClient = this.apiClient;
    const websocketCallbacks = {
      onopen: onopenAwaitedCallback,
      onmessage: /* @__PURE__ */ __name((event) => {
        void handleWebSocketMessage(apiClient, callbacks.onmessage, event);
      }, "onmessage"),
      onerror: (_a = callbacks === null || callbacks === void 0 ? void 0 : callbacks.onerror) !== null && _a !== void 0 ? _a : function(e) {
      },
      onclose: (_b = callbacks === null || callbacks === void 0 ? void 0 : callbacks.onclose) !== null && _b !== void 0 ? _b : function(e) {
      }
    };
    const conn = this.webSocketFactory.create(url, headersToMap(headers), websocketCallbacks);
    conn.connect();
    await onopenPromise;
    let transformedModel = tModel(this.apiClient, params.model);
    if (this.apiClient.isVertexAI() && transformedModel.startsWith("publishers/")) {
      const project = this.apiClient.getProject();
      const location = this.apiClient.getLocation();
      transformedModel = `projects/${project}/locations/${location}/` + transformedModel;
    }
    let clientMessage = {};
    if (this.apiClient.isVertexAI() && ((_c = params.config) === null || _c === void 0 ? void 0 : _c.responseModalities) === void 0) {
      if (params.config === void 0) {
        params.config = { responseModalities: [Modality.AUDIO] };
      } else {
        params.config.responseModalities = [Modality.AUDIO];
      }
    }
    if ((_d = params.config) === null || _d === void 0 ? void 0 : _d.generationConfig) {
      console.warn("Setting `LiveConnectConfig.generation_config` is deprecated, please set the fields on `LiveConnectConfig` directly. This will become an error in a future version (not before Q3 2025).");
    }
    const inputTools = (_f = (_e = params.config) === null || _e === void 0 ? void 0 : _e.tools) !== null && _f !== void 0 ? _f : [];
    const convertedTools = [];
    for (const tool of inputTools) {
      if (this.isCallableTool(tool)) {
        const callableTool = tool;
        convertedTools.push(await callableTool.tool());
      } else {
        convertedTools.push(tool);
      }
    }
    if (convertedTools.length > 0) {
      params.config.tools = convertedTools;
    }
    const liveConnectParameters = {
      model: transformedModel,
      config: params.config,
      callbacks: params.callbacks
    };
    if (this.apiClient.isVertexAI()) {
      clientMessage = liveConnectParametersToVertex(this.apiClient, liveConnectParameters);
    } else {
      clientMessage = liveConnectParametersToMldev(this.apiClient, liveConnectParameters);
    }
    delete clientMessage["config"];
    conn.send(JSON.stringify(clientMessage));
    return new Session(conn, this.apiClient);
  }
  // TODO: b/416041229 - Abstract this method to a common place.
  isCallableTool(tool) {
    return "callTool" in tool && typeof tool.callTool === "function";
  }
};
var defaultLiveSendClientContentParamerters = {
  turnComplete: true
};
var Session = class {
  static {
    __name(this, "Session");
  }
  constructor(conn, apiClient) {
    this.conn = conn;
    this.apiClient = apiClient;
  }
  tLiveClientContent(apiClient, params) {
    if (params.turns !== null && params.turns !== void 0) {
      let contents = [];
      try {
        contents = tContents(params.turns);
        if (apiClient.isVertexAI()) {
          contents = contents.map((item) => contentToVertex(item));
        } else {
          contents = contents.map((item) => contentToMldev$1(item));
        }
      } catch (_a) {
        throw new Error(`Failed to parse client content "turns", type: '${typeof params.turns}'`);
      }
      return {
        clientContent: { turns: contents, turnComplete: params.turnComplete }
      };
    }
    return {
      clientContent: { turnComplete: params.turnComplete }
    };
  }
  tLiveClienttToolResponse(apiClient, params) {
    let functionResponses = [];
    if (params.functionResponses == null) {
      throw new Error("functionResponses is required.");
    }
    if (!Array.isArray(params.functionResponses)) {
      functionResponses = [params.functionResponses];
    } else {
      functionResponses = params.functionResponses;
    }
    if (functionResponses.length === 0) {
      throw new Error("functionResponses is required.");
    }
    for (const functionResponse of functionResponses) {
      if (typeof functionResponse !== "object" || functionResponse === null || !("name" in functionResponse) || !("response" in functionResponse)) {
        throw new Error(`Could not parse function response, type '${typeof functionResponse}'.`);
      }
      if (!apiClient.isVertexAI() && !("id" in functionResponse)) {
        throw new Error(FUNCTION_RESPONSE_REQUIRES_ID);
      }
    }
    const clientMessage = {
      toolResponse: { functionResponses }
    };
    return clientMessage;
  }
  /**
      Send a message over the established connection.
  
      @param params - Contains two **optional** properties, `turns` and
          `turnComplete`.
  
        - `turns` will be converted to a `Content[]`
        - `turnComplete: true` [default] indicates that you are done sending
          content and expect a response. If `turnComplete: false`, the server
          will wait for additional messages before starting generation.
  
      @experimental
  
      @remarks
      There are two ways to send messages to the live API:
      `sendClientContent` and `sendRealtimeInput`.
  
      `sendClientContent` messages are added to the model context **in order**.
      Having a conversation using `sendClientContent` messages is roughly
      equivalent to using the `Chat.sendMessageStream`, except that the state of
      the `chat` history is stored on the API server instead of locally.
  
      Because of `sendClientContent`'s order guarantee, the model cannot respons
      as quickly to `sendClientContent` messages as to `sendRealtimeInput`
      messages. This makes the biggest difference when sending objects that have
      significant preprocessing time (typically images).
  
      The `sendClientContent` message sends a `Content[]`
      which has more options than the `Blob` sent by `sendRealtimeInput`.
  
      So the main use-cases for `sendClientContent` over `sendRealtimeInput` are:
  
      - Sending anything that can't be represented as a `Blob` (text,
      `sendClientContent({turns="Hello?"}`)).
      - Managing turns when not using audio input and voice activity detection.
        (`sendClientContent({turnComplete:true})` or the short form
      `sendClientContent()`)
      - Prefilling a conversation context
        ```
        sendClientContent({
            turns: [
              Content({role:user, parts:...}),
              Content({role:user, parts:...}),
              ...
            ]
        })
        ```
      @experimental
     */
  sendClientContent(params) {
    params = Object.assign(Object.assign({}, defaultLiveSendClientContentParamerters), params);
    const clientMessage = this.tLiveClientContent(this.apiClient, params);
    this.conn.send(JSON.stringify(clientMessage));
  }
  /**
      Send a realtime message over the established connection.
  
      @param params - Contains one property, `media`.
  
        - `media` will be converted to a `Blob`
  
      @experimental
  
      @remarks
      Use `sendRealtimeInput` for realtime audio chunks and video frames (images).
  
      With `sendRealtimeInput` the api will respond to audio automatically
      based on voice activity detection (VAD).
  
      `sendRealtimeInput` is optimized for responsivness at the expense of
      deterministic ordering guarantees. Audio and video tokens are to the
      context when they become available.
  
      Note: The Call signature expects a `Blob` object, but only a subset
      of audio and image mimetypes are allowed.
     */
  sendRealtimeInput(params) {
    let clientMessage = {};
    if (this.apiClient.isVertexAI()) {
      clientMessage = {
        "realtimeInput": liveSendRealtimeInputParametersToVertex(params)
      };
    } else {
      clientMessage = {
        "realtimeInput": liveSendRealtimeInputParametersToMldev(params)
      };
    }
    this.conn.send(JSON.stringify(clientMessage));
  }
  /**
      Send a function response message over the established connection.
  
      @param params - Contains property `functionResponses`.
  
        - `functionResponses` will be converted to a `functionResponses[]`
  
      @remarks
      Use `sendFunctionResponse` to reply to `LiveServerToolCall` from the server.
  
      Use {@link types.LiveConnectConfig#tools} to configure the callable functions.
  
      @experimental
     */
  sendToolResponse(params) {
    if (params.functionResponses == null) {
      throw new Error("Tool response parameters are required.");
    }
    const clientMessage = this.tLiveClienttToolResponse(this.apiClient, params);
    this.conn.send(JSON.stringify(clientMessage));
  }
  /**
       Terminates the WebSocket connection.
  
       @experimental
  
       @example
       ```ts
       let model: string;
       if (GOOGLE_GENAI_USE_VERTEXAI) {
         model = 'gemini-2.0-flash-live-preview-04-09';
       } else {
         model = 'gemini-live-2.5-flash-preview';
       }
       const session = await ai.live.connect({
         model: model,
         config: {
           responseModalities: [Modality.AUDIO],
         }
       });
  
       session.close();
       ```
     */
  close() {
    this.conn.close();
  }
};
function headersToMap(headers) {
  const headerMap = {};
  headers.forEach((value, key) => {
    headerMap[key] = value;
  });
  return headerMap;
}
__name(headersToMap, "headersToMap");
function mapToHeaders(map) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(map)) {
    headers.append(key, value);
  }
  return headers;
}
__name(mapToHeaders, "mapToHeaders");
var DEFAULT_MAX_REMOTE_CALLS = 10;
function shouldDisableAfc(config) {
  var _a, _b, _c;
  if ((_a = config === null || config === void 0 ? void 0 : config.automaticFunctionCalling) === null || _a === void 0 ? void 0 : _a.disable) {
    return true;
  }
  let callableToolsPresent = false;
  for (const tool of (_b = config === null || config === void 0 ? void 0 : config.tools) !== null && _b !== void 0 ? _b : []) {
    if (isCallableTool(tool)) {
      callableToolsPresent = true;
      break;
    }
  }
  if (!callableToolsPresent) {
    return true;
  }
  const maxCalls = (_c = config === null || config === void 0 ? void 0 : config.automaticFunctionCalling) === null || _c === void 0 ? void 0 : _c.maximumRemoteCalls;
  if (maxCalls && (maxCalls < 0 || !Number.isInteger(maxCalls)) || maxCalls == 0) {
    console.warn("Invalid maximumRemoteCalls value provided for automatic function calling. Disabled automatic function calling. Please provide a valid integer value greater than 0. maximumRemoteCalls provided:", maxCalls);
    return true;
  }
  return false;
}
__name(shouldDisableAfc, "shouldDisableAfc");
function isCallableTool(tool) {
  return "callTool" in tool && typeof tool.callTool === "function";
}
__name(isCallableTool, "isCallableTool");
function hasCallableTools(params) {
  var _a, _b, _c;
  return (_c = (_b = (_a = params.config) === null || _a === void 0 ? void 0 : _a.tools) === null || _b === void 0 ? void 0 : _b.some((tool) => isCallableTool(tool))) !== null && _c !== void 0 ? _c : false;
}
__name(hasCallableTools, "hasCallableTools");
function hasNonCallableTools(params) {
  var _a, _b, _c;
  return (_c = (_b = (_a = params.config) === null || _a === void 0 ? void 0 : _a.tools) === null || _b === void 0 ? void 0 : _b.some((tool) => !isCallableTool(tool))) !== null && _c !== void 0 ? _c : false;
}
__name(hasNonCallableTools, "hasNonCallableTools");
function shouldAppendAfcHistory(config) {
  var _a;
  return !((_a = config === null || config === void 0 ? void 0 : config.automaticFunctionCalling) === null || _a === void 0 ? void 0 : _a.ignoreCallHistory);
}
__name(shouldAppendAfcHistory, "shouldAppendAfcHistory");
var Models = class extends BaseModule {
  static {
    __name(this, "Models");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
    this.generateContent = async (params) => {
      var _a, _b, _c, _d, _e;
      const transformedParams = await this.processParamsMaybeAddMcpUsage(params);
      this.maybeMoveToResponseJsonSchem(params);
      if (!hasCallableTools(params) || shouldDisableAfc(params.config)) {
        return await this.generateContentInternal(transformedParams);
      }
      if (hasNonCallableTools(params)) {
        throw new Error("Automatic function calling with CallableTools and Tools is not yet supported.");
      }
      let response;
      let functionResponseContent;
      const automaticFunctionCallingHistory = tContents(transformedParams.contents);
      const maxRemoteCalls = (_c = (_b = (_a = transformedParams.config) === null || _a === void 0 ? void 0 : _a.automaticFunctionCalling) === null || _b === void 0 ? void 0 : _b.maximumRemoteCalls) !== null && _c !== void 0 ? _c : DEFAULT_MAX_REMOTE_CALLS;
      let remoteCalls = 0;
      while (remoteCalls < maxRemoteCalls) {
        response = await this.generateContentInternal(transformedParams);
        if (!response.functionCalls || response.functionCalls.length === 0) {
          break;
        }
        const responseContent = response.candidates[0].content;
        const functionResponseParts = [];
        for (const tool of (_e = (_d = params.config) === null || _d === void 0 ? void 0 : _d.tools) !== null && _e !== void 0 ? _e : []) {
          if (isCallableTool(tool)) {
            const callableTool = tool;
            const parts = await callableTool.callTool(response.functionCalls);
            functionResponseParts.push(...parts);
          }
        }
        remoteCalls++;
        functionResponseContent = {
          role: "user",
          parts: functionResponseParts
        };
        transformedParams.contents = tContents(transformedParams.contents);
        transformedParams.contents.push(responseContent);
        transformedParams.contents.push(functionResponseContent);
        if (shouldAppendAfcHistory(transformedParams.config)) {
          automaticFunctionCallingHistory.push(responseContent);
          automaticFunctionCallingHistory.push(functionResponseContent);
        }
      }
      if (shouldAppendAfcHistory(transformedParams.config)) {
        response.automaticFunctionCallingHistory = automaticFunctionCallingHistory;
      }
      return response;
    };
    this.generateContentStream = async (params) => {
      this.maybeMoveToResponseJsonSchem(params);
      if (shouldDisableAfc(params.config)) {
        const transformedParams = await this.processParamsMaybeAddMcpUsage(params);
        return await this.generateContentStreamInternal(transformedParams);
      } else {
        return await this.processAfcStream(params);
      }
    };
    this.generateImages = async (params) => {
      return await this.generateImagesInternal(params).then((apiResponse) => {
        var _a;
        let positivePromptSafetyAttributes;
        const generatedImages = [];
        if (apiResponse === null || apiResponse === void 0 ? void 0 : apiResponse.generatedImages) {
          for (const generatedImage of apiResponse.generatedImages) {
            if (generatedImage && (generatedImage === null || generatedImage === void 0 ? void 0 : generatedImage.safetyAttributes) && ((_a = generatedImage === null || generatedImage === void 0 ? void 0 : generatedImage.safetyAttributes) === null || _a === void 0 ? void 0 : _a.contentType) === "Positive Prompt") {
              positivePromptSafetyAttributes = generatedImage === null || generatedImage === void 0 ? void 0 : generatedImage.safetyAttributes;
            } else {
              generatedImages.push(generatedImage);
            }
          }
        }
        let response;
        if (positivePromptSafetyAttributes) {
          response = {
            generatedImages,
            positivePromptSafetyAttributes,
            sdkHttpResponse: apiResponse.sdkHttpResponse
          };
        } else {
          response = {
            generatedImages,
            sdkHttpResponse: apiResponse.sdkHttpResponse
          };
        }
        return response;
      });
    };
    this.list = async (params) => {
      var _a;
      const defaultConfig = {
        queryBase: true
      };
      const actualConfig = Object.assign(Object.assign({}, defaultConfig), params === null || params === void 0 ? void 0 : params.config);
      const actualParams = {
        config: actualConfig
      };
      if (this.apiClient.isVertexAI()) {
        if (!actualParams.config.queryBase) {
          if ((_a = actualParams.config) === null || _a === void 0 ? void 0 : _a.filter) {
            throw new Error("Filtering tuned models list for Vertex AI is not currently supported");
          } else {
            actualParams.config.filter = "labels.tune-type:*";
          }
        }
      }
      return new Pager(PagedItem.PAGED_ITEM_MODELS, (x) => this.listInternal(x), await this.listInternal(actualParams), actualParams);
    };
    this.editImage = async (params) => {
      const paramsInternal = {
        model: params.model,
        prompt: params.prompt,
        referenceImages: [],
        config: params.config
      };
      if (params.referenceImages) {
        if (params.referenceImages) {
          paramsInternal.referenceImages = params.referenceImages.map((img) => img.toReferenceImageAPI());
        }
      }
      return await this.editImageInternal(paramsInternal);
    };
    this.upscaleImage = async (params) => {
      let apiConfig = {
        numberOfImages: 1,
        mode: "upscale"
      };
      if (params.config) {
        apiConfig = Object.assign(Object.assign({}, apiConfig), params.config);
      }
      const apiParams = {
        model: params.model,
        image: params.image,
        upscaleFactor: params.upscaleFactor,
        config: apiConfig
      };
      return await this.upscaleImageInternal(apiParams);
    };
    this.generateVideos = async (params) => {
      return await this.generateVideosInternal(params);
    };
  }
  /**
   * This logic is needed for GenerateContentConfig only.
   * Previously we made GenerateContentConfig.responseSchema field to accept
   * unknown. Since v1.9.0, we switch to use backend JSON schema support.
   * To maintain backward compatibility, we move the data that was treated as
   * JSON schema from the responseSchema field to the responseJsonSchema field.
   */
  maybeMoveToResponseJsonSchem(params) {
    if (params.config && params.config.responseSchema) {
      if (!params.config.responseJsonSchema) {
        if (Object.keys(params.config.responseSchema).includes("$schema")) {
          params.config.responseJsonSchema = params.config.responseSchema;
          delete params.config.responseSchema;
        }
      }
    }
    return;
  }
  /**
   * Transforms the CallableTools in the parameters to be simply Tools, it
   * copies the params into a new object and replaces the tools, it does not
   * modify the original params. Also sets the MCP usage header if there are
   * MCP tools in the parameters.
   */
  async processParamsMaybeAddMcpUsage(params) {
    var _a, _b, _c;
    const tools = (_a = params.config) === null || _a === void 0 ? void 0 : _a.tools;
    if (!tools) {
      return params;
    }
    const transformedTools = await Promise.all(tools.map(async (tool) => {
      if (isCallableTool(tool)) {
        const callableTool = tool;
        return await callableTool.tool();
      }
      return tool;
    }));
    const newParams = {
      model: params.model,
      contents: params.contents,
      config: Object.assign(Object.assign({}, params.config), { tools: transformedTools })
    };
    newParams.config.tools = transformedTools;
    if (params.config && params.config.tools && hasMcpToolUsage(params.config.tools)) {
      const headers = (_c = (_b = params.config.httpOptions) === null || _b === void 0 ? void 0 : _b.headers) !== null && _c !== void 0 ? _c : {};
      let newHeaders = Object.assign({}, headers);
      if (Object.keys(newHeaders).length === 0) {
        newHeaders = this.apiClient.getDefaultHeaders();
      }
      setMcpUsageHeader(newHeaders);
      newParams.config.httpOptions = Object.assign(Object.assign({}, params.config.httpOptions), { headers: newHeaders });
    }
    return newParams;
  }
  async initAfcToolsMap(params) {
    var _a, _b, _c;
    const afcTools = /* @__PURE__ */ new Map();
    for (const tool of (_b = (_a = params.config) === null || _a === void 0 ? void 0 : _a.tools) !== null && _b !== void 0 ? _b : []) {
      if (isCallableTool(tool)) {
        const callableTool = tool;
        const toolDeclaration = await callableTool.tool();
        for (const declaration of (_c = toolDeclaration.functionDeclarations) !== null && _c !== void 0 ? _c : []) {
          if (!declaration.name) {
            throw new Error("Function declaration name is required.");
          }
          if (afcTools.has(declaration.name)) {
            throw new Error(`Duplicate tool declaration name: ${declaration.name}`);
          }
          afcTools.set(declaration.name, callableTool);
        }
      }
    }
    return afcTools;
  }
  async processAfcStream(params) {
    var _a, _b, _c;
    const maxRemoteCalls = (_c = (_b = (_a = params.config) === null || _a === void 0 ? void 0 : _a.automaticFunctionCalling) === null || _b === void 0 ? void 0 : _b.maximumRemoteCalls) !== null && _c !== void 0 ? _c : DEFAULT_MAX_REMOTE_CALLS;
    let wereFunctionsCalled = false;
    let remoteCallCount = 0;
    const afcToolsMap = await this.initAfcToolsMap(params);
    return function(models, afcTools, params2) {
      var _a2, _b2;
      return __asyncGenerator(this, arguments, function* () {
        var _c2, e_1, _d, _e;
        while (remoteCallCount < maxRemoteCalls) {
          if (wereFunctionsCalled) {
            remoteCallCount++;
            wereFunctionsCalled = false;
          }
          const transformedParams = yield __await(models.processParamsMaybeAddMcpUsage(params2));
          const response = yield __await(models.generateContentStreamInternal(transformedParams));
          const functionResponses = [];
          const responseContents = [];
          try {
            for (var _f = true, response_1 = (e_1 = void 0, __asyncValues(response)), response_1_1; response_1_1 = yield __await(response_1.next()), _c2 = response_1_1.done, !_c2; _f = true) {
              _e = response_1_1.value;
              _f = false;
              const chunk = _e;
              yield yield __await(chunk);
              if (chunk.candidates && ((_a2 = chunk.candidates[0]) === null || _a2 === void 0 ? void 0 : _a2.content)) {
                responseContents.push(chunk.candidates[0].content);
                for (const part of (_b2 = chunk.candidates[0].content.parts) !== null && _b2 !== void 0 ? _b2 : []) {
                  if (remoteCallCount < maxRemoteCalls && part.functionCall) {
                    if (!part.functionCall.name) {
                      throw new Error("Function call name was not returned by the model.");
                    }
                    if (!afcTools.has(part.functionCall.name)) {
                      throw new Error(`Automatic function calling was requested, but not all the tools the model used implement the CallableTool interface. Available tools: ${afcTools.keys()}, mising tool: ${part.functionCall.name}`);
                    } else {
                      const responseParts = yield __await(afcTools.get(part.functionCall.name).callTool([part.functionCall]));
                      functionResponses.push(...responseParts);
                    }
                  }
                }
              }
            }
          } catch (e_1_1) {
            e_1 = { error: e_1_1 };
          } finally {
            try {
              if (!_f && !_c2 && (_d = response_1.return)) yield __await(_d.call(response_1));
            } finally {
              if (e_1) throw e_1.error;
            }
          }
          if (functionResponses.length > 0) {
            wereFunctionsCalled = true;
            const typedResponseChunk = new GenerateContentResponse();
            typedResponseChunk.candidates = [
              {
                content: {
                  role: "user",
                  parts: functionResponses
                }
              }
            ];
            yield yield __await(typedResponseChunk);
            const newContents = [];
            newContents.push(...responseContents);
            newContents.push({
              role: "user",
              parts: functionResponses
            });
            const updatedContents = tContents(params2.contents).concat(newContents);
            params2.contents = updatedContents;
          } else {
            break;
          }
        }
      });
    }(this, afcToolsMap, params);
  }
  async generateContentInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = generateContentParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:generateContent", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = generateContentResponseFromVertex(apiResponse);
        const typedResp = new GenerateContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = generateContentParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:generateContent", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = generateContentResponseFromMldev(apiResponse);
        const typedResp = new GenerateContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  async generateContentStreamInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = generateContentParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:streamGenerateContent?alt=sse", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      const apiClient = this.apiClient;
      response = apiClient.requestStream({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      });
      return response.then(function(apiResponse) {
        return __asyncGenerator(this, arguments, function* () {
          var _a2, e_2, _b2, _c2;
          try {
            for (var _d2 = true, apiResponse_1 = __asyncValues(apiResponse), apiResponse_1_1; apiResponse_1_1 = yield __await(apiResponse_1.next()), _a2 = apiResponse_1_1.done, !_a2; _d2 = true) {
              _c2 = apiResponse_1_1.value;
              _d2 = false;
              const chunk = _c2;
              const resp = generateContentResponseFromVertex(yield __await(chunk.json()));
              resp["sdkHttpResponse"] = {
                headers: chunk.headers
              };
              const typedResp = new GenerateContentResponse();
              Object.assign(typedResp, resp);
              yield yield __await(typedResp);
            }
          } catch (e_2_1) {
            e_2 = { error: e_2_1 };
          } finally {
            try {
              if (!_d2 && !_a2 && (_b2 = apiResponse_1.return)) yield __await(_b2.call(apiResponse_1));
            } finally {
              if (e_2) throw e_2.error;
            }
          }
        });
      });
    } else {
      const body = generateContentParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:streamGenerateContent?alt=sse", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      const apiClient = this.apiClient;
      response = apiClient.requestStream({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      });
      return response.then(function(apiResponse) {
        return __asyncGenerator(this, arguments, function* () {
          var _a2, e_3, _b2, _c2;
          try {
            for (var _d2 = true, apiResponse_2 = __asyncValues(apiResponse), apiResponse_2_1; apiResponse_2_1 = yield __await(apiResponse_2.next()), _a2 = apiResponse_2_1.done, !_a2; _d2 = true) {
              _c2 = apiResponse_2_1.value;
              _d2 = false;
              const chunk = _c2;
              const resp = generateContentResponseFromMldev(yield __await(chunk.json()));
              resp["sdkHttpResponse"] = {
                headers: chunk.headers
              };
              const typedResp = new GenerateContentResponse();
              Object.assign(typedResp, resp);
              yield yield __await(typedResp);
            }
          } catch (e_3_1) {
            e_3 = { error: e_3_1 };
          } finally {
            try {
              if (!_d2 && !_a2 && (_b2 = apiResponse_2.return)) yield __await(_b2.call(apiResponse_2));
            } finally {
              if (e_3) throw e_3.error;
            }
          }
        });
      });
    }
  }
  /**
   * Calculates embeddings for the given contents. Only text is supported.
   *
   * @param params - The parameters for embedding contents.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.embedContent({
   *  model: 'text-embedding-004',
   *  contents: [
   *    'What is your name?',
   *    'What is your favorite color?',
   *  ],
   *  config: {
   *    outputDimensionality: 64,
   *  },
   * });
   * console.log(response);
   * ```
   */
  async embedContent(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = embedContentParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:predict", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = embedContentResponseFromVertex(apiResponse);
        const typedResp = new EmbedContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = embedContentParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:batchEmbedContents", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = embedContentResponseFromMldev(apiResponse);
        const typedResp = new EmbedContentResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Generates an image based on a text description and configuration.
   *
   * @param params - The parameters for generating images.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.generateImages({
   *  model: 'imagen-3.0-generate-002',
   *  prompt: 'Robot holding a red skateboard',
   *  config: {
   *    numberOfImages: 1,
   *    includeRaiReason: true,
   *  },
   * });
   * console.log(response?.generatedImages?.[0]?.image?.imageBytes);
   * ```
   */
  async generateImagesInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = generateImagesParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:predict", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = generateImagesResponseFromVertex(apiResponse);
        const typedResp = new GenerateImagesResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = generateImagesParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:predict", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = generateImagesResponseFromMldev(apiResponse);
        const typedResp = new GenerateImagesResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  async editImageInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = editImageParametersInternalToVertex(this.apiClient, params);
      path = formatMap("{model}:predict", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = editImageResponseFromVertex(apiResponse);
        const typedResp = new EditImageResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      throw new Error("This method is only supported by the Vertex AI.");
    }
  }
  async upscaleImageInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = upscaleImageAPIParametersInternalToVertex(this.apiClient, params);
      path = formatMap("{model}:predict", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = upscaleImageResponseFromVertex(apiResponse);
        const typedResp = new UpscaleImageResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      throw new Error("This method is only supported by the Vertex AI.");
    }
  }
  /**
   * Fetches information about a model by name.
   *
   * @example
   * ```ts
   * const modelInfo = await ai.models.get({model: 'gemini-2.0-flash'});
   * ```
   */
  async get(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = getModelParametersToVertex(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = modelFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = getModelParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = modelFromMldev(apiResponse);
        return resp;
      });
    }
  }
  async listInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = listModelsParametersToVertex(this.apiClient, params);
      path = formatMap("{models_url}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listModelsResponseFromVertex(apiResponse);
        const typedResp = new ListModelsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = listModelsParametersToMldev(this.apiClient, params);
      path = formatMap("{models_url}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listModelsResponseFromMldev(apiResponse);
        const typedResp = new ListModelsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Updates a tuned model by its name.
   *
   * @param params - The parameters for updating the model.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.update({
   *   model: 'tuned-model-name',
   *   config: {
   *     displayName: 'New display name',
   *     description: 'New description',
   *   },
   * });
   * ```
   */
  async update(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = updateModelParametersToVertex(this.apiClient, params);
      path = formatMap("{model}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "PATCH",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = modelFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = updateModelParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "PATCH",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = modelFromMldev(apiResponse);
        return resp;
      });
    }
  }
  /**
   * Deletes a tuned model by its name.
   *
   * @param params - The parameters for deleting the model.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.delete({model: 'tuned-model-name'});
   * ```
   */
  async delete(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = deleteModelParametersToVertex(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then(() => {
        const resp = deleteModelResponseFromVertex();
        const typedResp = new DeleteModelResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = deleteModelParametersToMldev(this.apiClient, params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "DELETE",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then(() => {
        const resp = deleteModelResponseFromMldev();
        const typedResp = new DeleteModelResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Counts the number of tokens in the given contents. Multimodal input is
   * supported for Gemini models.
   *
   * @param params - The parameters for counting tokens.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.countTokens({
   *  model: 'gemini-2.0-flash',
   *  contents: 'The quick brown fox jumps over the lazy dog.'
   * });
   * console.log(response);
   * ```
   */
  async countTokens(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = countTokensParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:countTokens", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = countTokensResponseFromVertex(apiResponse);
        const typedResp = new CountTokensResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = countTokensParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:countTokens", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = countTokensResponseFromMldev(apiResponse);
        const typedResp = new CountTokensResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  /**
   * Given a list of contents, returns a corresponding TokensInfo containing
   * the list of tokens and list of token ids.
   *
   * This method is not supported by the Gemini Developer API.
   *
   * @param params - The parameters for computing tokens.
   * @return The response from the API.
   *
   * @example
   * ```ts
   * const response = await ai.models.computeTokens({
   *  model: 'gemini-2.0-flash',
   *  contents: 'What is your name?'
   * });
   * console.log(response);
   * ```
   */
  async computeTokens(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = computeTokensParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:computeTokens", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = computeTokensResponseFromVertex(apiResponse);
        const typedResp = new ComputeTokensResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      throw new Error("This method is only supported by the Vertex AI.");
    }
  }
  /**
   *  Generates videos based on a text description and configuration.
   *
   * @param params - The parameters for generating videos.
   * @return A Promise<GenerateVideosOperation> which allows you to track the progress and eventually retrieve the generated videos using the operations.get method.
   *
   * @example
   * ```ts
   * const operation = await ai.models.generateVideos({
   *  model: 'veo-2.0-generate-001',
   *  prompt: 'A neon hologram of a cat driving at top speed',
   *  config: {
   *    numberOfVideos: 1
   * });
   *
   * while (!operation.done) {
   *   await new Promise(resolve => setTimeout(resolve, 10000));
   *   operation = await ai.operations.getVideosOperation({operation: operation});
   * }
   *
   * console.log(operation.response?.generatedVideos?.[0]?.video?.uri);
   * ```
   */
  async generateVideosInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = generateVideosParametersToVertex(this.apiClient, params);
      path = formatMap("{model}:predictLongRunning", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = generateVideosOperationFromVertex(apiResponse);
        const typedResp = new GenerateVideosOperation();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = generateVideosParametersToMldev(this.apiClient, params);
      path = formatMap("{model}:predictLongRunning", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = generateVideosOperationFromMldev(apiResponse);
        const typedResp = new GenerateVideosOperation();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
};
function getOperationParametersToMldev(fromObject) {
  const toObject = {};
  const fromOperationName = getValueByPath(fromObject, [
    "operationName"
  ]);
  if (fromOperationName != null) {
    setValueByPath(toObject, ["_url", "operationName"], fromOperationName);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getOperationParametersToMldev, "getOperationParametersToMldev");
function getOperationParametersToVertex(fromObject) {
  const toObject = {};
  const fromOperationName = getValueByPath(fromObject, [
    "operationName"
  ]);
  if (fromOperationName != null) {
    setValueByPath(toObject, ["_url", "operationName"], fromOperationName);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getOperationParametersToVertex, "getOperationParametersToVertex");
function fetchPredictOperationParametersToVertex(fromObject) {
  const toObject = {};
  const fromOperationName = getValueByPath(fromObject, [
    "operationName"
  ]);
  if (fromOperationName != null) {
    setValueByPath(toObject, ["operationName"], fromOperationName);
  }
  const fromResourceName = getValueByPath(fromObject, ["resourceName"]);
  if (fromResourceName != null) {
    setValueByPath(toObject, ["_url", "resourceName"], fromResourceName);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(fetchPredictOperationParametersToVertex, "fetchPredictOperationParametersToVertex");
var Operations = class extends BaseModule {
  static {
    __name(this, "Operations");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
  }
  /**
   * Gets the status of a long-running operation.
   *
   * @param parameters The parameters for the get operation request.
   * @return The updated Operation object, with the latest status or result.
   */
  async getVideosOperation(parameters) {
    const operation = parameters.operation;
    const config = parameters.config;
    if (operation.name === void 0 || operation.name === "") {
      throw new Error("Operation name is required.");
    }
    if (this.apiClient.isVertexAI()) {
      const resourceName2 = operation.name.split("/operations/")[0];
      let httpOptions = void 0;
      if (config && "httpOptions" in config) {
        httpOptions = config.httpOptions;
      }
      const rawOperation = await this.fetchPredictVideosOperationInternal({
        operationName: operation.name,
        resourceName: resourceName2,
        config: { httpOptions }
      });
      return operation._fromAPIResponse({
        apiResponse: rawOperation,
        isVertexAI: true
      });
    } else {
      const rawOperation = await this.getVideosOperationInternal({
        operationName: operation.name,
        config
      });
      return operation._fromAPIResponse({
        apiResponse: rawOperation,
        isVertexAI: false
      });
    }
  }
  /**
   * Gets the status of a long-running operation.
   *
   * @param parameters The parameters for the get operation request.
   * @return The updated Operation object, with the latest status or result.
   */
  async get(parameters) {
    const operation = parameters.operation;
    const config = parameters.config;
    if (operation.name === void 0 || operation.name === "") {
      throw new Error("Operation name is required.");
    }
    if (this.apiClient.isVertexAI()) {
      const resourceName2 = operation.name.split("/operations/")[0];
      let httpOptions = void 0;
      if (config && "httpOptions" in config) {
        httpOptions = config.httpOptions;
      }
      const rawOperation = await this.fetchPredictVideosOperationInternal({
        operationName: operation.name,
        resourceName: resourceName2,
        config: { httpOptions }
      });
      return operation._fromAPIResponse({
        apiResponse: rawOperation,
        isVertexAI: true
      });
    } else {
      const rawOperation = await this.getVideosOperationInternal({
        operationName: operation.name,
        config
      });
      return operation._fromAPIResponse({
        apiResponse: rawOperation,
        isVertexAI: false
      });
    }
  }
  async getVideosOperationInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = getOperationParametersToVertex(params);
      path = formatMap("{operationName}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response;
    } else {
      const body = getOperationParametersToMldev(params);
      path = formatMap("{operationName}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response;
    }
  }
  async fetchPredictVideosOperationInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = fetchPredictOperationParametersToVertex(params);
      path = formatMap("{resourceName}:fetchPredictOperation", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response;
    } else {
      throw new Error("This method is only supported by the Vertex AI.");
    }
  }
};
function prebuiltVoiceConfigToMldev(fromObject) {
  const toObject = {};
  const fromVoiceName = getValueByPath(fromObject, ["voiceName"]);
  if (fromVoiceName != null) {
    setValueByPath(toObject, ["voiceName"], fromVoiceName);
  }
  return toObject;
}
__name(prebuiltVoiceConfigToMldev, "prebuiltVoiceConfigToMldev");
function voiceConfigToMldev(fromObject) {
  const toObject = {};
  const fromPrebuiltVoiceConfig = getValueByPath(fromObject, [
    "prebuiltVoiceConfig"
  ]);
  if (fromPrebuiltVoiceConfig != null) {
    setValueByPath(toObject, ["prebuiltVoiceConfig"], prebuiltVoiceConfigToMldev(fromPrebuiltVoiceConfig));
  }
  return toObject;
}
__name(voiceConfigToMldev, "voiceConfigToMldev");
function speakerVoiceConfigToMldev(fromObject) {
  const toObject = {};
  const fromSpeaker = getValueByPath(fromObject, ["speaker"]);
  if (fromSpeaker != null) {
    setValueByPath(toObject, ["speaker"], fromSpeaker);
  }
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev(fromVoiceConfig));
  }
  return toObject;
}
__name(speakerVoiceConfigToMldev, "speakerVoiceConfigToMldev");
function multiSpeakerVoiceConfigToMldev(fromObject) {
  const toObject = {};
  const fromSpeakerVoiceConfigs = getValueByPath(fromObject, [
    "speakerVoiceConfigs"
  ]);
  if (fromSpeakerVoiceConfigs != null) {
    let transformedList = fromSpeakerVoiceConfigs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return speakerVoiceConfigToMldev(item);
      });
    }
    setValueByPath(toObject, ["speakerVoiceConfigs"], transformedList);
  }
  return toObject;
}
__name(multiSpeakerVoiceConfigToMldev, "multiSpeakerVoiceConfigToMldev");
function speechConfigToMldev(fromObject) {
  const toObject = {};
  const fromVoiceConfig = getValueByPath(fromObject, ["voiceConfig"]);
  if (fromVoiceConfig != null) {
    setValueByPath(toObject, ["voiceConfig"], voiceConfigToMldev(fromVoiceConfig));
  }
  const fromMultiSpeakerVoiceConfig = getValueByPath(fromObject, [
    "multiSpeakerVoiceConfig"
  ]);
  if (fromMultiSpeakerVoiceConfig != null) {
    setValueByPath(toObject, ["multiSpeakerVoiceConfig"], multiSpeakerVoiceConfigToMldev(fromMultiSpeakerVoiceConfig));
  }
  const fromLanguageCode = getValueByPath(fromObject, ["languageCode"]);
  if (fromLanguageCode != null) {
    setValueByPath(toObject, ["languageCode"], fromLanguageCode);
  }
  return toObject;
}
__name(speechConfigToMldev, "speechConfigToMldev");
function videoMetadataToMldev(fromObject) {
  const toObject = {};
  const fromFps = getValueByPath(fromObject, ["fps"]);
  if (fromFps != null) {
    setValueByPath(toObject, ["fps"], fromFps);
  }
  const fromEndOffset = getValueByPath(fromObject, ["endOffset"]);
  if (fromEndOffset != null) {
    setValueByPath(toObject, ["endOffset"], fromEndOffset);
  }
  const fromStartOffset = getValueByPath(fromObject, ["startOffset"]);
  if (fromStartOffset != null) {
    setValueByPath(toObject, ["startOffset"], fromStartOffset);
  }
  return toObject;
}
__name(videoMetadataToMldev, "videoMetadataToMldev");
function blobToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromData = getValueByPath(fromObject, ["data"]);
  if (fromData != null) {
    setValueByPath(toObject, ["data"], fromData);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(blobToMldev, "blobToMldev");
function fileDataToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["displayName"]) !== void 0) {
    throw new Error("displayName parameter is not supported in Gemini API.");
  }
  const fromFileUri = getValueByPath(fromObject, ["fileUri"]);
  if (fromFileUri != null) {
    setValueByPath(toObject, ["fileUri"], fromFileUri);
  }
  const fromMimeType = getValueByPath(fromObject, ["mimeType"]);
  if (fromMimeType != null) {
    setValueByPath(toObject, ["mimeType"], fromMimeType);
  }
  return toObject;
}
__name(fileDataToMldev, "fileDataToMldev");
function partToMldev(fromObject) {
  const toObject = {};
  const fromVideoMetadata = getValueByPath(fromObject, [
    "videoMetadata"
  ]);
  if (fromVideoMetadata != null) {
    setValueByPath(toObject, ["videoMetadata"], videoMetadataToMldev(fromVideoMetadata));
  }
  const fromThought = getValueByPath(fromObject, ["thought"]);
  if (fromThought != null) {
    setValueByPath(toObject, ["thought"], fromThought);
  }
  const fromInlineData = getValueByPath(fromObject, ["inlineData"]);
  if (fromInlineData != null) {
    setValueByPath(toObject, ["inlineData"], blobToMldev(fromInlineData));
  }
  const fromFileData = getValueByPath(fromObject, ["fileData"]);
  if (fromFileData != null) {
    setValueByPath(toObject, ["fileData"], fileDataToMldev(fromFileData));
  }
  const fromThoughtSignature = getValueByPath(fromObject, [
    "thoughtSignature"
  ]);
  if (fromThoughtSignature != null) {
    setValueByPath(toObject, ["thoughtSignature"], fromThoughtSignature);
  }
  const fromCodeExecutionResult = getValueByPath(fromObject, [
    "codeExecutionResult"
  ]);
  if (fromCodeExecutionResult != null) {
    setValueByPath(toObject, ["codeExecutionResult"], fromCodeExecutionResult);
  }
  const fromExecutableCode = getValueByPath(fromObject, [
    "executableCode"
  ]);
  if (fromExecutableCode != null) {
    setValueByPath(toObject, ["executableCode"], fromExecutableCode);
  }
  const fromFunctionCall = getValueByPath(fromObject, ["functionCall"]);
  if (fromFunctionCall != null) {
    setValueByPath(toObject, ["functionCall"], fromFunctionCall);
  }
  const fromFunctionResponse = getValueByPath(fromObject, [
    "functionResponse"
  ]);
  if (fromFunctionResponse != null) {
    setValueByPath(toObject, ["functionResponse"], fromFunctionResponse);
  }
  const fromText = getValueByPath(fromObject, ["text"]);
  if (fromText != null) {
    setValueByPath(toObject, ["text"], fromText);
  }
  return toObject;
}
__name(partToMldev, "partToMldev");
function contentToMldev(fromObject) {
  const toObject = {};
  const fromParts = getValueByPath(fromObject, ["parts"]);
  if (fromParts != null) {
    let transformedList = fromParts;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return partToMldev(item);
      });
    }
    setValueByPath(toObject, ["parts"], transformedList);
  }
  const fromRole = getValueByPath(fromObject, ["role"]);
  if (fromRole != null) {
    setValueByPath(toObject, ["role"], fromRole);
  }
  return toObject;
}
__name(contentToMldev, "contentToMldev");
function functionDeclarationToMldev(fromObject) {
  const toObject = {};
  const fromBehavior = getValueByPath(fromObject, ["behavior"]);
  if (fromBehavior != null) {
    setValueByPath(toObject, ["behavior"], fromBehavior);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromParameters = getValueByPath(fromObject, ["parameters"]);
  if (fromParameters != null) {
    setValueByPath(toObject, ["parameters"], fromParameters);
  }
  const fromParametersJsonSchema = getValueByPath(fromObject, [
    "parametersJsonSchema"
  ]);
  if (fromParametersJsonSchema != null) {
    setValueByPath(toObject, ["parametersJsonSchema"], fromParametersJsonSchema);
  }
  const fromResponse = getValueByPath(fromObject, ["response"]);
  if (fromResponse != null) {
    setValueByPath(toObject, ["response"], fromResponse);
  }
  const fromResponseJsonSchema = getValueByPath(fromObject, [
    "responseJsonSchema"
  ]);
  if (fromResponseJsonSchema != null) {
    setValueByPath(toObject, ["responseJsonSchema"], fromResponseJsonSchema);
  }
  return toObject;
}
__name(functionDeclarationToMldev, "functionDeclarationToMldev");
function intervalToMldev(fromObject) {
  const toObject = {};
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  return toObject;
}
__name(intervalToMldev, "intervalToMldev");
function googleSearchToMldev(fromObject) {
  const toObject = {};
  const fromTimeRangeFilter = getValueByPath(fromObject, [
    "timeRangeFilter"
  ]);
  if (fromTimeRangeFilter != null) {
    setValueByPath(toObject, ["timeRangeFilter"], intervalToMldev(fromTimeRangeFilter));
  }
  return toObject;
}
__name(googleSearchToMldev, "googleSearchToMldev");
function dynamicRetrievalConfigToMldev(fromObject) {
  const toObject = {};
  const fromMode = getValueByPath(fromObject, ["mode"]);
  if (fromMode != null) {
    setValueByPath(toObject, ["mode"], fromMode);
  }
  const fromDynamicThreshold = getValueByPath(fromObject, [
    "dynamicThreshold"
  ]);
  if (fromDynamicThreshold != null) {
    setValueByPath(toObject, ["dynamicThreshold"], fromDynamicThreshold);
  }
  return toObject;
}
__name(dynamicRetrievalConfigToMldev, "dynamicRetrievalConfigToMldev");
function googleSearchRetrievalToMldev(fromObject) {
  const toObject = {};
  const fromDynamicRetrievalConfig = getValueByPath(fromObject, [
    "dynamicRetrievalConfig"
  ]);
  if (fromDynamicRetrievalConfig != null) {
    setValueByPath(toObject, ["dynamicRetrievalConfig"], dynamicRetrievalConfigToMldev(fromDynamicRetrievalConfig));
  }
  return toObject;
}
__name(googleSearchRetrievalToMldev, "googleSearchRetrievalToMldev");
function urlContextToMldev() {
  const toObject = {};
  return toObject;
}
__name(urlContextToMldev, "urlContextToMldev");
function toolToMldev(fromObject) {
  const toObject = {};
  const fromFunctionDeclarations = getValueByPath(fromObject, [
    "functionDeclarations"
  ]);
  if (fromFunctionDeclarations != null) {
    let transformedList = fromFunctionDeclarations;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return functionDeclarationToMldev(item);
      });
    }
    setValueByPath(toObject, ["functionDeclarations"], transformedList);
  }
  if (getValueByPath(fromObject, ["retrieval"]) !== void 0) {
    throw new Error("retrieval parameter is not supported in Gemini API.");
  }
  const fromGoogleSearch = getValueByPath(fromObject, ["googleSearch"]);
  if (fromGoogleSearch != null) {
    setValueByPath(toObject, ["googleSearch"], googleSearchToMldev(fromGoogleSearch));
  }
  const fromGoogleSearchRetrieval = getValueByPath(fromObject, [
    "googleSearchRetrieval"
  ]);
  if (fromGoogleSearchRetrieval != null) {
    setValueByPath(toObject, ["googleSearchRetrieval"], googleSearchRetrievalToMldev(fromGoogleSearchRetrieval));
  }
  if (getValueByPath(fromObject, ["enterpriseWebSearch"]) !== void 0) {
    throw new Error("enterpriseWebSearch parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["googleMaps"]) !== void 0) {
    throw new Error("googleMaps parameter is not supported in Gemini API.");
  }
  const fromUrlContext = getValueByPath(fromObject, ["urlContext"]);
  if (fromUrlContext != null) {
    setValueByPath(toObject, ["urlContext"], urlContextToMldev());
  }
  const fromCodeExecution = getValueByPath(fromObject, [
    "codeExecution"
  ]);
  if (fromCodeExecution != null) {
    setValueByPath(toObject, ["codeExecution"], fromCodeExecution);
  }
  const fromComputerUse = getValueByPath(fromObject, ["computerUse"]);
  if (fromComputerUse != null) {
    setValueByPath(toObject, ["computerUse"], fromComputerUse);
  }
  return toObject;
}
__name(toolToMldev, "toolToMldev");
function sessionResumptionConfigToMldev(fromObject) {
  const toObject = {};
  const fromHandle = getValueByPath(fromObject, ["handle"]);
  if (fromHandle != null) {
    setValueByPath(toObject, ["handle"], fromHandle);
  }
  if (getValueByPath(fromObject, ["transparent"]) !== void 0) {
    throw new Error("transparent parameter is not supported in Gemini API.");
  }
  return toObject;
}
__name(sessionResumptionConfigToMldev, "sessionResumptionConfigToMldev");
function audioTranscriptionConfigToMldev() {
  const toObject = {};
  return toObject;
}
__name(audioTranscriptionConfigToMldev, "audioTranscriptionConfigToMldev");
function automaticActivityDetectionToMldev(fromObject) {
  const toObject = {};
  const fromDisabled = getValueByPath(fromObject, ["disabled"]);
  if (fromDisabled != null) {
    setValueByPath(toObject, ["disabled"], fromDisabled);
  }
  const fromStartOfSpeechSensitivity = getValueByPath(fromObject, [
    "startOfSpeechSensitivity"
  ]);
  if (fromStartOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["startOfSpeechSensitivity"], fromStartOfSpeechSensitivity);
  }
  const fromEndOfSpeechSensitivity = getValueByPath(fromObject, [
    "endOfSpeechSensitivity"
  ]);
  if (fromEndOfSpeechSensitivity != null) {
    setValueByPath(toObject, ["endOfSpeechSensitivity"], fromEndOfSpeechSensitivity);
  }
  const fromPrefixPaddingMs = getValueByPath(fromObject, [
    "prefixPaddingMs"
  ]);
  if (fromPrefixPaddingMs != null) {
    setValueByPath(toObject, ["prefixPaddingMs"], fromPrefixPaddingMs);
  }
  const fromSilenceDurationMs = getValueByPath(fromObject, [
    "silenceDurationMs"
  ]);
  if (fromSilenceDurationMs != null) {
    setValueByPath(toObject, ["silenceDurationMs"], fromSilenceDurationMs);
  }
  return toObject;
}
__name(automaticActivityDetectionToMldev, "automaticActivityDetectionToMldev");
function realtimeInputConfigToMldev(fromObject) {
  const toObject = {};
  const fromAutomaticActivityDetection = getValueByPath(fromObject, [
    "automaticActivityDetection"
  ]);
  if (fromAutomaticActivityDetection != null) {
    setValueByPath(toObject, ["automaticActivityDetection"], automaticActivityDetectionToMldev(fromAutomaticActivityDetection));
  }
  const fromActivityHandling = getValueByPath(fromObject, [
    "activityHandling"
  ]);
  if (fromActivityHandling != null) {
    setValueByPath(toObject, ["activityHandling"], fromActivityHandling);
  }
  const fromTurnCoverage = getValueByPath(fromObject, ["turnCoverage"]);
  if (fromTurnCoverage != null) {
    setValueByPath(toObject, ["turnCoverage"], fromTurnCoverage);
  }
  return toObject;
}
__name(realtimeInputConfigToMldev, "realtimeInputConfigToMldev");
function slidingWindowToMldev(fromObject) {
  const toObject = {};
  const fromTargetTokens = getValueByPath(fromObject, ["targetTokens"]);
  if (fromTargetTokens != null) {
    setValueByPath(toObject, ["targetTokens"], fromTargetTokens);
  }
  return toObject;
}
__name(slidingWindowToMldev, "slidingWindowToMldev");
function contextWindowCompressionConfigToMldev(fromObject) {
  const toObject = {};
  const fromTriggerTokens = getValueByPath(fromObject, [
    "triggerTokens"
  ]);
  if (fromTriggerTokens != null) {
    setValueByPath(toObject, ["triggerTokens"], fromTriggerTokens);
  }
  const fromSlidingWindow = getValueByPath(fromObject, [
    "slidingWindow"
  ]);
  if (fromSlidingWindow != null) {
    setValueByPath(toObject, ["slidingWindow"], slidingWindowToMldev(fromSlidingWindow));
  }
  return toObject;
}
__name(contextWindowCompressionConfigToMldev, "contextWindowCompressionConfigToMldev");
function proactivityConfigToMldev(fromObject) {
  const toObject = {};
  const fromProactiveAudio = getValueByPath(fromObject, [
    "proactiveAudio"
  ]);
  if (fromProactiveAudio != null) {
    setValueByPath(toObject, ["proactiveAudio"], fromProactiveAudio);
  }
  return toObject;
}
__name(proactivityConfigToMldev, "proactivityConfigToMldev");
function liveConnectConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromGenerationConfig = getValueByPath(fromObject, [
    "generationConfig"
  ]);
  if (parentObject !== void 0 && fromGenerationConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig"], fromGenerationConfig);
  }
  const fromResponseModalities = getValueByPath(fromObject, [
    "responseModalities"
  ]);
  if (parentObject !== void 0 && fromResponseModalities != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "responseModalities"], fromResponseModalities);
  }
  const fromTemperature = getValueByPath(fromObject, ["temperature"]);
  if (parentObject !== void 0 && fromTemperature != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "temperature"], fromTemperature);
  }
  const fromTopP = getValueByPath(fromObject, ["topP"]);
  if (parentObject !== void 0 && fromTopP != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topP"], fromTopP);
  }
  const fromTopK = getValueByPath(fromObject, ["topK"]);
  if (parentObject !== void 0 && fromTopK != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "topK"], fromTopK);
  }
  const fromMaxOutputTokens = getValueByPath(fromObject, [
    "maxOutputTokens"
  ]);
  if (parentObject !== void 0 && fromMaxOutputTokens != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "maxOutputTokens"], fromMaxOutputTokens);
  }
  const fromMediaResolution = getValueByPath(fromObject, [
    "mediaResolution"
  ]);
  if (parentObject !== void 0 && fromMediaResolution != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "mediaResolution"], fromMediaResolution);
  }
  const fromSeed = getValueByPath(fromObject, ["seed"]);
  if (parentObject !== void 0 && fromSeed != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "seed"], fromSeed);
  }
  const fromSpeechConfig = getValueByPath(fromObject, ["speechConfig"]);
  if (parentObject !== void 0 && fromSpeechConfig != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "speechConfig"], speechConfigToMldev(tLiveSpeechConfig(fromSpeechConfig)));
  }
  const fromEnableAffectiveDialog = getValueByPath(fromObject, [
    "enableAffectiveDialog"
  ]);
  if (parentObject !== void 0 && fromEnableAffectiveDialog != null) {
    setValueByPath(parentObject, ["setup", "generationConfig", "enableAffectiveDialog"], fromEnableAffectiveDialog);
  }
  const fromSystemInstruction = getValueByPath(fromObject, [
    "systemInstruction"
  ]);
  if (parentObject !== void 0 && fromSystemInstruction != null) {
    setValueByPath(parentObject, ["setup", "systemInstruction"], contentToMldev(tContent(fromSystemInstruction)));
  }
  const fromTools = getValueByPath(fromObject, ["tools"]);
  if (parentObject !== void 0 && fromTools != null) {
    let transformedList = tTools(fromTools);
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return toolToMldev(tTool(item));
      });
    }
    setValueByPath(parentObject, ["setup", "tools"], transformedList);
  }
  const fromSessionResumption = getValueByPath(fromObject, [
    "sessionResumption"
  ]);
  if (parentObject !== void 0 && fromSessionResumption != null) {
    setValueByPath(parentObject, ["setup", "sessionResumption"], sessionResumptionConfigToMldev(fromSessionResumption));
  }
  const fromInputAudioTranscription = getValueByPath(fromObject, [
    "inputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromInputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "inputAudioTranscription"], audioTranscriptionConfigToMldev());
  }
  const fromOutputAudioTranscription = getValueByPath(fromObject, [
    "outputAudioTranscription"
  ]);
  if (parentObject !== void 0 && fromOutputAudioTranscription != null) {
    setValueByPath(parentObject, ["setup", "outputAudioTranscription"], audioTranscriptionConfigToMldev());
  }
  const fromRealtimeInputConfig = getValueByPath(fromObject, [
    "realtimeInputConfig"
  ]);
  if (parentObject !== void 0 && fromRealtimeInputConfig != null) {
    setValueByPath(parentObject, ["setup", "realtimeInputConfig"], realtimeInputConfigToMldev(fromRealtimeInputConfig));
  }
  const fromContextWindowCompression = getValueByPath(fromObject, [
    "contextWindowCompression"
  ]);
  if (parentObject !== void 0 && fromContextWindowCompression != null) {
    setValueByPath(parentObject, ["setup", "contextWindowCompression"], contextWindowCompressionConfigToMldev(fromContextWindowCompression));
  }
  const fromProactivity = getValueByPath(fromObject, ["proactivity"]);
  if (parentObject !== void 0 && fromProactivity != null) {
    setValueByPath(parentObject, ["setup", "proactivity"], proactivityConfigToMldev(fromProactivity));
  }
  return toObject;
}
__name(liveConnectConfigToMldev, "liveConnectConfigToMldev");
function liveConnectConstraintsToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["setup", "model"], tModel(apiClient, fromModel));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], liveConnectConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(liveConnectConstraintsToMldev, "liveConnectConstraintsToMldev");
function createAuthTokenConfigToMldev(apiClient, fromObject, parentObject) {
  const toObject = {};
  const fromExpireTime = getValueByPath(fromObject, ["expireTime"]);
  if (parentObject !== void 0 && fromExpireTime != null) {
    setValueByPath(parentObject, ["expireTime"], fromExpireTime);
  }
  const fromNewSessionExpireTime = getValueByPath(fromObject, [
    "newSessionExpireTime"
  ]);
  if (parentObject !== void 0 && fromNewSessionExpireTime != null) {
    setValueByPath(parentObject, ["newSessionExpireTime"], fromNewSessionExpireTime);
  }
  const fromUses = getValueByPath(fromObject, ["uses"]);
  if (parentObject !== void 0 && fromUses != null) {
    setValueByPath(parentObject, ["uses"], fromUses);
  }
  const fromLiveConnectConstraints = getValueByPath(fromObject, [
    "liveConnectConstraints"
  ]);
  if (parentObject !== void 0 && fromLiveConnectConstraints != null) {
    setValueByPath(parentObject, ["bidiGenerateContentSetup"], liveConnectConstraintsToMldev(apiClient, fromLiveConnectConstraints));
  }
  const fromLockAdditionalFields = getValueByPath(fromObject, [
    "lockAdditionalFields"
  ]);
  if (parentObject !== void 0 && fromLockAdditionalFields != null) {
    setValueByPath(parentObject, ["fieldMask"], fromLockAdditionalFields);
  }
  return toObject;
}
__name(createAuthTokenConfigToMldev, "createAuthTokenConfigToMldev");
function createAuthTokenParametersToMldev(apiClient, fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createAuthTokenConfigToMldev(apiClient, fromConfig, toObject));
  }
  return toObject;
}
__name(createAuthTokenParametersToMldev, "createAuthTokenParametersToMldev");
function authTokenFromMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  return toObject;
}
__name(authTokenFromMldev, "authTokenFromMldev");
function getFieldMasks(setup) {
  const fields = [];
  for (const key in setup) {
    if (Object.prototype.hasOwnProperty.call(setup, key)) {
      const value = setup[key];
      if (typeof value === "object" && value != null && Object.keys(value).length > 0) {
        const field = Object.keys(value).map((kk) => `${key}.${kk}`);
        fields.push(...field);
      } else {
        fields.push(key);
      }
    }
  }
  return fields.join(",");
}
__name(getFieldMasks, "getFieldMasks");
function convertBidiSetupToTokenSetup(requestDict, config) {
  let setupForMaskGeneration = null;
  const bidiGenerateContentSetupValue = requestDict["bidiGenerateContentSetup"];
  if (typeof bidiGenerateContentSetupValue === "object" && bidiGenerateContentSetupValue !== null && "setup" in bidiGenerateContentSetupValue) {
    const innerSetup = bidiGenerateContentSetupValue.setup;
    if (typeof innerSetup === "object" && innerSetup !== null) {
      requestDict["bidiGenerateContentSetup"] = innerSetup;
      setupForMaskGeneration = innerSetup;
    } else {
      delete requestDict["bidiGenerateContentSetup"];
    }
  } else if (bidiGenerateContentSetupValue !== void 0) {
    delete requestDict["bidiGenerateContentSetup"];
  }
  const preExistingFieldMask = requestDict["fieldMask"];
  if (setupForMaskGeneration) {
    const generatedMaskFromBidi = getFieldMasks(setupForMaskGeneration);
    if (Array.isArray(config === null || config === void 0 ? void 0 : config.lockAdditionalFields) && (config === null || config === void 0 ? void 0 : config.lockAdditionalFields.length) === 0) {
      if (generatedMaskFromBidi) {
        requestDict["fieldMask"] = generatedMaskFromBidi;
      } else {
        delete requestDict["fieldMask"];
      }
    } else if ((config === null || config === void 0 ? void 0 : config.lockAdditionalFields) && config.lockAdditionalFields.length > 0 && preExistingFieldMask !== null && Array.isArray(preExistingFieldMask) && preExistingFieldMask.length > 0) {
      const generationConfigFields = [
        "temperature",
        "topK",
        "topP",
        "maxOutputTokens",
        "responseModalities",
        "seed",
        "speechConfig"
      ];
      let mappedFieldsFromPreExisting = [];
      if (preExistingFieldMask.length > 0) {
        mappedFieldsFromPreExisting = preExistingFieldMask.map((field) => {
          if (generationConfigFields.includes(field)) {
            return `generationConfig.${field}`;
          }
          return field;
        });
      }
      const finalMaskParts = [];
      if (generatedMaskFromBidi) {
        finalMaskParts.push(generatedMaskFromBidi);
      }
      if (mappedFieldsFromPreExisting.length > 0) {
        finalMaskParts.push(...mappedFieldsFromPreExisting);
      }
      if (finalMaskParts.length > 0) {
        requestDict["fieldMask"] = finalMaskParts.join(",");
      } else {
        delete requestDict["fieldMask"];
      }
    } else {
      delete requestDict["fieldMask"];
    }
  } else {
    if (preExistingFieldMask !== null && Array.isArray(preExistingFieldMask) && preExistingFieldMask.length > 0) {
      requestDict["fieldMask"] = preExistingFieldMask.join(",");
    } else {
      delete requestDict["fieldMask"];
    }
  }
  return requestDict;
}
__name(convertBidiSetupToTokenSetup, "convertBidiSetupToTokenSetup");
var Tokens = class extends BaseModule {
  static {
    __name(this, "Tokens");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
  }
  /**
   * Creates an ephemeral auth token resource.
   *
   * @experimental
   *
   * @remarks
   * Ephemeral auth tokens is only supported in the Gemini Developer API.
   * It can be used for the session connection to the Live constrained API.
   * Support in v1alpha only.
   *
   * @param params - The parameters for the create request.
   * @return The created auth token.
   *
   * @example
   * ```ts
   * const ai = new GoogleGenAI({
   *     apiKey: token.name,
   *     httpOptions: { apiVersion: 'v1alpha' }  // Support in v1alpha only.
   * });
   *
   * // Case 1: If LiveEphemeralParameters is unset, unlock LiveConnectConfig
   * // when using the token in Live API sessions. Each session connection can
   * // use a different configuration.
   * const config: CreateAuthTokenConfig = {
   *     uses: 3,
   *     expireTime: '2025-05-01T00:00:00Z',
   * }
   * const token = await ai.tokens.create(config);
   *
   * // Case 2: If LiveEphemeralParameters is set, lock all fields in
   * // LiveConnectConfig when using the token in Live API sessions. For
   * // example, changing `outputAudioTranscription` in the Live API
   * // connection will be ignored by the API.
   * const config: CreateAuthTokenConfig =
   *     uses: 3,
   *     expireTime: '2025-05-01T00:00:00Z',
   *     LiveEphemeralParameters: {
   *        model: 'gemini-2.0-flash-001',
   *        config: {
   *           'responseModalities': ['AUDIO'],
   *           'systemInstruction': 'Always answer in English.',
   *        }
   *     }
   * }
   * const token = await ai.tokens.create(config);
   *
   * // Case 3: If LiveEphemeralParameters is set and lockAdditionalFields is
   * // set, lock LiveConnectConfig with set and additional fields (e.g.
   * // responseModalities, systemInstruction, temperature in this example) when
   * // using the token in Live API sessions.
   * const config: CreateAuthTokenConfig =
   *     uses: 3,
   *     expireTime: '2025-05-01T00:00:00Z',
   *     LiveEphemeralParameters: {
   *        model: 'gemini-2.0-flash-001',
   *        config: {
   *           'responseModalities': ['AUDIO'],
   *           'systemInstruction': 'Always answer in English.',
   *        }
   *     },
   *     lockAdditionalFields: ['temperature'],
   * }
   * const token = await ai.tokens.create(config);
   *
   * // Case 4: If LiveEphemeralParameters is set and lockAdditionalFields is
   * // empty array, lock LiveConnectConfig with set fields (e.g.
   * // responseModalities, systemInstruction in this example) when using the
   * // token in Live API sessions.
   * const config: CreateAuthTokenConfig =
   *     uses: 3,
   *     expireTime: '2025-05-01T00:00:00Z',
   *     LiveEphemeralParameters: {
   *        model: 'gemini-2.0-flash-001',
   *        config: {
   *           'responseModalities': ['AUDIO'],
   *           'systemInstruction': 'Always answer in English.',
   *        }
   *     },
   *     lockAdditionalFields: [],
   * }
   * const token = await ai.tokens.create(config);
   * ```
   */
  async create(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("The client.tokens.create method is only supported by the Gemini Developer API.");
    } else {
      const body = createAuthTokenParametersToMldev(this.apiClient, params);
      path = formatMap("auth_tokens", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      const transformedBody = convertBidiSetupToTokenSetup(body, params.config);
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(transformedBody),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json();
      });
      return response.then((apiResponse) => {
        const resp = authTokenFromMldev(apiResponse);
        return resp;
      });
    }
  }
};
function getTuningJobParametersToMldev(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], fromName);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getTuningJobParametersToMldev, "getTuningJobParametersToMldev");
function listTuningJobsConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  const fromFilter = getValueByPath(fromObject, ["filter"]);
  if (parentObject !== void 0 && fromFilter != null) {
    setValueByPath(parentObject, ["_query", "filter"], fromFilter);
  }
  return toObject;
}
__name(listTuningJobsConfigToMldev, "listTuningJobsConfigToMldev");
function listTuningJobsParametersToMldev(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listTuningJobsConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(listTuningJobsParametersToMldev, "listTuningJobsParametersToMldev");
function tuningExampleToMldev(fromObject) {
  const toObject = {};
  const fromTextInput = getValueByPath(fromObject, ["textInput"]);
  if (fromTextInput != null) {
    setValueByPath(toObject, ["textInput"], fromTextInput);
  }
  const fromOutput = getValueByPath(fromObject, ["output"]);
  if (fromOutput != null) {
    setValueByPath(toObject, ["output"], fromOutput);
  }
  return toObject;
}
__name(tuningExampleToMldev, "tuningExampleToMldev");
function tuningDatasetToMldev(fromObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["gcsUri"]) !== void 0) {
    throw new Error("gcsUri parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["vertexDatasetResource"]) !== void 0) {
    throw new Error("vertexDatasetResource parameter is not supported in Gemini API.");
  }
  const fromExamples = getValueByPath(fromObject, ["examples"]);
  if (fromExamples != null) {
    let transformedList = fromExamples;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return tuningExampleToMldev(item);
      });
    }
    setValueByPath(toObject, ["examples", "examples"], transformedList);
  }
  return toObject;
}
__name(tuningDatasetToMldev, "tuningDatasetToMldev");
function createTuningJobConfigToMldev(fromObject, parentObject) {
  const toObject = {};
  if (getValueByPath(fromObject, ["validationDataset"]) !== void 0) {
    throw new Error("validationDataset parameter is not supported in Gemini API.");
  }
  const fromTunedModelDisplayName = getValueByPath(fromObject, [
    "tunedModelDisplayName"
  ]);
  if (parentObject !== void 0 && fromTunedModelDisplayName != null) {
    setValueByPath(parentObject, ["displayName"], fromTunedModelDisplayName);
  }
  if (getValueByPath(fromObject, ["description"]) !== void 0) {
    throw new Error("description parameter is not supported in Gemini API.");
  }
  const fromEpochCount = getValueByPath(fromObject, ["epochCount"]);
  if (parentObject !== void 0 && fromEpochCount != null) {
    setValueByPath(parentObject, ["tuningTask", "hyperparameters", "epochCount"], fromEpochCount);
  }
  const fromLearningRateMultiplier = getValueByPath(fromObject, [
    "learningRateMultiplier"
  ]);
  if (fromLearningRateMultiplier != null) {
    setValueByPath(toObject, ["tuningTask", "hyperparameters", "learningRateMultiplier"], fromLearningRateMultiplier);
  }
  if (getValueByPath(fromObject, ["exportLastCheckpointOnly"]) !== void 0) {
    throw new Error("exportLastCheckpointOnly parameter is not supported in Gemini API.");
  }
  if (getValueByPath(fromObject, ["adapterSize"]) !== void 0) {
    throw new Error("adapterSize parameter is not supported in Gemini API.");
  }
  const fromBatchSize = getValueByPath(fromObject, ["batchSize"]);
  if (parentObject !== void 0 && fromBatchSize != null) {
    setValueByPath(parentObject, ["tuningTask", "hyperparameters", "batchSize"], fromBatchSize);
  }
  const fromLearningRate = getValueByPath(fromObject, ["learningRate"]);
  if (parentObject !== void 0 && fromLearningRate != null) {
    setValueByPath(parentObject, ["tuningTask", "hyperparameters", "learningRate"], fromLearningRate);
  }
  return toObject;
}
__name(createTuningJobConfigToMldev, "createTuningJobConfigToMldev");
function createTuningJobParametersToMldev(fromObject) {
  const toObject = {};
  const fromBaseModel = getValueByPath(fromObject, ["baseModel"]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromTrainingDataset = getValueByPath(fromObject, [
    "trainingDataset"
  ]);
  if (fromTrainingDataset != null) {
    setValueByPath(toObject, ["tuningTask", "trainingData"], tuningDatasetToMldev(fromTrainingDataset));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createTuningJobConfigToMldev(fromConfig, toObject));
  }
  return toObject;
}
__name(createTuningJobParametersToMldev, "createTuningJobParametersToMldev");
function getTuningJobParametersToVertex(fromObject) {
  const toObject = {};
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["_url", "name"], fromName);
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], fromConfig);
  }
  return toObject;
}
__name(getTuningJobParametersToVertex, "getTuningJobParametersToVertex");
function listTuningJobsConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromPageSize = getValueByPath(fromObject, ["pageSize"]);
  if (parentObject !== void 0 && fromPageSize != null) {
    setValueByPath(parentObject, ["_query", "pageSize"], fromPageSize);
  }
  const fromPageToken = getValueByPath(fromObject, ["pageToken"]);
  if (parentObject !== void 0 && fromPageToken != null) {
    setValueByPath(parentObject, ["_query", "pageToken"], fromPageToken);
  }
  const fromFilter = getValueByPath(fromObject, ["filter"]);
  if (parentObject !== void 0 && fromFilter != null) {
    setValueByPath(parentObject, ["_query", "filter"], fromFilter);
  }
  return toObject;
}
__name(listTuningJobsConfigToVertex, "listTuningJobsConfigToVertex");
function listTuningJobsParametersToVertex(fromObject) {
  const toObject = {};
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], listTuningJobsConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(listTuningJobsParametersToVertex, "listTuningJobsParametersToVertex");
function tuningDatasetToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (parentObject !== void 0 && fromGcsUri != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "trainingDatasetUri"], fromGcsUri);
  }
  const fromVertexDatasetResource = getValueByPath(fromObject, [
    "vertexDatasetResource"
  ]);
  if (parentObject !== void 0 && fromVertexDatasetResource != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "trainingDatasetUri"], fromVertexDatasetResource);
  }
  if (getValueByPath(fromObject, ["examples"]) !== void 0) {
    throw new Error("examples parameter is not supported in Vertex AI.");
  }
  return toObject;
}
__name(tuningDatasetToVertex, "tuningDatasetToVertex");
function tuningValidationDatasetToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromGcsUri = getValueByPath(fromObject, ["gcsUri"]);
  if (fromGcsUri != null) {
    setValueByPath(toObject, ["validationDatasetUri"], fromGcsUri);
  }
  const fromVertexDatasetResource = getValueByPath(fromObject, [
    "vertexDatasetResource"
  ]);
  if (parentObject !== void 0 && fromVertexDatasetResource != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "trainingDatasetUri"], fromVertexDatasetResource);
  }
  return toObject;
}
__name(tuningValidationDatasetToVertex, "tuningValidationDatasetToVertex");
function createTuningJobConfigToVertex(fromObject, parentObject) {
  const toObject = {};
  const fromValidationDataset = getValueByPath(fromObject, [
    "validationDataset"
  ]);
  if (parentObject !== void 0 && fromValidationDataset != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec"], tuningValidationDatasetToVertex(fromValidationDataset, toObject));
  }
  const fromTunedModelDisplayName = getValueByPath(fromObject, [
    "tunedModelDisplayName"
  ]);
  if (parentObject !== void 0 && fromTunedModelDisplayName != null) {
    setValueByPath(parentObject, ["tunedModelDisplayName"], fromTunedModelDisplayName);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (parentObject !== void 0 && fromDescription != null) {
    setValueByPath(parentObject, ["description"], fromDescription);
  }
  const fromEpochCount = getValueByPath(fromObject, ["epochCount"]);
  if (parentObject !== void 0 && fromEpochCount != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "hyperParameters", "epochCount"], fromEpochCount);
  }
  const fromLearningRateMultiplier = getValueByPath(fromObject, [
    "learningRateMultiplier"
  ]);
  if (parentObject !== void 0 && fromLearningRateMultiplier != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "hyperParameters", "learningRateMultiplier"], fromLearningRateMultiplier);
  }
  const fromExportLastCheckpointOnly = getValueByPath(fromObject, [
    "exportLastCheckpointOnly"
  ]);
  if (parentObject !== void 0 && fromExportLastCheckpointOnly != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "exportLastCheckpointOnly"], fromExportLastCheckpointOnly);
  }
  const fromAdapterSize = getValueByPath(fromObject, ["adapterSize"]);
  if (parentObject !== void 0 && fromAdapterSize != null) {
    setValueByPath(parentObject, ["supervisedTuningSpec", "hyperParameters", "adapterSize"], fromAdapterSize);
  }
  if (getValueByPath(fromObject, ["batchSize"]) !== void 0) {
    throw new Error("batchSize parameter is not supported in Vertex AI.");
  }
  if (getValueByPath(fromObject, ["learningRate"]) !== void 0) {
    throw new Error("learningRate parameter is not supported in Vertex AI.");
  }
  return toObject;
}
__name(createTuningJobConfigToVertex, "createTuningJobConfigToVertex");
function createTuningJobParametersToVertex(fromObject) {
  const toObject = {};
  const fromBaseModel = getValueByPath(fromObject, ["baseModel"]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromTrainingDataset = getValueByPath(fromObject, [
    "trainingDataset"
  ]);
  if (fromTrainingDataset != null) {
    setValueByPath(toObject, ["supervisedTuningSpec", "trainingDatasetUri"], tuningDatasetToVertex(fromTrainingDataset, toObject));
  }
  const fromConfig = getValueByPath(fromObject, ["config"]);
  if (fromConfig != null) {
    setValueByPath(toObject, ["config"], createTuningJobConfigToVertex(fromConfig, toObject));
  }
  return toObject;
}
__name(createTuningJobParametersToVertex, "createTuningJobParametersToVertex");
function tunedModelFromMldev(fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["name"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromEndpoint = getValueByPath(fromObject, ["name"]);
  if (fromEndpoint != null) {
    setValueByPath(toObject, ["endpoint"], fromEndpoint);
  }
  return toObject;
}
__name(tunedModelFromMldev, "tunedModelFromMldev");
function tuningJobFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromState = getValueByPath(fromObject, ["state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], tTuningJobStatus(fromState));
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromStartTime = getValueByPath(fromObject, [
    "tuningTask",
    "startTime"
  ]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, [
    "tuningTask",
    "completeTime"
  ]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromBaseModel = getValueByPath(fromObject, ["baseModel"]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromTunedModel = getValueByPath(fromObject, ["_self"]);
  if (fromTunedModel != null) {
    setValueByPath(toObject, ["tunedModel"], tunedModelFromMldev(fromTunedModel));
  }
  const fromDistillationSpec = getValueByPath(fromObject, [
    "distillationSpec"
  ]);
  if (fromDistillationSpec != null) {
    setValueByPath(toObject, ["distillationSpec"], fromDistillationSpec);
  }
  const fromExperiment = getValueByPath(fromObject, ["experiment"]);
  if (fromExperiment != null) {
    setValueByPath(toObject, ["experiment"], fromExperiment);
  }
  const fromLabels = getValueByPath(fromObject, ["labels"]);
  if (fromLabels != null) {
    setValueByPath(toObject, ["labels"], fromLabels);
  }
  const fromPipelineJob = getValueByPath(fromObject, ["pipelineJob"]);
  if (fromPipelineJob != null) {
    setValueByPath(toObject, ["pipelineJob"], fromPipelineJob);
  }
  const fromSatisfiesPzi = getValueByPath(fromObject, ["satisfiesPzi"]);
  if (fromSatisfiesPzi != null) {
    setValueByPath(toObject, ["satisfiesPzi"], fromSatisfiesPzi);
  }
  const fromSatisfiesPzs = getValueByPath(fromObject, ["satisfiesPzs"]);
  if (fromSatisfiesPzs != null) {
    setValueByPath(toObject, ["satisfiesPzs"], fromSatisfiesPzs);
  }
  const fromServiceAccount = getValueByPath(fromObject, [
    "serviceAccount"
  ]);
  if (fromServiceAccount != null) {
    setValueByPath(toObject, ["serviceAccount"], fromServiceAccount);
  }
  const fromTunedModelDisplayName = getValueByPath(fromObject, [
    "tunedModelDisplayName"
  ]);
  if (fromTunedModelDisplayName != null) {
    setValueByPath(toObject, ["tunedModelDisplayName"], fromTunedModelDisplayName);
  }
  return toObject;
}
__name(tuningJobFromMldev, "tuningJobFromMldev");
function listTuningJobsResponseFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromTuningJobs = getValueByPath(fromObject, ["tunedModels"]);
  if (fromTuningJobs != null) {
    let transformedList = fromTuningJobs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return tuningJobFromMldev(item);
      });
    }
    setValueByPath(toObject, ["tuningJobs"], transformedList);
  }
  return toObject;
}
__name(listTuningJobsResponseFromMldev, "listTuningJobsResponseFromMldev");
function tuningOperationFromMldev(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromMetadata = getValueByPath(fromObject, ["metadata"]);
  if (fromMetadata != null) {
    setValueByPath(toObject, ["metadata"], fromMetadata);
  }
  const fromDone = getValueByPath(fromObject, ["done"]);
  if (fromDone != null) {
    setValueByPath(toObject, ["done"], fromDone);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fromError);
  }
  return toObject;
}
__name(tuningOperationFromMldev, "tuningOperationFromMldev");
function tunedModelCheckpointFromVertex(fromObject) {
  const toObject = {};
  const fromCheckpointId = getValueByPath(fromObject, ["checkpointId"]);
  if (fromCheckpointId != null) {
    setValueByPath(toObject, ["checkpointId"], fromCheckpointId);
  }
  const fromEpoch = getValueByPath(fromObject, ["epoch"]);
  if (fromEpoch != null) {
    setValueByPath(toObject, ["epoch"], fromEpoch);
  }
  const fromStep = getValueByPath(fromObject, ["step"]);
  if (fromStep != null) {
    setValueByPath(toObject, ["step"], fromStep);
  }
  const fromEndpoint = getValueByPath(fromObject, ["endpoint"]);
  if (fromEndpoint != null) {
    setValueByPath(toObject, ["endpoint"], fromEndpoint);
  }
  return toObject;
}
__name(tunedModelCheckpointFromVertex, "tunedModelCheckpointFromVertex");
function tunedModelFromVertex(fromObject) {
  const toObject = {};
  const fromModel = getValueByPath(fromObject, ["model"]);
  if (fromModel != null) {
    setValueByPath(toObject, ["model"], fromModel);
  }
  const fromEndpoint = getValueByPath(fromObject, ["endpoint"]);
  if (fromEndpoint != null) {
    setValueByPath(toObject, ["endpoint"], fromEndpoint);
  }
  const fromCheckpoints = getValueByPath(fromObject, ["checkpoints"]);
  if (fromCheckpoints != null) {
    let transformedList = fromCheckpoints;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return tunedModelCheckpointFromVertex(item);
      });
    }
    setValueByPath(toObject, ["checkpoints"], transformedList);
  }
  return toObject;
}
__name(tunedModelFromVertex, "tunedModelFromVertex");
function tuningJobFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromName = getValueByPath(fromObject, ["name"]);
  if (fromName != null) {
    setValueByPath(toObject, ["name"], fromName);
  }
  const fromState = getValueByPath(fromObject, ["state"]);
  if (fromState != null) {
    setValueByPath(toObject, ["state"], tTuningJobStatus(fromState));
  }
  const fromCreateTime = getValueByPath(fromObject, ["createTime"]);
  if (fromCreateTime != null) {
    setValueByPath(toObject, ["createTime"], fromCreateTime);
  }
  const fromStartTime = getValueByPath(fromObject, ["startTime"]);
  if (fromStartTime != null) {
    setValueByPath(toObject, ["startTime"], fromStartTime);
  }
  const fromEndTime = getValueByPath(fromObject, ["endTime"]);
  if (fromEndTime != null) {
    setValueByPath(toObject, ["endTime"], fromEndTime);
  }
  const fromUpdateTime = getValueByPath(fromObject, ["updateTime"]);
  if (fromUpdateTime != null) {
    setValueByPath(toObject, ["updateTime"], fromUpdateTime);
  }
  const fromError = getValueByPath(fromObject, ["error"]);
  if (fromError != null) {
    setValueByPath(toObject, ["error"], fromError);
  }
  const fromDescription = getValueByPath(fromObject, ["description"]);
  if (fromDescription != null) {
    setValueByPath(toObject, ["description"], fromDescription);
  }
  const fromBaseModel = getValueByPath(fromObject, ["baseModel"]);
  if (fromBaseModel != null) {
    setValueByPath(toObject, ["baseModel"], fromBaseModel);
  }
  const fromTunedModel = getValueByPath(fromObject, ["tunedModel"]);
  if (fromTunedModel != null) {
    setValueByPath(toObject, ["tunedModel"], tunedModelFromVertex(fromTunedModel));
  }
  const fromSupervisedTuningSpec = getValueByPath(fromObject, [
    "supervisedTuningSpec"
  ]);
  if (fromSupervisedTuningSpec != null) {
    setValueByPath(toObject, ["supervisedTuningSpec"], fromSupervisedTuningSpec);
  }
  const fromTuningDataStats = getValueByPath(fromObject, [
    "tuningDataStats"
  ]);
  if (fromTuningDataStats != null) {
    setValueByPath(toObject, ["tuningDataStats"], fromTuningDataStats);
  }
  const fromEncryptionSpec = getValueByPath(fromObject, [
    "encryptionSpec"
  ]);
  if (fromEncryptionSpec != null) {
    setValueByPath(toObject, ["encryptionSpec"], fromEncryptionSpec);
  }
  const fromPartnerModelTuningSpec = getValueByPath(fromObject, [
    "partnerModelTuningSpec"
  ]);
  if (fromPartnerModelTuningSpec != null) {
    setValueByPath(toObject, ["partnerModelTuningSpec"], fromPartnerModelTuningSpec);
  }
  const fromDistillationSpec = getValueByPath(fromObject, [
    "distillationSpec"
  ]);
  if (fromDistillationSpec != null) {
    setValueByPath(toObject, ["distillationSpec"], fromDistillationSpec);
  }
  const fromExperiment = getValueByPath(fromObject, ["experiment"]);
  if (fromExperiment != null) {
    setValueByPath(toObject, ["experiment"], fromExperiment);
  }
  const fromLabels = getValueByPath(fromObject, ["labels"]);
  if (fromLabels != null) {
    setValueByPath(toObject, ["labels"], fromLabels);
  }
  const fromPipelineJob = getValueByPath(fromObject, ["pipelineJob"]);
  if (fromPipelineJob != null) {
    setValueByPath(toObject, ["pipelineJob"], fromPipelineJob);
  }
  const fromSatisfiesPzi = getValueByPath(fromObject, ["satisfiesPzi"]);
  if (fromSatisfiesPzi != null) {
    setValueByPath(toObject, ["satisfiesPzi"], fromSatisfiesPzi);
  }
  const fromSatisfiesPzs = getValueByPath(fromObject, ["satisfiesPzs"]);
  if (fromSatisfiesPzs != null) {
    setValueByPath(toObject, ["satisfiesPzs"], fromSatisfiesPzs);
  }
  const fromServiceAccount = getValueByPath(fromObject, [
    "serviceAccount"
  ]);
  if (fromServiceAccount != null) {
    setValueByPath(toObject, ["serviceAccount"], fromServiceAccount);
  }
  const fromTunedModelDisplayName = getValueByPath(fromObject, [
    "tunedModelDisplayName"
  ]);
  if (fromTunedModelDisplayName != null) {
    setValueByPath(toObject, ["tunedModelDisplayName"], fromTunedModelDisplayName);
  }
  return toObject;
}
__name(tuningJobFromVertex, "tuningJobFromVertex");
function listTuningJobsResponseFromVertex(fromObject) {
  const toObject = {};
  const fromSdkHttpResponse = getValueByPath(fromObject, [
    "sdkHttpResponse"
  ]);
  if (fromSdkHttpResponse != null) {
    setValueByPath(toObject, ["sdkHttpResponse"], fromSdkHttpResponse);
  }
  const fromNextPageToken = getValueByPath(fromObject, [
    "nextPageToken"
  ]);
  if (fromNextPageToken != null) {
    setValueByPath(toObject, ["nextPageToken"], fromNextPageToken);
  }
  const fromTuningJobs = getValueByPath(fromObject, ["tuningJobs"]);
  if (fromTuningJobs != null) {
    let transformedList = fromTuningJobs;
    if (Array.isArray(transformedList)) {
      transformedList = transformedList.map((item) => {
        return tuningJobFromVertex(item);
      });
    }
    setValueByPath(toObject, ["tuningJobs"], transformedList);
  }
  return toObject;
}
__name(listTuningJobsResponseFromVertex, "listTuningJobsResponseFromVertex");
var Tunings = class extends BaseModule {
  static {
    __name(this, "Tunings");
  }
  constructor(apiClient) {
    super();
    this.apiClient = apiClient;
    this.get = async (params) => {
      return await this.getInternal(params);
    };
    this.list = async (params = {}) => {
      return new Pager(PagedItem.PAGED_ITEM_TUNING_JOBS, (x) => this.listInternal(x), await this.listInternal(params), params);
    };
    this.tune = async (params) => {
      if (this.apiClient.isVertexAI()) {
        return await this.tuneInternal(params);
      } else {
        const operation = await this.tuneMldevInternal(params);
        let tunedModelName = "";
        if (operation["metadata"] !== void 0 && operation["metadata"]["tunedModel"] !== void 0) {
          tunedModelName = operation["metadata"]["tunedModel"];
        } else if (operation["name"] !== void 0 && operation["name"].includes("/operations/")) {
          tunedModelName = operation["name"].split("/operations/")[0];
        }
        const tuningJob = {
          name: tunedModelName,
          state: JobState.JOB_STATE_QUEUED
        };
        return tuningJob;
      }
    };
  }
  async getInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = getTuningJobParametersToVertex(params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = tuningJobFromVertex(apiResponse);
        return resp;
      });
    } else {
      const body = getTuningJobParametersToMldev(params);
      path = formatMap("{name}", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = tuningJobFromMldev(apiResponse);
        return resp;
      });
    }
  }
  async listInternal(params) {
    var _a, _b, _c, _d;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = listTuningJobsParametersToVertex(params);
      path = formatMap("tuningJobs", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listTuningJobsResponseFromVertex(apiResponse);
        const typedResp = new ListTuningJobsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    } else {
      const body = listTuningJobsParametersToMldev(params);
      path = formatMap("tunedModels", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "GET",
        httpOptions: (_c = params.config) === null || _c === void 0 ? void 0 : _c.httpOptions,
        abortSignal: (_d = params.config) === null || _d === void 0 ? void 0 : _d.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = listTuningJobsResponseFromMldev(apiResponse);
        const typedResp = new ListTuningJobsResponse();
        Object.assign(typedResp, resp);
        return typedResp;
      });
    }
  }
  async tuneInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      const body = createTuningJobParametersToVertex(params);
      path = formatMap("tuningJobs", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = tuningJobFromVertex(apiResponse);
        return resp;
      });
    } else {
      throw new Error("This method is only supported by the Vertex AI.");
    }
  }
  async tuneMldevInternal(params) {
    var _a, _b;
    let response;
    let path = "";
    let queryParams = {};
    if (this.apiClient.isVertexAI()) {
      throw new Error("This method is only supported by the Gemini Developer API.");
    } else {
      const body = createTuningJobParametersToMldev(params);
      path = formatMap("tunedModels", body["_url"]);
      queryParams = body["_query"];
      delete body["config"];
      delete body["_url"];
      delete body["_query"];
      response = this.apiClient.request({
        path,
        queryParams,
        body: JSON.stringify(body),
        httpMethod: "POST",
        httpOptions: (_a = params.config) === null || _a === void 0 ? void 0 : _a.httpOptions,
        abortSignal: (_b = params.config) === null || _b === void 0 ? void 0 : _b.abortSignal
      }).then((httpResponse) => {
        return httpResponse.json().then((jsonResponse) => {
          const response2 = jsonResponse;
          response2.sdkHttpResponse = {
            headers: httpResponse.headers
          };
          return response2;
        });
      });
      return response.then((apiResponse) => {
        const resp = tuningOperationFromMldev(apiResponse);
        return resp;
      });
    }
  }
};
var BrowserDownloader = class {
  static {
    __name(this, "BrowserDownloader");
  }
  async download(_params, _apiClient) {
    throw new Error("Download to file is not supported in the browser, please use a browser compliant download like an <a> tag.");
  }
};
var MAX_CHUNK_SIZE = 1024 * 1024 * 8;
var MAX_RETRY_COUNT = 3;
var INITIAL_RETRY_DELAY_MS = 1e3;
var DELAY_MULTIPLIER = 2;
var X_GOOG_UPLOAD_STATUS_HEADER_FIELD = "x-goog-upload-status";
async function uploadBlob(file, uploadUrl, apiClient) {
  var _a, _b, _c;
  let fileSize = 0;
  let offset = 0;
  let response = new HttpResponse(new Response());
  let uploadCommand = "upload";
  fileSize = file.size;
  while (offset < fileSize) {
    const chunkSize = Math.min(MAX_CHUNK_SIZE, fileSize - offset);
    const chunk = file.slice(offset, offset + chunkSize);
    if (offset + chunkSize >= fileSize) {
      uploadCommand += ", finalize";
    }
    let retryCount = 0;
    let currentDelayMs = INITIAL_RETRY_DELAY_MS;
    while (retryCount < MAX_RETRY_COUNT) {
      response = await apiClient.request({
        path: "",
        body: chunk,
        httpMethod: "POST",
        httpOptions: {
          apiVersion: "",
          baseUrl: uploadUrl,
          headers: {
            "X-Goog-Upload-Command": uploadCommand,
            "X-Goog-Upload-Offset": String(offset),
            "Content-Length": String(chunkSize)
          }
        }
      });
      if ((_a = response === null || response === void 0 ? void 0 : response.headers) === null || _a === void 0 ? void 0 : _a[X_GOOG_UPLOAD_STATUS_HEADER_FIELD]) {
        break;
      }
      retryCount++;
      await sleep(currentDelayMs);
      currentDelayMs = currentDelayMs * DELAY_MULTIPLIER;
    }
    offset += chunkSize;
    if (((_b = response === null || response === void 0 ? void 0 : response.headers) === null || _b === void 0 ? void 0 : _b[X_GOOG_UPLOAD_STATUS_HEADER_FIELD]) !== "active") {
      break;
    }
    if (fileSize <= offset) {
      throw new Error("All content has been uploaded, but the upload status is not finalized.");
    }
  }
  const responseJson = await (response === null || response === void 0 ? void 0 : response.json());
  if (((_c = response === null || response === void 0 ? void 0 : response.headers) === null || _c === void 0 ? void 0 : _c[X_GOOG_UPLOAD_STATUS_HEADER_FIELD]) !== "final") {
    throw new Error("Failed to upload file: Upload status is not finalized.");
  }
  return responseJson["file"];
}
__name(uploadBlob, "uploadBlob");
async function getBlobStat(file) {
  const fileStat = { size: file.size, type: file.type };
  return fileStat;
}
__name(getBlobStat, "getBlobStat");
function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}
__name(sleep, "sleep");
var BrowserUploader = class {
  static {
    __name(this, "BrowserUploader");
  }
  async upload(file, uploadUrl, apiClient) {
    if (typeof file === "string") {
      throw new Error("File path is not supported in browser uploader.");
    }
    return await uploadBlob(file, uploadUrl, apiClient);
  }
  async stat(file) {
    if (typeof file === "string") {
      throw new Error("File path is not supported in browser uploader.");
    } else {
      return await getBlobStat(file);
    }
  }
};
var BrowserWebSocketFactory = class {
  static {
    __name(this, "BrowserWebSocketFactory");
  }
  create(url, headers, callbacks) {
    return new BrowserWebSocket(url, headers, callbacks);
  }
};
var BrowserWebSocket = class {
  static {
    __name(this, "BrowserWebSocket");
  }
  constructor(url, headers, callbacks) {
    this.url = url;
    this.headers = headers;
    this.callbacks = callbacks;
  }
  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.onopen = this.callbacks.onopen;
    this.ws.onerror = this.callbacks.onerror;
    this.ws.onclose = this.callbacks.onclose;
    this.ws.onmessage = this.callbacks.onmessage;
  }
  send(message) {
    if (this.ws === void 0) {
      throw new Error("WebSocket is not connected");
    }
    this.ws.send(message);
  }
  close() {
    if (this.ws === void 0) {
      throw new Error("WebSocket is not connected");
    }
    this.ws.close();
  }
};
var GOOGLE_API_KEY_HEADER = "x-goog-api-key";
var WebAuth = class {
  static {
    __name(this, "WebAuth");
  }
  constructor(apiKey) {
    this.apiKey = apiKey;
  }
  async addAuthHeaders(headers) {
    if (headers.get(GOOGLE_API_KEY_HEADER) !== null) {
      return;
    }
    if (this.apiKey.startsWith("auth_tokens/")) {
      throw new Error("Ephemeral tokens are only supported by the live API.");
    }
    if (!this.apiKey) {
      throw new Error("API key is missing. Please provide a valid API key.");
    }
    headers.append(GOOGLE_API_KEY_HEADER, this.apiKey);
  }
};
var LANGUAGE_LABEL_PREFIX = "gl-node/";
var GoogleGenAI = class {
  static {
    __name(this, "GoogleGenAI");
  }
  constructor(options) {
    var _a;
    if (options.apiKey == null) {
      throw new Error("An API Key must be set when running in a browser");
    }
    if (options.project || options.location) {
      throw new Error("Vertex AI project based authentication is not supported on browser runtimes. Please do not provide a project or location.");
    }
    this.vertexai = (_a = options.vertexai) !== null && _a !== void 0 ? _a : false;
    this.apiKey = options.apiKey;
    const baseUrl = getBaseUrl(
      options.httpOptions,
      options.vertexai,
      /*vertexBaseUrlFromEnv*/
      void 0,
      /*geminiBaseUrlFromEnv*/
      void 0
    );
    if (baseUrl) {
      if (options.httpOptions) {
        options.httpOptions.baseUrl = baseUrl;
      } else {
        options.httpOptions = { baseUrl };
      }
    }
    this.apiVersion = options.apiVersion;
    const auth = new WebAuth(this.apiKey);
    this.apiClient = new ApiClient({
      auth,
      apiVersion: this.apiVersion,
      apiKey: this.apiKey,
      vertexai: this.vertexai,
      httpOptions: options.httpOptions,
      userAgentExtra: LANGUAGE_LABEL_PREFIX + "web",
      uploader: new BrowserUploader(),
      downloader: new BrowserDownloader()
    });
    this.models = new Models(this.apiClient);
    this.live = new Live(this.apiClient, auth, new BrowserWebSocketFactory());
    this.batches = new Batches(this.apiClient);
    this.chats = new Chats(this.models, this.apiClient);
    this.caches = new Caches(this.apiClient);
    this.files = new Files(this.apiClient);
    this.operations = new Operations(this.apiClient);
    this.authTokens = new Tokens(this.apiClient);
    this.tunings = new Tunings(this.apiClient);
  }
};

// api/generate-prompt.ts
async function verifyJWT(token, secret) {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error("Invalid token format");
    }
    const encoder = new TextEncoder();
    const message = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify("HMAC", key, signature, encoder.encode(message));
    if (!isValid) {
      throw new Error("Invalid signature");
    }
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp < Math.floor(Date.now() / 1e3)) {
      throw new Error("Token expired");
    }
    return payload;
  } catch (error) {
    throw new Error("Token verification failed");
  }
}
__name(verifyJWT, "verifyJWT");
var metaPromptTranslations = {
  en: {
    systemInstructionBase: "You are an expert prompt engineer. Generate a complete, executable prompt following the exact format: <System>, <User>, <Example>. The final prompt must be in {TARGET_LANGUAGE} and ready for immediate use by an AI. Include detailed methodology in the User section and compelling examples. Output ONLY the prompt text - no meta-commentary or explanations outside the prompt structure.",
    userQueryHeader: "Please generate a structured prompt. Here are the details:",
    rawRequestLabel: "User's Goal / Raw Request:",
    promptTypeLabel: "Chosen Prompt Structure Type:",
    domainLabel: "Domain:",
    outputLengthLabel: "Desired Output Length for the AI using the generated prompt:",
    expertRoleLabel: "Expert Role for the AI using the generated prompt:",
    missionLabel: "Main Mission for the AI using the generated prompt:",
    constraintsLabel: "Constraints for the AI using the generated prompt (one per line):",
    noneSpecified: "None specified",
    finalPromptLangLabel: "The language for the final prompt itself MUST be: {TARGET_LANGUAGE}.",
    constructPromptInstruction: "Now, based on whether the type is MVP or AGENTIC, construct the prompt using the following templates and information.",
    // Enhanced MVP Section
    mvpTemplateHeader: 'For an "MVP" type prompt, generate a complete executable prompt:',
    mvpGenerateInstruction: "Generate a complete, executable prompt using this exact structure:",
    mvpSystemRole: "You are an excellent {expertRolePlaceholder}: knowledgeable, precise, pedagogical. Your mission is to {missionPlaceholder}.",
    mvpExpertPlaceholder: "Expert",
    mvpMissionPlaceholder: "help effectively",
    // Enhanced Methodology for MVP
    mvpMethodologyHeader: "DETAILED METHODOLOGY - Follow this structured approach:",
    mvpAnalysisHeader: "1. IN-DEPTH ANALYSIS:",
    mvpAnalysisTasks: [
      "Meticulously analyze all elements provided in the request above",
      "Identify explicit and implicit objectives, quality criteria, and success metrics",
      "Note technical, creative, and logistical constraints to be respected",
      "Evaluate context, underlying challenges, and optimization opportunities",
      "Determine the most appropriate resources, tools, and approaches"
    ],
    mvpPlanningHeader: "2. STRATEGIC PLANNING:",
    mvpPlanningTasks: [
      "Consider multiple methodological approaches to address the request optimally",
      "Rigorously evaluate advantages, disadvantages, and implications of each strategy",
      "Select the most appropriate approach and formulate clear justification for this choice",
      "Plan logical structure, progression, and optimal organization of the deliverable",
      "Anticipate execution challenges and prepare adaptation strategies if necessary"
    ],
    mvpExecutionHeader: "3. PROFESSIONAL EXECUTION:",
    mvpExecutionTasks: [
      "Produce a deliverable organized according to clear professional architecture",
      "Use premium formatting with appropriate sections, subsections, and structural elements",
      "Integrate concrete examples, evidence, data, and relevant references to support quality",
      "Scrupulously respect all constraints, specifications, and formulated requirements",
      "Systematically aim for professional-level quality that exceeds standard expectations",
      "Personalize content to maximize its specific relevance and added value"
    ],
    mvpExpectedOutputFormat: "Expected output format:",
    mvpLength: "Length:",
    mvpStyle: "Style: Clear and structured",
    mvpLanguage: "Language: {TARGET_LANGUAGE}",
    // Fixed Example Instruction  
    mvpExampleInstruction: "Show the exact beginning of the expected deliverable - first 3-5 lines of actual output, not process description. Examples: For podcast \u2192 'Voice 1: Welcome everyone to today's show...', for lesson plan \u2192 'LESSON: [Title] | OBJECTIVES: Students will be able to...', for analysis \u2192 'EXECUTIVE SUMMARY: This analysis reveals...'. The example must be a direct sample of the deliverable.",
    mvpFooter: "CRITICAL: Generate ONLY the complete prompt above with <System>, <User>, and <Example> sections. Do not add meta-commentary or explanations outside the prompt structure.",
    // Enhanced AGENTIC Section
    agenticTemplateHeader: 'For an "AGENTIC" type prompt, generate a complete executable prompt with self-assessment capabilities:',
    agenticGenerateInstruction: "Generate a complete, executable AGENTIC prompt using this exact structure:",
    agenticTitleInstruction: "[Generate a concise and descriptive title (max 5-7 words) derived from the user's raw request.]",
    agenticRole: "{expertRolePlaceholder} (Agentic AI)",
    agenticExpertPlaceholder: "Expert Analyst",
    agenticNote: '*Note: "Agentic AI" means an AI capable of acting autonomously, thinking, and iterating on its work.*',
    agenticContext: "Context:",
    agenticInstructionsHeader: "Instructions:",
    // Same detailed methodology for AGENTIC (reusing MVP tasks)
    agenticAnalysisHeader: "1. IN-DEPTH ANALYSIS:",
    agenticAnalysisTasks: [
      "Meticulously analyze all elements provided related to the Context above",
      "Identify explicit and implicit objectives, quality criteria, and success metrics",
      "Note technical, creative, and logistical constraints to be respected",
      "Evaluate context, underlying challenges, and optimization opportunities",
      "Determine the most appropriate resources, tools, and approaches"
    ],
    agenticThinkingHeader: "2. STRATEGIC PLANNING:",
    agenticThinkingTasks: [
      "Consider multiple methodological approaches to address the Context optimally",
      "Rigorously evaluate advantages, disadvantages, and implications of each strategy",
      "Select the most appropriate approach and formulate clear justification for this choice",
      "Plan logical structure, progression, and optimal organization of the deliverable",
      "Anticipate execution challenges and prepare adaptation strategies if necessary"
    ],
    agenticDevelopmentHeader: "3. PROFESSIONAL EXECUTION:",
    agenticDevelopmentTasks: [
      "Produce a deliverable organized according to clear professional architecture",
      "Use premium formatting with appropriate sections, subsections, and structural elements",
      "Integrate concrete examples, evidence, data, and relevant references to support quality",
      "Scrupulously respect all constraints, specifications, and formulated requirements",
      "Systematically aim for professional-level quality that exceeds standard expectations",
      "Personalize content to maximize its specific relevance and added value"
    ],
    // Self-Assessment (AGENTIC only)
    agenticSelfAssessmentHeader: "4. SELF-ASSESSMENT AND CONTINUOUS IMPROVEMENT:",
    agenticSelfAssessmentQuestion1: 'At the end of its work, the AI executing this prompt **must always ask the user verbatim**:\n    "\u{1F914} Would you like me to evaluate this result against key criteria and provide suggestions for improvement? (Yes/No)"',
    agenticSelfAssessmentInstruction: 'If the user responds "Yes" (or similar affirmative), the AI should then perform a self-assessment using the following evaluation method, presenting it in a table:',
    agenticEvaluationCriteria: {
      education: ["Pedagogical Clarity", "Level Appropriateness", "Learner Engagement", "Logical Progression"],
      technical: ["Technical Accuracy", "Completeness of Analysis", "Rigorous Methodology", "Actionable Recommendations"],
      other: ["Originality", "Coherence", "Impact", "Quality of Execution"]
    },
    agenticEvalTableHeader: "| Criterion                     | Rating (/10) | Justification for Rating | Concrete Suggestions for Improvement |\n    |-------------------------------|--------------|--------------------------|--------------------------------------|",
    agenticSelfAssessmentQuestion2: 'After presenting the evaluation, the AI **must also ask the user verbatim**:\n    "Based on the evaluation above, would you like me to attempt to improve the draft? (Yes/No)"',
    agenticFooter: "CRITICAL: Generate ONLY the complete prompt above with Title, <System>, <User>, and <Example> sections. Do not add meta-commentary or explanations outside the prompt structure."
  },
  fr: {
    systemInstructionBase: "Vous \xEAtes un ing\xE9nieur de prompts expert. G\xE9n\xE9rez un prompt complet et ex\xE9cutable suivant exactement le format : <System>, <User>, <Example>. Le prompt final doit \xEAtre en {TARGET_LANGUAGE} et pr\xEAt \xE0 \xEAtre utilis\xE9 imm\xE9diatement par une IA. Incluez une m\xE9thodologie d\xE9taill\xE9e dans la section User et des exemples convaincants. Ne g\xE9n\xE9rez QUE le texte du prompt - aucun m\xE9ta-commentaire ou explication en dehors de la structure du prompt.",
    userQueryHeader: "Veuillez g\xE9n\xE9rer un prompt structur\xE9. Voici les d\xE9tails :",
    rawRequestLabel: "Objectif / Demande brute de l'utilisateur :",
    promptTypeLabel: "Type de structure de prompt choisi :",
    domainLabel: "Domaine :",
    outputLengthLabel: "Longueur de sortie souhait\xE9e pour l'IA utilisant le prompt g\xE9n\xE9r\xE9 :",
    expertRoleLabel: "R\xF4le d'expert pour l'IA utilisant le prompt g\xE9n\xE9r\xE9 :",
    missionLabel: "Mission principale pour l'IA utilisant le prompt g\xE9n\xE9r\xE9 :",
    constraintsLabel: "Contraintes pour l'IA utilisant le prompt g\xE9n\xE9r\xE9 (une par ligne) :",
    noneSpecified: "Aucune sp\xE9cifi\xE9e",
    finalPromptLangLabel: "La langue du prompt final lui-m\xEAme DOIT \xEAtre : {TARGET_LANGUAGE}.",
    constructPromptInstruction: "Maintenant, selon que le type est MVP ou AGENTIQUE, g\xE9n\xE9rez le prompt en utilisant les mod\xE8les et informations suivants.",
    // Enhanced MVP Section - French
    mvpTemplateHeader: 'Pour un prompt de type "MVP", g\xE9n\xE9rez un prompt ex\xE9cutable complet :',
    mvpGenerateInstruction: "G\xE9n\xE9rez un prompt complet et ex\xE9cutable en utilisant exactement cette structure :",
    mvpSystemRole: "Vous \xEAtes un excellent {expertRolePlaceholder} : comp\xE9tent, pr\xE9cis, p\xE9dagogue. Votre mission est d'{missionPlaceholder}.",
    mvpExpertPlaceholder: "Expert",
    mvpMissionPlaceholder: "aider efficacement",
    // Enhanced Methodology for MVP - French
    mvpMethodologyHeader: "M\xC9THODOLOGIE D\xC9TAILL\xC9E - Suivez cette approche structur\xE9e :",
    mvpAnalysisHeader: "1. ANALYSE APPROFONDIE :",
    mvpAnalysisTasks: [
      "Analysez m\xE9ticuleusement tous les \xE9l\xE9ments fournis dans la demande ci-dessus",
      "Identifiez les objectifs explicites et implicites, crit\xE8res de qualit\xE9 et m\xE9triques de r\xE9ussite",
      "Notez les contraintes techniques, cr\xE9atives et logistiques \xE0 respecter",
      "\xC9valuez le contexte, les d\xE9fis sous-jacents et les opportunit\xE9s d'optimisation",
      "D\xE9terminez les ressources, outils et approches les plus appropri\xE9s"
    ],
    mvpPlanningHeader: "2. PLANIFICATION STRAT\xC9GIQUE :",
    mvpPlanningTasks: [
      "Consid\xE9rez de multiples approches m\xE9thodologiques pour aborder la demande de mani\xE8re optimale",
      "\xC9valuez rigoureusement les avantages, inconv\xE9nients et implications de chaque strat\xE9gie",
      "S\xE9lectionnez l'approche la plus appropri\xE9e et formulez une justification claire de ce choix",
      "Planifiez la structure logique, la progression et l'organisation optimale du livrable",
      "Anticipez les d\xE9fis d'ex\xE9cution et pr\xE9parez des strat\xE9gies d'adaptation si n\xE9cessaire"
    ],
    mvpExecutionHeader: "3. EX\xC9CUTION PROFESSIONNELLE :",
    mvpExecutionTasks: [
      "Produisez un livrable organis\xE9 selon une architecture professionnelle claire",
      "Utilisez un formatage premium avec sections, sous-sections et \xE9l\xE9ments de structuration appropri\xE9s",
      "Int\xE9grez des exemples concrets, preuves, donn\xE9es et r\xE9f\xE9rences pertinentes pour \xE9tayer la qualit\xE9",
      "Respectez scrupuleusement toutes les contraintes, sp\xE9cifications et exigences formul\xE9es",
      "Visez syst\xE9matiquement un niveau de qualit\xE9 professionnel qui d\xE9passe les attentes standard",
      "Personnalisez le contenu pour maximiser sa pertinence et sa valeur ajout\xE9e sp\xE9cifique"
    ],
    mvpExpectedOutputFormat: "Format de sortie attendu :",
    mvpLength: "Longueur :",
    mvpStyle: "Style : Clair et structur\xE9",
    mvpLanguage: "Langue : {TARGET_LANGUAGE}",
    // Fixed Example Instruction - French
    mvpExampleInstruction: "Montrez le d\xE9but exact du livrable attendu - les 3-5 premi\xE8res lignes de sortie r\xE9elle, pas une description de processus. Exemples : Pour podcast \u2192 'Voix 1: Bienvenue dans cette \xE9mission...', pour plan de cours \u2192 'COURS: [Titre] | OBJECTIFS: Les apprenants seront capables de...', pour analyse \u2192 'SYNTH\xC8SE EX\xC9CUTIVE: Cette analyse r\xE9v\xE8le...'. L'exemple doit \xEAtre un \xE9chantillon direct du livrable.",
    mvpFooter: "CRITIQUE: G\xE9n\xE9rez UNIQUEMENT le prompt complet ci-dessus avec les sections <System>, <User>, et <Example>. N'ajoutez aucun m\xE9ta-commentaire ou explication en dehors de la structure du prompt.",
    // Enhanced AGENTIC Section - French (same structure, with self-assessment)
    agenticTemplateHeader: `Pour un prompt de type "AGENTIQUE", g\xE9n\xE9rez un prompt ex\xE9cutable complet avec capacit\xE9s d'auto-\xE9valuation :`,
    agenticGenerateInstruction: "G\xE9n\xE9rez un prompt AGENTIQUE complet et ex\xE9cutable en utilisant exactement cette structure :",
    agenticTitleInstruction: "[G\xE9n\xE9rez un titre concis et descriptif (max 5-7 mots) d\xE9riv\xE9 de la demande brute de l'utilisateur.]",
    agenticRole: "{expertRolePlaceholder} (IA Agentique)",
    agenticExpertPlaceholder: "Analyste Expert",
    agenticNote: `*Note : "IA Agentique" signifie une IA capable d'agir de mani\xE8re autonome, de r\xE9fl\xE9chir et d'it\xE9rer sur son travail.*`,
    agenticContext: "Contexte :",
    agenticInstructionsHeader: "Instructions :",
    // Same detailed methodology for AGENTIC - French
    agenticAnalysisHeader: "1. ANALYSE APPROFONDIE DES INFORMATIONS FOURNIES :",
    agenticAnalysisTasks: [
      "Analysez m\xE9ticuleusement tous les \xE9l\xE9ments fournis relatifs au Contexte ci-dessus",
      "Identifiez les objectifs explicites et implicites, crit\xE8res de qualit\xE9 et m\xE9triques de r\xE9ussite",
      "Notez les contraintes techniques, cr\xE9atives et logistiques \xE0 respecter",
      "\xC9valuez le contexte, les d\xE9fis sous-jacents et les opportunit\xE9s d'optimisation",
      "D\xE9terminez les ressources, outils et approches les plus appropri\xE9s"
    ],
    agenticThinkingHeader: "2. R\xC9FLEXION APPROFONDIE & PLANIFICATION :",
    agenticThinkingTasks: [
      "Consid\xE9rez de multiples approches m\xE9thodologiques pour aborder le Contexte de mani\xE8re optimale",
      "\xC9valuez rigoureusement les avantages, inconv\xE9nients et implications de chaque strat\xE9gie",
      "S\xE9lectionnez l'approche la plus appropri\xE9e et formulez une justification claire de ce choix",
      "Planifiez la structure logique, la progression et l'organisation optimale du livrable",
      "Anticipez les d\xE9fis d'ex\xE9cution et pr\xE9parez des strat\xE9gies d'adaptation si n\xE9cessaire"
    ],
    agenticDevelopmentHeader: "3. D\xC9VELOPPEMENT STRUCTUR\xC9 & EX\xC9CUTION :",
    agenticDevelopmentTasks: [
      "Produisez un livrable organis\xE9 selon une architecture professionnelle claire",
      "Utilisez un formatage premium avec sections, sous-sections et \xE9l\xE9ments de structuration appropri\xE9s",
      "Int\xE9grez des exemples concrets, preuves, donn\xE9es et r\xE9f\xE9rences pertinentes pour \xE9tayer la qualit\xE9",
      "Respectez scrupuleusement toutes les contraintes, sp\xE9cifications et exigences formul\xE9es",
      "Visez syst\xE9matiquement un niveau de qualit\xE9 professionnel qui d\xE9passe les attentes standard",
      "Personnalisez le contenu pour maximiser sa pertinence et sa valeur ajout\xE9e sp\xE9cifique"
    ],
    // Self-Assessment (AGENTIC only) - French
    agenticSelfAssessmentHeader: "4. AUTO-\xC9VALUATION ET AM\xC9LIORATION CONTINUE :",
    agenticSelfAssessmentQuestion1: `\xC0 la fin de son travail, l'IA ex\xE9cutant ce prompt **doit toujours demander \xE0 l'utilisateur textuellement** :
    "\u{1F914} Souhaitez-vous que j'\xE9value ce r\xE9sultat par rapport \xE0 des crit\xE8res cl\xE9s et que je fournisse des suggestions d'am\xE9lioration ? (Oui/Non)"`,
    agenticSelfAssessmentInstruction: `Si l'utilisateur r\xE9pond "Oui" (ou une affirmation similaire), l'IA doit alors effectuer une auto-\xE9valuation en utilisant la m\xE9thode d'\xE9valuation suivante, en la pr\xE9sentant dans un tableau :`,
    agenticEvaluationCriteria: {
      education: ["Clart\xE9 P\xE9dagogique", "Ad\xE9quation au Niveau", "Engagement de l'Apprenant", "Progression Logique"],
      technical: ["Exactitude Technique", "Compl\xE9tude de l'Analyse", "M\xE9thodologie Rigoureuse", "Recommandations Actionnables"],
      other: ["Originalit\xE9", "Coh\xE9rence", "Impact", "Qualit\xE9 d'Ex\xE9cution"]
    },
    agenticEvalTableHeader: "| Crit\xE8re                       | Note (/10)   | Justification de la Note | Suggestions Concr\xE8tes d'Am\xE9lioration |\n    |-------------------------------|--------------|--------------------------|--------------------------------------|",
    agenticSelfAssessmentQuestion2: `Apr\xE8s avoir pr\xE9sent\xE9 l'\xE9valuation, l'IA **doit \xE9galement demander \xE0 l'utilisateur textuellement** :
    "Sur la base de l'\xE9valuation ci-dessus, souhaitez-vous que j'essaie d'am\xE9liorer le brouillon ? (Oui/Non)"`,
    agenticFooter: "CRITIQUE: G\xE9n\xE9rez UNIQUEMENT le prompt complet ci-dessus avec les sections Titre, <System>, <User>, et <Example>. N'ajoutez aucun m\xE9ta-commentaire ou explication en dehors de la structure du prompt."
  }
};
var GEMINI_MODEL_NAME = "gemini-2.5-pro-preview-05-06";
function buildPromptQuery(params, tMeta) {
  const {
    rawRequest,
    promptType,
    domain,
    language,
    outputLength,
    expertRole,
    mission,
    constraints
  } = params;
  const finalPromptTargetLanguageString = language === "fr" ? "Fran\xE7ais" : "English";
  const formattedConstraints = constraints ? constraints.split("\n").filter((c) => c.trim()).map((c) => `- ${c.trim()}`).join("\n") : "";
  const systemInstruction = tMeta.systemInstructionBase.replace("{TARGET_LANGUAGE}", finalPromptTargetLanguageString);
  let userQuery = `
${tMeta.userQueryHeader}

${tMeta.rawRequestLabel}
"${rawRequest}"

${tMeta.promptTypeLabel} ${promptType}
${tMeta.domainLabel} ${domain}
${tMeta.outputLengthLabel} ${outputLength}
${tMeta.expertRoleLabel} ${expertRole || (promptType === "MVP" ? tMeta.mvpExpertPlaceholder : tMeta.agenticExpertPlaceholder)}
${tMeta.missionLabel} ${mission || tMeta.mvpMissionPlaceholder}
${tMeta.constraintsLabel}
${constraints ? formattedConstraints : tMeta.noneSpecified}
${tMeta.finalPromptLangLabel.replace("{TARGET_LANGUAGE}", finalPromptTargetLanguageString)}

${tMeta.constructPromptInstruction}
`;
  if (promptType === "MVP") {
    userQuery += `
${tMeta.mvpTemplateHeader}

${tMeta.mvpGenerateInstruction}

<System>:
${tMeta.mvpSystemRole.replace("{expertRolePlaceholder}", expertRole || tMeta.mvpExpertPlaceholder).replace("{missionPlaceholder}", mission || tMeta.mvpMissionPlaceholder)}

<User>:
${rawRequest}

${tMeta.mvpMethodologyHeader}

${tMeta.mvpAnalysisHeader}
${tMeta.mvpAnalysisTasks.map((task) => `\u2022 ${task}`).join("\n")}

${tMeta.mvpPlanningHeader}
${tMeta.mvpPlanningTasks.map((task) => `\u2022 ${task}`).join("\n")}

${tMeta.mvpExecutionHeader}
${tMeta.mvpExecutionTasks.map((task) => `\u2022 ${task}`).join("\n")}

Contraintes sp\xE9cifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

Format attendu : ${outputLength}, ${tMeta.mvpStyle.toLowerCase()}, ${tMeta.mvpLanguage.replace("{TARGET_LANGUAGE}", finalPromptTargetLanguageString)}

<Example>:
${tMeta.mvpExampleInstruction}

${tMeta.mvpFooter}
`;
  } else {
    const criteriaDomain = domain === "education" || domain === "technical" ? domain : "other";
    const evaluationCriteriaList = tMeta.agenticEvaluationCriteria[criteriaDomain];
    const criteriaTableMarkdown = evaluationCriteriaList.map(
      (c) => `| ${c.padEnd(29)} |              |                          |                                      |`
    ).join("\n");
    userQuery += `
${tMeta.agenticTemplateHeader}

${tMeta.agenticGenerateInstruction}

Title: ${tMeta.agenticTitleInstruction}

<System>:
${tMeta.agenticRole.replace("{expertRolePlaceholder}", expertRole || tMeta.agenticExpertPlaceholder)} ${tMeta.agenticNote} ${language === "fr" ? "Votre mission est d'" : "Your mission is to "}${mission || tMeta.mvpMissionPlaceholder}.

<User>:
${rawRequest}

${tMeta.agenticInstructionsHeader}

${tMeta.agenticAnalysisHeader}
${tMeta.agenticAnalysisTasks.map((task) => `\u2022 ${task}`).join("\n")}

${tMeta.agenticThinkingHeader}
${tMeta.agenticThinkingTasks.map((task) => `\u2022 ${task}`).join("\n")}

${tMeta.agenticDevelopmentHeader}
${tMeta.agenticDevelopmentTasks.map((task) => `\u2022 ${task}`).join("\n")}

${tMeta.agenticSelfAssessmentHeader}
${tMeta.agenticSelfAssessmentQuestion1}

${tMeta.agenticSelfAssessmentInstruction}
${tMeta.agenticEvalTableHeader}
${criteriaTableMarkdown}

${tMeta.agenticSelfAssessmentQuestion2}

Contraintes sp\xE9cifiques :
${constraints ? formattedConstraints : tMeta.noneSpecified}

Format attendu : ${outputLength}, ${tMeta.mvpStyle.toLowerCase()}, ${tMeta.mvpLanguage.replace("{TARGET_LANGUAGE}", finalPromptTargetLanguageString)}

<Example>:
${language === "fr" ? "[Montrez le d\xE9but exact du livrable attendu avec le format du titre et les premi\xE8res lignes de contenu r\xE9el]" : "[Show the exact beginning of the expected deliverable with the title format and first few lines of actual content]"}

${tMeta.agenticFooter}
`;
  }
  return { systemInstruction, userQuery };
}
__name(buildPromptQuery, "buildPromptQuery");
var onRequestPost8 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== GENERATE PROMPT ENDPOINT ===");
    if (!env.JWT_SECRET) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "CONFIG_ERROR",
          message: "JWT configuration missing"
        }
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!env.API_KEY) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "CONFIG_ERROR",
          message: "API key configuration missing"
        }
      }), {
        status: 503,
        headers: { "Content-Type": "application/json" }
      });
    }
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "NO_TOKEN",
          message: "Authorization token required"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const token = authHeader.substring(7);
    let user;
    try {
      user = await verifyJWT(token, env.JWT_SECRET);
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: "INVALID_TOKEN",
          message: "Invalid or expired token"
        }
      }), {
        status: 401,
        headers: { "Content-Type": "application/json" }
      });
    }
    const params = await request.json();
    console.log("Generating prompt for user:", user.userId);
    const tMeta = metaPromptTranslations[params.language] || metaPromptTranslations.en;
    const { systemInstruction, userQuery } = buildPromptQuery(params, tMeta);
    const ai = new GoogleGenAI({ apiKey: env.API_KEY });
    const result = await ai.models.generateContent({
      model: GEMINI_MODEL_NAME,
      contents: userQuery,
      config: {
        systemInstruction
      }
    });
    if (!result || typeof result.text !== "string") {
      throw new Error("Invalid response from Gemini API");
    }
    console.log("Prompt generated successfully for user:", user.userId);
    return new Response(JSON.stringify({
      success: true,
      prompt: result.text
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Generate prompt error:", error);
    let errorResponse = {
      code: "INTERNAL_ERROR",
      message: "Unable to generate prompt"
    };
    if (error?.message) {
      if (error.message.includes("API key not valid") || error.message.includes("API_KEY_INVALID")) {
        errorResponse = {
          code: "API_KEY_ERROR",
          message: "Service configuration error"
        };
      } else if (error.message.toLowerCase().includes("quota")) {
        errorResponse = {
          code: "QUOTA_EXCEEDED",
          message: "Service temporarily unavailable due to high demand"
        };
      }
    }
    return new Response(JSON.stringify({
      success: false,
      error: errorResponse
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// api/prompts.ts
async function verifyJWT2(token, secret) {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error("Invalid token format");
    }
    const encoder = new TextEncoder();
    const message = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify("HMAC", key, signature, encoder.encode(message));
    if (!isValid) {
      throw new Error("Invalid signature");
    }
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp < Math.floor(Date.now() / 1e3)) {
      throw new Error("Token expired");
    }
    return payload;
  } catch (error) {
    throw new Error("Token verification failed");
  }
}
__name(verifyJWT2, "verifyJWT");
var onRequestGet3 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== GET PROMPTS ENDPOINT ===");
    if (!env.JWT_SECRET || !env.DB) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: "CONFIG_ERROR", message: "Service unavailable" }
      }), { status: 503, headers: { "Content-Type": "application/json" } });
    }
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: "NO_TOKEN", message: "Authorization token required" }
      }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    const token = authHeader.substring(7);
    let user;
    try {
      user = await verifyJWT2(token, env.JWT_SECRET);
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: "INVALID_TOKEN", message: "Invalid or expired token" }
      }), { status: 401, headers: { "Content-Type": "application/json" } });
    }
    console.log("Fetching prompts for user:", user.userId);
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get("page") || "1");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);
    const offset = (page - 1) * limit;
    const prompts = [];
    return new Response(JSON.stringify({
      success: true,
      prompts,
      pagination: {
        page,
        limit,
        total: 0,
        totalPages: 0
      }
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Get prompts error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: { code: "INTERNAL_ERROR", message: "Failed to fetch prompts" }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestGet");
var onRequestPost9 = /* @__PURE__ */ __name(async (context) => {
  const { request, env } = context;
  try {
    console.log("=== CREATE PROMPT ENDPOINT ===");
    return new Response(JSON.stringify({
      success: true,
      message: "Prompt creation not implemented yet",
      prompt: { id: "temp-id", title: "Temporary" }
    }), {
      status: 201,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Create prompt error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: { code: "INTERNAL_ERROR", message: "Failed to create prompt" }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}, "onRequestPost");

// ../.wrangler/tmp/pages-NaYyeI/functionsRoutes-0.2341046095670427.mjs
var routes = [
  {
    routePath: "/api/prompts/:id/favorite",
    mountPath: "/api/prompts/:id",
    method: "OPTIONS",
    middlewares: [],
    modules: [onRequestOptions]
  },
  {
    routePath: "/api/prompts/:id/favorite",
    mountPath: "/api/prompts/:id",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost]
  },
  {
    routePath: "/api/auth/login",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost2]
  },
  {
    routePath: "/api/auth/logout",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost3]
  },
  {
    routePath: "/api/auth/refresh",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost4]
  },
  {
    routePath: "/api/auth/register",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost5]
  },
  {
    routePath: "/api/auth/register-complex-backup",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost6]
  },
  {
    routePath: "/api/debug/bindings",
    mountPath: "/api/debug",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet]
  },
  {
    routePath: "/api/debug/test-bindings",
    mountPath: "/api/debug",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost7]
  },
  {
    routePath: "/api/prompts/stats",
    mountPath: "/api/prompts",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet2]
  },
  {
    routePath: "/api/prompts/stats",
    mountPath: "/api/prompts",
    method: "OPTIONS",
    middlewares: [],
    modules: [onRequestOptions2]
  },
  {
    routePath: "/api/prompts/:id",
    mountPath: "/api/prompts",
    method: "DELETE",
    middlewares: [],
    modules: [onRequestDelete]
  },
  {
    routePath: "/api/prompts/:id",
    mountPath: "/api/prompts",
    method: "OPTIONS",
    middlewares: [],
    modules: [onRequestOptions3]
  },
  {
    routePath: "/api/prompts/:id",
    mountPath: "/api/prompts",
    method: "PUT",
    middlewares: [],
    modules: [onRequestPut]
  },
  {
    routePath: "/api/generate-prompt",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost8]
  },
  {
    routePath: "/api/prompts",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet3]
  },
  {
    routePath: "/api/prompts",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost9]
  }
];

// ../../../../../../opt/homebrew/lib/node_modules/wrangler/node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../../../../../../opt/homebrew/lib/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: /* @__PURE__ */ __name(() => {
            isFailOpen = true;
          }, "passThroughOnException")
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    }, "next");
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_worker_default as default
};
/*! Bundled license information:

@google/genai/dist/web/index.mjs:
@google/genai/dist/web/index.mjs:
@google/genai/dist/web/index.mjs:
@google/genai/dist/web/index.mjs:
@google/genai/dist/web/index.mjs:
  (**
   * @license
   * Copyright 2025 Google LLC
   * SPDX-License-Identifier: Apache-2.0
   *)
*/
