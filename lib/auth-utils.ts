/**
 * Core Authentication Utilities for Cloudflare Workers
 * 
 * This module provides secure authentication utilities optimized for Cloudflare's edge environment.
 * All functions are designed to be:
 * - Edge-compatible (no Node.js dependencies)
 * - Security-first (following OWASP guidelines)
 * - Performance-optimized for distributed edge computing
 * - Type-safe with comprehensive error handling
 * 
 * Security Considerations:
 * - Uses Web Crypto API for all cryptographic operations
 * - Implements timing-safe string comparisons
 * - Follows secure coding practices for authentication flows
 * - Includes comprehensive input validation and sanitization
 */

import { 
  User, 
  AuthUser, 
  LoginRequest, 
  RegisterRequest, 
  JWTPayload, 
  AuthTokens, 
  PasswordValidationRules, 
  PasswordValidationResult,
  AuthError,
  Session
} from '../types';

// Security Configuration Constants
// These values are optimized for edge environments while maintaining security
export const AUTH_CONFIG = {
  // Bcrypt rounds optimized for edge performance vs security trade-off
  BCRYPT_ROUNDS: 12, // Reduced from typical 15 for edge performance, still secure
  
  // JWT Configuration
  JWT_ACCESS_EXPIRES_IN: 15 * 60, // 15 minutes in seconds
  JWT_REFRESH_EXPIRES_IN: 7 * 24 * 60 * 60, // 7 days in seconds
  
  // Account Security
  MAX_LOGIN_ATTEMPTS: 5,
  ACCOUNT_LOCK_DURATION: 15 * 60 * 1000, // 15 minutes in milliseconds
  
  // Password Requirements (OWASP compliant)
  PASSWORD_RULES: {
    minLength: 12, // OWASP recommends minimum 12 characters
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxLength: 128 // Prevent DoS attacks
  } as PasswordValidationRules,
  
  // Security Headers
  SECURE_HEADERS: {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  }
} as const;

/**
 * Authentication Error Codes
 * Standardized error codes for consistent error handling
 */
export const AUTH_ERRORS = {
  INVALID_CREDENTIALS: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password', statusCode: 401 },
  ACCOUNT_LOCKED: { code: 'ACCOUNT_LOCKED', message: 'Account temporarily locked due to too many failed attempts', statusCode: 423 },
  ACCOUNT_DISABLED: { code: 'ACCOUNT_DISABLED', message: 'Account has been disabled', statusCode: 403 },
  TOKEN_EXPIRED: { code: 'TOKEN_EXPIRED', message: 'Token has expired', statusCode: 401 },
  TOKEN_INVALID: { code: 'TOKEN_INVALID', message: 'Invalid token', statusCode: 401 },
  USER_NOT_FOUND: { code: 'USER_NOT_FOUND', message: 'User not found', statusCode: 404 },
  USER_EXISTS: { code: 'USER_EXISTS', message: 'User already exists', statusCode: 409 },
  WEAK_PASSWORD: { code: 'WEAK_PASSWORD', message: 'Password does not meet security requirements', statusCode: 400 },
  PASSWORDS_DONT_MATCH: { code: 'PASSWORDS_DONT_MATCH', message: 'Passwords do not match', statusCode: 400 },
  INVALID_EMAIL: { code: 'INVALID_EMAIL', message: 'Invalid email format', statusCode: 400 },
  RATE_LIMITED: { code: 'RATE_LIMITED', message: 'Too many requests, please try again later', statusCode: 429 },
  INTERNAL_ERROR: { code: 'INTERNAL_ERROR', message: 'Internal server error', statusCode: 500 }
} as const;

/**
 * Edge-compatible bcrypt implementation using Web Crypto API
 * Optimized for Cloudflare Workers environment
 */
export class EdgeBcrypt {
  private static readonly BCRYPT_CHARSET = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  
  /**
   * Generate a cryptographically secure salt
   * Uses Web Crypto API for true randomness
   */
  private static async generateSalt(rounds: number): Promise<string> {
    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    
    // Convert to bcrypt-compatible base64
    let salt = '$2b$' + rounds.toString().padStart(2, '0') + '$';
    
    // Encode salt bytes using bcrypt charset
    for (let i = 0; i < saltBytes.length; i += 3) {
      const chunk = (saltBytes[i] << 16) | ((saltBytes[i + 1] || 0) << 8) | (saltBytes[i + 2] || 0);
      salt += this.BCRYPT_CHARSET[(chunk >>> 18) & 63];
      salt += this.BCRYPT_CHARSET[(chunk >>> 12) & 63];
      salt += this.BCRYPT_CHARSET[(chunk >>> 6) & 63];
      salt += this.BCRYPT_CHARSET[chunk & 63];
    }
    
    return salt.substring(0, 29); // Standard bcrypt salt length
  }
  
  /**
   * Hash a password using edge-optimized bcrypt
   * @param password - Plain text password to hash
   * @param rounds - Number of salt rounds (default: 12 for edge optimization)
   */
  static async hash(password: string, rounds: number = AUTH_CONFIG.BCRYPT_ROUNDS): Promise<string> {
    if (!password || password.length === 0) {
      throw new Error('Password cannot be empty');
    }
    
    if (password.length > AUTH_CONFIG.PASSWORD_RULES.maxLength) {
      throw new Error('Password too long');
    }
    
    // Generate salt
    const salt = await this.generateSalt(rounds);
    
    // Use PBKDF2 as bcrypt alternative (more edge-friendly)
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const saltBytes = encoder.encode(salt);
    
    const key = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    
    // Fixed: Use reasonable iterations to prevent DoS attacks
    // Linear scaling instead of exponential to maintain performance on edge
    const iterations = Math.min(100000, rounds * 10000); // Cap at 100k iterations
    const hashBytes = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations,
        hash: 'SHA-256'
      },
      key,
      256
    );
    
    // Encode result in bcrypt-like format
    const hashArray = new Uint8Array(hashBytes);
    let encoded = '';
    for (let i = 0; i < hashArray.length; i += 3) {
      const chunk = (hashArray[i] << 16) | ((hashArray[i + 1] || 0) << 8) | (hashArray[i + 2] || 0);
      encoded += this.BCRYPT_CHARSET[(chunk >>> 18) & 63];
      encoded += this.BCRYPT_CHARSET[(chunk >>> 12) & 63];
      encoded += this.BCRYPT_CHARSET[(chunk >>> 6) & 63];
      encoded += this.BCRYPT_CHARSET[chunk & 63];
    }
    
    return salt + encoded.substring(0, 31);
  }
  
  /**
   * Compare password with hash using timing-safe comparison
   * @param password - Plain text password
   * @param hash - Stored password hash
   */
  static async compare(password: string, hash: string): Promise<boolean> {
    if (!password || !hash || hash.length < 60) {
      return false;
    }
    
    try {
      // Extract salt and rounds from hash
      const parts = hash.split('$');
      if (parts.length !== 4 || parts[1] !== '2b') {
        return false;
      }
      
      const rounds = parseInt(parts[2], 10);
      const salt = `$${parts[1]}$${parts[2]}$${parts[3].substring(0, 22)}`;
      
      // Re-hash the password with the same salt
      const encoder = new TextEncoder();
      const passwordBytes = encoder.encode(password);
      const saltBytes = encoder.encode(salt);
      
      const key = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      );
      
      // Fixed: Use reasonable iterations to prevent DoS attacks
    // Linear scaling instead of exponential to maintain performance on edge
    const iterations = Math.min(100000, rounds * 10000); // Cap at 100k iterations
      const hashBytes = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltBytes,
          iterations,
          hash: 'SHA-256'
        },
        key,
        256
      );
      
      // Encode and compare
      const hashArray = new Uint8Array(hashBytes);
      let encoded = '';
      for (let i = 0; i < hashArray.length; i += 3) {
        const chunk = (hashArray[i] << 16) | ((hashArray[i + 1] || 0) << 8) | (hashArray[i + 2] || 0);
        encoded += this.BCRYPT_CHARSET[(chunk >>> 18) & 63];
        encoded += this.BCRYPT_CHARSET[(chunk >>> 12) & 63];
        encoded += this.BCRYPT_CHARSET[(chunk >>> 6) & 63];
        encoded += this.BCRYPT_CHARSET[chunk & 63];
      }
      
      const computedHash = salt + encoded.substring(0, 31);
      
      // Timing-safe comparison
      return await this.timingSafeEqual(computedHash, hash);
    } catch (error) {
      // Log error for monitoring but don't expose details
      console.error('Password comparison error:', error);
      return false;
    }
  }
  
  /**
   * Timing-safe string comparison to prevent timing attacks
   */
  private static async timingSafeEqual(a: string, b: string): Promise<boolean> {
    if (a.length !== b.length) {
      return false;
    }
    
    // Use Web Crypto API for timing-safe comparison
    const encoder = new TextEncoder();
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);
    
    // XOR all bytes and check if result is zero
    let result = 0;
    for (let i = 0; i < aBytes.length; i++) {
      result |= aBytes[i] ^ bBytes[i];
    }
    
    return result === 0;
  }
}

/**
 * JWT Token Management
 * Secure JWT implementation using Web Crypto API for edge environments
 */
export class JWTManager {
  private static encoder = new TextEncoder();
  
  /**
   * Generate a secure random secret key for JWT signing
   * Should be called once and stored securely (environment variable)
   */
  static async generateSecretKey(): Promise<string> {
    const key = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign', 'verify']
    );
    
    const keyData = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(keyData)));
  }
  
  /**
   * Import JWT secret key from base64 string
   */
  private static async importKey(secret: string): Promise<CryptoKey> {
    const keyData = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
    return await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );
  }
  
  /**
   * Base64URL encode (RFC 7515 compliant)
   */
  private static base64urlEncode(data: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...data));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
  
  /**
   * Base64URL decode
   */
  private static base64urlDecode(str: string): Uint8Array {
    // Add padding if needed
    const padded = str + '===='.substring(0, (4 - (str.length % 4)) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  }
  
  /**
   * Generate JWT access and refresh tokens
   * @param user - Authenticated user data
   * @param secret - JWT signing secret
   */
  static async generateTokens(user: AuthUser, secret: string): Promise<AuthTokens> {
    const now = Math.floor(Date.now() / 1000);
    const accessExpiresAt = now + AUTH_CONFIG.JWT_ACCESS_EXPIRES_IN;
    const refreshExpiresAt = now + AUTH_CONFIG.JWT_REFRESH_EXPIRES_IN;
    
    // Access token payload
    const accessPayload: JWTPayload = {
      userId: user.id,
      email: user.email,
      iat: now,
      exp: accessExpiresAt,
      type: 'access'
    };
    
    // Refresh token payload
    const refreshPayload: JWTPayload = {
      userId: user.id,
      email: user.email,
      iat: now,
      exp: refreshExpiresAt,
      type: 'refresh'
    };
    
    const [accessToken, refreshToken] = await Promise.all([
      this.sign(accessPayload, secret),
      this.sign(refreshPayload, secret)
    ]);
    
    return {
      accessToken,
      refreshToken,
      expiresAt: accessExpiresAt * 1000 // Convert to milliseconds
    };
  }
  
  /**
   * Sign JWT token
   */
  private static async sign(payload: JWTPayload, secret: string): Promise<string> {
    const header = {
      alg: 'HS256',
      typ: 'JWT'
    };
    
    // Encode header and payload
    const encodedHeader = this.base64urlEncode(this.encoder.encode(JSON.stringify(header)));
    const encodedPayload = this.base64urlEncode(this.encoder.encode(JSON.stringify(payload)));
    
    // Create signature
    const data = `${encodedHeader}.${encodedPayload}`;
    const key = await this.importKey(secret);
    const signature = await crypto.subtle.sign('HMAC', key, this.encoder.encode(data));
    const encodedSignature = this.base64urlEncode(new Uint8Array(signature));
    
    return `${data}.${encodedSignature}`;
  }
  
  /**
   * Verify and decode JWT token
   * @param token - JWT token to verify
   * @param secret - JWT signing secret
   */
  static async verify(token: string, secret: string): Promise<JWTPayload> {
    if (!token || typeof token !== 'string') {
      throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
    }
    
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
    }
    
    const [headerB64, payloadB64, signatureB64] = parts;
    
    try {
      // Verify signature
      const data = `${headerB64}.${payloadB64}`;
      const key = await this.importKey(secret);
      const signature = this.base64urlDecode(signatureB64);
      
      const isValid = await crypto.subtle.verify(
        'HMAC',
        key,
        signature,
        this.encoder.encode(data)
      );
      
      if (!isValid) {
        throw new Error(AUTH_ERRORS.TOKEN_INVALID.message);
      }
      
      // Decode payload
      const payload = JSON.parse(
        new TextDecoder().decode(this.base64urlDecode(payloadB64))
      ) as JWTPayload;
      
      // Check expiration
      const now = Math.floor(Date.now() / 1000);
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
}

/**
 * Password Validation and Strength Checking
 * Implements OWASP password guidelines
 */
export class PasswordValidator {
  /**
   * Validate password against security rules
   * @param password - Password to validate
   * @param rules - Validation rules (optional, uses default if not provided)
   */
  static validate(password: string, rules: PasswordValidationRules = AUTH_CONFIG.PASSWORD_RULES): PasswordValidationResult {
    const errors: string[] = [];
    
    // Length checks
    if (password.length < rules.minLength) {
      errors.push(`Password must be at least ${rules.minLength} characters long`);
    }
    
    if (password.length > rules.maxLength) {
      errors.push(`Password must not exceed ${rules.maxLength} characters`);
    }
    
    // Character requirement checks
    if (rules.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (rules.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (rules.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (rules.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    // Check for common patterns (basic implementation)
    if (this.hasCommonPatterns(password)) {
      errors.push('Password contains common patterns and may be easily guessed');
    }
    
    // Calculate strength
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
  private static hasCommonPatterns(password: string): boolean {
    const commonPatterns = [
      /(.)\1{2,}/, // Repeated characters (aaa, 111)
      /123456|abcdef|qwerty/i, // Sequential patterns
      /password|admin|login|user/i, // Common words
      /^(.{1,2})\1+$/ // Very short repeated patterns
    ];
    
    return commonPatterns.some(pattern => pattern.test(password));
  }
  
  /**
   * Calculate password strength
   */
  private static calculateStrength(password: string): 'weak' | 'medium' | 'strong' {
    let score = 0;
    
    // Length scoring
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    
    // Character diversity
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
    
    // Additional complexity
    if (password.length >= 16) score += 1;
    if (/[^a-zA-Z0-9!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1; // Unicode or other special chars
    
    // Penalty for common patterns
    if (this.hasCommonPatterns(password)) score -= 2;
    
    if (score >= 6) return 'strong';
    if (score >= 4) return 'medium';
    return 'weak';
  }
}

/**
 * Input Validation and Sanitization
 * Secure input handling to prevent injection attacks
 */
export class InputValidator {
  /**
   * Validate and sanitize email address
   * Uses RFC 5322 compliant regex with additional security checks
   */
  static validateEmail(email: string): { isValid: boolean; sanitized: string; error?: string } {
    if (!email || typeof email !== 'string') {
      return { isValid: false, sanitized: '', error: 'Email is required' };
    }
    
    // Sanitize input
    const sanitized = email.trim().toLowerCase();
    
    // Length check (prevent DoS)
    if (sanitized.length > 254) {
      return { isValid: false, sanitized: '', error: 'Email address too long' };
    }
    
    // RFC 5322 compliant regex (simplified for security)
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(sanitized)) {
      return { isValid: false, sanitized: '', error: 'Invalid email format' };
    }
    
    // Additional security checks
    if (sanitized.includes('..') || sanitized.startsWith('.') || sanitized.endsWith('.')) {
      return { isValid: false, sanitized: '', error: 'Invalid email format' };
    }
    
    // Check for potentially malicious patterns
    const maliciousPatterns = [
      /<script/i,
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /<iframe/i,
      /<object/i,
      /<embed/i
    ];
    
    if (maliciousPatterns.some(pattern => pattern.test(sanitized))) {
      return { isValid: false, sanitized: '', error: 'Invalid email format' };
    }
    
    return { isValid: true, sanitized };
  }
  
  /**
   * Sanitize user input for safe database storage
   * Prevents XSS and injection attacks
   */
  static sanitizeInput(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }
    
    return input
      .trim()
      .replace(/[<>'"&]/g, (char) => {
        const entities: { [key: string]: string } = {
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#x27;',
          '&': '&amp;'
        };
        return entities[char] || char;
      })
      .slice(0, 1000); // Reasonable length limit
  }
  
  /**
   * Validate request data structure
   */
  static validateLoginRequest(data: any): { isValid: boolean; request?: LoginRequest; errors: string[] } {
    const errors: string[] = [];
    
    if (!data || typeof data !== 'object') {
      return { isValid: false, errors: ['Invalid request data'] };
    }
    
    const emailValidation = this.validateEmail(data.email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.error || 'Invalid email');
    }
    
    if (!data.password || typeof data.password !== 'string') {
      errors.push('Password is required');
    } else if (data.password.length > AUTH_CONFIG.PASSWORD_RULES.maxLength) {
      errors.push('Password too long');
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
  static validateRegisterRequest(data: any): { isValid: boolean; request?: RegisterRequest; errors: string[] } {
    const errors: string[] = [];
    
    if (!data || typeof data !== 'object') {
      return { isValid: false, errors: ['Invalid request data'] };
    }
    
    const emailValidation = this.validateEmail(data.email);
    if (!emailValidation.isValid) {
      errors.push(emailValidation.error || 'Invalid email');
    }
    
    if (!data.password || typeof data.password !== 'string') {
      errors.push('Password is required');
    }
    
    if (!data.confirmPassword || typeof data.confirmPassword !== 'string') {
      errors.push('Password confirmation is required');
    }
    
    if (data.password !== data.confirmPassword) {
      errors.push(AUTH_ERRORS.PASSWORDS_DONT_MATCH.message);
    }
    
    // Validate password strength
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
  static validateGeneratePromptRequest(data: any): { isValid: boolean; data?: any; errors: string[] } {
    const errors: string[] = [];
    
    if (!data || typeof data !== 'object') {
      return { isValid: false, errors: ['Invalid request data'] };
    }
    
    // Validate rawRequest
    if (!data.rawRequest || typeof data.rawRequest !== 'string') {
      errors.push('Raw request is required');
    } else if (data.rawRequest.trim().length === 0) {
      errors.push('Raw request cannot be empty');
    } else if (data.rawRequest.length > 5000) {
      errors.push('Raw request exceeds maximum length of 5000 characters');
    }
    
    // Validate promptType
    if (!data.promptType || !['MVP', 'AGENTIC'].includes(data.promptType)) {
      errors.push('Invalid prompt type. Must be MVP or AGENTIC');
    }
    
    // Validate domain
    if (!data.domain || !['education', 'technical', 'creative', 'analysis', 'other'].includes(data.domain)) {
      errors.push('Invalid domain. Must be one of: education, technical, creative, analysis, other');
    }
    
    // Validate language
    if (!data.language || !['fr', 'en'].includes(data.language)) {
      errors.push('Invalid language. Must be fr or en');
    }
    
    // Validate outputLength
    if (!data.outputLength || !['short', 'medium', 'long'].includes(data.outputLength)) {
      errors.push('Invalid output length. Must be short, medium, or long');
    }
    
    // Validate optional fields with length limits
    if (data.expertRole !== undefined) {
      if (typeof data.expertRole !== 'string') {
        errors.push('Expert role must be a string');
      } else if (data.expertRole.length > 200) {
        errors.push('Expert role exceeds maximum length of 200 characters');
      }
    }
    
    if (data.mission !== undefined) {
      if (typeof data.mission !== 'string') {
        errors.push('Mission must be a string');
      } else if (data.mission.length > 500) {
        errors.push('Mission description exceeds maximum length of 500 characters');
      }
    }
    
    if (data.constraints !== undefined) {
      if (typeof data.constraints !== 'string') {
        errors.push('Constraints must be a string');
      } else if (data.constraints.length > 1000) {
        errors.push('Constraints exceed maximum length of 1000 characters');
      }
    }
    
    // Sanitize optional string fields
    const sanitizedData = {
      rawRequest: data.rawRequest ? this.sanitizeInput(data.rawRequest) : '',
      promptType: data.promptType,
      domain: data.domain,
      language: data.language,
      outputLength: data.outputLength,
      expertRole: data.expertRole ? this.sanitizeInput(data.expertRole) : undefined,
      mission: data.mission ? this.sanitizeInput(data.mission) : undefined,
      constraints: data.constraints ? this.sanitizeInput(data.constraints) : undefined
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
}

/**
 * Session Management Utilities
 * Secure session handling for authentication state
 */
export class SessionManager {
  /**
   * Generate a unique session ID
   */
  static generateSessionId(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Create a new session
   */
  static createSession(userId: string, tokens: AuthTokens, ipAddress?: string, userAgent?: string): Session {
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
  static isSessionValid(session: Session): boolean {
    const now = Date.now();
    return session.expiresAt > now;
  }
  
  /**
   * Update session last used timestamp
   */
  static updateSessionActivity(session: Session): Session {
    return {
      ...session,
      lastUsedAt: Date.now()
    };
  }
}

/**
 * Utility Functions
 */
export class AuthUtils {
  /**
   * Generate secure random string for various auth purposes
   */
  static generateSecureRandom(length: number = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  
  /**
   * Extract IP address from request, handling Cloudflare headers
   */
  static getClientIP(request: Request): string | undefined {
    // Cloudflare provides the real IP in CF-Connecting-IP header
    return request.headers.get('CF-Connecting-IP') || 
           request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
           request.headers.get('X-Real-IP') ||
           undefined;
  }
  
  /**
   * Extract User-Agent safely
   */
  static getUserAgent(request: Request): string | undefined {
    const userAgent = request.headers.get('User-Agent');
    return userAgent ? InputValidator.sanitizeInput(userAgent) : undefined;
  }
  
  /**
   * Create standardized error response
   */
  static createErrorResponse(error: AuthError): Response {
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
  static createSuccessResponse(data: any): Response {
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
}