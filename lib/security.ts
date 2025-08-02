/**
 * Security Middleware and Validation for Cloudflare Workers
 * 
 * This module provides comprehensive security middleware optimized for Cloudflare's
 * distributed edge environment. All functions are designed to:
 * - Prevent common web application vulnerabilities (OWASP Top 10)
 * - Implement defense-in-depth security strategies
 * - Provide edge-optimized rate limiting and DDoS protection
 * - Ensure secure request/response handling with proper headers
 * - Maintain high performance in distributed edge computing scenarios
 * 
 * Security Features:
 * - Rate limiting with distributed state management
 * - CORS handling with secure defaults
 * - Input validation and sanitization
 * - Security headers implementation
 * - Request size limiting (DoS prevention)
 * - Comprehensive logging for security monitoring
 */

import { 
  RateLimitConfig, 
  RateLimitState, 
  SecurityHeaders, 
  AuthError,
  JWTPayload
} from '../types';
import { AUTH_CONFIG, AUTH_ERRORS, JWTManager, InputValidator, AuthUtils } from './auth-utils';

/**
 * Rate Limiting Configuration for Different Endpoints
 * Optimized for edge environments with distributed state considerations
 */
export const RATE_LIMIT_CONFIGS = {
  // Authentication endpoints - more permissive for development
  LOGIN: {
    windowMs: 5 * 60 * 1000, // 5 minutes (reduced window)
    maxRequests: 20, // 20 attempts per IP per 5 minutes (increased)
    skipSuccessfulRequests: true, // Don't count successful logins
    skipFailedRequests: false
  } as RateLimitConfig,
  
  REGISTER: {
    windowMs: 15 * 60 * 1000, // 15 minutes  
    maxRequests: 20, // 20 registrations per IP per 15 minutes (increased)
    skipSuccessfulRequests: true, // Don't count successful registrations
    skipFailedRequests: false
  } as RateLimitConfig,
  
  // Token refresh - moderate limiting
  REFRESH_TOKEN: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxRequests: 10, // 10 refreshes per IP per 5 minutes
    skipSuccessfulRequests: true,
    skipFailedRequests: false
  } as RateLimitConfig,
  
  // General API endpoints
  API: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100, // 100 requests per IP per minute
    skipSuccessfulRequests: true,
    skipFailedRequests: false
  } as RateLimitConfig,
  
  // Password reset - very restrictive
  PASSWORD_RESET: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 3, // 3 reset attempts per IP per hour
    skipSuccessfulRequests: false,
    skipFailedRequests: false
  } as RateLimitConfig
} as const;

/**
 * Security Configuration Constants
 */
export const SECURITY_CONFIG = {
  // Request size limits (DoS prevention)
  MAX_REQUEST_SIZE: 1024 * 1024, // 1MB max request size
  MAX_JSON_SIZE: 100 * 1024, // 100KB max JSON payload
  
  // CORS configuration
  ALLOWED_ORIGINS: [
    'https://yourdomain.com',
    'https://www.yourdomain.com'
    // Add your production domains here
  ],
  
  // Content Security Policy
  CSP_DIRECTIVES: {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'", // Adjust based on your needs
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data: https:",
    'font-src': "'self'",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'base-uri': "'self'",
    'form-action': "'self'"
  },
  
  // Security headers with strict defaults
  SECURITY_HEADERS: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin'
  } as SecurityHeaders
} as const;

/**
 * Distributed Rate Limiter
 * Optimized for Cloudflare Workers with KV storage for state persistence
 */
export class EdgeRateLimiter {
  private kvNamespace?: KVNamespace;
  
  constructor(kvNamespace?: KVNamespace) {
    this.kvNamespace = kvNamespace;
  }
  
  /**
   * Generate rate limit key for distributed tracking
   */
  private generateKey(identifier: string, endpoint: string): string {
    return `rate_limit:${endpoint}:${identifier}`;
  }
  
  /**
   * Check and update rate limit state
   * @param identifier - Usually IP address or user ID
   * @param endpoint - API endpoint identifier
   * @param config - Rate limiting configuration
   */
  async checkRateLimit(
    identifier: string, 
    endpoint: string, 
    config: RateLimitConfig
  ): Promise<{ allowed: boolean; state: RateLimitState; resetTime: number }> {
    const key = this.generateKey(identifier, endpoint);
    const now = Date.now();
    const windowStart = now - config.windowMs;
    
    let state: RateLimitState;
    
    try {
      // Try to get existing state from KV store (if available)
      const existingState = this.kvNamespace ? 
        await this.kvNamespace.get(key, 'json') as RateLimitState | null : null;
      
      if (existingState && existingState.resetTime > now) {
        // Window is still active
        state = {
          count: existingState.count + 1,
          resetTime: existingState.resetTime,
          blocked: existingState.count >= config.maxRequests
        };
      } else {
        // New window or expired window
        state = {
          count: 1,
          resetTime: now + config.windowMs,
          blocked: false
        };
      }
      
      // Update state in KV store (if available)
      if (this.kvNamespace) {
        await this.kvNamespace.put(
          key, 
          JSON.stringify(state), 
          { expirationTtl: Math.ceil(config.windowMs / 1000) }
        );
      }
      
      return {
        allowed: !state.blocked,
        state,
        resetTime: state.resetTime
      };
      
    } catch (error) {
      // Fail open - allow request if we can't check rate limit
      console.error('Rate limiter error:', error);
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
  async resetRateLimit(identifier: string, endpoint: string): Promise<void> {
    if (!this.kvNamespace) return;
    
    const key = this.generateKey(identifier, endpoint);
    await this.kvNamespace.delete(key);
  }
  
  /**
   * Get current rate limit state without incrementing
   */
  async getRateLimitState(identifier: string, endpoint: string): Promise<RateLimitState | null> {
    if (!this.kvNamespace) return null;
    
    const key = this.generateKey(identifier, endpoint);
    return await this.kvNamespace.get(key, 'json') as RateLimitState | null;
  }
}

/**
 * CORS Handler
 * Secure CORS implementation with configurable origins
 */
export class CORSHandler {
  private allowedOrigins: string[];
  private allowCredentials: boolean;
  
  constructor(allowedOrigins: string[] = SECURITY_CONFIG.ALLOWED_ORIGINS, allowCredentials: boolean = true) {
    this.allowedOrigins = allowedOrigins;
    this.allowCredentials = allowCredentials;
  }
  
  /**
   * Check if origin is allowed
   */
  private isOriginAllowed(origin: string): boolean {
    // Allow localhost for development (remove in production)
    if (origin.startsWith('http://localhost:') || origin.startsWith('https://localhost:')) {
      return process.env.NODE_ENV === 'development';
    }
    
    return this.allowedOrigins.includes(origin);
  }
  
  /**
   * Handle CORS preflight request
   */
  handlePreflight(request: Request): Response {
    const origin = request.headers.get('Origin');
    const method = request.headers.get('Access-Control-Request-Method');
    const headers = request.headers.get('Access-Control-Request-Headers');
    
    // Validate origin
    if (!origin || !this.isOriginAllowed(origin)) {
      return new Response(null, { 
        status: 403,
        statusText: 'Forbidden - Invalid Origin'
      });
    }
    
    // Validate method
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
    if (!method || !allowedMethods.includes(method)) {
      return new Response(null, { 
        status: 405,
        statusText: 'Method Not Allowed'
      });
    }
    
    const responseHeaders: Record<string, string> = {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': allowedMethods.join(', '),
      'Access-Control-Allow-Headers': headers || 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400', // 24 hours
      'Vary': 'Origin'
    };
    
    if (this.allowCredentials) {
      responseHeaders['Access-Control-Allow-Credentials'] = 'true';
    }
    
    return new Response(null, {
      status: 204,
      headers: responseHeaders
    });
  }
  
  /**
   * Add CORS headers to response
   */
  addCORSHeaders(response: Response, origin: string | null): Response {
    if (!origin || !this.isOriginAllowed(origin)) {
      return response;
    }
    
    const newHeaders = new Headers(response.headers);
    newHeaders.set('Access-Control-Allow-Origin', origin);
    newHeaders.set('Vary', 'Origin');
    
    if (this.allowCredentials) {
      newHeaders.set('Access-Control-Allow-Credentials', 'true');
    }
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
}

/**
 * Request Validator
 * Comprehensive request validation and sanitization
 */
export class RequestValidator {
  /**
   * Validate request size (DoS prevention)
   */
  static validateRequestSize(request: Request): { valid: boolean; error?: AuthError } {
    const contentLength = request.headers.get('Content-Length');
    
    if (contentLength) {
      const size = parseInt(contentLength, 10);
      if (isNaN(size) || size > SECURITY_CONFIG.MAX_REQUEST_SIZE) {
        return {
          valid: false,
          error: {
            code: 'REQUEST_TOO_LARGE',
            message: 'Request size exceeds maximum allowed limit',
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
  static validateContentType(request: Request, expectedTypes: string[] = ['application/json']): { valid: boolean; error?: AuthError } {
    const contentType = request.headers.get('Content-Type');
    
    if (!contentType) {
      return {
        valid: false,
        error: {
          code: 'MISSING_CONTENT_TYPE',
          message: 'Content-Type header is required',
          statusCode: 400
        }
      };
    }
    
    const mainType = contentType.split(';')[0].trim().toLowerCase();
    if (!expectedTypes.includes(mainType)) {
      return {
        valid: false,
        error: {
          code: 'INVALID_CONTENT_TYPE',
          message: `Content-Type must be one of: ${expectedTypes.join(', ')}`,
          statusCode: 415
        }
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Parse and validate JSON body
   */
  static async parseAndValidateJSON(request: Request): Promise<{ valid: boolean; data?: any; error?: AuthError }> {
    try {
      console.log('=== SecurityHelpers.parseAndValidateJSON ===');
      console.log('Request bodyUsed before text():', request.bodyUsed);
      
      const text = await request.text();
      
      console.log('Text received - length:', text.length);
      console.log('Text content (first 200 chars):', text.substring(0, 200));
      console.log('Text content (full):', text);
      
      // Check JSON size
      if (text.length > SECURITY_CONFIG.MAX_JSON_SIZE) {
        return {
          valid: false,
          error: {
            code: 'JSON_TOO_LARGE',
            message: 'JSON payload too large',
            statusCode: 413
          }
        };
      }
      
      // Parse JSON
      const data = JSON.parse(text);
      
      // Basic structure validation
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        return {
          valid: false,
          error: {
            code: 'INVALID_JSON_STRUCTURE',
            message: 'JSON must be an object',
            statusCode: 400
          }
        };
      }
      
      return { valid: true, data };
      
    } catch (error) {
      return {
        valid: false,
        error: {
          code: 'INVALID_JSON',
          message: 'Invalid JSON format',
          statusCode: 400
        }
      };
    }
  }
  
  /**
   * Validate HTTP method
   */
  static validateMethod(request: Request, allowedMethods: string[]): { valid: boolean; error?: AuthError } {
    if (!allowedMethods.includes(request.method)) {
      return {
        valid: false,
        error: {
          code: 'METHOD_NOT_ALLOWED',
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
  static extractBearerToken(request: Request): { valid: boolean; token?: string; error?: AuthError } {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader) {
      return {
        valid: false,
        error: AUTH_ERRORS.TOKEN_INVALID
      };
    }
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
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
}

/**
 * Security Headers Manager
 * Comprehensive security headers implementation
 */
export class SecurityHeadersManager {
  /**
   * Generate Content Security Policy header value
   */
  private static generateCSP(): string {
    const directives = Object.entries(SECURITY_CONFIG.CSP_DIRECTIVES)
      .map(([directive, value]) => `${directive} ${value}`)
      .join('; ');
    
    return directives;
  }
  
  /**
   * Get all security headers
   */
  static getSecurityHeaders(): Record<string, string> {
    const headers = { ...SECURITY_CONFIG.SECURITY_HEADERS };
    headers['Content-Security-Policy'] = this.generateCSP();
    
    return headers;
  }
  
  /**
   * Add security headers to response
   */
  static addSecurityHeaders(response: Response): Response {
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
}

/**
 * Authentication Middleware
 * JWT verification and user authentication
 */
export class AuthMiddleware {
  private jwtSecret: string;
  
  constructor(jwtSecret: string) {
    this.jwtSecret = jwtSecret;
  }
  
  /**
   * Verify JWT token and extract user information
   */
  async verifyToken(request: Request): Promise<{ valid: boolean; payload?: JWTPayload; error?: AuthError }> {
    const tokenResult = RequestValidator.extractBearerToken(request);
    
    if (!tokenResult.valid) {
      return { valid: false, error: tokenResult.error };
    }
    
    try {
      const payload = await JWTManager.verify(tokenResult.token!, this.jwtSecret);
      
      // Additional payload validation
      if (payload.type !== 'access') {
        return {
          valid: false,
          error: {
            code: 'INVALID_TOKEN_TYPE',
            message: 'Invalid token type for this endpoint',
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
    return async (request: Request): Promise<{ authorized: boolean; userId?: string; error?: Response }> => {
      const result = await this.verifyToken(request);
      
      if (!result.valid) {
        return {
          authorized: false,
          error: AuthUtils.createErrorResponse(result.error!)
        };
      }
      
      return {
        authorized: true,
        userId: result.payload!.userId
      };
    };
  }
}

/**
 * Security Monitoring and Logging
 * Structured logging for security events
 */
export class SecurityLogger {
  /**
   * Log authentication event
   */
  static logAuthEvent(
    event: 'login_attempt' | 'login_success' | 'login_failure' | 'token_refresh' | 'logout',
    details: {
      userId?: string;
      email?: string;
      ipAddress?: string;
      userAgent?: string;
      reason?: string;
      timestamp?: number;
    }
  ): void {
    const logEntry = {
      type: 'auth_event',
      event,
      timestamp: details.timestamp || Date.now(),
      ...details
    };
    
    // In production, send to your logging service
    console.log(JSON.stringify(logEntry));
  }
  
  /**
   * Log security event
   */
  static logSecurityEvent(
    event: 'rate_limit_exceeded' | 'invalid_origin' | 'suspicious_request' | 'auth_failure',
    details: {
      ipAddress?: string;
      userAgent?: string;
      endpoint?: string;
      reason?: string;
      severity?: 'low' | 'medium' | 'high' | 'critical';
      timestamp?: number;
    }
  ): void {
    const logEntry = {
      type: 'security_event',
      event,
      timestamp: details.timestamp || Date.now(),
      severity: details.severity || 'medium',
      ...details
    };
    
    // In production, send to your security monitoring service
    console.log(JSON.stringify(logEntry));
  }
  
  /**
   * Log rate limit event
   */
  static logRateLimitEvent(
    identifier: string,
    endpoint: string,
    state: RateLimitState,
    allowed: boolean
  ): void {
    this.logSecurityEvent('rate_limit_exceeded', {
      ipAddress: identifier,
      endpoint,
      reason: `Rate limit ${allowed ? 'approached' : 'exceeded'}: ${state.count} requests`,
      severity: allowed ? 'low' : 'medium'
    });
  }
}

/**
 * Complete Security Middleware Stack
 * Combines all security measures into a single middleware
 */
export class SecurityMiddleware {
  private rateLimiter: EdgeRateLimiter;
  private corsHandler: CORSHandler;
  private authMiddleware?: AuthMiddleware;
  
  constructor(
    kvNamespace?: KVNamespace,
    jwtSecret?: string,
    corsOptions?: { origins?: string[]; credentials?: boolean }
  ) {
    this.rateLimiter = new EdgeRateLimiter(kvNamespace);
    this.corsHandler = new CORSHandler(corsOptions?.origins, corsOptions?.credentials);
    
    if (jwtSecret) {
      this.authMiddleware = new AuthMiddleware(jwtSecret);
    }
  }
  
  /**
   * Apply all security checks to a request
   */
  async applySecurityChecks(
    request: Request,
    options: {
      rateLimitConfig?: RateLimitConfig;
      requireAuth?: boolean;
      allowedMethods?: string[];
      endpoint?: string;
    } = {}
  ): Promise<{
    allowed: boolean;
    response?: Response;
    userId?: string;
    rateLimitState?: RateLimitState;
  }> {
    const origin = request.headers.get('Origin');
    const clientIP = AuthUtils.getClientIP(request) || 'unknown';
    const endpoint = options.endpoint || 'default';
    
    try {
      // Handle CORS preflight
      if (request.method === 'OPTIONS') {
        return {
          allowed: true,
          response: this.corsHandler.handlePreflight(request)
        };
      }
      
      // Validate HTTP method
      if (options.allowedMethods) {
        const methodResult = RequestValidator.validateMethod(request, options.allowedMethods);
        if (!methodResult.valid) {
          const response = AuthUtils.createErrorResponse(methodResult.error!);
          return {
            allowed: false,
            response: SecurityHeadersManager.addSecurityHeaders(response)
          };
        }
      }
      
      // Validate request size
      const sizeResult = RequestValidator.validateRequestSize(request);
      if (!sizeResult.valid) {
        const response = AuthUtils.createErrorResponse(sizeResult.error!);
        return {
          allowed: false,
          response: SecurityHeadersManager.addSecurityHeaders(response)
        };
      }
      
      // Apply rate limiting
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
          headers.set('Retry-After', Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000).toString());
          
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
      
      // Apply authentication if required
      let userId: string | undefined;
      if (options.requireAuth && this.authMiddleware) {
        const authResult = await this.authMiddleware.createMiddleware()(request);
        if (!authResult.authorized) {
          SecurityLogger.logAuthEvent('login_failure', {
            ipAddress: clientIP,
            userAgent: AuthUtils.getUserAgent(request),
            reason: 'Invalid or missing token'
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
        rateLimitState: options.rateLimitConfig ? 
          (await this.rateLimiter.checkRateLimit(clientIP, endpoint, options.rateLimitConfig)).state : 
          undefined
      };
      
    } catch (error) {
      console.error('Security middleware error:', error);
      SecurityLogger.logSecurityEvent('suspicious_request', {
        ipAddress: clientIP,
        endpoint,
        reason: 'Security middleware error',
        severity: 'high'
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
  wrapResponse(response: Response, request: Request): Response {
    const origin = request.headers.get('Origin');
    
    // Add CORS headers
    const corsResponse = this.corsHandler.addCORSHeaders(response, origin);
    
    // Add security headers
    return SecurityHeadersManager.addSecurityHeaders(corsResponse);
  }
}

/**
 * Helper Functions for Common Security Tasks
 */
export class SecurityHelpers {
  /**
   * Create a secure response with proper headers
   */
  static createSecureResponse(
    data: any,
    status: number = 200,
    additionalHeaders: Record<string, string> = {}
  ): Response {
    const headers = {
      'Content-Type': 'application/json',
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
  static async validateRequest<T>(
    request: Request,
    validator: (data: any) => { isValid: boolean; data?: T; errors: string[] }
  ): Promise<{ valid: boolean; data?: T; response?: Response }> {
    // Validate content type
    const contentTypeResult = RequestValidator.validateContentType(request);
    if (!contentTypeResult.valid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse(contentTypeResult.error!)
      };
    }
    
    // Parse JSON
    const jsonResult = await RequestValidator.parseAndValidateJSON(request);
    if (!jsonResult.valid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse(jsonResult.error!)
      };
    }
    
    // Validate data structure
    const validationResult = validator(jsonResult.data);
    if (!validationResult.isValid) {
      return {
        valid: false,
        response: AuthUtils.createErrorResponse({
          code: 'VALIDATION_ERROR',
          message: validationResult.errors.join('; '),
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
  static extractRequestMetadata(request: Request): {
    ipAddress?: string;
    userAgent?: string;
    origin?: string;
    timestamp: number;
  } {
    return {
      ipAddress: AuthUtils.getClientIP(request),
      userAgent: AuthUtils.getUserAgent(request),
      origin: request.headers.get('Origin') || undefined,
      timestamp: Date.now()
    };
  }
}

// All classes are already exported above with individual export statements