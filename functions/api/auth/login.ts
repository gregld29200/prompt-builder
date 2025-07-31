/**
 * Authentication Login Endpoint
 * 
 * Secure login implementation with comprehensive security measures:
 * - Rate limiting to prevent brute force attacks
 * - Account lockout after failed attempts
 * - Secure password verification using timing-safe comparisons
 * - JWT token generation with refresh token support
 * - Comprehensive security logging
 * - IP and device tracking for security monitoring
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../lib/security';

import { 
  EdgeBcrypt, 
  JWTManager, 
  SessionManager, 
  InputValidator, 
  AuthUtils, 
  AUTH_ERRORS, 
  AUTH_CONFIG 
} from '../../../lib/auth-utils';

import type { 
  AuthUser, 
  LoginRequest, 
  AuthTokens, 
  Session 
} from '../../../types';

// Cloudflare Pages Functions context interface
interface EventContext {
  request: Request;
  env: {
    DB: D1Database;
    KV?: KVNamespace;
    JWT_SECRET: string;
    ENVIRONMENT?: string;
  };
  params: any;
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

/**
 * Database Operations for User Authentication
 */
class AuthDatabase {
  constructor(private db: D1Database) {}

  /**
   * Get user by email with security fields
   */
  async getUserByEmail(email: string): Promise<any | null> {
    const stmt = this.db.prepare(`
      SELECT 
        id, email, password_hash, email_verified, is_active,
        failed_login_attempts, locked_until, last_login_at,
        last_login_ip, created_at, updated_at
      FROM users 
      WHERE email = ? COLLATE NOCASE
    `);
    
    const result = await stmt.bind(email).first();
    return result;
  }

  /**
   * Update user login tracking and reset failed attempts
   */
  async updateSuccessfulLogin(userId: string, ipAddress: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE users 
      SET 
        failed_login_attempts = 0,
        locked_until = NULL,
        last_login_at = datetime('now'),
        last_login_ip = ?,
        updated_at = datetime('now')
      WHERE id = ?
    `);
    
    await stmt.bind(ipAddress, userId).run();
  }

  /**
   * Update failed login attempts and potentially lock account
   */
  async updateFailedLogin(userId: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE users 
      SET 
        failed_login_attempts = failed_login_attempts + 1,
        locked_until = CASE 
          WHEN failed_login_attempts + 1 >= ?
          THEN datetime('now', '+' || ? || ' seconds')
          ELSE locked_until
        END,
        updated_at = datetime('now')
      WHERE id = ?
    `);
    
    await stmt.bind(
      AUTH_CONFIG.MAX_LOGIN_ATTEMPTS,
      AUTH_CONFIG.ACCOUNT_LOCK_DURATION / 1000, // Convert to seconds
      userId
    ).run();
  }

  /**
   * Create new session record
   */
  async createSession(session: Session): Promise<void> {
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
      null, // device_fingerprint - can be enhanced later
      0 // is_revoked
    ).run();
  }

  /**
   * Revoke all existing sessions for user (useful for security)
   */
  async revokeUserSessions(userId: string, reason: string = 'new_login'): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = ?
      WHERE user_id = ? AND is_revoked = 0
    `);
    
    await stmt.bind(reason, userId).run();
  }
}

/**
 * Main login handler with comprehensive security
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  
  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('auth_failure', {
      endpoint: 'login',
      reason: 'Missing environment configuration',
      severity: 'critical'
    });
    
    return AuthUtils.createErrorResponse({
      code: 'CONFIG_ERROR',
      message: 'Service temporarily unavailable',
      statusCode: 503
    });
  }

  try {
    const db = new AuthDatabase(env.DB);
    
    // Initialize security middleware
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    
    // Apply comprehensive security checks
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.LOGIN,
      requireAuth: false, // Login endpoint doesn't require existing auth
      allowedMethods: ['POST'],
      endpoint: 'login'
    });
    
    if (!securityResult.allowed) {
      SecurityLogger.logSecurityEvent('rate_limit_exceeded', {
        endpoint: 'login',
        ipAddress: AuthUtils.getClientIP(request),
        severity: 'medium'
      });
      
      return security.wrapResponse(securityResult.response!, request);
    }

    // Extract client information for security tracking
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    
    // Validate and sanitize input
    const validationResult = await SecurityHelpers.validateRequest<LoginRequest>(
      request,
      InputValidator.validateLoginRequest
    );
    
    if (!validationResult.valid) {
      SecurityLogger.logAuthEvent('login_failure', {
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid input data'
      });
      
      return security.wrapResponse(validationResult.response!, request);
    }
    
    const { email, password } = validationResult.data!;
    
    // Get user from database
    const user = await db.getUserByEmail(email);
    
    if (!user) {
      SecurityLogger.logAuthEvent('login_failure', {
        email,
        ipAddress: clientIP,
        userAgent,
        reason: 'User not found'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.INVALID_CREDENTIALS),
        request
      );
    }

    // Check if account is active
    if (!user.is_active) {
      SecurityLogger.logAuthEvent('login_failure', {
        userId: user.id,
        email,
        ipAddress: clientIP,
        userAgent,
        reason: 'Account disabled'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.ACCOUNT_DISABLED),
        request
      );
    }

    // Check if account is locked
    if (user.locked_until) {
      const lockUntil = new Date(user.locked_until);
      const now = new Date();
      
      if (lockUntil > now) {
        SecurityLogger.logAuthEvent('login_failure', {
          userId: user.id,
          email,
          ipAddress: clientIP,
          userAgent,
          reason: 'Account locked'
        });
        
        return security.wrapResponse(
          AuthUtils.createErrorResponse(AUTH_ERRORS.ACCOUNT_LOCKED),
          request
        );
      }
    }

    // Verify password using timing-safe comparison
    const isValidPassword = await EdgeBcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      // Update failed login attempts
      await db.updateFailedLogin(user.id);
      
      SecurityLogger.logAuthEvent('login_failure', {
        userId: user.id,
        email,
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid password'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.INVALID_CREDENTIALS),
        request
      );
    }

    // Create authenticated user object
    const authUser: AuthUser = {
      id: user.id,
      email: user.email,
      isActive: user.is_active,
      lastLoginAt: user.last_login_at ? new Date(user.last_login_at).getTime() : undefined
    };

    // Generate JWT tokens
    const tokens: AuthTokens = await JWTManager.generateTokens(authUser, env.JWT_SECRET);
    
    // Create session record
    const session: Session = SessionManager.createSession(
      user.id,
      tokens,
      clientIP,
      userAgent
    );

    // Database operations in transaction-like pattern
    await Promise.all([
      db.updateSuccessfulLogin(user.id, clientIP || 'unknown'),
      db.revokeUserSessions(user.id, 'new_login'), // Revoke existing sessions for security
      db.createSession(session)
    ]);

    // Log successful authentication
    SecurityLogger.logAuthEvent('login_success', {
      userId: user.id,
      email,
      ipAddress: clientIP,
      userAgent
    });

    // Return success response with tokens
    const responseData = {
      success: true,
      user: {
        id: authUser.id,
        email: authUser.email,
        isActive: authUser.isActive
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt
      }
    };

    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );

  } catch (error) {
    // Secure error handling with logging
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'login',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';
    
    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to process login request',
      statusCode: 500,
      ...(isDevelopment && { 
        details: error instanceof Error ? error.message : 'Unknown error' 
      })
    });
  }
};