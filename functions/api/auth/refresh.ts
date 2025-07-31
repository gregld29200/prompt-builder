/**
 * JWT Token Refresh Endpoint
 * 
 * Secure token refresh implementation with comprehensive security measures:
 * - Rate limiting to prevent token abuse
 * - Refresh token validation and verification
 * - Session tracking and management
 * - Token rotation for enhanced security
 * - Comprehensive security logging
 * - Automatic session cleanup
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../lib/security';

import { 
  JWTManager, 
  SessionManager, 
  InputValidator, 
  AuthUtils, 
  AUTH_ERRORS 
} from '../../../lib/auth-utils';

import type { 
  AuthUser, 
  AuthTokens, 
  JWTPayload,
  Session,
  RefreshTokenRequest 
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
 * Database Operations for Token Refresh
 */
class RefreshDatabase {
  constructor(private db: D1Database) {}

  /**
   * Get user by ID with security fields
   */
  async getUserById(userId: string): Promise<any | null> {
    const stmt = this.db.prepare(`
      SELECT 
        id, email, email_verified, is_active,
        failed_login_attempts, locked_until, last_login_at
      FROM users 
      WHERE id = ? AND is_active = 1
    `);
    
    const result = await stmt.bind(userId).first();
    return result;
  }

  /**
   * Get active session by refresh token
   */
  async getSessionByRefreshToken(refreshToken: string): Promise<any | null> {
    const stmt = this.db.prepare(`
      SELECT 
        id, user_id, access_token, refresh_token, expires_at,
        created_at, last_used_at, ip_address, user_agent,
        is_revoked, revoked_at, revoked_reason
      FROM sessions 
      WHERE refresh_token = ? 
      AND is_revoked = 0 
      AND datetime(expires_at) > datetime('now')
    `);
    
    const result = await stmt.bind(refreshToken).first();
    return result;
  }

  /**
   * Update session with new tokens and activity
   */
  async updateSession(sessionId: string, newTokens: AuthTokens, ipAddress?: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        access_token = ?,
        refresh_token = ?,
        expires_at = ?,
        last_used_at = datetime('now'),
        ip_address = COALESCE(?, ip_address)
      WHERE id = ?
    `);
    
    await stmt.bind(
      newTokens.accessToken,
      newTokens.refreshToken,
      new Date(newTokens.expiresAt).toISOString(),
      ipAddress,
      sessionId
    ).run();
  }

  /**
   * Revoke session (for security purposes)
   */
  async revokeSession(sessionId: string, reason: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = ?
      WHERE id = ?
    `);
    
    await stmt.bind(reason, sessionId).run();
  }

  /**
   * Clean up expired sessions (maintenance operation)
   */
  async cleanupExpiredSessions(): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = 'expired'
      WHERE datetime(expires_at) <= datetime('now')
      AND is_revoked = 0
    `);
    
    await stmt.run();
  }
}

/**
 * Validate refresh token request
 */
function validateRefreshTokenRequest(data: any): { isValid: boolean; data?: RefreshTokenRequest; errors: string[] } {
  const errors: string[] = [];
  
  if (!data || typeof data !== 'object') {
    return { isValid: false, errors: ['Invalid request data'] };
  }
  
  if (!data.refreshToken || typeof data.refreshToken !== 'string') {
    errors.push('Refresh token is required');
  } else if (data.refreshToken.trim().length === 0) {
    errors.push('Refresh token cannot be empty');
  } else if (data.refreshToken.length > 2048) { // Reasonable JWT length limit
    errors.push('Refresh token format invalid');
  }
  
  if (errors.length > 0) {
    return { isValid: false, errors };
  }
  
  return {
    isValid: true,
    data: {
      refreshToken: data.refreshToken.trim()
    },
    errors: []
  };
}

/**
 * Main token refresh handler with comprehensive security
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  
  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('auth_failure', {
      endpoint: 'refresh',
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
    const db = new RefreshDatabase(env.DB);
    
    // Initialize security middleware
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    
    // Apply comprehensive security checks
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.REFRESH_TOKEN,
      requireAuth: false, // Refresh doesn't require valid access token
      allowedMethods: ['POST'],
      endpoint: 'refresh'
    });
    
    if (!securityResult.allowed) {
      SecurityLogger.logSecurityEvent('rate_limit_exceeded', {
        endpoint: 'refresh',
        ipAddress: AuthUtils.getClientIP(request),
        severity: 'medium'
      });
      
      return security.wrapResponse(securityResult.response!, request);
    }

    // Extract client information for security tracking
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    
    // Validate and sanitize input
    const validationResult = await SecurityHelpers.validateRequest<RefreshTokenRequest>(
      request,
      validateRefreshTokenRequest
    );
    
    if (!validationResult.valid) {
      SecurityLogger.logAuthEvent('token_refresh_failure', {
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid input data'
      });
      
      return security.wrapResponse(validationResult.response!, request);
    }
    
    const { refreshToken } = validationResult.data!;
    
    // Verify refresh token JWT signature and expiration
    let payload: JWTPayload;
    try {
      payload = await JWTManager.verify(refreshToken, env.JWT_SECRET);
      
      // Validate token type
      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }
    } catch (error) {
      SecurityLogger.logAuthEvent('token_refresh_failure', {
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid refresh token'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.TOKEN_INVALID),
        request
      );
    }

    // Get session from database using refresh token
    const session = await db.getSessionByRefreshToken(refreshToken);
    if (!session) {
      SecurityLogger.logAuthEvent('token_refresh_failure', {
        userId: payload.userId,
        ipAddress: clientIP,
        userAgent,
        reason: 'Session not found or revoked'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.TOKEN_INVALID),
        request
      );
    }

    // Get user information
    const user = await db.getUserById(session.user_id);
    if (!user) {
      // Revoke session if user doesn't exist or is inactive
      await db.revokeSession(session.id, 'user_not_found');
      
      SecurityLogger.logAuthEvent('token_refresh_failure', {
        userId: payload.userId,
        ipAddress: clientIP,
        userAgent,
        reason: 'User not found or inactive'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.USER_NOT_FOUND),
        request
      );
    }

    // Check if account is locked
    if (user.locked_until) {
      const lockUntil = new Date(user.locked_until);
      const now = new Date();
      
      if (lockUntil > now) {
        await db.revokeSession(session.id, 'account_locked');
        
        SecurityLogger.logAuthEvent('token_refresh_failure', {
          userId: user.id,
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

    // Security check: Compare IP addresses for suspicious activity
    if (session.ip_address && clientIP && session.ip_address !== clientIP) {
      SecurityLogger.logSecurityEvent('suspicious_request', {
        userId: user.id,
        endpoint: 'refresh',
        ipAddress: clientIP,
        reason: `IP changed from ${session.ip_address} to ${clientIP}`,
        severity: 'medium'
      });
      
    }

    // Create authenticated user object
    const authUser: AuthUser = {
      id: user.id,
      email: user.email,
      isActive: user.is_active,
      lastLoginAt: user.last_login_at ? new Date(user.last_login_at).getTime() : undefined
    };

    // Generate new JWT tokens (token rotation for security)
    const newTokens: AuthTokens = await JWTManager.generateTokens(authUser, env.JWT_SECRET);
    
    // Update session with new tokens
    await db.updateSession(session.id, newTokens, clientIP);

    // Perform maintenance: cleanup expired sessions
    context.waitUntil(db.cleanupExpiredSessions());

    // Log successful token refresh
    SecurityLogger.logAuthEvent('token_refresh', {
      userId: user.id,
      ipAddress: clientIP,
      userAgent
    });

    // Return success response with new tokens
    const responseData = {
      success: true,
      tokens: {
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        expiresAt: newTokens.expiresAt
      },
      user: {
        id: authUser.id,
        email: authUser.email,
        isActive: authUser.isActive
      }
    };

    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );

  } catch (error) {
    // Secure error handling with logging
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'refresh',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';
    
    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to refresh token',
      statusCode: 500,
      ...(isDevelopment && { 
        details: error instanceof Error ? error.message : 'Unknown error' 
      })
    });
  }
};