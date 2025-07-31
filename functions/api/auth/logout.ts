/**
 * Authentication Logout Endpoint
 * 
 * Secure logout implementation with comprehensive session management:
 * - JWT token invalidation through session revocation
 * - Database session cleanup with detailed tracking
 * - Support for single device logout and "logout all devices"
 * - Comprehensive security logging for audit trails
 * - Rate limiting to prevent logout abuse
 * - Proper error handling and response standardization
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../lib/security';

import { 
  JWTManager, 
  AuthUtils, 
  AUTH_ERRORS, 
  AUTH_CONFIG 
} from '../../../lib/auth-utils';

import type { 
  JWTPayload 
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
 * Logout request payload interface
 */
interface LogoutRequest {
  logoutAllDevices?: boolean; // Optional flag to logout from all devices
}

/**
 * Database Operations for Session Management
 */
class SessionDatabase {
  constructor(private db: D1Database) {}

  /**
   * Revoke specific session by access token
   */
  async revokeSessionByToken(accessToken: string, reason: string = 'user_logout'): Promise<boolean> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = ?
      WHERE access_token = ? AND is_revoked = 0
    `);
    
    const result = await stmt.bind(reason, accessToken).run();
    return result.changes > 0;
  }

  /**
   * Revoke all active sessions for a user
   */
  async revokeAllUserSessions(userId: string, reason: string = 'logout_all_devices'): Promise<number> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = ?
      WHERE user_id = ? AND is_revoked = 0
    `);
    
    const result = await stmt.bind(reason, userId).run();
    return result.changes;
  }

  /**
   * Get session details for logging purposes
   */
  async getSessionDetails(accessToken: string): Promise<any | null> {
    const stmt = this.db.prepare(`
      SELECT 
        s.id, s.user_id, s.created_at, s.last_used_at, 
        s.ip_address, s.user_agent, s.device_fingerprint,
        u.email
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.access_token = ? AND s.is_revoked = 0
    `);
    
    return await stmt.bind(accessToken).first();
  }

  /**
   * Count active sessions for a user
   */
  async countActiveSessions(userId: string): Promise<number> {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count
      FROM sessions 
      WHERE user_id = ? AND is_revoked = 0 AND expires_at > datetime('now')
    `);
    
    const result = await stmt.bind(userId).first();
    return result?.count || 0;
  }

  /**
   * Clean up expired sessions (maintenance operation)
   */
  async cleanupExpiredSessions(): Promise<number> {
    const stmt = this.db.prepare(`
      UPDATE sessions 
      SET 
        is_revoked = 1,
        revoked_at = datetime('now'),
        revoked_reason = 'expired'
      WHERE expires_at <= datetime('now') AND is_revoked = 0
    `);
    
    const result = await stmt.run();
    return result.changes;
  }
}

/**
 * Input validation for logout request
 */
class LogoutValidator {
  /**
   * Validate logout request payload
   */
  static validateLogoutRequest(data: any): { isValid: boolean; request?: LogoutRequest; errors: string[] } {
    const errors: string[] = [];
    
    // Data is optional, but if provided, validate structure
    if (data !== null && data !== undefined) {
      if (typeof data !== 'object' || Array.isArray(data)) {
        return { isValid: false, errors: ['Invalid request data structure'] };
      }
      
      // Validate logoutAllDevices if provided
      if ('logoutAllDevices' in data) {
        if (typeof data.logoutAllDevices !== 'boolean') {
          errors.push('logoutAllDevices must be a boolean value');
        }
      }
      
      // Check for unexpected fields
      const allowedFields = ['logoutAllDevices'];
      const providedFields = Object.keys(data);
      const unexpectedFields = providedFields.filter(field => !allowedFields.includes(field));
      
      if (unexpectedFields.length > 0) {
        errors.push(`Unexpected fields: ${unexpectedFields.join(', ')}`);
      }
    }
    
    if (errors.length > 0) {
      return { isValid: false, errors };
    }
    
    return {
      isValid: true,
      request: {
        logoutAllDevices: data?.logoutAllDevices || false
      },
      errors: []
    };
  }
}

/**
 * Main logout handler with comprehensive security
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  
  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('auth_failure', {
      endpoint: 'logout',
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
    const db = new SessionDatabase(env.DB);
    
    // Initialize security middleware
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    
    // Apply comprehensive security checks (authentication required)
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API, // Use general API rate limiting
      requireAuth: true, // Logout requires valid authentication
      allowedMethods: ['POST'],
      endpoint: 'logout'
    });
    
    if (!securityResult.allowed) {
      SecurityLogger.logSecurityEvent('rate_limit_exceeded', {
        endpoint: 'logout',
        ipAddress: AuthUtils.getClientIP(request),
        severity: 'medium'
      });
      
      return security.wrapResponse(securityResult.response!, request);
    }

    // Extract client information for security tracking
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    const userId = securityResult.userId!; // Available because requireAuth: true

    // Extract access token from Authorization header for session lookup
    const authHeader = request.headers.get('Authorization');
    const accessToken = authHeader?.split(' ')[1]; // Bearer token format

    if (!accessToken) {
      SecurityLogger.logAuthEvent('logout', {
        userId,
        ipAddress: clientIP,
        userAgent,
        reason: 'Missing access token'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.TOKEN_INVALID),
        request
      );
    }

    // Get session details for logging before revoking
    const sessionDetails = await db.getSessionDetails(accessToken);
    
    // Validate and sanitize input (optional for logout)
    let logoutRequest: LogoutRequest = { logoutAllDevices: false };
    
    if (request.headers.get('Content-Type')?.includes('application/json')) {
      const validationResult = await SecurityHelpers.validateRequest<LogoutRequest>(
        request,
        LogoutValidator.validateLogoutRequest
      );
      
      if (!validationResult.valid) {
        SecurityLogger.logAuthEvent('logout', {
          userId,
          ipAddress: clientIP,
          userAgent,
          reason: 'Invalid logout request data'
        });
        
        return security.wrapResponse(validationResult.response!, request);
      }
      
      logoutRequest = validationResult.data!;
    }

    // Perform logout operations
    let revokedSessionsCount = 0;
    let logoutType = 'single_device';
    
    if (logoutRequest.logoutAllDevices) {
      // Logout from all devices
      revokedSessionsCount = await db.revokeAllUserSessions(userId, 'logout_all_devices');
      logoutType = 'all_devices';
    } else {
      // Logout from current device only
      const revoked = await db.revokeSessionByToken(accessToken, 'user_logout');
      revokedSessionsCount = revoked ? 1 : 0;
    }

    // Background cleanup of expired sessions (don't wait for completion)
    context.waitUntil(db.cleanupExpiredSessions());

    // Get remaining active sessions count for response
    const remainingSessionsCount = await db.countActiveSessions(userId);

    // Log successful logout
    SecurityLogger.logAuthEvent('logout', {
      userId,
      email: sessionDetails?.email,
      ipAddress: clientIP,
      userAgent,
      reason: `Successful ${logoutType} logout`
    });

    // Log security event for monitoring
    SecurityLogger.logSecurityEvent('auth_failure', {
      endpoint: 'logout',
      ipAddress: clientIP,
      userAgent,
      reason: `User logged out (${logoutType}): ${revokedSessionsCount} sessions revoked`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      message: logoutRequest.logoutAllDevices 
        ? 'Successfully logged out from all devices' 
        : 'Successfully logged out',
      data: {
        logoutType,
        revokedSessions: revokedSessionsCount,
        remainingSessions: remainingSessionsCount,
        timestamp: Date.now()
      }
    };

    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData),
      request
    );

  } catch (error) {
    // Secure error handling with logging
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'logout',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';
    
    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to process logout request',
      statusCode: 500,
      ...(isDevelopment && { 
        details: error instanceof Error ? error.message : 'Unknown error' 
      })
    });
  }
};

/**
 * Handle OPTIONS request for CORS preflight
 */
export const onRequestOptions: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  
  try {
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);
    
    const securityResult = await security.applySecurityChecks(request, {
      allowedMethods: ['POST', 'OPTIONS'],
      endpoint: 'logout'
    });
    
    return security.wrapResponse(securityResult.response!, request);
    
  } catch (error) {
    return new Response(null, { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};