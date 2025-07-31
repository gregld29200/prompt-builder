/**
 * Prompts Statistics API Endpoint
 * 
 * Provides aggregated statistics about user's prompts:
 * - Total prompts count
 * - Favorite prompts count  
 * - Breakdown by domain, type, and language
 * - Optimized for dashboard and analytics display
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../lib/security';

import { 
  AuthUtils, 
  AUTH_ERRORS 
} from '../../../lib/auth-utils';

import { 
  PromptsDatabase, 
  PromptError 
} from '../../../lib/prompts-db';

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
 * GET /api/prompts/stats - Get user's prompt statistics
 */
export const onRequestGet: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts_stats',
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
    const db = new PromptsDatabase(env.DB);

    // Initialize security middleware
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);

    // Apply comprehensive security checks (authentication required)
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ['GET'],
      endpoint: 'prompts_stats'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);

    // Get user's prompt statistics
    const stats = await db.getUserPromptStats(userId);

    // Log successful request
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_stats',
      ipAddress: clientIP,
      reason: `Retrieved stats for user: ${stats.totalPrompts} total prompts`,
      severity: 'low'
    });

    // Return success response
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
    // Handle known prompt errors
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent('api_error', {
        endpoint: 'prompts_stats',
        ipAddress: AuthUtils.getClientIP(request),
        reason: error.message,
        severity: 'medium'
      });

      return AuthUtils.createErrorResponse({
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      });
    }

    // Handle unknown errors
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts_stats',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to fetch prompt statistics',
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
      allowedMethods: ['GET', 'OPTIONS'],
      endpoint: 'prompts_stats'
    });

    return security.wrapResponse(securityResult.response!, request);

  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};