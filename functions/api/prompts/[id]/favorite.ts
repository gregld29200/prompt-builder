/**
 * Prompt Favorite Management API Endpoint
 * 
 * Handle favorite status operations for specific prompts:
 * - POST: Toggle favorite status (true/false)
 * - Comprehensive security and ownership validation
 * - Optimized for edge environments with minimal latency
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../../lib/security';

import { 
  AuthUtils, 
  AUTH_ERRORS 
} from '../../../../lib/auth-utils';

import { 
  PromptsDatabase, 
  PromptError 
} from '../../../../lib/prompts-db';

// Cloudflare Pages Functions context interface
interface EventContext {
  request: Request;
  env: {
    DB: D1Database;
    KV?: KVNamespace;
    JWT_SECRET: string;
    ENVIRONMENT?: string;
  };
  params: {
    id: string;
  };
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

/**
 * Input validation for favorite operations
 */
class FavoriteValidator {
  /**
   * Validate prompt ID parameter
   */
  static validatePromptId(id: string): { isValid: boolean; error?: string } {
    if (!id || typeof id !== 'string') {
      return { isValid: false, error: 'Prompt ID is required' };
    }

    // Basic UUID format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return { isValid: false, error: 'Invalid prompt ID format' };
    }

    return { isValid: true };
  }

  /**
   * Validate favorite toggle request (optional body)
   */
  static validateFavoriteRequest(data: any): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // Body is optional for toggle operation
    if (data !== null && data !== undefined) {
      if (typeof data !== 'object' || Array.isArray(data)) {
        errors.push('Request body must be an object if provided');
      } else {
        // Check for unexpected fields
        const allowedFields: string[] = []; // No fields expected for simple toggle
        const providedFields = Object.keys(data);
        const unexpectedFields = providedFields.filter(field => !allowedFields.includes(field));
        
        if (unexpectedFields.length > 0) {
          errors.push(`Unexpected fields: ${unexpectedFields.join(', ')}`);
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

/**
 * POST /api/prompts/[id]/favorite - Toggle favorite status
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env, params } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts_favorite',
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

    // Validate prompt ID parameter
    const idValidation = FavoriteValidator.validatePromptId(params.id);
    if (!idValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: 'INVALID_PROMPT_ID',
        message: idValidation.error!,
        statusCode: 400
      });
    }

    const promptId = params.id;

    // Initialize security middleware
    const security = new SecurityMiddleware(env.KV, env.JWT_SECRET);

    // Apply comprehensive security checks (authentication required)
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.API,
      requireAuth: true,
      allowedMethods: ['POST'],
      endpoint: 'prompts_favorite'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);

    // Validate request body (optional for toggle operation)
    let requestData = null;
    
    if (request.headers.get('Content-Type')?.includes('application/json')) {
      const validationResult = await SecurityHelpers.validateRequest<any>(
        request,
        FavoriteValidator.validateFavoriteRequest
      );

      if (!validationResult.valid) {
        SecurityLogger.logSecurityEvent('invalid_request', {
          endpoint: 'prompts_favorite',
          ipAddress: clientIP,
          userAgent,
          reason: 'Invalid favorite toggle request data',
          severity: 'low'
        });

        return security.wrapResponse(validationResult.response!, request);
      }

      requestData = validationResult.data;
    }

    // Toggle favorite status
    const result = await db.toggleFavorite(promptId, userId);

    // Log successful toggle
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_favorite',
      ipAddress: clientIP,
      userAgent,
      reason: `Toggled favorite for prompt ${promptId} to ${result.isFavorite}`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      message: `Prompt ${result.isFavorite ? 'added to' : 'removed from'} favorites`,
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
    // Handle known prompt errors
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent('api_error', {
        endpoint: 'prompts_favorite',
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
      endpoint: 'prompts_favorite',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to toggle favorite status',
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
      endpoint: 'prompts_favorite'
    });

    return security.wrapResponse(securityResult.response!, request);

  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};