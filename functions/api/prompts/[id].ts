/**
 * Individual Prompt Management API Endpoints
 * 
 * Handle operations on specific prompts by ID:
 * - PUT: Update existing prompt (title, favorite status, optional fields)
 * - DELETE: Delete prompt with ownership validation
 * - Comprehensive security and ownership validation
 * - Performance-optimized for edge environments
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../../lib/security';

import { 
  AuthUtils, 
  AUTH_ERRORS, 
  InputValidator 
} from '../../../lib/auth-utils';

import { 
  PromptsDatabase, 
  PromptError,
  type UpdatePromptData 
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
  params: {
    id: string;
  };
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

/**
 * Input validation for prompt updates
 */
class PromptUpdateValidator {
  /**
   * Validate PUT request data for updating prompts
   */
  static validateUpdatePromptRequest(data: any): {
    isValid: boolean;
    data?: UpdatePromptData;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      return { isValid: false, errors: ['Invalid request data structure'] };
    }

    // Check that at least one field is provided for update
    const allowedFields = ['title', 'isFavorite', 'expertRole', 'mission', 'constraints'];
    const providedFields = Object.keys(data);
    const validFields = providedFields.filter(field => allowedFields.includes(field));

    if (validFields.length === 0) {
      errors.push('At least one field must be provided for update');
    }

    // Check for unexpected fields
    const unexpectedFields = providedFields.filter(field => !allowedFields.includes(field));
    if (unexpectedFields.length > 0) {
      errors.push(`Unexpected fields: ${unexpectedFields.join(', ')}`);
    }

    // Validate each provided field
    if ('title' in data) {
      if (data.title !== null && (typeof data.title !== 'string' || data.title.length > 100)) {
        errors.push('title must be a string with maximum 100 characters or null');
      }
    }

    if ('isFavorite' in data) {
      if (typeof data.isFavorite !== 'boolean') {
        errors.push('isFavorite must be a boolean');
      }
    }

    if ('expertRole' in data) {
      if (data.expertRole !== null && data.expertRole !== undefined) {
        if (typeof data.expertRole !== 'string' || data.expertRole.length > 200) {
          errors.push('expertRole must be a string with maximum 200 characters or null');
        }
      }
    }

    if ('mission' in data) {
      if (data.mission !== null && data.mission !== undefined) {
        if (typeof data.mission !== 'string' || data.mission.length > 500) {
          errors.push('mission must be a string with maximum 500 characters or null');
        }
      }
    }

    if ('constraints' in data) {
      if (data.constraints !== null && data.constraints !== undefined) {
        if (typeof data.constraints !== 'string' || data.constraints.length > 1000) {
          errors.push('constraints must be a string with maximum 1000 characters or null');
        }
      }
    }

    if (errors.length > 0) {
      return { isValid: false, errors };
    }

    // Sanitize string inputs
    const sanitizedData: UpdatePromptData = {};

    if ('title' in data) {
      sanitizedData.title = data.title ? InputValidator.sanitizeInput(data.title) : data.title;
    }

    if ('isFavorite' in data) {
      sanitizedData.isFavorite = data.isFavorite;
    }

    if ('expertRole' in data) {
      sanitizedData.expertRole = data.expertRole ? InputValidator.sanitizeInput(data.expertRole) : data.expertRole;
    }

    if ('mission' in data) {
      sanitizedData.mission = data.mission ? InputValidator.sanitizeInput(data.mission) : data.mission;
    }

    if ('constraints' in data) {
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
}

/**
 * PUT /api/prompts/[id] - Update existing prompt
 */
export const onRequestPut: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env, params } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts_update',
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
    const idValidation = PromptUpdateValidator.validatePromptId(params.id);
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
      allowedMethods: ['PUT'],
      endpoint: 'prompts_update'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);

    // Validate and sanitize input
    const validationResult = await SecurityHelpers.validateRequest<UpdatePromptData>(
      request,
      PromptUpdateValidator.validateUpdatePromptRequest
    );

    if (!validationResult.valid) {
      SecurityLogger.logSecurityEvent('invalid_request', {
        endpoint: 'prompts_update',
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid update prompt request data',
        severity: 'low'
      });

      return security.wrapResponse(validationResult.response!, request);
    }

    const updateData = validationResult.data!;

    // Update the prompt
    const updatedPrompt = await db.updatePrompt(promptId, userId, updateData);

    if (!updatedPrompt) {
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: 'PROMPT_NOT_FOUND',
          message: 'Prompt not found or access denied',
          statusCode: 404
        }),
        request
      );
    }

    // Log successful update
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_update',
      ipAddress: clientIP,
      userAgent,
      reason: `Updated prompt ${promptId}`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      message: 'Prompt updated successfully',
      data: {
        prompt: updatedPrompt
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
        endpoint: 'prompts_update',
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
      endpoint: 'prompts_update',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to update prompt',
      statusCode: 500,
      ...(isDevelopment && {
        details: error instanceof Error ? error.message : 'Unknown error'
      })
    });
  }
};

/**
 * DELETE /api/prompts/[id] - Delete prompt
 */
export const onRequestDelete: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env, params } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts_delete',
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
    const idValidation = PromptUpdateValidator.validatePromptId(params.id);
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
      allowedMethods: ['DELETE'],
      endpoint: 'prompts_delete'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);

    // Delete the prompt
    const deleted = await db.deletePrompt(promptId, userId);

    if (!deleted) {
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: 'PROMPT_NOT_FOUND',
          message: 'Prompt not found or access denied',
          statusCode: 404
        }),
        request
      );
    }

    // Log successful deletion
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_delete',
      ipAddress: clientIP,
      userAgent,
      reason: `Deleted prompt ${promptId}`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      message: 'Prompt deleted successfully',
      data: {
        deletedId: promptId
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
        endpoint: 'prompts_delete',
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
      endpoint: 'prompts_delete',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to delete prompt',
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
      allowedMethods: ['PUT', 'DELETE', 'OPTIONS'],
      endpoint: 'prompts_individual'
    });

    return security.wrapResponse(securityResult.response!, request);

  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};