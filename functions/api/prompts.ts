/**
 * Prompts Management API Endpoints
 * 
 * Comprehensive CRUD operations for the prompts system with:
 * - GET: Fetch user's prompts with pagination, filtering, sorting, and search
 * - POST: Create new prompts with auto-generated titles and validation
 * - Secure authentication and authorization for all operations
 * - Rate limiting and comprehensive error handling
 * - Performance-optimized queries for edge environments
 * - Comprehensive input validation and sanitization
 */

import { 
  SecurityMiddleware, 
  RATE_LIMIT_CONFIGS, 
  SecurityHelpers, 
  SecurityLogger 
} from '../../lib/security';

import { 
  AuthUtils, 
  AUTH_ERRORS, 
  InputValidator 
} from '../../lib/auth-utils';

import { 
  PromptsDatabase, 
  PromptError,
  type CreatePromptData,
  type PromptFilters,
  type PaginationOptions 
} from '../../lib/prompts-db';

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
 * Input validation for prompts queries
 */
class PromptsValidator {
  /**
   * Validate GET query parameters
   */
  static validateGetPromptsQuery(searchParams: URLSearchParams): {
    isValid: boolean;
    filters?: PromptFilters;
    pagination?: PaginationOptions;
    errors: string[];
  } {
    const errors: string[] = [];
    const filters: PromptFilters = {};
    const pagination: PaginationOptions = {};

    // Validate pagination parameters
    if (searchParams.has('page')) {
      const page = parseInt(searchParams.get('page') || '1', 10);
      if (isNaN(page) || page < 1) {
        errors.push('Page must be a positive integer');
      } else {
        pagination.page = page;
      }
    }

    if (searchParams.has('limit')) {
      const limit = parseInt(searchParams.get('limit') || '20', 10);
      if (isNaN(limit) || limit < 1 || limit > 100) {
        errors.push('Limit must be between 1 and 100');
      } else {
        pagination.limit = limit;
      }
    }

    // Validate sorting parameters
    if (searchParams.has('sortBy')) {
      const sortBy = searchParams.get('sortBy');
      if (!['created_at', 'updated_at', 'title', 'is_favorite'].includes(sortBy || '')) {
        errors.push('sortBy must be one of: created_at, updated_at, title, is_favorite');
      } else {
        pagination.sortBy = sortBy as 'created_at' | 'updated_at' | 'title' | 'is_favorite';
      }
    }

    if (searchParams.has('sortOrder')) {
      const sortOrder = searchParams.get('sortOrder')?.toUpperCase();
      if (!['ASC', 'DESC'].includes(sortOrder || '')) {
        errors.push('sortOrder must be ASC or DESC');
      } else {
        pagination.sortOrder = sortOrder as 'ASC' | 'DESC';
      }
    }

    // Validate filter parameters
    if (searchParams.has('domain')) {
      const domain = searchParams.get('domain');
      if (!['education', 'technical', 'creative', 'analysis', 'other'].includes(domain || '')) {
        errors.push('domain must be one of: education, technical, creative, analysis, other');
      } else {
        filters.domain = domain!;
      }
    }

    if (searchParams.has('promptType')) {
      const promptType = searchParams.get('promptType');
      if (!['MVP', 'AGENTIC'].includes(promptType || '')) {
        errors.push('promptType must be MVP or AGENTIC');
      } else {
        filters.promptType = promptType!;
      }
    }

    if (searchParams.has('language')) {
      const language = searchParams.get('language');
      if (!['fr', 'en'].includes(language || '')) {
        errors.push('language must be fr or en');
      } else {
        filters.language = language!;
      }
    }

    if (searchParams.has('isFavorite')) {
      const isFavorite = searchParams.get('isFavorite');
      if (!['true', 'false'].includes(isFavorite || '')) {
        errors.push('isFavorite must be true or false');
      } else {
        filters.isFavorite = isFavorite === 'true';
      }
    }

    if (searchParams.has('search')) {
      const search = searchParams.get('search');
      if (search && search.length > 200) {
        errors.push('search query must be less than 200 characters');
      } else if (search) {
        filters.search = InputValidator.sanitizeInput(search);
      }
    }

    if (errors.length > 0) {
      return { isValid: false, errors };
    }

    return {
      isValid: true,
      filters,
      pagination,
      errors: []
    };
  }

  /**
   * Validate POST request data for creating prompts
   */
  static validateCreatePromptRequest(data: any): {
    isValid: boolean;
    data?: Omit<CreatePromptData, 'userId'>;
    errors: string[];
  } {
    const errors: string[] = [];

    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      return { isValid: false, errors: ['Invalid request data structure'] };
    }

    // Required fields
    if (!data.rawRequest || typeof data.rawRequest !== 'string') {
      errors.push('rawRequest is required and must be a string');
    } else if (data.rawRequest.trim().length === 0) {
      errors.push('rawRequest cannot be empty');
    } else if (data.rawRequest.length > 5000) {
      errors.push('rawRequest exceeds maximum length of 5000 characters');
    }

    if (!data.generatedPrompt || typeof data.generatedPrompt !== 'string') {
      errors.push('generatedPrompt is required and must be a string');
    } else if (data.generatedPrompt.trim().length === 0) {
      errors.push('generatedPrompt cannot be empty');
    } else if (data.generatedPrompt.length > 10000) {
      errors.push('generatedPrompt exceeds maximum length of 10000 characters');
    }

    if (!data.promptType || !['MVP', 'AGENTIC'].includes(data.promptType)) {
      errors.push('promptType is required and must be MVP or AGENTIC');
    }

    if (!data.domain || !['education', 'technical', 'creative', 'analysis', 'other'].includes(data.domain)) {
      errors.push('domain is required and must be one of: education, technical, creative, analysis, other');
    }

    if (!data.language || !['fr', 'en'].includes(data.language)) {
      errors.push('language is required and must be fr or en');
    }

    if (!data.outputLength || !['short', 'medium', 'long'].includes(data.outputLength)) {
      errors.push('outputLength is required and must be short, medium, or long');
    }

    // Optional fields validation
    if (data.title !== undefined) {
      if (typeof data.title !== 'string') {
        errors.push('title must be a string');
      } else if (data.title.length > 100) {
        errors.push('title exceeds maximum length of 100 characters');
      }
    }

    if (data.expertRole !== undefined) {
      if (typeof data.expertRole !== 'string') {
        errors.push('expertRole must be a string');
      } else if (data.expertRole.length > 200) {
        errors.push('expertRole exceeds maximum length of 200 characters');
      }
    }

    if (data.mission !== undefined) {
      if (typeof data.mission !== 'string') {
        errors.push('mission must be a string');
      } else if (data.mission.length > 500) {
        errors.push('mission exceeds maximum length of 500 characters');
      }
    }

    if (data.constraints !== undefined) {
      if (typeof data.constraints !== 'string') {
        errors.push('constraints must be a string');
      } else if (data.constraints.length > 1000) {
        errors.push('constraints exceeds maximum length of 1000 characters');
      }
    }

    if (data.isFavorite !== undefined && typeof data.isFavorite !== 'boolean') {
      errors.push('isFavorite must be a boolean');
    }

    if (errors.length > 0) {
      return { isValid: false, errors };
    }

    // Sanitize string inputs
    const sanitizedData = {
      rawRequest: InputValidator.sanitizeInput(data.rawRequest),
      generatedPrompt: InputValidator.sanitizeInput(data.generatedPrompt),
      promptType: data.promptType,
      domain: data.domain,
      language: data.language,
      outputLength: data.outputLength,
      title: data.title ? InputValidator.sanitizeInput(data.title) : undefined,
      expertRole: data.expertRole ? InputValidator.sanitizeInput(data.expertRole) : undefined,
      mission: data.mission ? InputValidator.sanitizeInput(data.mission) : undefined,
      constraints: data.constraints ? InputValidator.sanitizeInput(data.constraints) : undefined,
      isFavorite: data.isFavorite
    };

    return {
      isValid: true,
      data: sanitizedData,
      errors: []
    };
  }
}

/**
 * GET /api/prompts - Fetch user's prompts with pagination, filtering, and search
 */
export const onRequestGet: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts',
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
      endpoint: 'prompts_get'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);

    // Parse and validate query parameters
    const url = new URL(request.url);
    const searchParams = url.searchParams;

    const validationResult = PromptsValidator.validateGetPromptsQuery(searchParams);
    if (!validationResult.isValid) {
      SecurityLogger.logSecurityEvent('invalid_request', {
        endpoint: 'prompts_get',
        ipAddress: clientIP,
        reason: `Invalid query parameters: ${validationResult.errors.join(', ')}`,
        severity: 'low'
      });

      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: 'VALIDATION_ERROR',
          message: validationResult.errors.join('; '),
          statusCode: 400
        }),
        request
      );
    }

    // Fetch prompts from database
    const result = await db.getUserPrompts(
      userId,
      validationResult.filters || {},
      validationResult.pagination || {}
    );

    // Log successful request
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_get',
      ipAddress: clientIP,
      reason: `Retrieved ${result.prompts.length} prompts`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      data: {
        prompts: result.prompts,
        pagination: result.pagination
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
        endpoint: 'prompts_get',
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
      endpoint: 'prompts_get',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to fetch prompts',
      statusCode: 500,
      ...(isDevelopment && {
        details: error instanceof Error ? error.message : 'Unknown error'
      })
    });
  }
};

/**
 * POST /api/prompts - Create a new prompt
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;

  // Validate environment configuration
  if (!env.JWT_SECRET || !env.DB) {
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'prompts',
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
      allowedMethods: ['POST'],
      endpoint: 'prompts_post'
    });

    if (!securityResult.allowed) {
      return security.wrapResponse(securityResult.response!, request);
    }

    const userId = securityResult.userId!;
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);

    // Validate and sanitize input
    const validationResult = await SecurityHelpers.validateRequest<Omit<CreatePromptData, 'userId'>>(
      request,
      PromptsValidator.validateCreatePromptRequest
    );

    if (!validationResult.valid) {
      SecurityLogger.logSecurityEvent('invalid_request', {
        endpoint: 'prompts_post',
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid create prompt request data',
        severity: 'low'
      });

      return security.wrapResponse(validationResult.response!, request);
    }

    const promptData = validationResult.data!;

    // Create the prompt
    const createData: CreatePromptData = {
      ...promptData,
      userId
    };

    const createdPrompt = await db.createPrompt(createData);

    // Log successful creation
    SecurityLogger.logSecurityEvent('api_success', {
      endpoint: 'prompts_post',
      ipAddress: clientIP,
      userAgent,
      reason: `Created prompt ${createdPrompt.id}`,
      severity: 'low'
    });

    // Return success response
    const responseData = {
      success: true,
      message: 'Prompt created successfully',
      data: {
        prompt: createdPrompt
      }
    };

    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData, 201),
      request
    );

  } catch (error) {
    // Handle known prompt errors
    if (error instanceof PromptError) {
      SecurityLogger.logSecurityEvent('api_error', {
        endpoint: 'prompts_post',
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
      endpoint: 'prompts_post',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    const isDevelopment = env.ENVIRONMENT === 'development';

    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to create prompt',
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
      allowedMethods: ['GET', 'POST', 'OPTIONS'],
      endpoint: 'prompts'
    });

    return security.wrapResponse(securityResult.response!, request);

  } catch (error) {
    return new Response(null, {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};