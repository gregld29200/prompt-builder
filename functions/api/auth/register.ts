/**
 * Authentication Registration Endpoint
 * 
 * Secure user registration implementation with comprehensive security measures:
 * - Rate limiting to prevent abuse
 * - Strong password validation (OWASP compliant)
 * - Email validation and sanitization
 * - Duplicate email prevention
 * - Secure password hashing using edge-optimized bcrypt
 * - Comprehensive security logging
 * - Input sanitization to prevent injection attacks
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
  PasswordValidator,
  AuthUtils, 
  AUTH_ERRORS 
} from '../../../lib/auth-utils';

import type { 
  AuthUser, 
  RegisterRequest, 
  AuthTokens, 
  Session 
} from '../../../types';

// Cloudflare Pages Functions context interface
interface EventContext {
  request: Request;
  env: {
    DB: D1Database;
    RATE_LIMITER: KVNamespace; // Primary KV binding name matching namespace title
    JWT_SECRET: string;
    ENVIRONMENT?: string;
    [key: string]: any; // Allow for dynamic binding discovery
  };
  params: any;
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

/**
 * Database Operations for User Registration
 */
class RegisterDatabase {
  constructor(private db: D1Database) {}

  /**
   * Check if user exists by email
   */
  async userExists(email: string): Promise<boolean> {
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
  async createUser(email: string, passwordHash: string, ipAddress?: string): Promise<string> {
    // Generate UUID for user
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
      0, // email_verified - false by default
      1, // is_active - true by default
      0  // failed_login_attempts - start at 0
    ).run();
    
    return userId;
  }

  /**
   * Create initial session for newly registered user
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
}

/**
 * Main registration handler with comprehensive security
 */
export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;
  
  // DEBUGGING: Comprehensive environment inspection
  console.log('=== ENVIRONMENT DEBUG START ===');
  console.log('Full env object keys:', Object.keys(env));
  console.log('env.JWT_SECRET exists:', !!env.JWT_SECRET);
  console.log('env.JWT_SECRET type:', typeof env.JWT_SECRET);
  console.log('env.DB exists:', !!env.DB);
  console.log('env.DB type:', typeof env.DB);
  console.log('env.KV exists:', !!env.KV);
  console.log('env.KV type:', typeof env.KV);
  console.log('env.ENVIRONMENT:', env.ENVIRONMENT);
  
  // Check for alternative binding names that might exist
  const allEnvKeys = Object.keys(env);
  console.log('All environment keys:', allEnvKeys);
  
  // Look for any database-related bindings
  const dbKeys = allEnvKeys.filter(key => key.toLowerCase().includes('db') || key.toLowerCase().includes('database'));
  console.log('Database-related keys:', dbKeys);
  
  // Look for any KV-related bindings
  const kvKeys = allEnvKeys.filter(key => key.toLowerCase().includes('kv') || key.toLowerCase().includes('rate'));
  console.log('KV-related keys:', kvKeys);
  
  // Check for secret-related bindings
  const secretKeys = allEnvKeys.filter(key => key.toLowerCase().includes('secret') || key.toLowerCase().includes('jwt'));
  console.log('Secret-related keys:', secretKeys);
  console.log('=== ENVIRONMENT DEBUG END ===');
  
  // Enhanced validation with detailed error reporting
  const missingBindings = [];
  if (!env.JWT_SECRET) missingBindings.push('JWT_SECRET');
  if (!env.DB) missingBindings.push('DB');
  
  if (missingBindings.length > 0) {
    const errorDetails = {
      endpoint: 'register',
      reason: `Missing environment bindings: ${missingBindings.join(', ')}`,
      severity: 'critical',
      availableKeys: Object.keys(env),
      contextInfo: {
        functionPath: context.functionPath,
        environment: env.ENVIRONMENT || 'unknown'
      }
    };
    
    console.error('CONFIG_ERROR Details:', errorDetails);
    
    SecurityLogger.logSecurityEvent('auth_failure', errorDetails);
    
    return AuthUtils.createErrorResponse({
      code: 'CONFIG_ERROR',
      message: 'Service temporarily unavailable',
      statusCode: 503,
      // In development, include diagnostic info
      ...(env.ENVIRONMENT === 'development' && {
        debug: {
          missingBindings,
          availableKeys: Object.keys(env),
          functionPath: context.functionPath
        }
      })
    });
  }

  try {
    const db = new RegisterDatabase(env.DB);
    
    // Initialize security middleware with correct KV binding
    const kvNamespace = env.RATE_LIMITER;
    console.log('Using KV namespace RATE_LIMITER:', kvNamespace ? 'Available' : 'Not available');
    const security = new SecurityMiddleware(kvNamespace, env.JWT_SECRET);
    
    // Apply comprehensive security checks with strict rate limiting for registration
    const securityResult = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.REGISTER,
      requireAuth: false, // Registration doesn't require existing auth
      allowedMethods: ['POST'],
      endpoint: 'register'
    });
    
    if (!securityResult.allowed) {
      SecurityLogger.logSecurityEvent('rate_limit_exceeded', {
        endpoint: 'register',
        ipAddress: AuthUtils.getClientIP(request),
        severity: 'medium'
      });
      
      return security.wrapResponse(securityResult.response!, request);
    }

    // Extract client information for security tracking
    const clientIP = AuthUtils.getClientIP(request);
    const userAgent = AuthUtils.getUserAgent(request);
    
    // Validate and sanitize input with comprehensive registration validation
    const validationResult = await SecurityHelpers.validateRequest<RegisterRequest>(
      request,
      InputValidator.validateRegisterRequest
    );
    
    if (!validationResult.valid) {
      SecurityLogger.logAuthEvent('registration_failure', {
        ipAddress: clientIP,
        userAgent,
        reason: 'Invalid input data'
      });
      
      return security.wrapResponse(validationResult.response!, request);
    }
    
    const { email, password } = validationResult.data!;
    
    // Additional password strength validation (belt and suspenders approach)
    const passwordValidation = PasswordValidator.validate(password);
    if (!passwordValidation.isValid) {
      SecurityLogger.logAuthEvent('registration_failure', {
        email,
        ipAddress: clientIP,
        userAgent,
        reason: 'Weak password'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse({
          code: 'WEAK_PASSWORD',
          message: passwordValidation.errors.join('; '),
          statusCode: 400
        }),
        request
      );
    }

    // Check if user already exists
    const userExists = await db.userExists(email);
    if (userExists) {
      SecurityLogger.logAuthEvent('registration_failure', {
        email,
        ipAddress: clientIP,
        userAgent,
        reason: 'User already exists'
      });
      
      return security.wrapResponse(
        AuthUtils.createErrorResponse(AUTH_ERRORS.USER_EXISTS),
        request
      );
    }

    // Hash password securely
    const passwordHash = await EdgeBcrypt.hash(password);
    
    // Create user record
    const userId = await db.createUser(email, passwordHash, clientIP);

    // Create authenticated user object
    const authUser: AuthUser = {
      id: userId,
      email: email,
      isActive: true,
      lastLoginAt: Date.now()
    };

    // Generate JWT tokens for immediate login after registration
    const tokens: AuthTokens = await JWTManager.generateTokens(authUser, env.JWT_SECRET);
    
    // Create session record
    const session: Session = SessionManager.createSession(
      userId,
      tokens,
      clientIP,
      userAgent
    );

    // Store session in database
    await db.createSession(session);

    // Log successful registration
    SecurityLogger.logAuthEvent('registration_success', {
      userId,
      email,
      ipAddress: clientIP,
      userAgent
    });

    // Return success response with tokens (auto-login after registration)
    const responseData = {
      success: true,
      message: 'Registration successful',
      user: {
        id: authUser.id,
        email: authUser.email,
        isActive: authUser.isActive,
        emailVerified: false // New accounts start unverified
      },
      tokens: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt
      }
    };

    return security.wrapResponse(
      SecurityHelpers.createSecureResponse(responseData, 201), // 201 Created
      request
    );

  } catch (error) {
    // Secure error handling with logging
    SecurityLogger.logSecurityEvent('api_error', {
      endpoint: 'register',
      ipAddress: AuthUtils.getClientIP(request),
      reason: error instanceof Error ? error.message : 'Unknown error',
      severity: 'high'
    });

    // Check for specific database errors
    if (error instanceof Error) {
      // SQLite unique constraint violation
      if (error.message.includes('UNIQUE constraint failed')) {
        return AuthUtils.createErrorResponse(AUTH_ERRORS.USER_EXISTS);
      }
      
      // Other database errors
      if (error.message.includes('database')) {
        return AuthUtils.createErrorResponse({
          code: 'DATABASE_ERROR',
          message: 'Unable to create account at this time',
          statusCode: 503
        });
      }
    }

    const isDevelopment = env.ENVIRONMENT === 'development';
    
    return AuthUtils.createErrorResponse({
      code: 'INTERNAL_ERROR',
      message: 'Unable to process registration request',
      statusCode: 500,
      ...(isDevelopment && { 
        details: error instanceof Error ? error.message : 'Unknown error' 
      })
    });
  }
};