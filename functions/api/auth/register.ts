// Secure registration endpoint with proper password hashing and validation
import { EdgeBcrypt, InputValidator, AuthUtils, AUTH_ERRORS } from '../../../lib/auth-utils.js';
import { SecurityMiddleware, RATE_LIMIT_CONFIGS } from '../../../lib/security.js';

// Simple UUID generator (avoiding external imports)
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

interface RegisterRequest {
  firstName: string;
  email: string;
  password: string;
}

// Remove insecure password and email validation - using secure utilities instead

// Simple JWT creation
async function createJWT(payload: any, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = { ...payload, iat: now, exp: now + 3600 }; // 1 hour
  
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m]);
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m]);
  
  const message = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m]);
  
  return `${message}.${signatureB64}`;
}

export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== SECURE REGISTER ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET || !env.DB) {
      console.log('Missing environment variables');
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
    // Apply rate limiting and security checks
    console.log('Applying security checks and rate limiting...');
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    const securityCheck = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.REGISTER,
      allowedMethods: ['POST'],
      endpoint: 'register'
    });
    
    if (!securityCheck.allowed) {
      console.log('Security check failed - request blocked');
      return security.wrapResponse(securityCheck.response!, request);
    }
    
    console.log('Security checks passed');
    
    // Parse and validate JSON input
    const rawData = await request.json();
    console.log('Received registration data:', { firstName: rawData.firstName, email: rawData.email, hasPassword: !!rawData.password });
    
    // Comprehensive input validation using secure utilities
    if (!rawData.firstName || typeof rawData.firstName !== 'string' || rawData.firstName.trim().length === 0) {
      return AuthUtils.createErrorResponse({
        code: 'MISSING_FIELDS',
        message: 'First name is required',
        statusCode: 400
      });
    }
    
    if (!rawData.email || !rawData.password) {
      return AuthUtils.createErrorResponse({
        code: 'MISSING_FIELDS', 
        message: 'Email and password are required',
        statusCode: 400
      });
    }
    
    // Validate email using secure validator
    const emailValidation = InputValidator.validateEmail(rawData.email);
    if (!emailValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: 'INVALID_EMAIL',
        message: emailValidation.error || 'Invalid email address',
        statusCode: 400
      });
    }
    
    // Validate password strength
    const passwordValidation = InputValidator.validateLoginRequest({ 
      email: emailValidation.sanitized, 
      password: rawData.password 
    });
    if (!passwordValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: 'WEAK_PASSWORD',
        message: passwordValidation.errors.join(', '),
        statusCode: 400
      });
    }
    
    // Sanitize firstName input
    const firstName = InputValidator.sanitizeInput(rawData.firstName);
    const data: RegisterRequest = {
      firstName,
      email: emailValidation.sanitized,
      password: rawData.password
    };
    
    // Check if user exists
    console.log('Checking if user exists...');
    try {
      const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(data.email).first();
      console.log('User check result:', existingUser);
      if (existingUser) {
        return AuthUtils.createErrorResponse({
          code: 'EMAIL_EXISTS',
          message: 'An account with this email already exists',
          statusCode: 409
        });
      }
    } catch (dbError) {
      console.error('Database check error:', dbError);
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
    // Create user with secure password hashing
    console.log('Creating new user...');
    const userId = generateUUID();
    
    // Use secure bcrypt hashing instead of weak SHA-256
    const hashedPassword = await EdgeBcrypt.hash(data.password);
    console.log('Password securely hashed with bcrypt');
    
    const now = new Date().toISOString();
    
    console.log('Inserting user into database...');
    try {
      await env.DB.prepare(`
        INSERT INTO users (id, first_name, email, password_hash, email_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(userId, data.firstName, data.email, hashedPassword, false, now, now).run();
      console.log('User inserted successfully');
    } catch (dbError) {
      console.error('Database insert error:', dbError);
      throw dbError;
    }
    
    // Create JWT
    console.log('Creating JWT token...');
    try {
      const token = await createJWT({ userId, firstName: data.firstName, email: data.email }, env.JWT_SECRET);
      console.log('JWT created successfully');
      
      console.log('User created successfully:', userId);
      
      const response = new Response(JSON.stringify({
        success: true,
        token,
        user: {
          id: userId,
          firstName: data.firstName,
          email: data.email,
          emailVerified: false
        }
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Wrap response with security headers and CORS
      return security.wrapResponse(response, request);
      
    } catch (jwtError) {
      console.error('JWT creation error:', jwtError);
      throw jwtError;
    }
    
  } catch (error) {
    console.error('Registration error:', error);
    
    const errorResponse = new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Registration failed. Please try again.'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
    
    // Apply security headers even to error responses
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    return security.wrapResponse(errorResponse, request);
  }
};