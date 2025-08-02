// Secure login endpoint with proper password verification and validation
import { EdgeBcrypt, InputValidator, AuthUtils, AUTH_ERRORS } from '../../../lib/auth-utils.js';
import { SecurityMiddleware, RATE_LIMIT_CONFIGS } from '../../../lib/security.js';

interface LoginRequest {
  email: string;
  password: string;
}

// Remove insecure password hashing - using secure EdgeBcrypt.compare instead

// Simple JWT creation (same as register)
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
    console.log('=== SECURE LOGIN ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET || !env.DB) {
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
    // Apply rate limiting and security checks
    console.log('Applying security checks and rate limiting...');
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    const securityCheck = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.LOGIN,
      allowedMethods: ['POST'],
      endpoint: 'login'
    });
    
    if (!securityCheck.allowed) {
      console.log('Security check failed - request blocked');
      return security.wrapResponse(securityCheck.response!, request);
    }
    
    console.log('Security checks passed');
    
    // Parse and validate JSON input using secure utilities
    const rawData = await request.json();
    console.log('Login attempt for:', rawData.email);
    
    // Comprehensive input validation using secure utilities
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
    
    const data: LoginRequest = {
      email: emailValidation.sanitized,
      password: rawData.password
    };
    
    // Find user with secure database query
    console.log('Looking up user...');
    try {
      const user = await env.DB.prepare('SELECT id, first_name, email, password_hash, email_verified FROM users WHERE email = ?').bind(data.email).first();
      
      if (!user) {
        console.log('User not found for email:', data.email);
        return AuthUtils.createErrorResponse(AUTH_ERRORS.INVALID_CREDENTIALS);
      }
      
      console.log('User found:', { id: user.id, email: user.email, firstName: user.first_name });
      
      // Verify password using secure bcrypt comparison
      console.log('Verifying password with secure bcrypt...');
      const isPasswordValid = await EdgeBcrypt.compare(data.password, user.password_hash);
      
      if (!isPasswordValid) {
        console.log('Password verification failed for user:', user.email);
        return AuthUtils.createErrorResponse(AUTH_ERRORS.INVALID_CREDENTIALS);
      }
      
      console.log('Password verified successfully');
    
      // Create JWT token
      console.log('Creating JWT token...');
      const token = await createJWT({ userId: user.id, firstName: user.first_name, email: user.email }, env.JWT_SECRET);
      console.log('JWT created successfully');
      
      console.log('Login successful for:', user.email);
      
      const response = new Response(JSON.stringify({
        success: true,
        token,
        user: {
          id: user.id,
          firstName: user.first_name,
          email: user.email,
          emailVerified: user.email_verified
        }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
      
      // Wrap response with security headers and CORS
      return security.wrapResponse(response, request);
      
    } catch (dbError) {
      console.error('Database or authentication error:', dbError);
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
  } catch (error) {
    console.error('Login error:', error);
    
    const errorResponse = new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Login failed. Please try again.'
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