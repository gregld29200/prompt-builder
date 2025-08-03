// Reset password endpoint - validates token and updates password
import { EdgeBcrypt, PasswordValidator, InputValidator, AuthUtils, AUTH_ERRORS } from '../../../lib/auth-utils.js';
import { SecurityMiddleware, RATE_LIMIT_CONFIGS } from '../../../lib/security.js';

interface ResetPasswordRequest {
  token: string;
  password: string;
}

// Simple JWT creation for auto-login after reset
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
    console.log('=== RESET PASSWORD ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET || !env.DB) {
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
    // Apply rate limiting and security checks
    console.log('Applying security checks and rate limiting...');
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    const securityCheck = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.LOGIN, // Reuse login rate limit
      allowedMethods: ['POST'],
      endpoint: 'reset-password'
    });
    
    if (!securityCheck.allowed) {
      console.log('Security check failed - request blocked');
      return security.wrapResponse(securityCheck.response!, request);
    }
    
    console.log('Security checks passed');
    
    // Parse and validate JSON input
    const rawData = await request.json();
    console.log('Reset password attempt with token:', rawData.token?.substring(0, 8) + '...');
    
    // Validate required fields
    if (!rawData.token || !rawData.password) {
      return AuthUtils.createErrorResponse({
        code: 'MISSING_FIELDS',
        message: 'Token and password are required',
        statusCode: 400
      });
    }
    
    // Validate token format (should be 64 character hex string)
    if (!/^[a-f0-9]{64}$/.test(rawData.token)) {
      return AuthUtils.createErrorResponse({
        code: 'INVALID_TOKEN',
        message: 'Invalid reset token format',
        statusCode: 400
      });
    }
    
    // Validate password strength
    const passwordValidation = PasswordValidator.validate(rawData.password);
    if (!passwordValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: 'WEAK_PASSWORD',
        message: passwordValidation.errors.join(', '),
        statusCode: 400
      });
    }
    
    const data: ResetPasswordRequest = {
      token: rawData.token,
      password: rawData.password
    };
    
    try {
      console.log('Looking up reset token...');
      
      // Find valid reset token with user info
      const resetRecord = await env.DB.prepare(`
        SELECT 
          rt.id as token_id,
          rt.user_id,
          rt.expires_at,
          rt.used,
          u.id as user_id,
          u.first_name,
          u.email
        FROM password_reset_tokens rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.token = ? AND rt.used = 0
      `).bind(data.token).first();
      
      if (!resetRecord) {
        console.log('Reset token not found or already used');
        return AuthUtils.createErrorResponse({
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired reset token',
          statusCode: 400
        });
      }
      
      // Check if token is expired
      const expiresAt = new Date(resetRecord.expires_at);
      const now = new Date();
      
      if (now > expiresAt) {
        console.log('Reset token expired');
        
        // Clean up expired token
        await env.DB.prepare('DELETE FROM password_reset_tokens WHERE id = ?').bind(resetRecord.token_id).run();
        
        return AuthUtils.createErrorResponse({
          code: 'TOKEN_EXPIRED',
          message: 'Reset token has expired',
          statusCode: 400
        });
      }
      
      console.log('Valid reset token found for user:', resetRecord.email);
      
      // Hash new password
      console.log('Hashing new password...');
      const hashedPassword = await EdgeBcrypt.hash(data.password);
      
      // Update password and mark token as used in a transaction
      console.log('Updating password and invalidating token...');
      
      // Start transaction by updating password
      const updateResult = await env.DB.prepare(
        'UPDATE users SET password_hash = ? WHERE id = ?'
      ).bind(hashedPassword, resetRecord.user_id).run();
      
      if (!updateResult.success) {
        throw new Error('Failed to update password');
      }
      
      // Mark token as used
      await env.DB.prepare(
        'UPDATE password_reset_tokens SET used = 1 WHERE id = ?'
      ).bind(resetRecord.token_id).run();
      
      // Clean up old/expired tokens for this user
      await env.DB.prepare(`
        DELETE FROM password_reset_tokens 
        WHERE user_id = ? AND (used = 1 OR expires_at < datetime('now'))
      `).bind(resetRecord.user_id).run();
      
      console.log('Password updated successfully');
      
      // Create JWT token for auto-login
      console.log('Creating JWT for auto-login...');
      const token = await createJWT({
        userId: resetRecord.user_id,
        firstName: resetRecord.first_name,
        email: resetRecord.email
      }, env.JWT_SECRET);
      
      console.log('Password reset successful for:', resetRecord.email);
      
      const response = new Response(JSON.stringify({
        success: true,
        message: 'Password reset successfully',
        token,
        user: {
          id: resetRecord.user_id,
          firstName: resetRecord.first_name,
          email: resetRecord.email,
          emailVerified: true // Assume verified if they can reset password
        }
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
      
      return security.wrapResponse(response, request);
      
    } catch (dbError) {
      console.error('Database error in reset password:', dbError);
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
  } catch (error) {
    console.error('Reset password error:', error);
    
    const errorResponse = new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Password reset failed. Please try again.'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
    
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    return security.wrapResponse(errorResponse, request);
  }
};