// Forgot password endpoint - sends reset email with Resend
import { InputValidator, AuthUtils, AUTH_ERRORS } from '../../../lib/auth-utils.js';
import { SecurityMiddleware, RATE_LIMIT_CONFIGS } from '../../../lib/security.js';

interface ForgotPasswordRequest {
  email: string;
}

// Generate secure reset token
function generateResetToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Send reset email using Resend
async function sendResetEmail(email: string, token: string, language: string, env: any): Promise<boolean> {
  try {
    const resetUrl = `${env.FRONTEND_URL || 'https://promptbuilder.teachinspire.com'}/reset-password?token=${token}&lang=${language}`;
    
    const emailTemplate = getEmailTemplate(resetUrl, language);
    
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'TeachInspire <noreply@teachinspire.com>',
        to: [email],
        subject: language === 'fr' 
          ? 'Réinitialisation de votre mot de passe - TeachInspire'
          : 'Reset your password - TeachInspire',
        html: emailTemplate
      }),
    });

    if (!response.ok) {
      console.error('Resend API error:', await response.text());
      return false;
    }

    console.log('Reset email sent successfully to:', email);
    return true;
  } catch (error) {
    console.error('Error sending reset email:', error);
    return false;
  }
}

// Email template function
function getEmailTemplate(resetUrl: string, language: string): string {
  const translations = {
    fr: {
      title: 'Réinitialisation de votre mot de passe',
      greeting: 'Bonjour,',
      message: 'Vous avez demandé la réinitialisation de votre mot de passe pour votre compte TeachInspire.',
      button: 'Réinitialiser mon mot de passe',
      expiry: 'Ce lien expire dans 15 minutes.',
      ignore: 'Si vous n\'avez pas demandé cette réinitialisation, vous pouvez ignorer cet email.',
      thanks: 'Merci,<br>L\'équipe TeachInspire'
    },
    en: {
      title: 'Reset your password',
      greeting: 'Hello,',
      message: 'You have requested to reset your password for your TeachInspire account.',
      button: 'Reset my password',
      expiry: 'This link expires in 15 minutes.',
      ignore: 'If you did not request this reset, you can safely ignore this email.',
      thanks: 'Thank you,<br>The TeachInspire team'
    }
  };

  const t = translations[language as keyof typeof translations] || translations.fr;

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${t.title}</title>
    </head>
    <body style="font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #2c3d57; background-color: #f8f7f2; margin: 0; padding: 0;">
      <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(44, 61, 87, 0.1); overflow: hidden;">
        <div style="background: linear-gradient(135deg, #85a2a3 0%, #f1d263 100%); padding: 40px; text-align: center;">
          <h1 style="color: white; margin: 0; font-size: 28px; font-weight: 700;">${t.title}</h1>
        </div>
        <div style="padding: 40px;">
          <p style="font-size: 16px; margin-bottom: 20px;">${t.greeting}</p>
          <p style="font-size: 16px; margin-bottom: 30px;">${t.message}</p>
          <div style="text-align: center; margin: 40px 0;">
            <a href="${resetUrl}" style="background: linear-gradient(135deg, #85a2a3 0%, #f1d263 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; font-weight: 600; font-size: 16px; display: inline-block; transition: transform 0.2s;">${t.button}</a>
          </div>
          <p style="font-size: 14px; color: #6b7280; margin-bottom: 10px;"><strong>${t.expiry}</strong></p>
          <p style="font-size: 14px; color: #6b7280; margin-bottom: 30px;">${t.ignore}</p>
          <p style="font-size: 16px; color: #2c3d57; margin: 0;">${t.thanks}</p>
        </div>
        <div style="background-color: #f8f7f2; padding: 20px; text-align: center; font-size: 12px; color: #6b7280;">
          <p style="margin: 0;">TeachInspire - Votre assistant IA pour l'éducation</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== FORGOT PASSWORD ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET || !env.DB || !env.RESEND_API_KEY) {
      console.error('Missing required environment variables');
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
    // Apply rate limiting and security checks
    console.log('Applying security checks and rate limiting...');
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    const securityCheck = await security.applySecurityChecks(request, {
      rateLimitConfig: RATE_LIMIT_CONFIGS.LOGIN, // Reuse login rate limit
      allowedMethods: ['POST'],
      endpoint: 'forgot-password'
    });
    
    if (!securityCheck.allowed) {
      console.log('Security check failed - request blocked');
      return security.wrapResponse(securityCheck.response!, request);
    }
    
    console.log('Security checks passed');
    
    // Parse and validate JSON input
    const rawData = await request.json();
    console.log('Forgot password request for:', rawData.email);
    
    // Validate email
    if (!rawData.email) {
      return AuthUtils.createErrorResponse({
        code: 'MISSING_EMAIL',
        message: 'Email is required',
        statusCode: 400
      });
    }
    
    const emailValidation = InputValidator.validateEmail(rawData.email);
    if (!emailValidation.isValid) {
      return AuthUtils.createErrorResponse({
        code: 'INVALID_EMAIL',
        message: emailValidation.error || 'Invalid email address',
        statusCode: 400
      });
    }
    
    const data: ForgotPasswordRequest = {
      email: emailValidation.sanitized
    };
    
    // Get language from request (default to French)
    const language = rawData.language || 'fr';
    
    try {
      // Check if user exists (but don't reveal this info)
      console.log('Looking up user...');
      const user = await env.DB.prepare('SELECT id, email FROM users WHERE email = ?').bind(data.email).first();
      
      if (user) {
        console.log('User found, generating reset token...');
        
        // Generate secure reset token
        const resetToken = generateResetToken();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        
        // Store reset token in database
        await env.DB.prepare(`
          INSERT INTO password_reset_tokens (user_id, token, expires_at)
          VALUES (?, ?, ?)
        `).bind(user.id, resetToken, expiresAt.toISOString()).run();
        
        console.log('Reset token stored, sending email...');
        
        // Send reset email
        const emailSent = await sendResetEmail(data.email, resetToken, language, env);
        
        if (!emailSent) {
          console.error('Failed to send reset email');
          // Don't reveal email sending failure to prevent enumeration
        }
      } else {
        console.log('User not found for email:', data.email);
        // Don't reveal that user doesn't exist (prevent email enumeration)
      }
      
      // Always return success to prevent email enumeration attacks
      console.log('Forgot password request completed');
      
      const response = new Response(JSON.stringify({
        success: true,
        message: language === 'fr' 
          ? 'Si cette adresse email existe dans notre système, vous recevrez un lien de réinitialisation.'
          : 'If this email exists in our system, you will receive a reset link.'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
      
      return security.wrapResponse(response, request);
      
    } catch (dbError) {
      console.error('Database error in forgot password:', dbError);
      return AuthUtils.createErrorResponse(AUTH_ERRORS.INTERNAL_ERROR);
    }
    
  } catch (error) {
    console.error('Forgot password error:', error);
    
    const errorResponse = new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Request failed. Please try again.'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
    
    const security = new SecurityMiddleware(env.RATE_LIMITER, env.JWT_SECRET);
    return security.wrapResponse(errorResponse, request);
  }
};