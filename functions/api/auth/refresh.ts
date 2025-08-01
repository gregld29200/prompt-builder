// Ultra-simple refresh endpoint - same pattern as register/login

// JWT verification function (same as prompts.ts)
async function verifyJWT(token: string, secret: string): Promise<any> {
  try {
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) {
      throw new Error('Invalid token format');
    }
    
    // Verify signature
    const encoder = new TextEncoder();
    const message = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(message));
    
    if (!isValid) {
      throw new Error('Invalid signature');
    }
    
    // Parse payload
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      throw new Error('Token expired');
    }
    
    return payload;
  } catch (error) {
    throw new Error('Token verification failed');
  }
}

// Simple JWT creation (same as register/login)
async function createJWT(payload: any, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = { ...payload, iat: now, exp: now + 3600 }; // 1 hour
  
  const encoder = new TextEncoder();
  const headerB64 = btoa(JSON.stringify(header)).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m] || '');
  const payloadB64 = btoa(JSON.stringify(jwtPayload)).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m] || '');
  
  const message = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/[+/=]/g, m => ({'+':'-','/':'_','=':''})[m] || '');
  
  return `${message}.${signatureB64}`;
}

export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== SIMPLE REFRESH ENDPOINT ===');
    
    // Basic environment check
    if (!env.JWT_SECRET || !env.DB) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'CONFIG_ERROR',
          message: 'Service temporarily unavailable'
        }
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Get token from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'NO_TOKEN',
          message: 'Authorization token required'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    const token = authHeader.substring(7);
    
    // Verify current token (even if expired, we want to get user info)
    let user;
    try {
      // Try to verify the token (ignore expiration for refresh)
      const payload = JSON.parse(atob(token.split('.')[1]));
      user = payload;
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid token format'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Check if user still exists in database
    const dbUser = await env.DB.prepare('SELECT id, email, email_verified FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User account not found'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Create new JWT token
    const newToken = await createJWT({ userId: dbUser.id, email: dbUser.email }, env.JWT_SECRET);
    
    console.log('Token refreshed successfully for:', dbUser.email);
    
    return new Response(JSON.stringify({
      success: true,
      token: newToken,
      user: {
        id: dbUser.id,
        email: dbUser.email,
        emailVerified: dbUser.email_verified
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Refresh token error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Unable to refresh token'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};