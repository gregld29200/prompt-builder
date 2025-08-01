// Simple working login endpoint
interface LoginRequest {
  email: string;
  password: string;
}

// Simple password hashing (same as register)
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'salt123'); // Same temporary salt
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

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
    console.log('=== SIMPLE LOGIN ENDPOINT ===');
    
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
    
    // Parse JSON
    const data: LoginRequest = await request.json();
    console.log('Login attempt for:', data.email);
    
    // Validation
    if (!data.email || !data.password) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'MISSING_FIELDS',
          message: 'Email and password are required'
        }
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Find user
    const user = await env.DB.prepare('SELECT id, email, password_hash, email_verified FROM users WHERE email = ?').bind(data.email).first();
    if (!user) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Verify password
    const hashedInputPassword = await hashPassword(data.password);
    if (hashedInputPassword !== user.password_hash) {
      return new Response(JSON.stringify({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Create JWT
    const token = await createJWT({ userId: user.id, email: user.email }, env.JWT_SECRET);
    
    console.log('Login successful for:', user.email);
    
    return new Response(JSON.stringify({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Unable to process login request'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};