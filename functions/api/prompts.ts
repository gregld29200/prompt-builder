// Simple prompts API endpoint

// JWT verification function
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

// GET /api/prompts - List user's prompts
export const onRequestGet = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== GET PROMPTS ENDPOINT ===');
    
    // Check environment
    if (!env.JWT_SECRET || !env.DB) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: 'CONFIG_ERROR', message: 'Service unavailable' }
      }), { status: 503, headers: { 'Content-Type': 'application/json' } });
    }
    
    // Get token from Authorization header
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: 'NO_TOKEN', message: 'Authorization token required' }
      }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    
    const token = authHeader.substring(7);
    
    // Verify JWT
    let user;
    try {
      user = await verifyJWT(token, env.JWT_SECRET);
    } catch (error) {
      return new Response(JSON.stringify({
        success: false,
        error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
      }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    
    console.log('Fetching prompts for user:', user.userId);
    
    // Get query parameters
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100);
    const offset = (page - 1) * limit;
    
    // Fetch user's prompts from database
    const results = await env.DB.prepare(`
      SELECT id, title, raw_request, generated_prompt, prompt_type, domain, language, 
             output_length, expert_role, mission, constraints, is_favorite, 
             created_at, updated_at
      FROM prompts 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ? OFFSET ?
    `).bind(user.userId, limit, offset).all();
    
    const prompts = results.results || [];
    
    // Get total count for pagination
    const countResult = await env.DB.prepare(`
      SELECT COUNT(*) as total FROM prompts WHERE user_id = ?
    `).bind(user.userId).first();
    
    const total = countResult?.total || 0;
    const totalPages = Math.ceil(total / limit);
    
    return new Response(JSON.stringify({
      success: true,
      prompts,
      pagination: {
        page,
        limit,
        total,
        totalPages
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Get prompts error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: { code: 'INTERNAL_ERROR', message: 'Failed to fetch prompts' }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// POST /api/prompts - Create new prompt
export const onRequestPost = async (context: any) => {
  const { request, env } = context;
  
  try {
    console.log('=== CREATE PROMPT ENDPOINT ===');
    
    // For now, just return success (we'll implement full functionality later)
    return new Response(JSON.stringify({
      success: true,
      message: 'Prompt creation not implemented yet',
      prompt: { id: 'temp-id', title: 'Temporary' }
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Create prompt error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: { code: 'INTERNAL_ERROR', message: 'Failed to create prompt' }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};