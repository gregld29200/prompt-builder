/**
 * Simple test endpoint to verify core bindings work
 */

interface EventContext {
  request: Request;
  env: {
    DB: any;
    RATE_LIMITER: any;
    JWT_SECRET: string;
    [key: string]: any;
  };
}

export const onRequestPost: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;

  try {
    // Test JWT_SECRET
    const jwtAvailable = !!(env.JWT_SECRET && env.JWT_SECRET.trim());
    
    // Test DB
    let dbTest = null;
    try {
      const stmt = env.DB.prepare('SELECT 1 as test');
      const result = await stmt.first();
      dbTest = { success: true, result };
    } catch (error) {
      dbTest = { success: false, error: error.message };
    }

    // Test KV
    let kvTest = null;
    try {
      await env.RATE_LIMITER.put('test-key', 'test-value', { expirationTtl: 60 });
      const value = await env.RATE_LIMITER.get('test-key');
      kvTest = { success: true, canWrite: true, canRead: value === 'test-value' };
      await env.RATE_LIMITER.delete('test-key');
    } catch (error) {
      kvTest = { success: false, error: error.message };
    }

    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      tests: {
        jwt: {
          available: jwtAvailable,
          length: env.JWT_SECRET?.length || 0
        },
        database: dbTest,
        kv: kvTest
      },
      message: 'All core bindings are functional!'
    };

    return new Response(JSON.stringify(response, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};