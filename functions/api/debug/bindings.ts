/**
 * Diagnostic endpoint to inspect available environment bindings
 * This helps debug binding configuration issues in Pages Functions
 */

interface EventContext {
  request: Request;
  env: {
    [key: string]: any;
  };
  params: any;
  waitUntil: (promise: Promise<any>) => void;
  next: (input?: Request | string, init?: RequestInit) => Promise<Response>;
  functionPath: string;
}

export const onRequestGet: (context: EventContext) => Promise<Response> = async (context) => {
  const { request, env } = context;

  // Only allow in development or with a debug token
  const url = new URL(request.url);
  const debugToken = url.searchParams.get('token');
  
  // Simple security check - only allow this in development or with correct token
  if (env.ENVIRONMENT !== 'development' && debugToken !== 'debug123') {
    return new Response(JSON.stringify({
      error: 'Access denied'
    }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    const diagnostics = {
      timestamp: new Date().toISOString(),
      functionPath: context.functionPath,
      environment: env.ENVIRONMENT,
      availableBindings: {
        keys: Object.keys(env),
        bindings: {}
      },
      bindingAnalysis: {
        secrets: [],
        databases: [],
        kv: [],
        other: []
      }
    };

    // Analyze each binding
    for (const [key, value] of Object.entries(env)) {
      const bindingInfo = {
        type: typeof value,
        available: !!value,
        constructor: value?.constructor?.name || 'unknown'
      };

      // Categorize bindings
      if (typeof value === 'string' && !key.startsWith('CF_')) {
        diagnostics.bindingAnalysis.secrets.push({ 
          name: key, 
          ...bindingInfo,
          // For secrets, check if string is non-empty
          available: typeof value === 'string' && value.trim() !== ''
        });
      } else if (value?.constructor?.name === 'D1Database') {
        diagnostics.bindingAnalysis.databases.push({ name: key, ...bindingInfo });
      } else if (value?.constructor?.name === 'KvNamespace') {
        diagnostics.bindingAnalysis.kv.push({ name: key, ...bindingInfo });
      } else {
        diagnostics.bindingAnalysis.other.push({ name: key, ...bindingInfo });
      }

      // Store safe representation of binding
      if (typeof value === 'string') {
        diagnostics.availableBindings.bindings[key] = '[SECRET STRING]';
      } else if (value?.constructor?.name) {
        diagnostics.availableBindings.bindings[key] = value.constructor.name;
      } else {
        diagnostics.availableBindings.bindings[key] = typeof value;
      }
    }

    // Check for specific expected bindings
    const expectedBindings = {
      JWT_SECRET: {
        expected: 'string',
        actual: typeof env.JWT_SECRET,
        available: typeof env.JWT_SECRET === 'string' && env.JWT_SECRET.trim() !== '',
        length: env.JWT_SECRET?.length || 0
      },
      DB: {
        expected: 'D1Database',
        actual: env.DB?.constructor?.name || typeof env.DB,
        available: !!env.DB
      },
      RATE_LIMITER: {
        expected: 'KvNamespace',
        actual: env.RATE_LIMITER?.constructor?.name || typeof env.RATE_LIMITER,
        available: !!env.RATE_LIMITER
      },
      KV: {
        expected: 'KvNamespace (fallback)',
        actual: env.KV?.constructor?.name || typeof env.KV,
        available: !!env.KV
      }
    };

    const response = {
      success: true,
      diagnostics,
      expectedBindings,
      recommendations: []
    };

    // Add recommendations based on findings
    if (!env.JWT_SECRET || env.JWT_SECRET.trim() === '') {
      response.recommendations.push(`JWT_SECRET secret is ${!env.JWT_SECRET ? 'missing' : 'empty'} - run: wrangler pages secret put JWT_SECRET`);
    }
    if (!env.DB) {
      response.recommendations.push('DB binding is missing - check wrangler.toml D1 configuration');
    }
    if (!env.RATE_LIMITER && !env.KV) {
      response.recommendations.push('KV namespace binding is missing - check wrangler.toml KV configuration');
    }

    return new Response(JSON.stringify(response, null, 2), {
      status: 200,
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      }
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