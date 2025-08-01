/**
 * Debug endpoint to verify Cloudflare Pages Functions bindings
 * 
 * This endpoint helps diagnose binding availability issues by:
 * - Listing all available environment keys
 * - Testing specific binding types (D1, KV, Secrets)
 * - Providing detailed binding status information
 */

interface EventContext {
  request: Request;
  env: {
    [key: string]: any;
  };
  params: any;
  waitUntil: (promise: Promise<any>) => void;
}

export const onRequestGet: (context: EventContext) => Promise<Response> = async (context) => {
  const { env } = context;
  
  try {
    // Get all environment keys
    const allKeys = Object.keys(env);
    
    // Categorize bindings
    const bindingInfo = {
      timestamp: new Date().toISOString(),
      totalBindings: allKeys.length,
      availableKeys: allKeys,
      bindings: {
        secrets: {},
        databases: {},
        kvNamespaces: {},
        other: {}
      }
    };
    
    // Test each binding type
    for (const key of allKeys) {
      const value = env[key];
      const type = typeof value;
      
      if (type === 'string') {
        // Likely a secret or environment variable
        bindingInfo.bindings.secrets[key] = {
          type: 'secret/variable',
          hasValue: !!value,
          length: value?.length || 0
        };
      } else if (value && typeof value === 'object') {
        // Check if it's a D1 database
        if (value.prepare && typeof value.prepare === 'function') {
          bindingInfo.bindings.databases[key] = {
            type: 'D1Database',
            hasPrepare: true,
            hasExec: typeof value.exec === 'function'
          };
        }
        // Check if it's a KV namespace
        else if (value.get && value.put && typeof value.get === 'function') {
          bindingInfo.bindings.kvNamespaces[key] = {
            type: 'KVNamespace',
            hasGet: typeof value.get === 'function',
            hasPut: typeof value.put === 'function',
            hasDelete: typeof value.delete === 'function'
          };
        } else {
          bindingInfo.bindings.other[key] = {
            type: type,
            constructor: value.constructor?.name || 'unknown'
          };
        }
      } else {
        bindingInfo.bindings.other[key] = {
          type: type,
          value: value
        };
      }
    }
    
    // Specific tests for expected bindings
    const expectedBindings = {
      JWT_SECRET: !!env.JWT_SECRET,
      DB: !!env.DB && typeof env.DB.prepare === 'function',
      RATE_LIMITER: !!env.RATE_LIMITER && typeof env.RATE_LIMITER.get === 'function',
      // Legacy KV binding check
      KV: !!env.KV && typeof env.KV.get === 'function'
    };
    
    const response = {
      success: true,
      message: 'Binding diagnostic complete',
      data: {
        ...bindingInfo,
        expectedBindings,
        recommendations: []
      }
    };
    
    // Add recommendations based on findings
    if (!expectedBindings.JWT_SECRET) {
      response.data.recommendations.push('JWT_SECRET not found - check wrangler pages secret list');
    }
    if (!expectedBindings.DB) {
      response.data.recommendations.push('DB binding not found or invalid - check wrangler.toml D1 configuration');
    }
    if (!expectedBindings.RATE_LIMITER && !expectedBindings.KV) {
      response.data.recommendations.push('No KV namespace found - check wrangler.toml KV configuration');
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
      error: 'Binding diagnostic failed',
      details: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    }, null, 2), {
      status: 500,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }
};