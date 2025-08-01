// Simple logout endpoint
export const onRequestPost = async (context: any) => {
  try {
    console.log('=== SIMPLE LOGOUT ENDPOINT ===');
    
    // For now, logout is just a client-side operation (clear localStorage)
    // In future, we could invalidate tokens in database
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Logged out successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Logout failed'
      }
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};