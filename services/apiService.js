// API service layer for handling all backend communications
// Uses the authentication context for JWT token management

class ApiService {
  constructor() {
    this.baseURL = '';
    this.authContext = null;
  }

  // Set auth context reference (will be called from AuthProvider)
  setAuthContext(authContext) {
    this.authContext = authContext;
  }

  // Get default headers with authentication
  getHeaders(additionalHeaders = {}) {
    const baseHeaders = {
      'Content-Type': 'application/json',
      ...additionalHeaders,
    };

    if (this.authContext && this.authContext.token) {
      baseHeaders['Authorization'] = `Bearer ${this.authContext.token}`;
    }

    return baseHeaders;
  }

  // Generic API request method with error handling and token refresh
  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const requestOptions = {
      ...options,
      headers: this.getHeaders(options.headers),
    };

    try {
      let response = await fetch(url, requestOptions);

      // Handle token expiration
      if (response.status === 401 && this.authContext && this.authContext.token) {
        // Try to refresh token
        const refreshed = await this.authContext.refreshToken();
        
        if (refreshed) {
          // Retry the request with new token
          requestOptions.headers = this.getHeaders(options.headers);
          response = await fetch(url, requestOptions);
        } else {
          // Refresh failed, redirect to login
          throw new Error('Authentication expired');
        }
      }

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      return data;
    } catch (error) {
      console.error(`API Error [${endpoint}]:`, error);
      throw error;
    }
  }

  // Authentication endpoints
  async login(email, password) {
    return this.makeRequest('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async register(email, password) {
    return this.makeRequest('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async logout() {
    return this.makeRequest('/api/auth/logout', {
      method: 'POST',
    });
  }

  async refreshToken() {
    return this.makeRequest('/api/auth/refresh', {
      method: 'POST',
    });
  }

  async forgotPassword(email, language = 'fr') {
    return this.makeRequest('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email, language }),
    });
  }

  async resetPassword(token, password) {
    return this.makeRequest('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    });
  }

  // Prompts endpoints
  async getPrompts(page = 1, limit = 20, filters = {}) {
    const queryParams = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...filters,
    });

    return this.makeRequest(`/api/prompts?${queryParams}`);
  }

  async createPrompt(promptData) {
    return this.makeRequest('/api/prompts', {
      method: 'POST',
      body: JSON.stringify(promptData),
    });
  }

  async updatePrompt(id, promptData) {
    return this.makeRequest(`/api/prompts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(promptData),
    });
  }

  async deletePrompt(id) {
    return this.makeRequest(`/api/prompts/${id}`, {
      method: 'DELETE',
    });
  }

  async toggleFavorite(id) {
    return this.makeRequest(`/api/prompts/${id}/favorite`, {
      method: 'POST',
    });
  }

  async getPromptStats() {
    return this.makeRequest('/api/prompts/stats');
  }
}

// Create singleton instance
const apiService = new ApiService();

export default apiService;