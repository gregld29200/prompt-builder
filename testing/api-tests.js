/**
 * API Testing Suite for Teachinspire Prompt Builder
 * 
 * Comprehensive test suite for authentication and prompts management API
 * Run with: node testing/api-tests.js
 * 
 * Prerequisites:
 * - Application deployed and accessible
 * - Environment variables configured
 * - Database initialized with schema
 */

// Configuration
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:8788';
const TEST_EMAIL = process.env.TEST_EMAIL || 'test@teachinspire.com';
const TEST_PASSWORD = process.env.TEST_PASSWORD || 'TestPassword123!';

// Test utilities
class APITester {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.authToken = null;
    this.userId = null;
    this.testResults = [];
  }

  async makeRequest(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.authToken && options.requireAuth !== false) {
      headers.Authorization = `Bearer ${this.authToken}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers
      });

      const contentType = response.headers.get('content-type');
      let data = null;
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      return {
        status: response.status,
        ok: response.ok,
        data,
        headers: Object.fromEntries(response.headers.entries())
      };
    } catch (error) {
      return {
        status: 0,
        ok: false,
        error: error.message,
        data: null
      };
    }
  }

  logTest(testName, success, details = '') {
    const status = success ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${testName}${details ? ': ' + details : ''}`);
    this.testResults.push({ testName, success, details });
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Generate test data
  generateTestEmail() {
    const timestamp = Date.now();
    return `test-${timestamp}@teachinspire.com`;
  }

  generateTestPrompt() {
    const timestamp = Date.now();
    return {
      rawRequest: `Test prompt request ${timestamp}`,
      generatedPrompt: `You are a helpful assistant. Task: Handle test request ${timestamp}. Please provide detailed assistance.`,
      promptType: 'MVP',
      domain: 'education',
      language: 'en',
      outputLength: 'medium',
      title: `Test Prompt ${timestamp}`,
      isFavorite: false
    };
  }
}

// Test suites
class AuthenticationTests {
  constructor(tester) {
    this.tester = tester;
  }

  async runAll() {
    console.log('\n🔐 Running Authentication Tests...\n');
    
    await this.testUserRegistration();
    await this.testDuplicateRegistration();
    await this.testInvalidEmailRegistration();
    await this.testWeakPasswordRegistration();
    await this.testUserLogin();
    await this.testInvalidLogin();
    await this.testTokenRefresh();
    await this.testLogout();
    await this.testRateLimiting();
  }

  async testUserRegistration() {
    const testEmail = this.tester.generateTestEmail();
    const response = await this.tester.makeRequest('/api/auth/register', {
      method: 'POST',
      requireAuth: false,
      body: JSON.stringify({
        email: testEmail,
        password: TEST_PASSWORD
      })
    });

    if (response.ok && response.data.success) {
      this.tester.authToken = response.data.tokens.accessToken;
      this.tester.userId = response.data.user.id;
      this.tester.logTest('User Registration', true, `User ${testEmail} registered successfully`);
    } else {
      this.tester.logTest('User Registration', false, `Status: ${response.status}, Error: ${response.data?.message || response.error}`);
    }
  }

  async testDuplicateRegistration() {
    // Try to register with the same email again
    const response = await this.tester.makeRequest('/api/auth/register', {
      method: 'POST',
      requireAuth: false,
      body: JSON.stringify({
        email: TEST_EMAIL, // Use a known email
        password: TEST_PASSWORD
      })
    });

    const success = !response.ok && (response.status === 409 || response.status === 400);
    this.tester.logTest('Duplicate Registration Prevention', success, 
      success ? 'Correctly rejected duplicate email' : `Unexpected status: ${response.status}`);
  }

  async testInvalidEmailRegistration() {
    const invalidEmails = ['notanemail', '@domain.com', 'test@', ''];
    let allFailed = true;

    for (const email of invalidEmails) {
      const response = await this.tester.makeRequest('/api/auth/register', {
        method: 'POST',
        requireAuth: false,
        body: JSON.stringify({
          email,
          password: TEST_PASSWORD
        })
      });

      if (response.ok) {
        allFailed = false;
        break;
      }
    }

    this.tester.logTest('Invalid Email Registration', allFailed, 
      allFailed ? 'All invalid emails rejected' : 'Some invalid emails were accepted');
  }

  async testWeakPasswordRegistration() {
    const weakPasswords = ['123456', 'password', 'short', ''];
    let allFailed = true;

    for (const password of weakPasswords) {
      const response = await this.tester.makeRequest('/api/auth/register', {
        method: 'POST',
        requireAuth: false,
        body: JSON.stringify({
          email: this.tester.generateTestEmail(),
          password
        })
      });

      if (response.ok) {
        allFailed = false;
        break;
      }
    }

    this.tester.logTest('Weak Password Registration', allFailed,
      allFailed ? 'All weak passwords rejected' : 'Some weak passwords were accepted');
  }

  async testUserLogin() {
    // First create a user to login with
    const testEmail = this.tester.generateTestEmail();
    await this.tester.makeRequest('/api/auth/register', {
      method: 'POST',
      requireAuth: false,
      body: JSON.stringify({
        email: testEmail,
        password: TEST_PASSWORD
      })
    });

    // Now test login
    const response = await this.tester.makeRequest('/api/auth/login', {
      method: 'POST',
      requireAuth: false,
      body: JSON.stringify({
        email: testEmail,
        password: TEST_PASSWORD
      })
    });

    if (response.ok && response.data.success && response.data.tokens) {
      this.tester.authToken = response.data.tokens.accessToken;
      this.tester.logTest('User Login', true, 'Login successful with valid credentials');
    } else {
      this.tester.logTest('User Login', false, `Status: ${response.status}, Error: ${response.data?.message || response.error}`);
    }
  }

  async testInvalidLogin() {
    const response = await this.tester.makeRequest('/api/auth/login', {
      method: 'POST',
      requireAuth: false,
      body: JSON.stringify({
        email: 'nonexistent@example.com',
        password: 'wrongpassword'
      })
    });

    const success = !response.ok && response.status === 401;
    this.tester.logTest('Invalid Login Prevention', success,
      success ? 'Correctly rejected invalid credentials' : `Unexpected status: ${response.status}`);
  }

  async testTokenRefresh() {
    if (!this.tester.authToken) {
      this.tester.logTest('Token Refresh', false, 'No auth token available for refresh test');
      return;
    }

    const response = await this.tester.makeRequest('/api/auth/refresh', {
      method: 'POST'
    });

    const success = response.ok && response.data.success && response.data.tokens;
    if (success) {
      this.tester.authToken = response.data.tokens.accessToken;
    }
    this.tester.logTest('Token Refresh', success,
      success ? 'Token refreshed successfully' : `Status: ${response.status}`);
  }

  async testLogout() {
    if (!this.tester.authToken) {
      this.tester.logTest('User Logout', false, 'No auth token available for logout test');
      return;
    }

    const response = await this.tester.makeRequest('/api/auth/logout', {
      method: 'POST'
    });

    const success = response.ok;
    this.tester.logTest('User Logout', success,
      success ? 'Logout successful' : `Status: ${response.status}`);
    
    // Clear token after logout test
    if (success) {
      this.tester.authToken = null;
    }
  }

  async testRateLimiting() {
    // Make multiple rapid requests to test rate limiting
    const promises = [];
    for (let i = 0; i < 10; i++) {
      promises.push(this.tester.makeRequest('/api/auth/login', {
        method: 'POST',
        requireAuth: false,
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'password'
        })
      }));
    }

    const responses = await Promise.all(promises);
    const rateLimited = responses.some(r => r.status === 429);
    
    this.tester.logTest('Rate Limiting', rateLimited,
      rateLimited ? 'Rate limiting active' : 'No rate limiting detected (may need higher load)');
  }
}

class PromptsTests {
  constructor(tester) {
    this.tester = tester;
    this.testPromptId = null;
  }

  async runAll() {
    console.log('\n📝 Running Prompts Management Tests...\n');
    
    // Ensure we have authentication
    await this.ensureAuthenticated();
    
    await this.testCreatePrompt();
    await this.testGetPrompts();
    await this.testGetPromptsWithPagination();
    await this.testGetPromptsWithFilters();
    await this.testGetSinglePrompt();
    await this.testUpdatePrompt();
    await this.testToggleFavorite();
    await this.testDeletePrompt();
    await this.testUnauthorizedAccess();
  }

  async ensureAuthenticated() {
    if (!this.tester.authToken) {
      const testEmail = this.tester.generateTestEmail();
      const registerResponse = await this.tester.makeRequest('/api/auth/register', {
        method: 'POST',
        requireAuth: false,
        body: JSON.stringify({
          email: testEmail,
          password: TEST_PASSWORD
        })
      });

      if (registerResponse.ok) {
        this.tester.authToken = registerResponse.data.tokens.accessToken;
        this.tester.userId = registerResponse.data.user.id;
      }
    }
  }

  async testCreatePrompt() {
    const promptData = this.tester.generateTestPrompt();
    const response = await this.tester.makeRequest('/api/prompts', {
      method: 'POST',
      body: JSON.stringify(promptData)
    });

    if (response.ok && response.data.success) {
      this.testPromptId = response.data.data.prompt.id;
      this.tester.logTest('Create Prompt', true, `Prompt created with ID: ${this.testPromptId}`);
    } else {
      this.tester.logTest('Create Prompt', false, `Status: ${response.status}, Error: ${response.data?.message || response.error}`);
    }
  }

  async testGetPrompts() {
    const response = await this.tester.makeRequest('/api/prompts');

    const success = response.ok && response.data.success && Array.isArray(response.data.data.prompts);
    this.tester.logTest('Get Prompts', success,
      success ? `Retrieved ${response.data.data.prompts.length} prompts` : `Status: ${response.status}`);
  }

  async testGetPromptsWithPagination() {
    const response = await this.tester.makeRequest('/api/prompts?page=1&limit=5');

    const success = response.ok && response.data.success && response.data.data.pagination;
    this.tester.logTest('Get Prompts with Pagination', success,
      success ? 'Pagination working correctly' : `Status: ${response.status}`);
  }

  async testGetPromptsWithFilters() {
    const response = await this.tester.makeRequest('/api/prompts?domain=education&promptType=MVP');

    const success = response.ok && response.data.success;
    this.tester.logTest('Get Prompts with Filters', success,
      success ? 'Filtering working correctly' : `Status: ${response.status}`);
  }

  async testGetSinglePrompt() {
    if (!this.testPromptId) {
      this.tester.logTest('Get Single Prompt', false, 'No test prompt ID available');
      return;
    }

    const response = await this.tester.makeRequest(`/api/prompts/${this.testPromptId}`);

    const success = response.ok && response.data.success;
    this.tester.logTest('Get Single Prompt', success,
      success ? 'Single prompt retrieved successfully' : `Status: ${response.status}`);
  }

  async testUpdatePrompt() {
    if (!this.testPromptId) {
      this.tester.logTest('Update Prompt', false, 'No test prompt ID available');
      return;
    }

    const updateData = {
      title: 'Updated Test Prompt',
      isFavorite: true
    };

    const response = await this.tester.makeRequest(`/api/prompts/${this.testPromptId}`, {
      method: 'PATCH',
      body: JSON.stringify(updateData)
    });

    const success = response.ok && response.data.success;
    this.tester.logTest('Update Prompt', success,
      success ? 'Prompt updated successfully' : `Status: ${response.status}`);
  }

  async testToggleFavorite() {
    if (!this.testPromptId) {
      this.tester.logTest('Toggle Favorite', false, 'No test prompt ID available');
      return;
    }

    const response = await this.tester.makeRequest(`/api/prompts/${this.testPromptId}/favorite`, {
      method: 'POST'
    });

    const success = response.ok && response.data.success;
    this.tester.logTest('Toggle Favorite', success,
      success ? 'Favorite toggled successfully' : `Status: ${response.status}`);
  }

  async testDeletePrompt() {
    if (!this.testPromptId) {
      this.tester.logTest('Delete Prompt', false, 'No test prompt ID available');
      return;
    }

    const response = await this.tester.makeRequest(`/api/prompts/${this.testPromptId}`, {
      method: 'DELETE'
    });

    const success = response.status === 204 || (response.ok && response.data.success);
    this.tester.logTest('Delete Prompt', success,
      success ? 'Prompt deleted successfully' : `Status: ${response.status}`);
  }

  async testUnauthorizedAccess() {
    const originalToken = this.tester.authToken;
    this.tester.authToken = null;

    const response = await this.tester.makeRequest('/api/prompts');

    const success = !response.ok && response.status === 401;
    this.tester.logTest('Unauthorized Access Prevention', success,
      success ? 'Correctly rejected unauthorized request' : `Unexpected status: ${response.status}`);

    // Restore token
    this.tester.authToken = originalToken;
  }
}

class SecurityTests {
  constructor(tester) {
    this.tester = tester;
  }

  async runAll() {
    console.log('\n🔒 Running Security Tests...\n');
    
    await this.testSQLInjection();
    await this.testXSSPrevention();
    await this.testCORSHeaders();
    await this.testSecurityHeaders();
  }

  async testSQLInjection() {
    const maliciousInputs = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "admin'--",
      "'; INSERT INTO users (email, password) VALUES ('hacker@evil.com', 'password'); --"
    ];

    let allBlocked = true;

    for (const input of maliciousInputs) {
      const response = await this.tester.makeRequest('/api/auth/login', {
        method: 'POST',
        requireAuth: false,
        body: JSON.stringify({
          email: input,
          password: 'password'
        })
      });

      // Should not succeed and should not return 500 (internal server error)
      if (response.ok || response.status === 500) {
        allBlocked = false;
        break;
      }
    }

    this.tester.logTest('SQL Injection Prevention', allBlocked,
      allBlocked ? 'All SQL injection attempts blocked' : 'Some SQL injection attempts may have succeeded');
  }

  async testXSSPrevention() {
    await this.tester.ensureAuthenticated();

    const xssPayloads = [
      "<script>alert('xss')</script>",
      "javascript:alert('xss')",
      "<img src=x onerror=alert('xss')>",
      "<svg onload=alert('xss')>"
    ];

    let allSanitized = true;

    for (const payload of xssPayloads) {
      const promptData = {
        ...this.tester.generateTestPrompt(),
        title: payload,
        rawRequest: payload
      };

      const response = await this.tester.makeRequest('/api/prompts', {
        method: 'POST',
        body: JSON.stringify(promptData)
      });

      if (response.ok) {
        // Check if the response contains the unsanitized payload
        const responseText = JSON.stringify(response.data);
        if (responseText.includes(payload)) {
          allSanitized = false;
          break;
        }
      }
    }

    this.tester.logTest('XSS Prevention', allSanitized,
      allSanitized ? 'XSS payloads properly sanitized' : 'Some XSS payloads may not be sanitized');
  }

  async testCORSHeaders() {
    const response = await this.tester.makeRequest('/api/auth/login', {
      method: 'OPTIONS',
      requireAuth: false
    });

    const hasCORSHeaders = response.headers['access-control-allow-origin'] !== undefined;
    this.tester.logTest('CORS Headers', hasCORSHeaders,
      hasCORSHeaders ? 'CORS headers present' : 'CORS headers missing');
  }

  async testSecurityHeaders() {
    const response = await this.tester.makeRequest('/api/prompts', {
      requireAuth: false
    });

    const securityHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection'
    ];

    const presentHeaders = securityHeaders.filter(header => response.headers[header]);
    
    this.tester.logTest('Security Headers', presentHeaders.length > 0,
      `Security headers present: ${presentHeaders.join(', ') || 'none'}`);
  }
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting API Test Suite for Teachinspire Prompt Builder\n');
  console.log(`Testing API at: ${API_BASE_URL}\n`);

  const tester = new APITester(API_BASE_URL);
  
  // Test API connectivity
  console.log('🔍 Testing API connectivity...');
  const healthCheck = await tester.makeRequest('/api/health', { requireAuth: false });
  if (!healthCheck.ok && healthCheck.status !== 404) {
    console.log('❌ API not accessible. Please ensure the application is running.');
    process.exit(1);
  }
  console.log('✅ API is accessible\n');

  // Run test suites
  const authTests = new AuthenticationTests(tester);
  await authTests.runAll();

  const promptsTests = new PromptsTests(tester);
  await promptsTests.runAll();

  const securityTests = new SecurityTests(tester);
  await securityTests.runAll();

  // Summary
  console.log('\n📊 Test Results Summary:');
  console.log('========================');
  
  const totalTests = tester.testResults.length;
  const passedTests = tester.testResults.filter(r => r.success).length;
  const failedTests = totalTests - passedTests;
  
  console.log(`Total Tests: ${totalTests}`);
  console.log(`Passed: ${passedTests} ✅`);
  console.log(`Failed: ${failedTests} ❌`);
  console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);

  if (failedTests > 0) {
    console.log('\n❌ Failed Tests:');
    tester.testResults
      .filter(r => !r.success)
      .forEach(r => console.log(`  - ${r.testName}: ${r.details}`));
  }

  console.log('\n✨ Testing completed!');
  
  // Exit with error code if tests failed
  process.exit(failedTests > 0 ? 1 : 0);
}

// Error handling
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Run tests if this file is executed directly
if (require.main === module) {
  runAllTests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
  });
}

module.exports = { APITester, AuthenticationTests, PromptsTests, SecurityTests };