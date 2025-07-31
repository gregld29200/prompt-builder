
export type PromptType = 'MVP' | 'AGENTIC';
export type Language = 'fr' | 'en';
export type Domain = 'education' | 'technical' | 'creative' | 'analysis' | 'other';
export type Complexity = 'auto' | 'simple' | 'complex'; // 'auto' might not be used if we always determine it
export type OutputLength = 'short' | 'medium' | 'long';

export interface SavedPrompt {
  id: string;
  timestamp: number;
  rawRequest: string;
  generatedPrompt: string;
  type: PromptType;
  domain: Domain;
  language: Language;
  favorite?: boolean; // Kept for potential future use
}

// For translations structure
interface TranslationSet {
  app: {
    title: string;
    subtitle: string;
  };
  input: {
    placeholder: string;
    button: string;
    charCount: string;
    minCharWarning: string;
  };
  analysis: {
    title: string;
    domain: string;
    complexity: string;
    recommendation: string;
    simple: string;
    complex: string;
  };
  approach: {
    title: string;
    mvp: {
      title: string;
      subtitle: string;
      description: string;
    };
    agentique: {
      title: string;
      subtitle: string;
      description: string;
    };
  };
  variables: {
    title: string;
    domain: string;
    outputLength: string;
    expertRole: string;
    mission: string;
    constraints: string;
    next: string;
    back: string;
    expertRolePlaceholder: string;
    missionPlaceholder: string;
    constraintsPlaceholder: string;
  };
  generation: {
    generating: string;
    title: string;
    error: string;
  };
  actions: {
    copy: string;
    save: string;
    export: string;
    generate: string;
    newPrompt: string;
    viewLibrary: string;
    copiedSuccess: string;
    copyError: string;
    savedSuccess: string;
    usePrompt: string;
  };
  library: {
    title: string;
    empty: string;
    close: string;
  };
  domains: {
    education: string;
    technical: string;
    creative: string;
    analysis: string;
    other: string;
  };
  lengths: {
    short: string;
    medium: string;
    long: string;
  };
  notifications: {
    copied: string;
    copyFailed: string;
    saved: string;
    apiError: string;
  }
}

export type Translations = {
  fr: TranslationSet;
  en: TranslationSet;
};

// Authentication and Security Types
// =================================

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  createdAt: number;
  updatedAt: number;
  isActive: boolean;
  lastLoginAt?: number;
  failedLoginAttempts: number;
  lockedUntil?: number;
}

export interface AuthUser {
  id: string;
  email: string;
  isActive: boolean;
  lastLoginAt?: number;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  confirmPassword: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  iat: number;
  exp: number;
  type: 'access' | 'refresh';
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface PasswordValidationRules {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  maxLength: number;
}

export interface PasswordValidationResult {
  isValid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong';
}

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export interface RateLimitState {
  count: number;
  resetTime: number;
  blocked: boolean;
}

export interface SecurityHeaders {
  'Content-Type': string;
  'X-Content-Type-Options': string;
  'X-Frame-Options': string;
  'X-XSS-Protection': string;
  'Strict-Transport-Security': string;
  'Content-Security-Policy': string;
  'Referrer-Policy': string;
  'Permissions-Policy': string;
}

export interface AuthError {
  code: string;
  message: string;
  statusCode: number;
}

export interface Session {
  id: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  createdAt: number;
  expiresAt: number;
  lastUsedAt: number;
  ipAddress?: string;
  userAgent?: string;
}

// Prompts Management Types
// =========================

export interface DatabasePrompt {
  id: string;
  user_id: string;
  title: string;
  raw_request: string;
  generated_prompt: string;
  prompt_type: 'MVP' | 'AGENTIC';
  domain: 'education' | 'technical' | 'creative' | 'analysis' | 'other';
  language: 'fr' | 'en';
  output_length: 'short' | 'medium' | 'long';
  expert_role?: string;
  mission?: string;
  constraints?: string;
  is_favorite: boolean;
  created_at: string;
  updated_at: string;
}

export interface APIPrompt {
  id: string;
  userId: string;
  title: string;
  rawRequest: string;
  generatedPrompt: string;
  promptType: 'MVP' | 'AGENTIC';
  domain: 'education' | 'technical' | 'creative' | 'analysis' | 'other';
  language: 'fr' | 'en';
  outputLength: 'short' | 'medium' | 'long';
  expertRole?: string;
  mission?: string;
  constraints?: string;
  isFavorite: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePromptRequest {
  rawRequest: string;
  generatedPrompt: string;
  promptType: 'MVP' | 'AGENTIC';
  domain: 'education' | 'technical' | 'creative' | 'analysis' | 'other';
  language: 'fr' | 'en';
  outputLength: 'short' | 'medium' | 'long';
  title?: string;
  expertRole?: string;
  mission?: string;
  constraints?: string;
  isFavorite?: boolean;
}

export interface UpdatePromptRequest {
  title?: string;
  isFavorite?: boolean;
  expertRole?: string;
  mission?: string;
  constraints?: string;
}

export interface PromptQueryParams {
  page?: number;
  limit?: number;
  sortBy?: 'created_at' | 'updated_at' | 'title' | 'is_favorite';
  sortOrder?: 'ASC' | 'DESC';
  domain?: 'education' | 'technical' | 'creative' | 'analysis' | 'other';
  promptType?: 'MVP' | 'AGENTIC';
  language?: 'fr' | 'en';
  isFavorite?: boolean;
  search?: string;
}

export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface PromptsListResponse {
  success: boolean;
  data: {
    prompts: APIPrompt[];
    pagination: PaginationMeta;
  };
}

export interface PromptResponse {
  success: boolean;
  message?: string;
  data: {
    prompt: APIPrompt;
  };
}

export interface PromptStatsResponse {
  success: boolean;
  data: {
    stats: {
      totalPrompts: number;
      favoritePrompts: number;
      promptsByDomain: Record<string, number>;
      promptsByType: Record<string, number>;
      promptsByLanguage: Record<string, number>;
    };
    timestamp: number;
  };
}

export interface FavoriteToggleResponse {
  success: boolean;
  message: string;
  data: {
    promptId: string;
    isFavorite: boolean;
    timestamp: number;
  };
}

export interface LogoutRequest {
  logoutAllDevices?: boolean;
}

export interface LogoutResponse {
  success: boolean;
  message: string;
  data: {
    logoutType: 'single_device' | 'all_devices';
    revokedSessions: number;
    remainingSessions: number;
    timestamp: number;
  };
}
