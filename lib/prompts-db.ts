/**
 * Prompts Database Operations for Cloudflare Workers
 * 
 * This module provides comprehensive database operations for the prompts system
 * optimized for Cloudflare's D1 distributed SQL database. All functions are designed to:
 * - Handle edge-distributed database constraints efficiently
 * - Implement proper data validation and sanitization
 * - Provide type-safe operations with comprehensive error handling
 * - Support pagination, filtering, and search functionality
 * - Maintain ownership validation and security controls
 * - Optimize query performance with proper indexing utilization
 */

import { InputValidator } from './auth-utils';

/**
 * Interface definitions for prompts operations
 */
export interface Prompt {
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

export interface CreatePromptData {
  userId: string;
  title?: string; // Will auto-generate if not provided
  rawRequest: string;
  generatedPrompt: string;
  promptType: 'MVP' | 'AGENTIC';
  domain: 'education' | 'technical' | 'creative' | 'analysis' | 'other';
  language: 'fr' | 'en';
  outputLength: 'short' | 'medium' | 'long';
  expertRole?: string;
  mission?: string;
  constraints?: string;
  isFavorite?: boolean;
}

export interface UpdatePromptData {
  title?: string;
  isFavorite?: boolean;
  expertRole?: string;
  mission?: string;
  constraints?: string;
}

export interface PromptFilters {
  domain?: string;
  promptType?: string;
  language?: string;
  isFavorite?: boolean;
  search?: string; // Search in title and raw_request
}

export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: 'created_at' | 'updated_at' | 'title' | 'is_favorite';
  sortOrder?: 'ASC' | 'DESC';
}

export interface PaginatedPromptsResult {
  prompts: Prompt[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
}

export interface PromptStats {
  totalPrompts: number;
  favoritePrompts: number;
  promptsByDomain: Record<string, number>;
  promptsByType: Record<string, number>;
  promptsByLanguage: Record<string, number>;
}

/**
 * Prompts Database Error Types
 */
export class PromptError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 500
  ) {
    super(message);
    this.name = 'PromptError';
  }
}

/**
 * Main Prompts Database Class
 */
export class PromptsDatabase {
  constructor(private db: D1Database) {}

  /**
   * Generate UUID for prompts (edge-compatible)
   */
  private generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    
    // Set version (4) and variant bits
    array[6] = (array[6] & 0x0f) | 0x40;
    array[8] = (array[8] & 0x3f) | 0x80;
    
    // Convert to UUID string format
    const hex = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20, 32)
    ].join('-');
  }

  /**
   * Auto-generate title from raw request (first 50 characters)
   */
  private generateTitle(rawRequest: string): string {
    const cleanRequest = rawRequest.trim();
    if (cleanRequest.length <= 50) {
      return cleanRequest;
    }
    
    // Try to break at word boundary
    const truncated = cleanRequest.substring(0, 47);
    const lastSpaceIndex = truncated.lastIndexOf(' ');
    
    if (lastSpaceIndex > 20) { // Ensure minimum meaningful length
      return truncated.substring(0, lastSpaceIndex) + '...';
    }
    
    return truncated + '...';
  }

  /**
   * Validate prompt data before database operations
   */
  private validatePromptData(data: CreatePromptData | UpdatePromptData, isUpdate: boolean = false): void {
    if (!isUpdate) {
      const createData = data as CreatePromptData;
      
      // Required fields for creation
      if (!createData.userId || typeof createData.userId !== 'string') {
        throw new PromptError('User ID is required', 'INVALID_USER_ID', 400);
      }
      
      if (!createData.rawRequest || typeof createData.rawRequest !== 'string') {
        throw new PromptError('Raw request is required', 'INVALID_RAW_REQUEST', 400);
      }
      
      if (createData.rawRequest.length > 5000) {
        throw new PromptError('Raw request exceeds maximum length', 'RAW_REQUEST_TOO_LONG', 400);
      }
      
      if (!createData.generatedPrompt || typeof createData.generatedPrompt !== 'string') {
        throw new PromptError('Generated prompt is required', 'INVALID_GENERATED_PROMPT', 400);
      }
      
      if (createData.generatedPrompt.length > 10000) {
        throw new PromptError('Generated prompt exceeds maximum length', 'GENERATED_PROMPT_TOO_LONG', 400);
      }
      
      // Validate enum fields
      if (!['MVP', 'AGENTIC'].includes(createData.promptType)) {
        throw new PromptError('Invalid prompt type', 'INVALID_PROMPT_TYPE', 400);
      }
      
      if (!['education', 'technical', 'creative', 'analysis', 'other'].includes(createData.domain)) {
        throw new PromptError('Invalid domain', 'INVALID_DOMAIN', 400);
      }
      
      if (!['fr', 'en'].includes(createData.language)) {
        throw new PromptError('Invalid language', 'INVALID_LANGUAGE', 400);
      }
      
      if (!['short', 'medium', 'long'].includes(createData.outputLength)) {
        throw new PromptError('Invalid output length', 'INVALID_OUTPUT_LENGTH', 400);
      }
    }
    
    // Validate optional fields (for both create and update)
    if (data.title !== undefined) {
      if (typeof data.title !== 'string' || data.title.length > 100) {
        throw new PromptError('Title must be a string with maximum 100 characters', 'INVALID_TITLE', 400);
      }
    }
    
    if (data.expertRole !== undefined) {
      if (typeof data.expertRole !== 'string' || data.expertRole.length > 200) {
        throw new PromptError('Expert role must be a string with maximum 200 characters', 'INVALID_EXPERT_ROLE', 400);
      }
    }
    
    if (data.mission !== undefined) {
      if (typeof data.mission !== 'string' || data.mission.length > 500) {
        throw new PromptError('Mission must be a string with maximum 500 characters', 'INVALID_MISSION', 400);
      }
    }
    
    if (data.constraints !== undefined) {
      if (typeof data.constraints !== 'string' || data.constraints.length > 1000) {
        throw new PromptError('Constraints must be a string with maximum 1000 characters', 'INVALID_CONSTRAINTS', 400);
      }
    }
    
    if (data.isFavorite !== undefined && typeof data.isFavorite !== 'boolean') {
      throw new PromptError('isFavorite must be a boolean', 'INVALID_IS_FAVORITE', 400);
    }
  }

  /**
   * Check if user owns a prompt
   */
  async validateOwnership(promptId: string, userId: string): Promise<boolean> {
    try {
      const stmt = this.db.prepare(`
        SELECT user_id FROM prompts 
        WHERE id = ? LIMIT 1
      `);
      
      const result = await stmt.bind(promptId).first();
      return result?.user_id === userId;
    } catch (error) {
      console.error('Error validating prompt ownership:', error);
      return false;
    }
  }

  /**
   * Create a new prompt
   */
  async createPrompt(data: CreatePromptData): Promise<Prompt> {
    this.validatePromptData(data);
    
    const id = this.generateId();
    const title = data.title || this.generateTitle(data.rawRequest);
    const now = new Date().toISOString();
    
    try {
      const stmt = this.db.prepare(`
        INSERT INTO prompts (
          id, user_id, title, raw_request, generated_prompt,
          prompt_type, domain, language, output_length,
          expert_role, mission, constraints, is_favorite,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      
      await stmt.bind(
        id,
        data.userId,
        title,
        data.rawRequest,
        data.generatedPrompt,
        data.promptType,
        data.domain,
        data.language,
        data.outputLength,
        data.expertRole || null,
        data.mission || null,
        data.constraints || null,
        data.isFavorite ? 1 : 0,
        now,
        now
      ).run();
      
      // Return the created prompt
      return {
        id,
        userId: data.userId,
        title,
        rawRequest: data.rawRequest,
        generatedPrompt: data.generatedPrompt,
        promptType: data.promptType,
        domain: data.domain,
        language: data.language,
        outputLength: data.outputLength,
        expertRole: data.expertRole,
        mission: data.mission,
        constraints: data.constraints,
        isFavorite: data.isFavorite || false,
        createdAt: now,
        updatedAt: now
      };
      
    } catch (error) {
      console.error('Error creating prompt:', error);
      throw new PromptError('Failed to create prompt', 'CREATE_FAILED', 500);
    }
  }

  /**
   * Get prompt by ID with ownership validation
   */
  async getPromptById(id: string, userId?: string): Promise<Prompt | null> {
    try {
      let stmt;
      let bindings;
      
      if (userId) {
        // Include ownership validation
        stmt = this.db.prepare(`
          SELECT * FROM prompts 
          WHERE id = ? AND user_id = ?
        `);
        bindings = [id, userId];
      } else {
        // Get without ownership validation (admin use case)
        stmt = this.db.prepare(`
          SELECT * FROM prompts 
          WHERE id = ?
        `);
        bindings = [id];
      }
      
      const result = await stmt.bind(...bindings).first();
      
      if (!result) {
        return null;
      }
      
      return {
        id: result.id,
        userId: result.user_id,
        title: result.title,
        rawRequest: result.raw_request,
        generatedPrompt: result.generated_prompt,
        promptType: result.prompt_type as 'MVP' | 'AGENTIC',
        domain: result.domain as 'education' | 'technical' | 'creative' | 'analysis' | 'other',
        language: result.language as 'fr' | 'en',
        outputLength: result.output_length as 'short' | 'medium' | 'long',
        expertRole: result.expert_role,
        mission: result.mission,
        constraints: result.constraints,
        isFavorite: Boolean(result.is_favorite),
        createdAt: result.created_at,
        updatedAt: result.updated_at
      };
      
    } catch (error) {
      console.error('Error getting prompt by ID:', error);
      throw new PromptError('Failed to retrieve prompt', 'GET_FAILED', 500);
    }
  }

  /**
   * Get user's prompts with pagination, filtering, and search
   */
  async getUserPrompts(
    userId: string,
    filters: PromptFilters = {},
    pagination: PaginationOptions = {}
  ): Promise<PaginatedPromptsResult> {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = pagination;
    
    // Validate pagination parameters
    if (page < 1 || limit < 1 || limit > 100) {
      throw new PromptError('Invalid pagination parameters', 'INVALID_PAGINATION', 400);
    }
    
    const offset = (page - 1) * limit;
    
    try {
      // Build WHERE clause conditions
      const conditions: string[] = ['user_id = ?'];
      const bindings: any[] = [userId];
      
      if (filters.domain) {
        conditions.push('domain = ?');
        bindings.push(filters.domain);
      }
      
      if (filters.promptType) {
        conditions.push('prompt_type = ?');
        bindings.push(filters.promptType);
      }
      
      if (filters.language) {
        conditions.push('language = ?');
        bindings.push(filters.language);
      }
      
      if (filters.isFavorite !== undefined) {
        conditions.push('is_favorite = ?');
        bindings.push(filters.isFavorite ? 1 : 0);
      }
      
      if (filters.search) {
        conditions.push('(title LIKE ? OR raw_request LIKE ?)');
        const searchPattern = `%${filters.search}%`;
        bindings.push(searchPattern, searchPattern);
      }
      
      const whereClause = conditions.join(' AND ');
      
      // Get total count
      const countStmt = this.db.prepare(`
        SELECT COUNT(*) as total 
        FROM prompts 
        WHERE ${whereClause}
      `);
      
      const countResult = await countStmt.bind(...bindings).first();
      const total = countResult?.total || 0;
      
      // Get prompts with pagination
      const stmt = this.db.prepare(`
        SELECT * FROM prompts 
        WHERE ${whereClause}
        ORDER BY ${sortBy} ${sortOrder}
        LIMIT ? OFFSET ?
      `);
      
      const results = await stmt.bind(...bindings, limit, offset).all();
      
      const prompts: Prompt[] = results.results.map((row: any) => ({
        id: row.id,
        userId: row.user_id,
        title: row.title,
        rawRequest: row.raw_request,
        generatedPrompt: row.generated_prompt,
        promptType: row.prompt_type as 'MVP' | 'AGENTIC',
        domain: row.domain as 'education' | 'technical' | 'creative' | 'analysis' | 'other',
        language: row.language as 'fr' | 'en',
        outputLength: row.output_length as 'short' | 'medium' | 'long',
        expertRole: row.expert_role,
        mission: row.mission,
        constraints: row.constraints,
        isFavorite: Boolean(row.is_favorite),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }));
      
      const totalPages = Math.ceil(total / limit);
      
      return {
        prompts,
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      };
      
    } catch (error) {
      console.error('Error getting user prompts:', error);
      throw new PromptError('Failed to retrieve prompts', 'GET_LIST_FAILED', 500);
    }
  }

  /**
   * Update an existing prompt
   */
  async updatePrompt(id: string, userId: string, data: UpdatePromptData): Promise<Prompt | null> {
    this.validatePromptData(data, true);
    
    // Validate ownership first
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError('Prompt not found or access denied', 'NOT_FOUND', 404);
    }
    
    // Build update query dynamically
    const updateFields: string[] = [];
    const bindings: any[] = [];
    
    if (data.title !== undefined) {
      updateFields.push('title = ?');
      bindings.push(data.title);
    }
    
    if (data.isFavorite !== undefined) {
      updateFields.push('is_favorite = ?');
      bindings.push(data.isFavorite ? 1 : 0);
    }
    
    if (data.expertRole !== undefined) {
      updateFields.push('expert_role = ?');
      bindings.push(data.expertRole || null);
    }
    
    if (data.mission !== undefined) {
      updateFields.push('mission = ?');
      bindings.push(data.mission || null);
    }
    
    if (data.constraints !== undefined) {
      updateFields.push('constraints = ?');
      bindings.push(data.constraints || null);
    }
    
    if (updateFields.length === 0) {
      // No fields to update, return current prompt
      return await this.getPromptById(id, userId);
    }
    
    // Always update the updated_at timestamp
    updateFields.push('updated_at = ?');
    bindings.push(new Date().toISOString());
    
    // Add WHERE clause bindings
    bindings.push(id, userId);
    
    try {
      const stmt = this.db.prepare(`
        UPDATE prompts 
        SET ${updateFields.join(', ')}
        WHERE id = ? AND user_id = ?
      `);
      
      const result = await stmt.bind(...bindings).run();
      
      if (result.changes === 0) {
        throw new PromptError('Prompt not found or access denied', 'NOT_FOUND', 404);
      }
      
      // Return updated prompt
      return await this.getPromptById(id, userId);
      
    } catch (error) {
      console.error('Error updating prompt:', error);
      if (error instanceof PromptError) {
        throw error;
      }
      throw new PromptError('Failed to update prompt', 'UPDATE_FAILED', 500);
    }
  }

  /**
   * Delete a prompt
   */
  async deletePrompt(id: string, userId: string): Promise<boolean> {
    // Validate ownership first
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError('Prompt not found or access denied', 'NOT_FOUND', 404);
    }
    
    try {
      const stmt = this.db.prepare(`
        DELETE FROM prompts 
        WHERE id = ? AND user_id = ?
      `);
      
      const result = await stmt.bind(id, userId).run();
      
      return result.changes > 0;
      
    } catch (error) {
      console.error('Error deleting prompt:', error);
      throw new PromptError('Failed to delete prompt', 'DELETE_FAILED', 500);
    }
  }

  /**
   * Toggle favorite status
   */
  async toggleFavorite(id: string, userId: string): Promise<{ isFavorite: boolean }> {
    // Validate ownership first
    const hasOwnership = await this.validateOwnership(id, userId);
    if (!hasOwnership) {
      throw new PromptError('Prompt not found or access denied', 'NOT_FOUND', 404);
    }
    
    try {
      // Get current favorite status
      const currentPrompt = await this.getPromptById(id, userId);
      if (!currentPrompt) {
        throw new PromptError('Prompt not found', 'NOT_FOUND', 404);
      }
      
      const newFavoriteStatus = !currentPrompt.isFavorite;
      
      const stmt = this.db.prepare(`
        UPDATE prompts 
        SET is_favorite = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `);
      
      await stmt.bind(
        newFavoriteStatus ? 1 : 0,
        new Date().toISOString(),
        id,
        userId
      ).run();
      
      return { isFavorite: newFavoriteStatus };
      
    } catch (error) {
      console.error('Error toggling favorite:', error);
      if (error instanceof PromptError) {
        throw error;
      }
      throw new PromptError('Failed to toggle favorite status', 'TOGGLE_FAVORITE_FAILED', 500);
    }
  }

  /**
   * Get user's prompt statistics
   */
  async getUserPromptStats(userId: string): Promise<PromptStats> {
    try {
      // Total prompts
      const totalStmt = this.db.prepare(`
        SELECT COUNT(*) as total FROM prompts WHERE user_id = ?
      `);
      const totalResult = await totalStmt.bind(userId).first();
      
      // Favorite prompts
      const favoriteStmt = this.db.prepare(`
        SELECT COUNT(*) as total FROM prompts WHERE user_id = ? AND is_favorite = 1
      `);
      const favoriteResult = await favoriteStmt.bind(userId).first();
      
      // Prompts by domain
      const domainStmt = this.db.prepare(`
        SELECT domain, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY domain
      `);
      const domainResults = await domainStmt.bind(userId).all();
      
      // Prompts by type
      const typeStmt = this.db.prepare(`
        SELECT prompt_type, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY prompt_type
      `);
      const typeResults = await typeStmt.bind(userId).all();
      
      // Prompts by language
      const languageStmt = this.db.prepare(`
        SELECT language, COUNT(*) as count 
        FROM prompts 
        WHERE user_id = ? 
        GROUP BY language
      `);
      const languageResults = await languageStmt.bind(userId).all();
      
      // Convert to objects
      const promptsByDomain: Record<string, number> = {};
      domainResults.results.forEach((row: any) => {
        promptsByDomain[row.domain] = row.count;
      });
      
      const promptsByType: Record<string, number> = {};
      typeResults.results.forEach((row: any) => {
        promptsByType[row.prompt_type] = row.count;
      });
      
      const promptsByLanguage: Record<string, number> = {};
      languageResults.results.forEach((row: any) => {
        promptsByLanguage[row.language] = row.count;
      });
      
      return {
        totalPrompts: totalResult?.total || 0,
        favoritePrompts: favoriteResult?.total || 0,
        promptsByDomain,
        promptsByType,
        promptsByLanguage
      };
      
    } catch (error) {
      console.error('Error getting prompt stats:', error);
      throw new PromptError('Failed to retrieve prompt statistics', 'STATS_FAILED', 500);
    }
  }
}