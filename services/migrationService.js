/**
 * localStorage Migration Service for Teachinspire Prompt Builder
 * 
 * Handles migration of prompts from localStorage to backend database
 * Features:
 * - Detects localStorage prompts and migrates on authentication
 * - Batch processing for efficient API usage
 * - Comprehensive error handling with retry logic
 * - Progress tracking and user feedback
 * - Data validation and format conversion
 * - Backup mechanism before clearing localStorage
 */

import apiService from './apiService.js';

// Constants
const LOCALSTORAGE_KEY = 'teachinspire-prompts';
const MIGRATION_STATUS_KEY = 'teachinspire-migration-status';
const BACKUP_KEY = 'teachinspire-prompts-backup';
const BATCH_SIZE = 5; // Process prompts in batches of 5
const MAX_RETRIES = 3;
const RETRY_DELAY = 2000; // 2 seconds

/**
 * Migration Service Class
 */
class MigrationService {
  constructor() {
    this.isRunning = false;
    this.progress = {
      total: 0,
      completed: 0,
      failed: 0,
      status: 'idle' // idle, running, completed, failed
    };
    this.listeners = new Set();
  }

  /**
   * Add progress listener
   */
  addProgressListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  /**
   * Notify all progress listeners
   */
  notifyProgress() {
    this.listeners.forEach(callback => {
      try {
        callback(this.progress);
      } catch (error) {
        console.error('Error in migration progress listener:', error);
      }
    });
  }

  /**
   * Update progress state and notify listeners
   */
  updateProgress(updates) {
    this.progress = { ...this.progress, ...updates };
    this.notifyProgress();
  }

  /**
   * Check if migration is needed
   * Returns true if localStorage has prompts but user hasn't migrated yet
   */
  isMigrationNeeded() {
    try {
      const localPrompts = this.getLocalStoragePrompts();
      const migrationStatus = this.getMigrationStatus();
      
      return localPrompts.length > 0 && !migrationStatus.completed;
    } catch (error) {
      console.error('Error checking migration status:', error);
      return false;
    }
  }

  /**
   * Get prompts from localStorage
   */
  getLocalStoragePrompts() {
    try {
      const stored = localStorage.getItem(LOCALSTORAGE_KEY);
      if (!stored) return [];
      
      const prompts = JSON.parse(stored);
      return Array.isArray(prompts) ? prompts : [];
    } catch (error) {
      console.error('Error reading localStorage prompts:', error);
      return [];
    }
  }

  /**
   * Get migration status from localStorage
   */
  getMigrationStatus() {
    try {
      const stored = localStorage.getItem(MIGRATION_STATUS_KEY);
      if (!stored) return { completed: false, timestamp: null };
      
      return JSON.parse(stored);
    } catch (error) {
      console.error('Error reading migration status:', error);
      return { completed: false, timestamp: null };
    }
  }

  /**
   * Set migration status in localStorage
   */
  setMigrationStatus(status) {
    try {
      localStorage.setItem(MIGRATION_STATUS_KEY, JSON.stringify({
        completed: status.completed,
        timestamp: Date.now(),
        totalMigrated: status.totalMigrated || 0,
        totalFailed: status.totalFailed || 0
      }));
    } catch (error) {
      console.error('Error saving migration status:', error);
    }
  }

  /**
   * Create backup of localStorage prompts
   */
  createBackup(prompts) {
    try {
      const backup = {
        prompts,
        timestamp: Date.now(),
        version: '1.0'
      };
      localStorage.setItem(BACKUP_KEY, JSON.stringify(backup));
      return true;
    } catch (error) {
      console.error('Error creating backup:', error);
      return false;
    }
  }

  /**
   * Generate a better title for migrated prompts
   */
  generateMigrationTitle(oldPrompt) {
    if (!oldPrompt.rawRequest) return 'Prompt Migré';
    
    const rawRequest = oldPrompt.rawRequest.toLowerCase();
    const domain = oldPrompt.domain || 'other';
    
    // Simple action detection for migration
    let actionWord = '';
    if (/créer|génér|développ|concevoir/.test(rawRequest)) actionWord = 'Création';
    else if (/transform|convert|adapt/.test(rawRequest)) actionWord = 'Transformation';
    else if (/analys|évalu|étudi/.test(rawRequest)) actionWord = 'Analyse';
    else if (/enseign|form|apprend/.test(rawRequest)) actionWord = 'Formation';
    else if (/organis|planifi/.test(rawRequest)) actionWord = 'Organisation';
    
    // Domain-specific words
    const domainWords = {
      education: 'Cours',
      technical: 'Solution',
      creative: 'Création',
      analysis: 'Analyse',
      other: 'Projet'
    };
    
    // Create title
    let title = '';
    if (actionWord) {
      title = `${actionWord} ${domainWords[domain] || 'Projet'}`;
    } else {
      title = `${domainWords[domain] || 'Projet'} ${oldPrompt.type || 'MVP'}`;
    }
    
    // Ensure reasonable length
    if (title.length < 10) {
      title = oldPrompt.rawRequest.substring(0, 47).trim() + (oldPrompt.rawRequest.length > 47 ? '...' : '');
    }
    
    return title;
  }

  /**
   * Convert old SavedPrompt format to new API format
   */
  convertPromptFormat(oldPrompt) {
    try {
      // Generate a better title for the migrated prompt
      const title = this.generateMigrationTitle(oldPrompt);

      // Map the old format to new API format (using snake_case as expected by API)
      const converted = {
        raw_request: oldPrompt.rawRequest || '',
        generated_prompt: oldPrompt.generatedPrompt || '',
        prompt_type: oldPrompt.type === 'AGENTIQUE' ? 'AGENTIC' : (oldPrompt.type || 'MVP'),
        domain: oldPrompt.domain || 'other',
        language: oldPrompt.language || 'fr',
        output_length: 'medium', // Default since this wasn't in old format
        title: title,
        is_favorite: oldPrompt.favorite || false,
        // Optional fields - set to empty strings if not available (API might require them)
        expert_role: '',
        mission: oldPrompt.rawRequest || '', // Use rawRequest as mission for migration
        constraints: ''
      };

      return converted;
    } catch (error) {
      console.error('Error converting prompt format:', error);
      throw new Error(`Failed to convert prompt: ${error.message}`);
    }
  }

  /**
   * Validate converted prompt data
   */
  validatePromptData(prompt) {
    const errors = [];

    if (!prompt.raw_request || typeof prompt.raw_request !== 'string') {
      errors.push('raw_request is required');
    } else if (prompt.raw_request.length > 5000) {
      errors.push('raw_request too long');
    }

    if (!prompt.generated_prompt || typeof prompt.generated_prompt !== 'string') {
      errors.push('generated_prompt is required');
    } else if (prompt.generated_prompt.length > 10000) {
      errors.push('generated_prompt too long');
    }

    if (!['MVP', 'AGENTIC'].includes(prompt.prompt_type)) {
      errors.push('Invalid prompt_type');
    }

    if (!['education', 'technical', 'creative', 'analysis', 'other'].includes(prompt.domain)) {
      errors.push('Invalid domain');
    }

    if (!['fr', 'en'].includes(prompt.language)) {
      errors.push('Invalid language');
    }

    if (!['short', 'medium', 'long'].includes(prompt.output_length)) {
      errors.push('Invalid output_length');
    }

    return errors;
  }

  /**
   * Upload a single prompt with retry logic
   */
  async uploadPromptWithRetry(prompt, retryCount = 0) {
    try {
      const convertedPrompt = this.convertPromptFormat(prompt);
      
      // Validate the converted prompt
      const validationErrors = this.validatePromptData(convertedPrompt);
      if (validationErrors.length > 0) {
        throw new Error(`Validation failed: ${validationErrors.join(', ')}`);
      }

      const result = await apiService.createPrompt(convertedPrompt);
      return { success: true, result, originalId: prompt.id };
    } catch (error) {
      console.error(`Upload attempt ${retryCount + 1} failed for prompt ${prompt.id}:`, error);
      
      if (retryCount < MAX_RETRIES) {
        // Wait before retrying
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * (retryCount + 1)));
        return this.uploadPromptWithRetry(prompt, retryCount + 1);
      }
      
      return { 
        success: false, 
        error: error.message, 
        originalId: prompt.id,
        retries: retryCount + 1
      };
    }
  }

  /**
   * Process a batch of prompts
   */
  async processBatch(prompts) {
    const batchResults = await Promise.allSettled(
      prompts.map(prompt => this.uploadPromptWithRetry(prompt))
    );

    const results = batchResults.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          success: false,
          error: result.reason?.message || 'Unknown error',
          originalId: prompts[index]?.id || 'unknown',
          retries: 0
        };
      }
    });

    return results;
  }

  /**
   * Main migration method
   */
  async migratePrompts(progressCallback = null) {
    if (this.isRunning) {
      throw new Error('Migration is already running');
    }

    try {
      this.isRunning = true;
      
      // Get localStorage prompts
      const localPrompts = this.getLocalStoragePrompts();
      
      if (localPrompts.length === 0) {
        this.updateProgress({
          status: 'completed',
          total: 0,
          completed: 0,
          failed: 0
        });
        return { success: true, total: 0, migrated: 0, failed: 0 };
      }

      // Initialize progress
      this.updateProgress({
        status: 'running',
        total: localPrompts.length,
        completed: 0,
        failed: 0
      });

      // Create backup
      const backupCreated = this.createBackup(localPrompts);
      if (!backupCreated) {
        console.warn('Failed to create backup, continuing with migration');
      }

      // Process prompts in batches
      const results = [];
      const batches = [];
      
      for (let i = 0; i < localPrompts.length; i += BATCH_SIZE) {
        batches.push(localPrompts.slice(i, i + BATCH_SIZE));
      }

      for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
        const batch = batches[batchIndex];
        
        try {
          const batchResults = await this.processBatch(batch);
          results.push(...batchResults);
          
          // Update progress
          const completed = results.filter(r => r.success).length;
          const failed = results.filter(r => !r.success).length;
          
          this.updateProgress({
            completed,
            failed
          });

          // Optional callback for external progress tracking
          if (progressCallback) {
            progressCallback({
              batch: batchIndex + 1,
              totalBatches: batches.length,
              completed,
              failed,
              total: localPrompts.length
            });
          }

          // Small delay between batches to avoid overwhelming the API
          if (batchIndex < batches.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 500));
          }
        } catch (error) {
          console.error(`Batch ${batchIndex + 1} failed:`, error);
          // Continue with next batch even if current batch fails
          results.push(...batch.map(prompt => ({
            success: false,
            error: `Batch processing failed: ${error.message}`,
            originalId: prompt.id,
            retries: 0
          })));
        }
      }

      // Calculate final results
      const successfulMigrations = results.filter(r => r.success);
      const failedMigrations = results.filter(r => !r.success);

      // Update final progress
      this.updateProgress({
        status: failedMigrations.length === 0 ? 'completed' : 'completed_with_errors',
        completed: successfulMigrations.length,
        failed: failedMigrations.length
      });

      // Save migration status
      this.setMigrationStatus({
        completed: true,
        totalMigrated: successfulMigrations.length,
        totalFailed: failedMigrations.length
      });

      // Clear localStorage only if we had some successful migrations
      if (successfulMigrations.length > 0) {
        this.clearLocalStoragePrompts();
      }

      const migrationResult = {
        success: successfulMigrations.length > 0,
        total: localPrompts.length,
        migrated: successfulMigrations.length,
        failed: failedMigrations.length,
        errors: failedMigrations.map(f => ({
          id: f.originalId,
          error: f.error,
          retries: f.retries
        }))
      };

      return migrationResult;

    } catch (error) {
      console.error('Migration failed:', error);
      
      this.updateProgress({
        status: 'failed'
      });

      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Clear localStorage prompts after successful migration
   */
  clearLocalStoragePrompts() {
    try {
      localStorage.removeItem(LOCALSTORAGE_KEY);
      console.log('Cleared localStorage prompts after successful migration');
    } catch (error) {
      console.error('Error clearing localStorage prompts:', error);
    }
  }

  /**
   * Reset migration status (for testing or retry scenarios)
   */
  resetMigrationStatus() {
    try {
      localStorage.removeItem(MIGRATION_STATUS_KEY);
      this.updateProgress({
        total: 0,
        completed: 0,
        failed: 0,
        status: 'idle'
      });
    } catch (error) {
      console.error('Error resetting migration status:', error);
    }
  }

  /**
   * Get backup data
   */
  getBackupData() {
    try {
      const stored = localStorage.getItem(BACKUP_KEY);
      if (!stored) return null;
      
      return JSON.parse(stored);
    } catch (error) {
      console.error('Error reading backup data:', error);
      return null;
    }
  }

  /**
   * Restore from backup (emergency function)
   */
  restoreFromBackup() {
    try {
      const backup = this.getBackupData();
      if (!backup || !backup.prompts) {
        throw new Error('No backup data found');
      }

      localStorage.setItem(LOCALSTORAGE_KEY, JSON.stringify(backup.prompts));
      this.resetMigrationStatus();
      
      return {
        success: true,
        restored: backup.prompts.length,
        backupTimestamp: backup.timestamp
      };
    } catch (error) {
      console.error('Error restoring from backup:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get current migration progress
   */
  getProgress() {
    return { ...this.progress };
  }

  /**
   * Check if migration is currently running
   */
  isRunning() {
    return this.isRunning;
  }
}

// Create singleton instance
const migrationService = new MigrationService();

export default migrationService;