import React from 'react';
import { CheckCircle, AlertCircle, Loader2, RefreshCw, X, Database, Upload, CheckSquare } from 'lucide-react';

/**
 * MigrationDialog Component
 * 
 * Displays migration progress and handles user interactions during localStorage migration
 * Features:
 * - Progress tracking with visual indicators
 * - Error handling with retry options
 * - Bilingual support
 * - Responsive design
 * - Accessible UI elements
 */
const MigrationDialog = ({ 
  migrationStatus, 
  onStartMigration, 
  onRetryMigration, 
  onSkipMigration, 
  translations,
  language = 'fr'
}) => {
  const t = translations.auth.migration;
  
  // Don't render if migration is not needed or already completed
  if (!migrationStatus.isNeeded || migrationStatus.completed) {
    return null;
  }

  const getProgressPercentage = () => {
    if (!migrationStatus.progress || migrationStatus.progress.total === 0) return 0;
    return Math.round((migrationStatus.progress.completed / migrationStatus.progress.total) * 100);
  };

  const getStatusIcon = () => {
    if (migrationStatus.error) {
      return React.createElement(AlertCircle, { className: "w-8 h-8 text-brand-error" });
    }
    
    if (migrationStatus.isRunning) {
      return React.createElement(Loader2, { className: "w-8 h-8 text-brand-primary-accent animate-spin" });
    }
    
    if (migrationStatus.progress?.status === 'completed') {
      return React.createElement(CheckCircle, { className: "w-8 h-8 text-brand-success" });
    }
    
    return React.createElement(Database, { className: "w-8 h-8 text-brand-primary-accent" });
  };

  const getStatusMessage = () => {
    if (migrationStatus.error) {
      return t.failed;
    }
    
    if (!migrationStatus.isRunning && !migrationStatus.progress) {
      return t.description;
    }
    
    if (migrationStatus.progress) {
      const { status, total, completed, failed } = migrationStatus.progress;
      
      switch (status) {
        case 'starting':
          return t.detecting;
        case 'running':
          if (total > 0) {
            return t.progress.replace('{completed}', completed).replace('{total}', total);
          }
          return t.uploading;
        case 'completed':
          if (failed > 0) {
            return t.successWithErrors
              .replace('{migrated}', completed)
              .replace('{failed}', failed);
          }
          return t.success.replace('{migrated}', completed);
        case 'completed_with_errors':
          return t.partialSuccess;
        case 'failed':
          return t.failed;
        default:
          return t.uploading;
      }
    }
    
    return t.uploading;
  };

  const getActionButtons = () => {
    if (migrationStatus.error) {
      return [
        React.createElement("button", {
          key: "retry",
          onClick: onRetryMigration,
          className: "px-4 py-2 bg-brand-primary-accent text-white rounded-lg font-medium hover:bg-opacity-80 transition-colors flex items-center gap-2",
          disabled: migrationStatus.isRunning
        },
          React.createElement(RefreshCw, { className: "w-4 h-4" }),
          t.retry
        ),
        React.createElement("button", {
          key: "skip",
          onClick: onSkipMigration,
          className: "px-4 py-2 border-2 border-gray-300 text-brand-muted-text rounded-lg font-medium hover:bg-gray-100 hover:border-gray-400 transition-colors",
          disabled: migrationStatus.isRunning
        },
          t.skip
        )
      ];
    }
    
    if (migrationStatus.progress?.status === 'completed' || migrationStatus.progress?.status === 'completed_with_errors') {
      return [
        React.createElement("button", {
          key: "close",
          onClick: onSkipMigration, // This will close the dialog
          className: "px-4 py-2 bg-brand-success text-white rounded-lg font-medium hover:bg-opacity-80 transition-colors flex items-center gap-2"
        },
          React.createElement(CheckSquare, { className: "w-4 h-4" }),
          language === 'fr' ? 'Terminé' : 'Done'
        )
      ];
    }
    
    if (migrationStatus.isRunning) {
      return [];
    }
    
    return [
      React.createElement("button", {
        key: "start",
        onClick: onStartMigration,
        className: "px-4 py-2 bg-brand-primary-accent text-white rounded-lg font-medium hover:bg-opacity-80 transition-colors flex items-center gap-2"
      },
        React.createElement(Upload, { className: "w-4 h-4" }),
        language === 'fr' ? 'Commencer la migration' : 'Start Migration'
      ),
      React.createElement("button", {
        key: "skip",
        onClick: onSkipMigration,
        className: "px-4 py-2 border-2 border-gray-300 text-brand-muted-text rounded-lg font-medium hover:bg-gray-100 hover:border-gray-400 transition-colors"
      },
        t.skip
      )
    ];
  };

  return React.createElement("div", { 
    className: "fixed inset-0 bg-black/60 flex items-center justify-center p-4 z-50 backdrop-blur-sm",
    role: "dialog",
    "aria-modal": "true",
    "aria-labelledby": "migration-title"
  },
    React.createElement("div", { className: "bg-brand-card-bg rounded-lg shadow-brand-lg max-w-md w-full p-6" },
      // Header
      React.createElement("div", { className: "flex items-center justify-between mb-6" },
        React.createElement("h2", { 
          id: "migration-title",
          className: "text-xl font-semibold text-brand-text" 
        }, t.title),
        // Don't show close button while migration is running
        !migrationStatus.isRunning && React.createElement("button", {
          onClick: onSkipMigration,
          className: "p-2 hover:bg-gray-100 rounded-full text-brand-muted-text hover:text-brand-text transition-colors",
          "aria-label": language === 'fr' ? 'Fermer' : 'Close'
        },
          React.createElement(X, { className: "w-5 h-5" })
        )
      ),
      
      // Status icon and message
      React.createElement("div", { className: "text-center mb-6" },
        React.createElement("div", { className: "mb-4" }, getStatusIcon()),
        React.createElement("p", { 
          className: "text-brand-text mb-2" 
        }, getStatusMessage()),
        
        // Progress bar (only show when migration is running)
        migrationStatus.isRunning && migrationStatus.progress && migrationStatus.progress.total > 0 && 
        React.createElement("div", { className: "mt-4" },
          React.createElement("div", { className: "w-full bg-gray-200 rounded-full h-2 mb-2" },
            React.createElement("div", {
              className: "bg-brand-primary-accent h-2 rounded-full transition-all duration-300 ease-out",
              style: { width: `${getProgressPercentage()}%` }
            })
          ),
          React.createElement("p", { className: "text-sm text-brand-muted-text" },
            `${getProgressPercentage()}% - ${migrationStatus.progress.completed}/${migrationStatus.progress.total} prompts`
          )
        )
      ),
      
      // Error details (if any)
      migrationStatus.error && React.createElement("div", { 
        className: "bg-brand-error/10 border border-brand-error/20 rounded-lg p-3 mb-4" 
      },
        React.createElement("p", { className: "text-sm text-brand-error" },
          migrationStatus.error
        )
      ),
      
      // Action buttons
      React.createElement("div", { className: "flex gap-3 justify-center" },
        ...getActionButtons()
      )
    )
  );
};

export default MigrationDialog;