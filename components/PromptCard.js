import React from 'react';
import { FileText, Trash2, Clock, Tag, Globe } from 'lucide-react';

/**
 * PromptCard Component - Clean, premium card for displaying saved prompts
 * 
 * Features:
 * - Premium design with subtle shadows and hover effects
 * - Responsive layout for both grid and list views
 * - Displays key prompt information: title, date, type, domain
 * - Action buttons for using and deleting prompts
 * - Accessible and touch-friendly interactions
 */
const PromptCard = ({ prompt, translations, viewMode = 'grid', onUsePrompt, onDeletePrompt }) => {
  const t = translations;
  
  // Extract prompt data with fallbacks
  const rawRequest = prompt.raw_request || prompt.rawRequest || '';
  const promptType = prompt.prompt_type || prompt.type || 'MVP';
  const domain = prompt.domain || 'other';
  const timestamp = prompt.created_at || prompt.timestamp || Date.now();
  const language = prompt.language || 'fr';
  
  // Format the display title (truncated raw request)
  const displayTitle = rawRequest.length > 80 
    ? rawRequest.substring(0, 80) + '...' 
    : rawRequest || 'Prompt sans titre';
    
  // Format the date
  const formattedDate = new Date(timestamp).toLocaleDateString(language, {
    year: 'numeric',
    month: 'short', 
    day: 'numeric'
  });

  // Get domain label
  const domainLabel = t.domains[domain] || domain;

  // Card classes based on view mode with premium styling
  const cardClasses = viewMode === 'grid'
    ? "bg-brand-card-bg rounded-xl shadow-brand hover:shadow-brand-lg transition-all duration-300 hover:-translate-y-1 border border-gray-100/60 overflow-hidden group backdrop-blur-sm"
    : "bg-brand-card-bg rounded-lg shadow-brand hover:shadow-brand-lg transition-all duration-200 border border-gray-100/60 overflow-hidden group backdrop-blur-sm";

  const contentClasses = viewMode === 'grid' 
    ? "p-6" 
    : "p-4 flex items-center justify-between";

  return React.createElement("div", { className: cardClasses },
    // Grid View Layout
    viewMode === 'grid' && React.createElement("div", { className: contentClasses },
      // Header with type badge
      React.createElement("div", { className: "flex items-start justify-between mb-4" },
        React.createElement("div", { className: "flex items-center gap-2" },
          React.createElement("span", { 
            className: `inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${
              promptType === 'AGENTIC' 
                ? 'bg-brand-secondary-accent/20 text-brand-secondary-accent' 
                : 'bg-brand-primary-accent/20 text-brand-primary-accent'
            }`
          }, promptType)
        ),
        React.createElement("div", { className: "flex items-center gap-1 text-brand-muted-text" },
          React.createElement(Clock, { className: "w-3 h-3" }),
          React.createElement("span", { className: "text-xs" }, formattedDate)
        )
      ),

      // Main content
      React.createElement("div", { className: "mb-6" },
        React.createElement("h3", { 
          className: "font-semibold text-brand-text text-base leading-tight mb-3 group-hover:text-brand-primary-accent transition-colors" 
        }, displayTitle),
        
        // Metadata
        React.createElement("div", { className: "flex items-center gap-4 text-sm text-brand-muted-text" },
          React.createElement("div", { className: "flex items-center gap-1" },
            React.createElement(Tag, { className: "w-3 h-3" }),
            React.createElement("span", null, domainLabel)
          ),
          React.createElement("div", { className: "flex items-center gap-1" },
            React.createElement(Globe, { className: "w-3 h-3" }),
            React.createElement("span", null, language.toUpperCase())
          )
        )
      ),

      // Action buttons
      React.createElement("div", { className: "flex gap-2" },
        React.createElement("button", {
          onClick: onUsePrompt,
          className: "flex-1 px-4 py-2.5 bg-brand-primary-accent text-white rounded-lg font-medium hover:bg-brand-primary-accent/90 hover:shadow-lg transform hover:scale-[1.02] transition-all duration-200 flex items-center justify-center gap-2 text-sm"
        },
          React.createElement(FileText, { className: "w-4 h-4" }),
          t.actions.usePrompt
        ),
        React.createElement("button", {
          onClick: onDeletePrompt,
          className: "px-3 py-2.5 bg-brand-error/10 text-brand-error rounded-lg hover:bg-brand-error hover:text-white hover:shadow-lg transform hover:scale-[1.02] transition-all duration-200 flex items-center justify-center"
        },
          React.createElement(Trash2, { className: "w-4 h-4" })
        )
      )
    ),

    // List View Layout
    viewMode === 'list' && React.createElement("div", { className: contentClasses },
      // Left side - Main content
      React.createElement("div", { className: "flex-1 min-w-0 mr-4" },
        React.createElement("div", { className: "flex items-center gap-3 mb-2" },
          React.createElement("h3", { 
            className: "font-semibold text-brand-text text-base truncate group-hover:text-brand-primary-accent transition-colors" 
          }, displayTitle),
          React.createElement("span", { 
            className: `inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
              promptType === 'AGENTIC' 
                ? 'bg-brand-secondary-accent/20 text-brand-secondary-accent' 
                : 'bg-brand-primary-accent/20 text-brand-primary-accent'
            }`
          }, promptType)
        ),
        React.createElement("div", { className: "flex items-center gap-4 text-sm text-brand-muted-text" },
          React.createElement("div", { className: "flex items-center gap-1" },
            React.createElement(Clock, { className: "w-3 h-3" }),
            React.createElement("span", null, formattedDate)
          ),
          React.createElement("div", { className: "flex items-center gap-1" },
            React.createElement(Tag, { className: "w-3 h-3" }),
            React.createElement("span", null, domainLabel)
          ),
          React.createElement("div", { className: "flex items-center gap-1" },
            React.createElement(Globe, { className: "w-3 h-3" }),
            React.createElement("span", null, language.toUpperCase())
          )
        )
      ),

      // Right side - Actions
      React.createElement("div", { className: "flex items-center gap-2 flex-shrink-0" },
        React.createElement("button", {
          onClick: onUsePrompt,
          className: "px-4 py-2 bg-brand-primary-accent text-white rounded-lg font-medium hover:bg-brand-primary-accent/90 transition-colors flex items-center gap-2 text-sm"
        },
          React.createElement(FileText, { className: "w-4 h-4" }),
          t.actions.usePrompt
        ),
        React.createElement("button", {
          onClick: onDeletePrompt,
          className: "px-3 py-2 bg-brand-error/10 text-brand-error rounded-lg hover:bg-brand-error hover:text-white transition-colors flex items-center justify-center"
        },
          React.createElement(Trash2, { className: "w-4 h-4" })
        )
      )
    )
  );
};

export default PromptCard;