import React from 'react';
import { ChevronRight } from 'lucide-react';

const QuickStartSelector = ({ translations, onSelectMode, selectedMode, language }) => {
  const options = translations.quickStart || {};
  
  // Fallback si pas de traductions
  if (!options || Object.keys(options).length === 0) {
    return null;
  }
  
  return React.createElement("div", { className: "bg-brand-card-bg rounded-lg p-6 mb-6 shadow-brand" },
    React.createElement("h3", { 
      className: "text-lg font-semibold text-brand-text mb-4 text-center" 
    }, 
      language === 'fr' ? "Comment souhaitez-vous procéder ?" : "How would you like to proceed?"
    ),
    React.createElement("div", { className: "grid md:grid-cols-2 gap-4" },
      Object.entries(options).map(([key, option]) =>
        React.createElement("button", {
          key,
          onClick: () => onSelectMode(key),
          className: `p-6 rounded-lg border-2 transition-all text-left hover:scale-105 transform ${
            selectedMode === key 
              ? 'border-brand-primary-accent bg-brand-primary-accent/10 shadow-lg' 
              : 'border-gray-200 hover:border-brand-primary-accent/50 hover:shadow-md'
          }`
        },
          React.createElement("div", { className: "flex items-start justify-between" },
            React.createElement("div", { className: "flex-1" },
              React.createElement("div", { className: "flex items-center gap-3 mb-2" },
                React.createElement("span", { className: "text-2xl" }, option.icon),
                React.createElement("h4", { className: "font-bold text-brand-text text-lg" }, option.title)
              ),
              React.createElement("p", { className: "text-sm font-medium text-brand-primary-accent mb-2" }, option.subtitle),
              React.createElement("p", { className: "text-sm text-brand-muted-text leading-relaxed" }, option.description)
            ),
            React.createElement(ChevronRight, { 
              className: `w-6 h-6 text-brand-primary-accent flex-shrink-0 transition-transform ${
                selectedMode === key ? 'transform rotate-90' : ''
              }` 
            })
          )
        )
      )
    )
  );
};

export default QuickStartSelector;