import React, { useState } from 'react';
import { HelpCircle, Lightbulb, Sparkles } from 'lucide-react';

const ContextualHelper = ({ field, domain, helpers, onSuggestionClick, language = 'fr' }) => {
  const [showTooltip, setShowTooltip] = useState(false);
  const helper = helpers[domain]?.[field];
  
  // Si pas de helper pour ce domaine/champ, ne rien afficher
  if (!helper) return null;
  
  // Textes selon la langue
  const texts = {
    fr: {
      suggestions: "Suggestions :",
      clickToUse: "Cliquer pour utiliser"
    },
    en: {
      suggestions: "Suggestions:",
      clickToUse: "Click to use"
    }
  };
  
  const t = texts[language] || texts.fr;
  
  return React.createElement("div", { className: "relative inline-block" },
    // Bouton d'aide
    React.createElement("button", {
      type: "button",
      onMouseEnter: () => setShowTooltip(true),
      onMouseLeave: () => setShowTooltip(false),
      onClick: () => setShowTooltip(!showTooltip),
      className: "text-brand-primary-accent hover:text-brand-text transition-colors p-1 rounded-full hover:bg-brand-primary-accent/10",
      title: helper.tip
    },
      React.createElement(HelpCircle, { className: "w-5 h-5" })
    ),
    
    // Tooltip avec suggestions
    showTooltip && React.createElement("div", {
      className: "absolute z-20 left-6 top-0 bg-white border border-gray-200 rounded-lg shadow-lg p-4 w-80 transform transition-all duration-200 scale-100",
      onMouseEnter: () => setShowTooltip(true),
      onMouseLeave: () => setShowTooltip(false)
    },
      // En-tête avec icône et tip
      React.createElement("div", { className: "flex items-start gap-3 mb-3 pb-3 border-b border-gray-100" },
        React.createElement(Lightbulb, { className: "w-5 h-5 text-brand-secondary-accent flex-shrink-0 mt-0.5" }),
        React.createElement("p", { className: "text-sm text-brand-muted-text leading-relaxed" }, helper.tip)
      ),
      
      // Section suggestions si disponibles
      helper.suggestions && React.createElement("div", { className: "space-y-2" },
        React.createElement("div", { className: "flex items-center gap-2 mb-2" },
          React.createElement(Sparkles, { className: "w-4 h-4 text-brand-primary-accent" }),
          React.createElement("p", { className: "text-sm font-semibold text-brand-text" }, t.suggestions)
        ),
        React.createElement("div", { className: "space-y-1 max-h-32 overflow-y-auto" },
          helper.suggestions.slice(0, 4).map((suggestion, index) =>
            React.createElement("button", {
              key: index,
              onClick: () => {
                onSuggestionClick(suggestion);
                setShowTooltip(false);
              },
              className: "block w-full text-left text-sm text-brand-primary-accent hover:bg-brand-primary-accent/5 p-2 rounded transition-colors border border-transparent hover:border-brand-primary-accent/20",
              title: t.clickToUse
            },
              React.createElement("span", { className: "block" }, suggestion)
            )
          )
        )
      )
    )
  );
};

export default ContextualHelper;