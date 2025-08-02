import React from 'react';
import { FileText, Archive, BookOpen } from 'lucide-react';

const FloatingLibraryButton = ({ onOpenLibrary, promptCount, language = 'fr' }) => {
  // Ne pas afficher si aucun prompt sauvé
  if (!promptCount || promptCount === 0) return null;
  
  // Textes selon la langue
  const texts = {
    fr: {
      saved: promptCount === 1 ? 'prompt sauvé' : 'prompts sauvés',
      library: 'Ma bibliothèque',
      access: 'Accéder à mes prompts'
    },
    en: {
      saved: promptCount === 1 ? 'saved prompt' : 'saved prompts',
      library: 'My library',
      access: 'Access my prompts'
    }
  };
  
  const t = texts[language] || texts.fr;
  
  return React.createElement("div", { 
    className: "fixed bottom-20 right-6 z-40" // Décalé vers le haut pour éviter conflit avec notifications
  },
    React.createElement("button", {
      onClick: onOpenLibrary,
      className: "group bg-brand-primary-accent hover:bg-brand-primary-accent/90 text-white rounded-full shadow-lg hover:shadow-xl transition-all duration-300 transform hover:scale-105 focus:outline-none focus:ring-4 focus:ring-brand-primary-accent/30",
      title: t.access
    },
      // Container principal du bouton
      React.createElement("div", { className: "flex items-center" },
        // Partie icône (toujours visible)
        React.createElement("div", { className: "p-4" },
          React.createElement(BookOpen, { className: "w-6 h-6" })
        ),
        
        // Partie texte (visible au hover sur desktop)
        React.createElement("div", { 
          className: "hidden md:group-hover:block pr-4 transition-all duration-300 overflow-hidden"
        },
          React.createElement("div", { className: "whitespace-nowrap" },
            React.createElement("div", { className: "text-sm font-semibold" }, t.library),
            React.createElement("div", { className: "text-xs opacity-90" }, 
              `${promptCount} ${t.saved}`
            )
          )
        )
      ),
      
      // Badge compteur (toujours visible)
      promptCount > 0 && React.createElement("div", {
        className: "absolute -top-2 -right-2 bg-brand-secondary-accent text-brand-text text-xs rounded-full min-w-6 h-6 flex items-center justify-center font-bold border-2 border-white shadow-sm"
      }, promptCount > 99 ? "99+" : promptCount.toString())
    ),
    
    // Version mobile: texte en dessous
    React.createElement("div", { 
      className: "md:hidden text-center mt-2"
    },
      React.createElement("div", { 
        className: "text-xs text-brand-muted-text font-medium bg-white/90 rounded px-2 py-1 shadow-sm"
      }, `${promptCount} ${t.saved}`)
    )
  );
};

export default FloatingLibraryButton;