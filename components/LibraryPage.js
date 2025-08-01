import React, { useState, useEffect } from 'react';
import { ArrowLeft, Search, Filter, Grid, List, Loader2 } from 'lucide-react';
import apiService from '../services/apiService.js';
import { useAuth } from '../auth/AuthContext.js';
import PromptCard from './PromptCard.js';

/**
 * LibraryPage Component - Dedicated page for browsing and managing saved prompts
 * 
 * Features:
 * - Premium layout with clean design
 * - Loading states and error handling
 * - Integration with existing API endpoints
 * - Responsive grid layout
 * - Navigation breadcrumbs
 */
const LibraryPage = ({ translations, onNavigateBack, onLoadPrompt }) => {
  const { user } = useAuth();
  const [prompts, setPrompts] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  
  const t = translations;

  // Load prompts on component mount
  useEffect(() => {
    const loadPrompts = async () => {
      if (!user) return;
      
      setIsLoading(true);
      setError(null);
      
      try {
        const response = await apiService.getPrompts(1, 50);
        setPrompts(response.data || []);
      } catch (err) {
        console.error('Failed to load prompts:', err);
        setError(err.message || 'Failed to load prompts');
      } finally {
        setIsLoading(false);
      }
    };

    loadPrompts();
  }, [user]);

  // Handle prompt deletion
  const handleDeletePrompt = async (promptId) => {
    try {
      await apiService.deletePrompt(promptId);
      setPrompts(prev => prev.filter(prompt => prompt.id !== promptId));
    } catch (err) {
      console.error('Failed to delete prompt:', err);
      setError(err.message || 'Failed to delete prompt');
    }
  };

  // Filter prompts based on search term
  const filteredPrompts = prompts.filter(prompt => {
    if (!searchTerm) return true;
    const rawRequest = prompt.raw_request || prompt.rawRequest || '';
    return rawRequest.toLowerCase().includes(searchTerm.toLowerCase());
  });

  return React.createElement("div", { className: "min-h-screen bg-brand-bg" },
    // Header Section
    React.createElement("div", { className: "bg-brand-card-bg/95 backdrop-blur-md shadow-brand sticky top-0 z-10 border-b border-gray-100/60" },
      React.createElement("div", { className: "container mx-auto px-4 sm:px-6 lg:px-8 py-6" },
        // Navigation breadcrumbs
        React.createElement("div", { className: "flex items-center gap-3 mb-4" },
          React.createElement("button", {
            onClick: onNavigateBack,
            className: "flex items-center gap-2 text-brand-primary-accent hover:text-brand-primary-accent/80 hover:bg-brand-primary-accent/10 px-3 py-2 rounded-lg transition-all duration-200 font-medium"
          },
            React.createElement(ArrowLeft, { className: "w-5 h-5" }),
            React.createElement("span", null, "Retour à l'app")
          ),
          React.createElement("span", { className: "text-brand-muted-text" }, "/"),
          React.createElement("span", { className: "text-brand-text font-medium" }, t.library.title)
        ),
        
        // Page Title and Stats
        React.createElement("div", { className: "flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4" },
          React.createElement("div", null,
            React.createElement("h1", { className: "font-playfair text-2xl md:text-3xl font-bold text-brand-text" }, 
              t.library.title
            ),
            React.createElement("p", { className: "text-brand-muted-text mt-1" },
              filteredPrompts.length, " prompt", filteredPrompts.length !== 1 ? "s" : "", " disponible", filteredPrompts.length !== 1 ? "s" : ""
            )
          ),
          
          // View mode toggle
          React.createElement("div", { className: "flex items-center gap-1 bg-brand-bg rounded-lg p-1 shadow-sm border border-gray-100/60" },
            React.createElement("button", {
              onClick: () => setViewMode('grid'),
              className: `p-2.5 rounded-md transition-all duration-200 ${viewMode === 'grid' ? 'bg-brand-primary-accent text-white shadow-sm' : 'text-brand-muted-text hover:text-brand-text hover:bg-white'}`
            },
              React.createElement(Grid, { className: "w-4 h-4" })
            ),
            React.createElement("button", {
              onClick: () => setViewMode('list'),
              className: `p-2.5 rounded-md transition-all duration-200 ${viewMode === 'list' ? 'bg-brand-primary-accent text-white shadow-sm' : 'text-brand-muted-text hover:text-brand-text hover:bg-white'}`
            },
              React.createElement(List, { className: "w-4 h-4" })
            )
          )
        )
      )
    ),

    // Main Content
    React.createElement("div", { className: "container mx-auto px-4 sm:px-6 lg:px-8 py-8" },
      // Search and Filters
      React.createElement("div", { className: "mb-8" },
        React.createElement("div", { className: "relative max-w-md" },
          React.createElement(Search, { className: "absolute left-3 top-1/2 transform -translate-y-1/2 text-brand-muted-text w-5 h-5" }),
          React.createElement("input", {
            type: "text",
            placeholder: "Rechercher dans mes prompts...",
            value: searchTerm,
            onChange: (e) => setSearchTerm(e.target.value),
            className: "w-full pl-10 pr-4 py-3 border-2 border-gray-200/80 rounded-xl focus:border-brand-primary-accent focus:ring-2 focus:ring-brand-primary-accent/20 outline-none text-base bg-brand-card-bg shadow-sm transition-all duration-200 hover:border-gray-300"
          })
        )
      ),

      // Content Area
      React.createElement("div", { className: "min-h-[400px]" },
        // Loading State
        isLoading && React.createElement("div", { className: "flex flex-col items-center justify-center py-16" },
          React.createElement(Loader2, { className: "w-8 h-8 animate-spin text-brand-primary-accent mb-4" }),
          React.createElement("p", { className: "text-brand-muted-text text-lg" }, "Chargement de vos prompts...")
        ),

        // Error State
        error && !isLoading && React.createElement("div", { className: "bg-brand-error/10 border border-brand-error/20 rounded-lg p-6 text-center" },
          React.createElement("p", { className: "text-brand-error font-medium mb-2" }, "Erreur de chargement"),
          React.createElement("p", { className: "text-brand-muted-text" }, error)
        ),

        // Empty State
        !isLoading && !error && filteredPrompts.length === 0 && React.createElement("div", { className: "text-center py-16" },
          React.createElement("div", { className: "mb-4" },
            React.createElement("div", { className: "w-16 h-16 mx-auto bg-brand-primary-accent/10 rounded-full flex items-center justify-center mb-4" },
              React.createElement(Search, { className: "w-8 h-8 text-brand-primary-accent" })
            )
          ),
          React.createElement("h3", { className: "text-xl font-semibold text-brand-text mb-2" },
            searchTerm ? "Aucun résultat trouvé" : t.library.empty
          ),
          React.createElement("p", { className: "text-brand-muted-text max-w-md mx-auto" },
            searchTerm 
              ? `Aucun prompt ne correspond à "${searchTerm}". Essayez un autre terme de recherche.`
              : "Vous n'avez pas encore sauvegardé de prompts. Commencez par créer votre premier prompt !"
          )
        ),

        // Prompts Grid/List
        !isLoading && !error && filteredPrompts.length > 0 && React.createElement("div", { 
          className: viewMode === 'grid' 
            ? "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
            : "space-y-4"
        },
          filteredPrompts.map(prompt => 
            React.createElement(PromptCard, {
              key: prompt.id,
              prompt: prompt,
              translations: translations,
              viewMode: viewMode,
              onUsePrompt: () => onLoadPrompt(prompt),
              onDeletePrompt: () => handleDeletePrompt(prompt.id)
            })
          )
        )
      )
    )
  );
};

export default LibraryPage;