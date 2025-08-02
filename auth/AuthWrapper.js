import React, { useState, useEffect } from 'react';
import { Loader2, Languages } from 'lucide-react';
import { useAuth } from './AuthContext.js';
import Login from './Login.js';
import Register from './Register.js';
import MigrationDialog from '../components/MigrationDialog.js';

const AuthWrapper = ({ children, translations, language, onLanguageChange }) => {
  const { 
    isAuthenticated, 
    isLoading, 
    migrationStatus, 
    runMigration, 
    skipMigration, 
    retryMigration 
  } = useAuth();
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'register'
  
  // Use the language from props instead of local state
  const currentLanguage = language || 'fr';
  
  // Get the current language translations
  const t = translations[currentLanguage];
  
  // Handle language toggle
  const toggleLanguage = () => {
    const newLanguage = currentLanguage === 'fr' ? 'en' : 'fr';
    if (onLanguageChange) {
      onLanguageChange(newLanguage);
    }
  };

  // Show loading spinner while checking authentication status
  if (isLoading) {
    return React.createElement("div", { className: "min-h-screen bg-brand-bg flex items-center justify-center" },
      React.createElement("div", { className: "text-center" },
        React.createElement("img", {
          src: "https://res.cloudinary.com/ducvoebot/image/upload/v1747991665/Teachinspire_logo_transparent_yjt3uf.png",
          alt: "Teachinspire Logo",
          className: "mx-auto h-16 w-auto mb-6"
        }),
        React.createElement(Loader2, { className: "w-8 h-8 animate-spin text-brand-primary-accent mx-auto mb-4" }),
        React.createElement("p", { className: "text-brand-muted-text" }, t.auth.loading || "Loading...")
      )
    );
  }

  // Show authentication forms if not authenticated
  if (!isAuthenticated) {
    const authComponent = authMode === 'login' 
      ? React.createElement(Login, {
          onSwitchToRegister: () => setAuthMode('register'),
          translations: t
        })
      : React.createElement(Register, {
          onSwitchToLogin: () => setAuthMode('login'),
          translations: t
        });

    return React.createElement("div", { className: "min-h-screen bg-brand-bg" },
      // Language toggle in top right corner
      React.createElement("div", { className: "absolute top-4 right-4" },
        React.createElement("button", {
          onClick: toggleLanguage,
          className: "flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-brand-primary-accent/10 text-brand-primary-accent transition-colors",
          "aria-label": currentLanguage === 'fr' ? 'Switch to English' : 'Passer au Français'
        },
          React.createElement(Languages, { className: "w-5 h-5" }),
          React.createElement("span", { className: "font-medium" }, currentLanguage.toUpperCase())
        )
      ),
      authComponent
    );
  }

  // Show main app if authenticated
  return React.createElement(React.Fragment, null,
    children,
    // Migration dialog overlay
    React.createElement(MigrationDialog, {
      migrationStatus,
      onStartMigration: runMigration,
      onRetryMigration: retryMigration,
      onSkipMigration: skipMigration,
      translations: t,
      language: currentLanguage
    })
  );
};

export default AuthWrapper;