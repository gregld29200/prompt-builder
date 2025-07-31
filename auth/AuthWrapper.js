import React, { useState, useEffect } from 'react';
import { Loader2 } from 'lucide-react';
import { useAuth } from './AuthContext.js';
import Login from './Login.js';
import Register from './Register.js';
import MigrationDialog from '../components/MigrationDialog.js';

const AuthWrapper = ({ children, translations }) => {
  const { 
    isAuthenticated, 
    isLoading, 
    migrationStatus, 
    runMigration, 
    skipMigration, 
    retryMigration 
  } = useAuth();
  const [authMode, setAuthMode] = useState('login'); // 'login' or 'register'
  const [currentLanguage, setCurrentLanguage] = useState('fr');
  
  // Get the current language translations
  const t = translations[currentLanguage];

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
    if (authMode === 'login') {
      return React.createElement(Login, {
        onSwitchToRegister: () => setAuthMode('register'),
        translations: t
      });
    } else {
      return React.createElement(Register, {
        onSwitchToLogin: () => setAuthMode('login'),
        translations: t
      });
    }
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