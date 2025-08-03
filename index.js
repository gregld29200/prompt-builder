
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.js';

// Global function to communicate language changes from landing page to React app
let appLanguageCallback = null;

window.setAppLanguage = (language) => {
  if (appLanguageCallback) {
    appLanguageCallback(language);
  }
};

// Enhanced App wrapper to handle language synchronization
const AppWithLanguageSync = () => {
  // Get current language from landing page or localStorage
  const getCurrentLanguage = () => {
    const urlLang = new URLSearchParams(window.location.search).get('lang');
    const storedLang = localStorage.getItem('preferred-language');
    const htmlLang = document.documentElement.lang;
    return urlLang || storedLang || htmlLang || 'fr';
  };

  const [initialLanguage, setInitialLanguage] = React.useState(getCurrentLanguage());

  React.useEffect(() => {
    // Register callback for language changes from landing page
    appLanguageCallback = setInitialLanguage;
    
    // Sync with landing page language on mount
    const currentLandingLang = getCurrentLanguage();
    if (currentLandingLang !== initialLanguage) {
      setInitialLanguage(currentLandingLang);
    }
    
    // Clean up on unmount
    return () => {
      appLanguageCallback = null;
    };
  }, []);

  return React.createElement(App, {
    initialLanguage: initialLanguage,
    onLanguageChange: (newLang) => {
      setInitialLanguage(newLang);
      localStorage.setItem('preferred-language', newLang);
      // Also update the HTML lang attribute
      document.documentElement.lang = newLang;
    }
  });
};

// Mount the app to #app instead of #root
const container = document.getElementById('app');
if (container) {
  const root = createRoot(container);
  root.render(React.createElement(AppWithLanguageSync));
} else {
  console.error('App container not found');
}
