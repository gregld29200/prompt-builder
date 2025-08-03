
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
  const [initialLanguage, setInitialLanguage] = React.useState(
    localStorage.getItem('preferred-language') || 'fr'
  );

  React.useEffect(() => {
    // Register callback for language changes from landing page
    appLanguageCallback = setInitialLanguage;
    
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
